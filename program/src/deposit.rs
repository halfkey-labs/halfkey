//! Deposit-address mode, SOL -> XMR (final round).
//!
//! Every order has its own address: the PDA ["order", order_hash] with
//! `order_hash = sha256("halfkey-order-v1" || program id || terms)` over the exact order terms
//! (`ORDER_TERMS_LEN` bytes: maker, amount, XMR amount, the maker's claim point, the user's
//! payout address keys, the refund address R, the deposit deadline, both windows, the quoted fee,
//! the integrator and its share, the tip, the quote hash, and an OTC flag for desk tranches). Nothing is opened in advance: the PDA
//! is a plain system account that only this program can sign for, so a wallet or an exchange
//! withdrawal just sends SOL to it.
//!
//! * `fill_deposit` (tag 44, anyone): before the deadline, with the maker's signature over
//!   `order_hash` in the previous instruction, moves what the escrow needs (amount + tip + rent)
//!   from the order address into a v2 direct-payout escrow ["swap", R, order_hash] whose locker
//!   (refund destination) is R and whose payout is the user's own Monero address. Underpaid:
//!   nothing moves (`Underpaid`). Overpaid: the excess stays at the order address for
//!   `order_refund`, or, below the rent-exempt minimum of an empty account, goes into the escrow
//!   and back to R with its rent at close. An order fills at most once (the escrow closes only
//!   from the deadline, and fills stop at the deadline).
//! * `order_refund` (tag 45, anyone): everything at the order address goes to R, and only to R:
//!   from the deadline, or at once after the fill (over- or late payment), at any time later.
//!   The caller earns the order's tip only for refunding an order that never filled.
//!
//! The escrow then lives as any v2 direct escrow: the maker pays the user's address with this
//! escrow's payment id and proves it (`direct::prove_direct`), anyone finishes with `claim_to`;
//! or at t1 anyone refunds it to R (`refund`, no secret).

use crate::escrow2::{self, Consent, Fund};
use crate::*;

pub const ORDER_SEED: &[u8] = b"order";
pub const ORDER_PREFIX: &[u8] = b"halfkey-order-v1";
pub const ORDER_TERMS_LEN: usize = 277;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrderTerms {
    pub maker: Pubkey,
    pub amount: u64,
    pub xmr_amount: u64,
    /// The maker's claim point (it reveals the scalar at claim; nothing depends on its secrecy).
    pub claim_point: [u8; 32],
    /// The user's own standard Monero address: spend and view public keys.
    pub pay_spend: [u8; 32],
    pub pay_view: [u8; 32],
    /// R: the only place the SOL can ever go back to.
    pub refund: Pubkey,
    pub deadline: i64,
    pub t0_secs: i64,
    pub window_secs: i64,
    pub fee_bps: u16,
    pub integrator: Pubkey,
    pub integrator_bps: u16,
    pub tip: u64,
    pub quote_hash: [u8; 32],
    /// 0, or F_OTC: the order funds an OTC tranche (OTC range, cap and reputation).
    pub flags: u8,
}

impl OrderTerms {
    pub fn parse(b: &[u8]) -> Result<Self, ProgramError> {
        req!(b.len() == ORDER_TERMS_LEN, HkError::BadInstruction);
        let mut r = Rd::new(b);
        let t = Self {
            maker: r.key()?,
            amount: r.u64()?,
            xmr_amount: r.u64()?,
            claim_point: r.b32()?,
            pay_spend: r.b32()?,
            pay_view: r.b32()?,
            refund: r.key()?,
            deadline: r.i64()?,
            t0_secs: r.i64()?,
            window_secs: r.i64()?,
            fee_bps: r.u16()?,
            integrator: r.key()?,
            integrator_bps: r.u16()?,
            tip: r.u64()?,
            quote_hash: r.b32()?,
            flags: r.u8()?,
        };
        r.done()?;
        Ok(t)
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![0u8; ORDER_TERMS_LEN];
        let mut w = Wr::new(&mut v);
        w.put(self.maker.as_ref());
        w.u64(self.amount);
        w.u64(self.xmr_amount);
        w.put(&self.claim_point);
        w.put(&self.pay_spend);
        w.put(&self.pay_view);
        w.put(self.refund.as_ref());
        w.i64(self.deadline);
        w.i64(self.t0_secs);
        w.i64(self.window_secs);
        w.u16(self.fee_bps);
        w.put(self.integrator.as_ref());
        w.u16(self.integrator_bps);
        w.u64(self.tip);
        w.put(&self.quote_hash);
        w.u8(self.flags);
        v
    }
}

/// The order hash over the raw terms bytes (what the maker signs; the escrow's swap id).
pub fn order_hash(pid: &Pubkey, terms: &[u8]) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[ORDER_PREFIX, pid.as_ref(), terms]).to_bytes()
}

/// Parse the terms off the instruction, hash them and check the order account is their PDA.
fn order_of(pid: &Pubkey, r: &mut Rd, order: &AccountInfo) -> Result<(OrderTerms, [u8; 32], u8), ProgramError> {
    let raw = r.take(ORDER_TERMS_LEN)?;
    r.done()?;
    let terms = OrderTerms::parse(raw)?;
    let h = order_hash(pid, raw);
    let (k, b) = Pubkey::find_program_address(&[ORDER_SEED, &h], pid);
    req!(k == *order.key, HkError::BadPda);
    // Only this program can sign for the PDA, and it never allocates or assigns it.
    req!(*order.owner == SYSTEM_PROGRAM && order.data_len() == 0, HkError::BadAccount);
    Ok((terms, h, b))
}

/// Accounts: [filler (signer, w), order (w), escrow (w), maker (w), config (w), system,
///            instructions sysvar, integrator account (only with an integrator)].
/// Data: the order terms (ORDER_TERMS_LEN bytes).
pub(crate) fn fill_deposit(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let filler = next_account_info(it)?;
    let order = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    let system = next_account_info(it)?;
    let ixs = next_account_info(it)?;
    signer(filler)?;
    writable(order)?;
    let (t, h, ob) = order_of(pid, r, order)?;
    let t_now = now()?;
    req!(t_now < t.deadline, HkError::Expired);
    // A deadline beyond MAX_ORDER_LIFE is refundable at once, so never fillable.
    req!(t.deadline - t_now <= final_logic::MAX_ORDER_LIFE, HkError::BadParam);
    // R receives the refund: never the default key (the System Program, which cannot be paid).
    req!(t.refund != Pubkey::default(), HkError::BadParam);
    req!(t.flags & !F_OTC == 0, HkError::BadParam);
    let q = LockReq {
        swap_id: h,
        claimer: t.maker,
        direction: DIR_SOL_TO_XMR,
        amount: t.amount,
        xmr_amount: t.xmr_amount,
        claim_point: t.claim_point,
        refund_point: t.pay_spend,
        view_pub: t.pay_view,
        quote_hash: t.quote_hash,
        t0_secs: t.t0_secs,
        window_secs: t.window_secs,
        wt: [Pubkey::default(); 2],
        consent_expiry: t.deadline,
        flags: F_DIRECT | t.flags,
    };
    let ext = EscrowExt { integrator: t.integrator, integrator_bps: t.integrator_bps, origin: 1, tip: t.tip, order_deadline: t.deadline };
    let integ = if t.integrator != Pubkey::default() { Some(next_account_info(it)?) } else { None };
    let oseeds: &[&[u8]] = &[ORDER_SEED, &h, &[ob]];
    escrow2::open_v2(
        pid, &q, ext, &t.refund, Fund::Order { order, seeds: oseeds }, escrow, maker, config, system, ixs, integ,
        Consent::Order { hash: h, fee_bps: t.fee_bps },
    )
}

/// Accounts: [caller (signer, w), order (w), refund address R (w), escrow ["swap", R, hash], system].
/// Data: the order terms.
pub(crate) fn order_refund(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let caller = next_account_info(it)?;
    let order = next_account_info(it)?;
    let dest = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(caller)?;
    writable(caller)?;
    writable(order)?;
    writable(dest)?;
    req!(*system.key == SYSTEM_PROGRAM, HkError::BadAccount);
    let (t, h, ob) = order_of(pid, r, order)?;
    req!(*dest.key == t.refund, HkError::BadAccount);
    let (ek, _) = Pubkey::find_program_address(&[SWAP_SEED, t.refund.as_ref(), &h], pid);
    req!(ek == *escrow.key, HkError::BadPda);
    // Filled: the escrow at this order's address exists (only this program can create it; before
    // the deadline it cannot have been closed).
    let filled = escrow.owner == pid && escrow.data_len() > 0;
    final_logic::order_refund_allowed(now()?, t.deadline, filled, dest.is_signer)?;
    let bal = order.lamports();
    req!(bal > 0, HkError::NothingPending);
    let (to_r, to_caller) = final_logic::order_refund_split(bal, t.tip, filled, Rent::get()?.minimum_balance(0));
    let seeds: &[&[u8]] = &[ORDER_SEED, &h, &[ob]];
    invoke_signed(
        &solana_system_interface::instruction::transfer(order.key, dest.key, to_r),
        &[order.clone(), dest.clone(), system.clone()],
        &[seeds],
    )?;
    if to_caller > 0 {
        invoke_signed(
            &solana_system_interface::instruction::transfer(order.key, caller.key, to_caller),
            &[order.clone(), caller.clone(), system.clone()],
            &[seeds],
        )?;
    }
    msg!("halfkey: order refunded");
    Ok(())
}
