//! Open offers (final round): the offer board and deal links.
//!
//! A bidder locks SOL in ["offer", bidder, offer_id] for `xmr_amount` piconero to its OWN standard
//! Monero address. Anyone with XMR may fill it:
//!
//! * `offer_take` (tag 58): the filler reserves the offer with a deposit (1%, at least 0.01 SOL)
//!   for `fill_window` (at least MIN_PROOF_WINDOW: broadcast, 10 confirmations, committee slack;
//!   clients default to 24 h). A reservation whose window has passed is forfeited first (the
//!   deposit goes to the bidder) and the offer is taken afresh.
//! * `offer_settle` (tag 59) op 0, release (anyone, inside the window): a direct payment proof
//!   (`direct.rs`) that the bidder's address received at least `xmr_amount` with THIS fill's
//!   payment id `sha256("halfkey-offer-pid-v1" || offer || created_at || fill_seq)[..8]`. The
//!   filler gets the amount minus the protocol fee and the integrator share, plus its deposit
//!   back; the submitter gets the tip; the bidder gets the account rent (the account closes).
//! * op 1, cancel: an open offer by its bidder at any time, by anyone once expired (for the tip);
//!   never during a live reservation. The bidder gets the amount, any forfeited deposit and the
//!   rent.
//! * op 2, forfeit (anyone): a lapsed reservation's deposit to the bidder; the offer reopens.
//!
//! The SOL can only ever go to the bidder or, against a proof for the live fill, to its filler.
//! Offers have their own open-TVL bucket (`config.offer_tvl`, capped at `max_open_tvl`). SOL only (SPL bags reach the board
//! through the any-coin route, which swaps to SOL first).

use crate::direct::{self, PID_DOMAIN_OFFER};
use crate::escrow2::{credit_integrator, load_integrator};
use crate::final_logic::{self, OF_OPEN};
use crate::xmr::{self, Statement};
use crate::*;

pub const OFFER_SEED: &[u8] = b"offer";
pub const DISC_OFFER: u8 = 0x0F;
pub const OFFER_LEN: usize = 296;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Offer {
    pub state: u8,
    pub bump: u8,
    pub offer_id: [u8; 32],
    pub bidder: Pubkey,
    pub amount: u64,
    pub xmr_amount: u64,
    /// The bidder's own standard Monero address.
    pub spend: [u8; 32],
    pub view: [u8; 32],
    pub fee_bps: u16,
    pub integrator_bps: u16,
    pub integrator: Pubkey,
    pub tip: u64,
    pub fill_window: i64,
    pub expires_at: i64,
    pub created_at: i64,
    /// Number of reservations so far (the live one's number while reserved).
    pub fill_seq: u64,
    pub filler: Pubkey,
    pub deposit: u64,
    pub reserved_at: i64,
    pub deadline: i64,
    pub forfeits: u64,
}

impl Offer {
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!(d.len() == OFFER_LEN && d[0] == DISC_OFFER, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let state = r.u8()?;
        let bump = r.u8()?;
        r.skip(4)?;
        Ok(Self {
            state,
            bump,
            offer_id: r.b32()?,
            bidder: r.key()?,
            amount: r.u64()?,
            xmr_amount: r.u64()?,
            spend: r.b32()?,
            view: r.b32()?,
            fee_bps: r.u16()?,
            integrator_bps: {
                let v = r.u16()?;
                r.skip(4)?;
                v
            },
            integrator: r.key()?,
            tip: r.u64()?,
            fill_window: r.i64()?,
            expires_at: r.i64()?,
            created_at: r.i64()?,
            fill_seq: r.u64()?,
            filler: r.key()?,
            deposit: r.u64()?,
            reserved_at: r.i64()?,
            deadline: r.i64()?,
            forfeits: r.u64()?,
        })
    }
    pub fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_OFFER);
        w.u8(1);
        w.u8(self.state);
        w.u8(self.bump);
        w.pad(4);
        w.put(&self.offer_id);
        w.put(self.bidder.as_ref());
        w.u64(self.amount);
        w.u64(self.xmr_amount);
        w.put(&self.spend);
        w.put(&self.view);
        w.u16(self.fee_bps);
        w.u16(self.integrator_bps);
        w.pad(4);
        w.put(self.integrator.as_ref());
        w.u64(self.tip);
        w.i64(self.fill_window);
        w.i64(self.expires_at);
        w.i64(self.created_at);
        w.u64(self.fill_seq);
        w.put(self.filler.as_ref());
        w.u64(self.deposit);
        w.i64(self.reserved_at);
        w.i64(self.deadline);
        w.u64(self.forfeits);
    }
}

fn load_offer(a: &AccountInfo, pid: &Pubkey) -> Result<Offer, ProgramError> {
    owned(a, pid)?;
    let o = Offer::load(&a.try_borrow_data()?)?;
    let k = Pubkey::create_program_address(&[OFFER_SEED, o.bidder.as_ref(), &o.offer_id, &[o.bump]], pid)
        .map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(o)
}

/// Accounts: [bidder (signer, w), offer (w), config (w), system, integrator account (only with an
///            integrator)].
/// Data: offer_id 32, amount u64, xmr_amount u64, spend 32, view 32, integrator 32,
///       integrator_bps u16, tip u64, fill_window i64, life i64.
pub(crate) fn open(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let bidder = next_account_info(it)?;
    let offer = next_account_info(it)?;
    let config = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(bidder)?;
    writable(offer)?;
    writable(config)?;
    let offer_id = r.b32()?;
    let amount = r.u64()?;
    let xmr_amount = r.u64()?;
    let spend = r.b32()?;
    let view = r.b32()?;
    let integrator = r.key()?;
    let integrator_bps = r.u16()?;
    let tip = r.u64()?;
    let fill_window = r.i64()?;
    let life = r.i64()?;
    r.done()?;
    let mut c = load_config(config, pid)?;
    req!(!c.paused, HkError::Paused);
    req!(amount <= c.max_swap, HkError::CapExceeded);
    // Offers have their own open-TVL bucket (same cap): a bidder parking SOL in offers can never
    // fill the escrows' cap and block swaps or deposit fills.
    let tvl = add(c.offer_tvl, amount)?;
    req!(tvl <= c.max_open_tvl, HkError::CapExceeded);
    final_logic::offer_terms(amount, xmr_amount, &integrator, integrator_bps, tip, fill_window, life)?;
    if integrator != Pubkey::default() {
        load_integrator(next_account_info(it)?, pid, &integrator)?;
    }
    req!(spend != view, HkError::BadPoint);
    req!(point_is_prime_order(&spend) && point_is_prime_order(&view), HkError::BadPoint);
    let (k, b) = Pubkey::find_program_address(&[OFFER_SEED, bidder.key.as_ref(), &offer_id], pid);
    req!(k == *offer.key, HkError::BadPda);
    create_pda(bidder, offer, system, pid, OFFER_LEN, &[OFFER_SEED, bidder.key.as_ref(), &offer_id, &[b]])?;
    transfer_in(bidder, offer, system, add(amount, tip)?)?;
    let t = now()?;
    Offer {
        state: OF_OPEN,
        bump: b,
        offer_id,
        bidder: *bidder.key,
        amount,
        xmr_amount,
        spend,
        view,
        fee_bps: c.fee_bps,
        integrator_bps,
        integrator,
        tip,
        fill_window,
        expires_at: t.checked_add(life).ok_or(HkError::Overflow)?,
        created_at: t,
        ..Default::default()
    }
    .store(&mut offer.try_borrow_mut_data()?);
    c.offer_tvl = tvl;
    c.store(&mut config.try_borrow_mut_data()?);
    msg!("halfkey: offer opened");
    Ok(())
}

/// Accounts: [filler (signer, w), offer (w), bidder (w), config, system]. Data: none.
pub(crate) fn take(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let filler = next_account_info(it)?;
    let offer = next_account_info(it)?;
    let bidder = next_account_info(it)?;
    let config = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(filler)?;
    writable(offer)?;
    writable(bidder)?;
    r.done()?;
    let c = load_config(config, pid)?;
    req!(!c.paused, HkError::Paused);
    let mut o = load_offer(offer, pid)?;
    req!(o.bidder == *bidder.key, HkError::BadAccount);
    let (forfeit, dep) = final_logic::offer_take(&mut o, filler.key, now()?)?;
    // The CPI first: the runtime checks lamport sums at every CPI, so no direct debit may be
    // pending across it.
    transfer_in(filler, offer, system, dep)?;
    pay(offer, bidder, forfeit)?;
    o.store(&mut offer.try_borrow_mut_data()?);
    msg!("halfkey: offer reserved (fill {})", o.fill_seq);
    Ok(())
}

/// Accounts:
///   op 0 release: [submitter (signer, w), offer (w), filler (w), bidder (w), config (w),
///                  fee_vault (w), attesters, header, used marker (w), system,
///                  integrator account (w; only with an integrator)]
///                 data: op u8 + the `prove_lock` payload;
///   op 1 cancel:  [who (signer, w), offer (w), bidder (w), config (w)], data: op;
///   op 2 forfeit: [who (signer), offer (w), bidder (w)], data: op.
/// Never paused (exits).
pub(crate) fn settle(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let who = next_account_info(it)?;
    let offer = next_account_info(it)?;
    signer(who)?;
    writable(offer)?;
    let op = r.u8()?;
    let mut o = load_offer(offer, pid)?;
    let t = now()?;
    match op {
        0 => {
            let filler = next_account_info(it)?;
            let bidder = next_account_info(it)?;
            let config = next_account_info(it)?;
            let vault = next_account_info(it)?;
            let att = next_account_info(it)?;
            let hdr = next_account_info(it)?;
            let used = next_account_info(it)?;
            let system = next_account_info(it)?;
            writable(who)?;
            writable(filler)?;
            writable(bidder)?;
            writable(config)?;
            writable(vault)?;
            let p = direct::read_proof(r)?;
            final_logic::offer_release_check(&o, t)?;
            req!(o.filler == *filler.key && o.bidder == *bidder.key, HkError::BadAccount);
            let mut c = load_config(config, pid)?;
            let vk = Pubkey::create_program_address(&[FEE_VAULT_SEED, &[c.vault_bump]], pid).map_err(|_| HkError::BadPda)?;
            req!(vk == *vault.key, HkError::BadPda);
            owned(vault, pid)?;
            let integ = if o.integrator != Pubkey::default() {
                let a = next_account_info(it)?;
                writable(a)?;
                load_integrator(a, pid, &o.integrator)?;
                Some(a)
            } else {
                None
            };
            let m = xmr::escrow_msg(&offer.key.to_bytes());
            let st = Statement { spend: o.spend, view: o.view, min_amount: o.xmr_amount, msg: &m };
            let rp = direct::pid_for(PID_DOMAIN_OFFER, &offer.key.to_bytes(), o.created_at, o.fill_seq, o.filler.as_ref());
            let (v, height, _) = direct::prove_and_burn(pid, who, system, att, hdr, used, &st, &p, &rp, direct::KIND_OFFER, offer.key)?;
            let (to_filler, fee, ifee) = final_logic::split3(o.amount, o.fee_bps, o.integrator_bps)?;
            pay(offer, filler, add(to_filler, o.deposit)?)?;
            pay(offer, vault, fee)?;
            if let Some(a) = integ {
                pay(offer, a, ifee)?;
                credit_integrator(a, pid, &o.integrator, ifee, o.amount)?;
            }
            pay(offer, who, o.tip)?;
            c.offer_tvl = c.offer_tvl.saturating_sub(o.amount);
            // Statistics only: saturating, so they can never block the release.
            c.total_swaps = c.total_swaps.saturating_add(1);
            c.total_volume = c.total_volume.saturating_add(o.amount);
            c.total_fees = c.total_fees.saturating_add(fee);
            c.store(&mut config.try_borrow_mut_data()?);
            msg!("halfkey: offer filled ({} piconero, block {})", v.amount, height);
            close_account(offer, bidder)
        }
        1 => {
            r.done()?;
            let bidder = next_account_info(it)?;
            let config = next_account_info(it)?;
            writable(who)?;
            writable(bidder)?;
            writable(config)?;
            req!(o.bidder == *bidder.key, HkError::BadAccount);
            let mut c = load_config(config, pid)?;
            let is_bidder = *who.key == o.bidder;
            let forfeit = final_logic::offer_cancel(&mut o, is_bidder, t)?;
            pay(offer, bidder, add(o.amount, forfeit)?)?;
            pay(offer, who, o.tip)?;
            c.offer_tvl = c.offer_tvl.saturating_sub(o.amount);
            c.store(&mut config.try_borrow_mut_data()?);
            msg!("halfkey: offer cancelled");
            close_account(offer, bidder)
        }
        2 => {
            r.done()?;
            let bidder = next_account_info(it)?;
            writable(bidder)?;
            req!(o.bidder == *bidder.key, HkError::BadAccount);
            let d = final_logic::offer_forfeit(&mut o, t)?;
            pay(offer, bidder, d)?;
            o.store(&mut offer.try_borrow_mut_data()?);
            msg!("halfkey: offer reservation forfeited");
            Ok(())
        }
        _ => Err(HkError::BadInstruction.into()),
    }
}
