//! Escrow v2 (final round): the v1 escrow plus an extension that carries an integrator share
//! and a finisher tip, locked by a wallet (`lock3`, tag 42) or filled from a deposit order
//! (`deposit.rs`), and the claim that needs no claimer signature (`claim_to`, tag 43).
//!
//! * **Integrator share.** `{integrator, bps <= 200}` is bound in the maker's consent and paid at
//!   settlement, next to the protocol fee, into the integrator's program-owned account
//!   ["integrator", key] (`integrator`, tag 56: register / withdraw). Paying a PDA the program
//!   owns means a claim can never fail on the recipient (a wallet emptied below rent would).
//! * **Finisher tip.** `tip` lamports sit in the escrow on top of the amount and go to whoever
//!   submits the claim (`claim_to`) or the refund (`refund`, already permissionless). Nobody has
//!   to trust a named watchtower to finish a swap: anyone may, for the tip.
//! * **claim_to.** Anyone may submit the claimer's secret; the SOL goes only to the escrow's bound
//!   claimer. That lets SOL reach an exchange deposit address or an empty wallet, and a relayer
//!   (or the key-holding agent of a wallet) can never redirect it. Works on v1 escrows too (no
//!   share, no tip). The v1 `claim` refuses v2 escrows, so a share or tip can never be skipped.
//! * **Direct payout (`F_DIRECT`, SOL->XMR).** The maker pays the user's own standard Monero
//!   address; the claim needs the user's `ready` or `direct::prove_direct` (a payment proof that
//!   also checks this escrow's payment id). Only the maker may abort; the refund reveals nothing;
//!   the claim window has the MIN_PROOF_WINDOW floor.
//!
//! v2 escrows use the same discriminator and the same PDA as v1, and every v1 instruction except
//! `claim` handles them (ready, abort, expire, refund + tip, close, prove_lock).

use crate::final_logic;
use crate::*;

pub const INTEGRATOR_SEED: &[u8] = b"integrator";
pub const DISC_INTEGRATOR: u8 = 0x1A;
pub const INTEGRATOR_LEN: usize = 80;
pub const CONSENT_PREFIX_V3: &[u8] = b"halfkey-consent-v3";

/// An integrator's fee account ["integrator", owner]. Never closed, so a settlement that pays it
/// always finds it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Integrator {
    pub bump: u8,
    pub owner: Pubkey,
    /// Lamports earned, all time (attribution / leaderboard), and withdrawn so far.
    pub earned: u64,
    pub withdrawn: u64,
    pub swaps: u64,
    pub volume: u64,
    pub created_at: i64,
}

impl Integrator {
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!(d.len() == INTEGRATOR_LEN && d[0] == DISC_INTEGRATOR, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let bump = r.u8()?;
        r.skip(5)?;
        Ok(Self { bump, owner: r.key()?, earned: r.u64()?, withdrawn: r.u64()?, swaps: r.u64()?, volume: r.u64()?, created_at: r.i64()? })
    }
    pub fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_INTEGRATOR);
        w.u8(1);
        w.u8(self.bump);
        w.pad(5);
        w.put(self.owner.as_ref());
        w.u64(self.earned);
        w.u64(self.withdrawn);
        w.u64(self.swaps);
        w.u64(self.volume);
        w.i64(self.created_at);
    }
}

pub fn integrator_pda(pid: &Pubkey, owner: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[INTEGRATOR_SEED, owner.as_ref()], pid)
}

/// The integrator account of `owner`: program-owned, right layout, the PDA of that owner.
pub(crate) fn load_integrator(a: &AccountInfo, pid: &Pubkey, owner: &Pubkey) -> Result<Integrator, ProgramError> {
    owned(a, pid)?;
    let g = Integrator::load(&a.try_borrow_data()?)?;
    req!(g.owner == *owner, HkError::BadAccount);
    let k = Pubkey::create_program_address(&[INTEGRATOR_SEED, owner.as_ref(), &[g.bump]], pid).map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(g)
}

/// Credit a settlement's integrator share (lamports already moved) to its stats.
pub(crate) fn credit_integrator(a: &AccountInfo, pid: &Pubkey, owner: &Pubkey, fee: u64, volume: u64) -> ProgramResult {
    let mut g = load_integrator(a, pid, owner)?;
    // Statistics only: saturating, so they can never block a settlement.
    g.earned = g.earned.saturating_add(fee);
    g.swaps = g.swaps.saturating_add(1);
    g.volume = g.volume.saturating_add(volume);
    g.store(&mut a.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: op 0 register [owner (signer, w), integrator (w), system];
///           op 1 withdraw [owner (signer, w), integrator (w)].
/// Data: op u8. Withdraw pays everything above the account's rent to the owner, never elsewhere.
pub(crate) fn integrator(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let acct = next_account_info(it)?;
    signer(owner)?;
    writable(acct)?;
    let op = r.u8()?;
    r.done()?;
    match op {
        0 => {
            let system = next_account_info(it)?;
            let (k, b) = integrator_pda(pid, owner.key);
            req!(k == *acct.key, HkError::BadPda);
            create_pda(owner, acct, system, pid, INTEGRATOR_LEN, &[INTEGRATOR_SEED, owner.key.as_ref(), &[b]])?;
            Integrator { bump: b, owner: *owner.key, created_at: now()?, ..Default::default() }.store(&mut acct.try_borrow_mut_data()?);
            msg!("halfkey: integrator registered");
            Ok(())
        }
        1 => {
            writable(owner)?;
            let mut g = load_integrator(acct, pid, owner.key)?;
            let keep = Rent::get()?.minimum_balance(INTEGRATOR_LEN);
            let amt = acct.lamports().saturating_sub(keep);
            g.withdrawn = add(g.withdrawn, amt)?;
            g.store(&mut acct.try_borrow_mut_data()?);
            pay(acct, owner, amt)
        }
        _ => Err(HkError::BadInstruction.into()),
    }
}

/// The v3 consent (v2 escrows): the v2 message under its own prefix, plus the integrator, its
/// share and the tip. Fixed length, so equal messages mean equal terms.
pub fn consent_message_v3(
    pid: &Pubkey,
    escrow: &Pubkey,
    locker: &Pubkey,
    q_claimer: &Pubkey,
    direction: u8,
    amount: u64,
    xmr_amount: u64,
    claim_point: &[u8; 32],
    refund_point: &[u8; 32],
    view_pub: &[u8; 32],
    quote_hash: &[u8; 32],
    t0_secs: i64,
    window_secs: i64,
    expiry: i64,
    fee_bps: u16,
    flags: u8,
    wt: &[Pubkey; 2],
    ext: &EscrowExt,
) -> Vec<u8> {
    let mut m = consent_message_v2(
        pid, escrow, locker, q_claimer, direction, amount, xmr_amount, claim_point, refund_point, view_pub, quote_hash,
        t0_secs, window_secs, expiry, fee_bps, flags, &Pubkey::default(), wt,
    );
    m.splice(0..CONSENT_PREFIX_V2.len(), CONSENT_PREFIX_V3.iter().copied());
    m.extend_from_slice(ext.integrator.as_ref());
    m.extend_from_slice(&ext.integrator_bps.to_le_bytes());
    m.extend_from_slice(&ext.tip.to_le_bytes());
    m
}

/// How a v2 escrow is funded.
pub(crate) enum Fund<'a, 'b> {
    /// The signing locker pays rent + amount + tip.
    Wallet { locker: &'b AccountInfo<'a> },
    /// A deposit order's system-owned PDA pays (it signs with its seeds); see `fill_take`.
    Order { order: &'b AccountInfo<'a>, seeds: &'b [&'b [u8]] },
}

/// What the maker consented to.
pub(crate) enum Consent {
    /// v3 consent over this escrow (SOL->XMR; XMR->SOL is locked by the maker itself).
    V3,
    /// The maker's signature over a deposit order's hash, at the fee it quoted.
    Order { hash: [u8; 32], fee_bps: u16 },
}

/// Open a v2 escrow. The checks of `open_escrow` (same functions, same order where they apply)
/// plus `final_logic::check_v2_terms` and the integrator account.
pub(crate) fn open_v2<'a, 'b>(
    pid: &Pubkey,
    q: &LockReq,
    mut ext: EscrowExt,
    locker_key: &Pubkey,
    fund: Fund<'a, 'b>,
    escrow: &'b AccountInfo<'a>,
    maker: &'b AccountInfo<'a>,
    config: &'b AccountInfo<'a>,
    system: &'b AccountInfo<'a>,
    ixs: &'b AccountInfo<'a>,
    integrator: Option<&'b AccountInfo<'a>>,
    consent: Consent,
) -> ProgramResult {
    writable(escrow)?;
    writable(maker)?;
    writable(config)?;
    let mut c = load_config(config, pid)?;
    let mut m = load_maker(maker, pid)?;
    let legacy = final_logic::check_v2_terms(
        q.direction, q.flags, &ext.integrator, ext.integrator_bps, ext.tip, q.amount, q.window_secs, &q.wt,
    )?;
    let tvl = logic::check_lock_terms(
        &c, &m, locker_key, &q.claimer, q.direction, q.amount, q.xmr_amount, q.t0_secs, q.window_secs, legacy,
    )?;
    if ext.integrator != Pubkey::default() {
        load_integrator(integrator.ok_or(HkError::BadAccount)?, pid, &ext.integrator)?;
    }
    req!(q.claim_point != q.refund_point, HkError::BadPoint);
    req!(point_is_prime_order(&q.claim_point), HkError::BadPoint);
    req!(point_is_prime_order(&q.refund_point), HkError::BadPoint);
    req!(point_is_prime_order(&q.view_pub), HkError::BadPoint);
    logic::check_watchtowers(&q.wt, &q.claimer, locker_key, legacy)?;
    let (ek, eb) = Pubkey::find_program_address(&[SWAP_SEED, locker_key.as_ref(), &q.swap_id], pid);
    req!(ek == *escrow.key, HkError::BadPda);
    let fee_bps = logic::effective_fee_bps(&c, &m);
    let t = now()?;
    match consent {
        Consent::V3 => {
            if q.direction == DIR_SOL_TO_XMR {
                req!(t <= q.consent_expiry, HkError::NoConsent);
                let msg = consent_message_v3(
                    pid, &ek, locker_key, &q.claimer, q.direction, q.amount, q.xmr_amount, &q.claim_point, &q.refund_point,
                    &q.view_pub, &q.quote_hash, q.t0_secs, q.window_secs, q.consent_expiry, fee_bps, q.flags, &q.wt, &ext,
                );
                require_ed25519(ixs, &m.authority, &solana_sha256_hasher::hash(&msg).to_bytes())?;
            }
        }
        Consent::Order { hash, fee_bps: quoted } => {
            req!(quoted == fee_bps, HkError::NoConsent);
            require_ed25519(ixs, &m.authority, &hash)?;
        }
    }
    let seeds: &[&[u8]] = &[SWAP_SEED, locker_key.as_ref(), &q.swap_id, &[eb]];
    let principal = add(q.amount, ext.tip)?;
    match fund {
        Fund::Wallet { locker } => {
            create_pda(locker, escrow, system, pid, ESCROW_LEN_V2, seeds)?;
            transfer_in(locker, escrow, system, principal)?;
        }
        Fund::Order { order, seeds: oseeds } => {
            req!(*system.key == SYSTEM_PROGRAM, HkError::BadAccount);
            req!(escrow.data_len() == 0 && *escrow.owner == SYSTEM_PROGRAM, HkError::AlreadyInitialized);
            let rent = Rent::get()?;
            let top = rent.minimum_balance(ESCROW_LEN_V2).saturating_sub(escrow.lamports());
            let take = final_logic::fill_take(order.lamports(), q.amount, ext.tip, top, rent.minimum_balance(0))?;
            invoke_signed(
                &solana_system_interface::instruction::allocate(escrow.key, ESCROW_LEN_V2 as u64),
                &[escrow.clone(), system.clone()],
                &[seeds],
            )?;
            invoke_signed(
                &solana_system_interface::instruction::assign(escrow.key, pid),
                &[escrow.clone(), system.clone()],
                &[seeds],
            )?;
            invoke_signed(
                &solana_system_interface::instruction::transfer(order.key, escrow.key, take),
                &[order.clone(), escrow.clone(), system.clone()],
                &[oseeds],
            )?;
        }
    }
    let (t0, t1) = logic::deadlines(t, q.t0_secs, q.window_secs)?;
    ext.order_deadline = if ext.origin == 1 { ext.order_deadline } else { 0 };
    let e = Escrow {
        state: ST_LOCKED,
        direction: q.direction,
        bump: eb,
        released: false,
        swap_id: q.swap_id,
        locker: *locker_key,
        claimer: q.claimer,
        maker: m.authority,
        amount: q.amount,
        xmr_amount: q.xmr_amount,
        fee_bps,
        claim_point: q.claim_point,
        refund_point: q.refund_point,
        view_pub: q.view_pub,
        quote_hash: q.quote_hash,
        watchtowers: q.wt,
        created_at: t,
        t0,
        t1,
        settled_at: 0,
        secret: [0; 32],
        flags: q.flags,
        link: Pubkey::default(),
        v2: true,
        ext,
    };
    e.store(&mut escrow.try_borrow_mut_data()?);
    logic::open_counters(&mut m, &mut c, q.amount, tvl)?;
    m.store(&mut maker.try_borrow_mut_data()?);
    c.store(&mut config.try_borrow_mut_data()?);
    msg!("halfkey: locked (v2)");
    Ok(())
}

/// Accounts: [locker (signer, w), escrow (w), maker (w), config (w), system, instructions sysvar,
///            integrator account (only with an integrator)]
/// Data: the `lock2` data (flags: F_PROOF for XMR->SOL, F_DIRECT for SOL->XMR) + integrator 32,
///       integrator_bps u16, tip u64. SOL->XMR needs the maker's v3 consent in the previous
///       instruction; XMR->SOL is locked by the maker itself.
pub(crate) fn lock3(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let locker = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    let system = next_account_info(it)?;
    let ixs = next_account_info(it)?;
    signer(locker)?;
    let mut q = read_lock_head(r)?;
    q.flags = r.u8()?;
    let ext = EscrowExt { integrator: r.key()?, integrator_bps: r.u16()?, origin: 0, tip: r.u64()?, order_deadline: 0 };
    r.done()?;
    let integ = if ext.integrator != Pubkey::default() { Some(next_account_info(it)?) } else { None };
    open_v2(pid, &q, ext, locker.key, Fund::Wallet { locker }, escrow, maker, config, system, ixs, integ, Consent::V3)
}

/// The `lock` fields (no flags, no `done`).
pub(crate) fn read_lock_head(r: &mut Rd) -> Result<LockReq, ProgramError> {
    Ok(LockReq {
        swap_id: r.b32()?,
        claimer: r.key()?,
        direction: r.u8()?,
        amount: r.u64()?,
        xmr_amount: r.u64()?,
        claim_point: r.b32()?,
        refund_point: r.b32()?,
        view_pub: r.b32()?,
        quote_hash: r.b32()?,
        t0_secs: r.i64()?,
        window_secs: r.i64()?,
        wt: [r.key()?, r.key()?],
        consent_expiry: r.i64()?,
        flags: 0,
    })
}

/// Accounts: [submitter (signer, w), escrow (w), claimer (w), maker (w), config (w), fee_vault (w),
///            integrator account (w; v2 with an integrator),
///            proof record (proof-gated escrow claimed without `ready` only)]. Data: secret.
/// The claim of `claim`, without the claimer's signature: the payout can only go to the escrow's
/// claimer, so who submits does not matter. v2: the integrator share to its account, the tip to
/// the submitter.
pub(crate) fn claim_to(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let sub = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let claimer = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    let vault = next_account_info(it)?;
    signer(sub)?;
    writable(sub)?;
    writable(escrow)?;
    writable(claimer)?;
    writable(vault)?;
    let secret = r.b32()?;
    r.done()?;

    let mut e = load_escrow(escrow, pid)?;
    let (mut m, mut c) = load_pair(&e, maker, config, pid)?;
    req!(e.claimer == *claimer.key, HkError::BadAccount);
    let vk = Pubkey::create_program_address(&[FEE_VAULT_SEED, &[c.vault_bump]], pid).map_err(|_| HkError::BadPda)?;
    req!(vk == *vault.key, HkError::BadPda);
    owned(vault, pid)?;
    let t = now()?;
    logic::claim_window(e.state, t, e.t0, e.t1)?;
    let (ibps, tip) = if e.v2 { (e.ext.integrator_bps, e.ext.tip) } else { (0, 0) };
    let integ = if e.v2 && e.ext.integrator != Pubkey::default() {
        let a = next_account_info(it)?;
        writable(a)?;
        load_integrator(a, pid, &e.ext.integrator)?;
        Some(a)
    } else {
        None
    };
    let rec = if zkproof::proof_allowed(e.direction, e.flags) && e.state == ST_LOCKED {
        Some(zkproof::load_proof(next_account_info(it)?, pid, &e)?)
    } else {
        None
    };
    zkproof::claim_gate(&e, escrow.key, rec.as_ref())?;
    check_reveal(&secret, &e.claim_point)?;

    let (to_claimer, fee, ifee) = final_logic::split3(e.amount, e.fee_bps, ibps)?;
    pay(escrow, claimer, to_claimer)?;
    pay(escrow, vault, fee)?;
    if let Some(a) = integ {
        pay(escrow, a, ifee)?;
        credit_integrator(a, pid, &e.ext.integrator, ifee, e.amount)?;
    }
    pay(escrow, sub, tip)?;

    release(&mut e, &mut m, &mut c)?;
    e.state = ST_CLAIMED;
    e.secret = secret;
    e.settled_at = t;
    e.store(&mut escrow.try_borrow_mut_data()?);
    m.completed = add(m.completed, 1)?;
    m.volume = add(m.volume, e.amount)?;
    logic::ext_count(&e, &mut m, logic::Outcome::Fill)?;
    m.store(&mut maker.try_borrow_mut_data()?);
    c.total_swaps = add(c.total_swaps, 1)?;
    c.total_volume = add(c.total_volume, e.amount)?;
    c.total_fees = add(c.total_fees, fee)?;
    c.store(&mut config.try_borrow_mut_data()?);
    msg!("halfkey: claimed (to)");
    Ok(())
}
