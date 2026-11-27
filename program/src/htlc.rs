//! HTLC kind: SOL <-> transparent ZEC, hash-locked on both chains.
//!
//! The Zcash side is a P2SH script (`OP_IF OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <H> OP_EQUALVERIFY
//! <claimPub> OP_CHECKSIG OP_ELSE <height> OP_CHECKLOCKTIMEVERIFY OP_DROP <refundPub> OP_CHECKSIG
//! OP_ENDIF`, `sdk/zec.ts`). The Solana side is this escrow: `hashlock = sha256(x)`, one deadline
//! `t1`, and the same maker registry, caps, fee vault and holder fee as the XMR kind.
//!
//!   * SOL -> ZEC (direction 4): the maker knows `x` and locks ZEC first (refund height L, the
//!     longer lock). The user checks it, pre-signs its ZEC claim (handed to watchtowers), then
//!     locks SOL here with the maker as claimer. The maker claims the SOL with `x`, which
//!     publishes `x`; any watchtower completes the user's ZEC claim with it.
//!   * ZEC -> SOL (direction 8): the user knows `x` and pays ZEC into the HTLC first. The maker
//!     locks SOL here with the user (a fresh wallet is fine) as claimer and `t1` well before L.
//!     The user claims the SOL with `x`; the maker reads `x` and claims the ZEC.
//!
//! Rules (pure functions in `logic.rs`, proven in `htlc_proofs.rs`):
//!   [lock, t1)  only the claimer acts: `claim` with the preimage, or `abort` (gives up its claim).
//!   [t1, inf)   `refund` only, permissionless, pays only the locker, reveals nothing.
//!   Aborted     `refund` only, any time.
//! No `ready`, and no locker or watchtower abort: a locker abort racing the claim would make the
//! claim fail on chain with `x` in its instruction data, handing the locker both sides.
//!
//! HTLC escrows are separate accounts (seed "htlc", discriminator DISC_HTLC), so every XMR
//! instruction rejects them at load, and these instructions reject XMR escrows the same way.

use crate::logic::{self, AbortKind};
use crate::*;

pub const HTLC_SEED: &[u8] = b"htlc";
pub const DISC_HTLC: u8 = 0x48;
pub const HTLC_LEN: usize = 280;
pub const HTLC_CONSENT_PREFIX: &[u8] = b"halfkey-htlc-consent-v1";

/// One HTLC escrow. Offsets of locker / claimer / maker match the XMR escrow (40 / 72 / 104), so
/// the same memcmp filters find a party's swaps of both kinds.
#[derive(Clone, Debug, Default)]
pub struct Htlc {
    pub state: u8,
    pub direction: u8,
    pub bump: u8,
    /// Open-swap counters (maker + global TVL) already released (abort / claim / refund).
    pub released: bool,
    pub swap_id: [u8; 32],
    pub locker: Pubkey,
    pub claimer: Pubkey,
    pub maker: Pubkey,
    /// Lamports locked.
    pub amount: u64,
    /// ZEC side in zatoshis (what the two parties agreed; not checked against Zcash on chain).
    pub zec_amount: u64,
    pub fee_bps: u16,
    /// sha256(x), x exactly 32 bytes.
    pub hashlock: [u8; 32],
    /// Hash of the maker's signed quote (binds the off-chain ZEC terms: HTLC outpoint, keys,
    /// refund height).
    pub quote_hash: [u8; 32],
    pub created_at: i64,
    pub t1: i64,
    pub settled_at: i64,
    /// The preimage, once claimed (all zero otherwise).
    pub secret: [u8; 32],
}

impl Htlc {
    pub(crate) fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!(d.len() == HTLC_LEN && d[0] == DISC_HTLC, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let state = r.u8()?;
        let direction = r.u8()?;
        let bump = r.u8()?;
        let released = r.u8()? != 0;
        r.skip(2)?;
        Ok(Self {
            state,
            direction,
            bump,
            released,
            swap_id: r.b32()?,
            locker: r.key()?,
            claimer: r.key()?,
            maker: r.key()?,
            amount: r.u64()?,
            zec_amount: r.u64()?,
            fee_bps: {
                let v = r.u16()?;
                r.skip(6)?;
                v
            },
            hashlock: r.b32()?,
            quote_hash: r.b32()?,
            created_at: r.i64()?,
            t1: r.i64()?,
            settled_at: r.i64()?,
            secret: r.b32()?,
        })
    }
    pub(crate) fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_HTLC);
        w.u8(1);
        w.u8(self.state);
        w.u8(self.direction);
        w.u8(self.bump);
        w.u8(self.released as u8);
        w.pad(2);
        w.put(&self.swap_id);
        w.put(self.locker.as_ref());
        w.put(self.claimer.as_ref());
        w.put(self.maker.as_ref());
        w.u64(self.amount);
        w.u64(self.zec_amount);
        w.u16(self.fee_bps);
        w.pad(6);
        w.put(&self.hashlock);
        w.put(&self.quote_hash);
        w.i64(self.created_at);
        w.i64(self.t1);
        w.i64(self.settled_at);
        w.put(&self.secret);
    }
}

fn load_htlc(a: &AccountInfo, pid: &Pubkey) -> Result<Htlc, ProgramError> {
    owned(a, pid)?;
    let h = Htlc::load(&a.try_borrow_data()?)?;
    let k = Pubkey::create_program_address(&[HTLC_SEED, h.locker.as_ref(), &h.swap_id, &[h.bump]], pid)
        .map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(h)
}

/// Load maker + config for an HTLC escrow and check they belong to it.
fn load_pair(h: &Htlc, maker: &AccountInfo, config: &AccountInfo, pid: &Pubkey) -> Result<(Maker, Config), ProgramError> {
    writable(maker)?;
    writable(config)?;
    let m = load_maker(maker, pid)?;
    req!(m.authority == h.maker, HkError::BadAccount);
    let c = load_config(config, pid)?;
    Ok((m, c))
}

/// The bytes a maker signs (as sha256) to consent to one SOL->ZEC lock. Own prefix, so it can
/// never be replayed as an XMR consent (or the reverse).
pub fn consent_message(
    pid: &Pubkey,
    escrow: &Pubkey,
    locker: &Pubkey,
    claimer: &Pubkey,
    direction: u8,
    amount: u64,
    zec_amount: u64,
    hashlock: &[u8; 32],
    quote_hash: &[u8; 32],
    t1_secs: i64,
    expiry: i64,
    fee_bps: u16,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(HTLC_CONSENT_PREFIX.len() + 32 * 6 + 1 + 8 * 5 + 2);
    m.extend_from_slice(HTLC_CONSENT_PREFIX);
    m.extend_from_slice(pid.as_ref());
    m.extend_from_slice(escrow.as_ref());
    m.extend_from_slice(locker.as_ref());
    m.extend_from_slice(claimer.as_ref());
    m.push(direction);
    m.extend_from_slice(&amount.to_le_bytes());
    m.extend_from_slice(&zec_amount.to_le_bytes());
    m.extend_from_slice(hashlock);
    m.extend_from_slice(quote_hash);
    m.extend_from_slice(&t1_secs.to_le_bytes());
    m.extend_from_slice(&expiry.to_le_bytes());
    m.extend_from_slice(&fee_bps.to_le_bytes());
    m
}

/// Accounts: [locker (signer, w), htlc (w), maker (w), config (w), system, instructions sysvar]
/// Data: swap_id 32, claimer 32, direction u8, amount u64, zec_amount u64, hashlock 32,
///       quote_hash 32, t1_secs i64, consent_expiry i64.
/// SOL->ZEC needs the maker's ed25519 consent over sha256(consent_message) in the previous
/// instruction. ZEC->SOL is locked by the maker itself, so its signature is the consent.
pub(crate) fn lock(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let locker = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    let system = next_account_info(it)?;
    let ixs = next_account_info(it)?;
    signer(locker)?;
    writable(escrow)?;
    writable(maker)?;
    writable(config)?;
    let swap_id = r.b32()?;
    let claimer = r.key()?;
    let direction = r.u8()?;
    let amount = r.u64()?;
    let zec_amount = r.u64()?;
    let hashlock = r.b32()?;
    let quote_hash = r.b32()?;
    let t1_secs = r.i64()?;
    let consent_expiry = r.i64()?;
    r.done()?;

    let mut c = load_config(config, pid)?;
    let mut m = load_maker(maker, pid)?;
    let tvl = logic::htlc_lock_terms(&c, &m, locker.key, &claimer, direction, amount, zec_amount, &hashlock, t1_secs)?;
    let (ek, eb) = Pubkey::find_program_address(&[HTLC_SEED, locker.key.as_ref(), &swap_id], pid);
    req!(ek == *escrow.key, HkError::BadPda);
    let fee_bps = logic::effective_fee_bps(&c, &m);

    // A point lock must be a usable ed25519 point (prime order, canonical, not the identity), or
    // nobody could ever claim it and the locked side would wait for t1 for nothing.
    if logic::is_point_dir(direction) {
        req!(point_is_prime_order(&hashlock), HkError::BadPoint);
    }

    let t = now()?;
    if logic::is_sol_to_zec(direction) {
        req!(t <= consent_expiry, HkError::NoConsent);
        let msg = consent_message(
            pid, &ek, locker.key, &claimer, direction, amount, zec_amount, &hashlock, &quote_hash, t1_secs,
            consent_expiry, fee_bps,
        );
        let digest = solana_sha256_hasher::hash(&msg).to_bytes();
        require_ed25519(ixs, &m.authority, &digest)?;
    }

    let seeds: &[&[u8]] = &[HTLC_SEED, locker.key.as_ref(), &swap_id, &[eb]];
    create_pda(locker, escrow, system, pid, HTLC_LEN, seeds)?;
    transfer_in(locker, escrow, system, amount)?;

    let t1 = t.checked_add(t1_secs).ok_or(HkError::Overflow)?;
    let h = Htlc {
        state: ST_LOCKED,
        direction,
        bump: eb,
        released: false,
        swap_id,
        locker: *locker.key,
        claimer,
        maker: m.authority,
        amount,
        zec_amount,
        fee_bps,
        hashlock,
        quote_hash,
        created_at: t,
        t1,
        settled_at: 0,
        secret: [0; 32],
    };
    h.store(&mut escrow.try_borrow_mut_data()?);
    logic::open_counters(&mut m, &mut c, amount, tvl)?;
    m.store(&mut maker.try_borrow_mut_data()?);
    c.store(&mut config.try_borrow_mut_data()?);
    msg!("halfkey: htlc locked");
    Ok(())
}

/// Accounts: [claimer (signer, w), htlc (w), maker (w), config (w), fee_vault (w)]. Data: x (32).
/// Only the claimer can submit the preimage (signer binding), so nobody can front-run it into a
/// different destination. Open from the lock until t1.
///
/// v1.5's claim rule ("a SOL->XMR claim needs Ready or an on-chain payment proof",
/// `zkproof::claim_gate`) is for the XMR kinds only. Here the claim IS the proof: the preimage of
/// the hashlock is what opens the ZEC script too, so publishing it pays the counterparty. There is
/// no proof record and no Ready for this kind (`zkproof::proof_gated` is false for 4/8/16/32).
///
/// The fee goes to the same fee vault as an XMR claim, so `split_fees` (rewards.rs) splits it
/// 50/50 between $HALFKEY stakers and the burn like any other fee: the split works on the vault's
/// balance, not on a per-kind counter.
///
/// `point`: `htlc_pt_claim` (tag 52) on a point lock: the secret is the scalar t, t*G == T.
pub(crate) fn claim(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd, point: bool) -> ProgramResult {
    let it = &mut accounts.iter();
    let claimer = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    let vault = next_account_info(it)?;
    signer(claimer)?;
    writable(claimer)?;
    writable(escrow)?;
    writable(vault)?;
    let secret = r.b32()?;
    r.done()?;

    let mut h = load_htlc(escrow, pid)?;
    let (mut m, mut c) = load_pair(&h, maker, config, pid)?;
    req!(h.claimer == *claimer.key, HkError::Unauthorized);
    let vk = Pubkey::create_program_address(&[FEE_VAULT_SEED, &[c.vault_bump]], pid).map_err(|_| HkError::BadPda)?;
    req!(vk == *vault.key, HkError::BadPda);
    owned(vault, pid)?;
    let t = now()?;
    logic::htlc_claim_window(h.state, t, h.t1)?;
    logic::htlc_check_secret(
        h.direction,
        point,
        &secret,
        &h.hashlock,
        |s| solana_sha256_hasher::hash(s).to_bytes(),
        |s| multiply_edwards(&PodScalar(*s), &PodEdwardsPoint(G)).map(|p| p.0),
    )?;

    let (to_claimer, fee) = logic::split_fee(h.amount, h.fee_bps)?;
    pay(escrow, claimer, to_claimer)?;
    pay(escrow, vault, fee)?;

    logic::htlc_release(&mut h, &mut m, &mut c)?;
    h.state = ST_CLAIMED;
    h.secret = secret;
    h.settled_at = t;
    h.store(&mut escrow.try_borrow_mut_data()?);

    m.completed = add(m.completed, 1)?;
    m.volume = add(m.volume, h.amount)?;
    m.store(&mut maker.try_borrow_mut_data()?);
    c.total_swaps = add(c.total_swaps, 1)?;
    c.total_volume = add(c.total_volume, h.amount)?;
    c.total_fees = add(c.total_fees, fee)?;
    c.store(&mut config.try_borrow_mut_data()?);
    msg!("halfkey: htlc claimed");
    Ok(())
}

/// Accounts: [claimer (signer), htlc (w), maker (w), config (w)]. The claimer gives up its claim
/// (SOL->ZEC: the maker declines; ZEC->SOL: the user cancels before revealing x). Reveals nothing;
/// the locker can then refund at once.
pub(crate) fn abort(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let who = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    signer(who)?;
    writable(escrow)?;
    r.done()?;
    let mut h = load_htlc(escrow, pid)?;
    let (mut m, mut c) = load_pair(&h, maker, config, pid)?;
    let t = now()?;
    match logic::htlc_abort_check(&h, who.key, t)? {
        AbortKind::Declined => m.declined = add(m.declined, 1)?,
        AbortKind::Cancelled => m.cancelled = add(m.cancelled, 1)?,
        AbortKind::Watchtower => m.aborted = add(m.aborted, 1)?,
    }
    logic::htlc_release(&mut h, &mut m, &mut c)?;
    h.state = ST_ABORTED;
    h.settled_at = t;
    h.store(&mut escrow.try_borrow_mut_data()?);
    m.store(&mut maker.try_borrow_mut_data()?);
    c.store(&mut config.try_borrow_mut_data()?);
    msg!("halfkey: htlc aborted");
    Ok(())
}

/// Accounts: [payer (signer), htlc (w), locker (w), maker (w), config (w)]. No data.
/// Anyone may submit (watchtowers relay it gaslessly); the SOL goes only to the locker and nothing
/// is revealed (the ZEC side refunds by its own timelock). When the counters were already released
/// (abort), the maker and config accounts are not read.
pub(crate) fn refund(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let payer = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let locker = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    signer(payer)?;
    writable(escrow)?;
    writable(locker)?;
    r.done()?;

    let mut h = load_htlc(escrow, pid)?;
    req!(h.locker == *locker.key, HkError::BadAccount);
    let t = now()?;
    logic::htlc_refund_window(h.state, t, h.t1)?;
    if !h.released {
        let (mut m, mut c) = load_pair(&h, maker, config, pid)?;
        logic::htlc_release(&mut h, &mut m, &mut c)?;
        m.expired = add(m.expired, 1)?;
        m.store(&mut maker.try_borrow_mut_data()?);
        c.store(&mut config.try_borrow_mut_data()?);
    }
    pay(escrow, locker, h.amount)?;
    h.state = ST_REFUNDED;
    h.settled_at = t;
    h.store(&mut escrow.try_borrow_mut_data()?);
    msg!("halfkey: htlc refunded");
    Ok(())
}

/// Accounts: [locker (signer, w), htlc (w)]. Reclaims the rent after settlement. The preimage of
/// a claimed escrow stays readable in the claim transaction.
pub(crate) fn close(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let locker = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    signer(locker)?;
    writable(locker)?;
    writable(escrow)?;
    r.done()?;
    let h = load_htlc(escrow, pid)?;
    req!(h.locker == *locker.key, HkError::Unauthorized);
    logic::htlc_close_allowed(h.state)?;
    close_account(escrow, locker)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_roundtrip_and_offsets() {
        let h = Htlc {
            state: ST_CLAIMED,
            direction: DIR_ZEC_TO_SOL,
            bump: 254,
            released: true,
            swap_id: [1; 32],
            locker: Pubkey::new_from_array([2; 32]),
            claimer: Pubkey::new_from_array([3; 32]),
            maker: Pubkey::new_from_array([4; 32]),
            amount: 5,
            zec_amount: 6,
            fee_bps: 50,
            hashlock: [7; 32],
            quote_hash: [8; 32],
            created_at: -9,
            t1: 10,
            settled_at: 11,
            secret: [12; 32],
        };
        let mut d = vec![0u8; HTLC_LEN];
        h.store(&mut d);
        let g = Htlc::load(&d).unwrap();
        assert_eq!((g.state, g.direction, g.bump, g.released), (ST_CLAIMED, DIR_ZEC_TO_SOL, 254, true));
        assert_eq!((g.amount, g.zec_amount, g.fee_bps, g.created_at, g.t1, g.settled_at), (5, 6, 50, -9, 10, 11));
        assert_eq!((g.hashlock, g.quote_hash, g.secret, g.swap_id), ([7; 32], [8; 32], [12; 32], [1; 32]));
        // Same party offsets as the XMR escrow (memcmp filters in the SDK).
        assert_eq!(&d[40..72], &[2; 32]);
        assert_eq!(&d[72..104], &[3; 32]);
        assert_eq!(&d[104..136], &[4; 32]);
        // The two kinds never load as each other.
        assert!(Escrow::load(&d).is_err());
        let mut e = vec![0u8; ESCROW_LEN];
        Escrow::default().store(&mut e);
        assert!(Htlc::load(&e).is_err());
        assert!(Htlc::load(&d[..HTLC_LEN - 1]).is_err());
    }

    #[test]
    fn consent_prefix_differs_from_xmr() {
        assert_ne!(HTLC_CONSENT_PREFIX, CONSENT_PREFIX);
        assert_ne!(HTLC_CONSENT_PREFIX, CONSENT_PREFIX_V2);
        assert!(!HTLC_CONSENT_PREFIX.starts_with(CONSENT_PREFIX));
        assert_ne!(DISC_HTLC, DISC_ESCROW);
        for d in [DISC_CONFIG, DISC_MAKER, DISC_ESCROW, DISC_LINK, DISC_VAULT] {
            assert_ne!(DISC_HTLC, d);
        }
    }

    /// Tripwire: every place this module moves lamports. A new site must be added here on purpose.
    #[test]
    fn lamport_debit_sites_unchanged() {
        let src = include_str!("htlc.rs");
        let body = src.split("#[cfg(test)]").next().unwrap();
        let mut f = "";
        let mut sites = Vec::new();
        for line in body.lines() {
            let l = line.trim_start();
            if let Some(rest) = l.strip_prefix("pub(crate) fn ").or_else(|| l.strip_prefix("fn ")).or_else(|| l.strip_prefix("pub fn ")) {
                f = rest.split(['(', '<']).next().unwrap();
                continue;
            }
            if l.starts_with("//") {
                continue;
            }
            if l.starts_with("pay(") || l.contains(" pay(") || l.contains("close_account(") || l.contains("try_borrow_mut_lamports") || l.contains("transfer_in(") {
                sites.push(format!("{f}:{}", l.split('(').next().unwrap()));
            }
        }
        assert_eq!(
            sites,
            [
                "lock:transfer_in",   // locker -> new escrow (system transfer, signed by the locker)
                "claim:pay",          // escrow -> claimer (amount - fee)
                "claim:pay",          // escrow -> fee vault
                "refund:pay",         // escrow -> locker (amount)
                "close:close_account" // settled escrow rent -> locker
            ]
        );
    }

    /// Tripwire: the only HTLC function that reads the pause flag is the lock check.
    #[test]
    fn paused_read_sites() {
        let readers = |src: &str| {
            let mut f = "";
            let mut out = Vec::new();
            for line in src.lines() {
                let l = line.trim_start();
                if let Some(rest) = l.strip_prefix("pub fn ").or_else(|| l.strip_prefix("pub(crate) fn ")).or_else(|| l.strip_prefix("fn ")) {
                    f = rest.split(['(', '<']).next().unwrap();
                }
                if !l.starts_with("//") && l.contains(".paused") && !l.contains(".paused =") {
                    out.push(f.to_string());
                }
            }
            out
        };
        let htlc_src = include_str!("htlc.rs").split("#[cfg(test)]").next().unwrap();
        assert!(readers(htlc_src).is_empty());
        let logic_src = include_str!("logic.rs");
        let htlc_logic = &logic_src[logic_src.find("// HTLC kind").unwrap()..];
        assert_eq!(readers(htlc_logic), ["htlc_lock_terms"]);
    }
}
