//! Executable model of one HTLC escrow's life (SOL <-> ZEC), shared by the Kani harnesses in
//! `htlc_proofs.rs` (all inputs, inductive invariant) and the proptest walk in `htlc_fuzz.rs`
//! (long runs, the real sha256).
//!
//! Each `step` follows its handler in `htlc.rs` and calls the same `logic` functions. Account
//! plumbing (owners, PDAs, discriminators, signer and writable flags, the maker/config/fee-vault
//! account checks) is assumed to have passed: e2e/htlc.test.ts covers it. Lamport balances of the
//! four parties are tracked, plus ghost history (claims, refunds, who aborted, the hash the claim
//! checked). Only compiled for Kani and tests.

use crate::htlc::Htlc;
use crate::logic;
pub use crate::model::{key, CLAIMER, LOCKER, RANDO, WT};
use crate::*;

#[derive(Clone, Debug)]
pub struct HWorld {
    pub h: Htlc,
    pub m: Maker,
    pub c: Config,
    pub closed: bool,
    /// Escrow rent plus any pre-funding of the escrow address (not part of the swap).
    pub rent: u64,
    // Lamports.
    pub escrow: u64,
    pub locker: u64,
    pub claimer: u64,
    pub vault: u64,
    // Ghost history.
    pub claims: u32,
    pub refunds: u32,
    pub aborted_by: Option<Pubkey>,
    /// sha256 of the secret the successful claim submitted.
    pub claimed_hash: Option<[u8; 32]>,
}

impl HWorld {
    pub fn total(&self) -> u128 {
        self.escrow as u128 + self.locker as u128 + self.claimer as u128 + self.vault as u128
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HOp {
    /// `htlc_claim` (tag 48): the hash-lock claim.
    Claim,
    Abort,
    Refund,
    Close,
    /// `htlc_pt_claim` (tag 52): the point-lock claim (ZEC v2).
    PtClaim,
}

pub const HOPS: [HOp; 5] = [HOp::Claim, HOp::Abort, HOp::Refund, HOp::Close, HOp::PtClaim];

/// The claim instruction for an escrow's kind.
pub fn claim_op(direction: u8) -> HOp {
    if logic::is_point_dir(direction) { HOp::PtClaim } else { HOp::Claim }
}

pub struct HLockIn {
    pub c: Config,
    pub m: Maker,
    pub direction: u8,
    pub amount: u64,
    pub zec_amount: u64,
    pub hashlock: [u8; 32],
    pub t1_secs: i64,
    pub t_lock: i64,
    pub rent: u64,
    /// locker, claimer, fee vault (after the locker paid in).
    pub balances: (u64, u64, u64),
}

/// `htlc::lock`: terms, fee, deadline and counters. The locker is `key(LOCKER)`, the claimer
/// `key(CLAIMER)`; the maker authority is whichever side the direction requires (else the terms
/// check rejects it). The consent check (ed25519 precompile) is not modelled.
pub fn lock(i: HLockIn) -> Result<HWorld, HkError> {
    let (locker, claimer) = (key(LOCKER), key(CLAIMER));
    let (mut c, mut m) = (i.c, i.m);
    let tvl = logic::htlc_lock_terms(&c, &m, &locker, &claimer, i.direction, i.amount, i.zec_amount, &i.hashlock, i.t1_secs)?;
    let fee_bps = logic::effective_fee_bps(&c, &m);
    let t1 = i.t_lock.checked_add(i.t1_secs).ok_or(HkError::Overflow)?;
    logic::open_counters(&mut m, &mut c, i.amount, tvl)?;
    let escrow = i.rent.checked_add(i.amount).ok_or(HkError::Overflow)?;
    let h = Htlc {
        state: ST_LOCKED,
        direction: i.direction,
        locker,
        claimer,
        maker: m.authority,
        amount: i.amount,
        zec_amount: i.zec_amount,
        fee_bps,
        hashlock: i.hashlock,
        created_at: i.t_lock,
        t1,
        ..Default::default()
    };
    Ok(HWorld {
        h,
        m,
        c,
        closed: false,
        rent: i.rent,
        escrow,
        locker: i.balances.0,
        claimer: i.balances.1,
        vault: i.balances.2,
        claims: 0,
        refunds: 0,
        aborted_by: None,
        claimed_hash: None,
    })
}

fn pay(from: &mut u64, to: &mut u64, x: u64) -> Result<(), HkError> {
    if x == 0 {
        return Ok(());
    }
    let (f, t) = logic::pay_amounts(*from, *to, x)?;
    *from = f;
    *to = t;
    Ok(())
}

/// One instruction. `sha` stands for the lock function: sha256 for a hash lock, s*G for a point lock
/// (Kani: an arbitrary result; fuzz: the real sha256 for both, the curve is not modelled). On
/// Err the caller discards `w` (transactions are atomic). `dest` is the account passed as the
/// locker (refund) and `signer` the signing account.
pub fn step<S>(w: &mut HWorld, op: HOp, signer: Pubkey, dest: Pubkey, t: i64, secret: [u8; 32], sha: S) -> Result<(), HkError>
where
    S: Fn(&[u8; 32]) -> [u8; 32],
{
    if w.closed {
        return Err(HkError::BadAccount); // a closed account has no data: every load fails
    }
    match op {
        HOp::Claim | HOp::PtClaim => {
            if w.h.claimer != signer {
                return Err(HkError::Unauthorized);
            }
            logic::htlc_claim_window(w.h.state, t, w.h.t1)?;
            logic::htlc_check_secret(w.h.direction, op == HOp::PtClaim, &secret, &w.h.hashlock, &sha, |s| Some(sha(s)))?;
            let (to_claimer, fee) = logic::split_fee(w.h.amount, w.h.fee_bps)?;
            pay(&mut w.escrow, &mut w.claimer, to_claimer)?;
            pay(&mut w.escrow, &mut w.vault, fee)?;
            logic::htlc_release(&mut w.h, &mut w.m, &mut w.c)?;
            w.h.state = ST_CLAIMED;
            w.h.secret = secret;
            w.h.settled_at = t;
            w.claims += 1;
            w.claimed_hash = Some(sha(&secret));
        }
        HOp::Abort => {
            let _kind = logic::htlc_abort_check(&w.h, &signer, t)?;
            logic::htlc_release(&mut w.h, &mut w.m, &mut w.c)?;
            w.h.state = ST_ABORTED;
            w.h.settled_at = t;
            w.aborted_by = Some(signer);
        }
        HOp::Refund => {
            if w.h.locker != dest {
                return Err(HkError::BadAccount);
            }
            logic::htlc_refund_window(w.h.state, t, w.h.t1)?;
            if !w.h.released {
                logic::htlc_release(&mut w.h, &mut w.m, &mut w.c)?;
            }
            pay(&mut w.escrow, &mut w.locker, w.h.amount)?;
            w.h.state = ST_REFUNDED;
            w.h.settled_at = t;
            w.refunds += 1;
        }
        HOp::Close => {
            if w.h.locker != signer {
                return Err(HkError::Unauthorized);
            }
            logic::htlc_close_allowed(w.h.state)?;
            let all = w.escrow;
            pay(&mut w.escrow, &mut w.locker, all)?;
            w.closed = true;
        }
    }
    Ok(())
}

/// The inductive invariant at clock `t` (the time of the last instruction).
pub fn inv(w: &HWorld, t: i64) -> bool {
    let h = &w.h;
    let locked_bal = w.rent as u128 + h.amount as u128;
    let roles = h.locker == key(LOCKER) && h.claimer == key(CLAIMER) && h.fee_bps <= MAX_FEE_BPS;
    let body = match h.state {
        ST_LOCKED => {
            !w.closed && !h.released && w.escrow as u128 == locked_bal && w.claims == 0 && w.refunds == 0 && w.aborted_by.is_none()
        }
        ST_ABORTED => {
            !w.closed
                && h.released
                && w.escrow as u128 == locked_bal
                && w.claims == 0
                && w.refunds == 0
                && w.aborted_by == Some(h.claimer)
                && h.settled_at < h.t1
                && h.settled_at <= t
        }
        ST_CLAIMED => {
            h.released
                && w.escrow == if w.closed { 0 } else { w.rent }
                && w.claims == 1
                && w.refunds == 0
                && w.claimed_hash == Some(h.hashlock)
                && h.settled_at < h.t1
                && h.settled_at <= t
        }
        ST_REFUNDED => {
            h.released
                && w.escrow == if w.closed { 0 } else { w.rent }
                && w.claims == 0
                && w.refunds == 1
                && (w.aborted_by == Some(h.claimer) || (w.aborted_by.is_none() && h.settled_at >= h.t1))
                && h.settled_at <= t
        }
        _ => false,
    };
    roles && body
}
