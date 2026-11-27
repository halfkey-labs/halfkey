//! Executable model of one escrow's life, shared by the Kani harness `sm_escrow_lifecycle`
//! (bounded, all inputs) and the proptest random walk in `fuzz.rs` (long runs, real curve code).
//!
//! Each `step` follows its handler's sequence of checks and effects in `lib.rs`, calling the same
//! `logic` functions. Account plumbing (owners, PDAs, discriminators, signer and writable flags,
//! the maker/config/vault account checks) is assumed to have passed: it is covered by
//! e2e/program.test.ts, not by this model. Lamport balances of the four parties are tracked.
//! Only compiled for Kani and tests.

use crate::logic;
use crate::*;

pub const LOCKER: u8 = 1;
pub const CLAIMER: u8 = 2;
pub const WT: u8 = 3;
pub const RANDO: u8 = 4;
/// The pay-link owner (recipient) of a pay escrow: modelled as the outsider, who has no other
/// role in the escrow.
pub const RECIPIENT: u8 = RANDO;
/// The escrow account's own address (what a v1.5 proof record must name).
pub const ESCROW: u8 = 9;

pub fn key(id: u8) -> Pubkey {
    let mut b = [0u8; 32];
    b[0] = id;
    Pubkey::new_from_array(b)
}

#[derive(Clone, Debug)]
pub struct World {
    pub e: Escrow,
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
    pub ready_at: Option<i64>,
    /// (who, state before, time) of the abort.
    pub abort: Option<(Pubkey, u8, i64)>,
    /// v1.5: the payment-proof record a claimer passes, as (record.escrow, record.amount). Any
    /// record `prove_lock` ever wrote (for any escrow, any amount), or none. Environment, not
    /// escrow state: no instruction in this model changes it.
    pub proof_arg: Option<(Pubkey, i64, u64)>,
}

impl World {
    pub fn total(&self) -> u128 {
        self.escrow as u128 + self.locker as u128 + self.claimer as u128 + self.vault as u128
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op {
    Ready,
    Abort,
    Claim,
    Refund,
    Expire,
    Close,
}

pub const OPS: [Op; 6] = [Op::Ready, Op::Abort, Op::Claim, Op::Refund, Op::Expire, Op::Close];

/// Inputs of `lock` that the model takes as given (the handler reads them from the tx).
pub struct LockIn {
    pub c: Config,
    pub m: Maker,
    pub direction: u8,
    pub amount: u64,
    pub xmr_amount: u64,
    pub t0_secs: i64,
    pub window_secs: i64,
    pub watchtowers: [Pubkey; 2],
    pub claim_point: [u8; 32],
    pub refund_point: [u8; 32],
    pub t_lock: i64,
    pub rent: u64,
    pub balances: (u64, u64, u64), // locker, claimer, vault (after the locker paid in)
    /// F_PAY | F_OTC | F_VAULT. For a pay escrow `refund_point` / view key are derived on chain
    /// from the link (curve math, not modelled: taken as given).
    pub flags: u8,
}

/// `lock`: the real terms, watchtower, fee, deadline and counter logic. The locker is
/// `key(LOCKER)`, the claimer `key(CLAIMER)`; the maker authority is whichever side the direction
/// requires (else the terms check rejects it).
pub fn lock(i: LockIn) -> Result<World, HkError> {
    let (locker, claimer) = (key(LOCKER), key(CLAIMER));
    let (mut c, mut m) = (i.c, i.m);
    let tvl = logic::check_lock_terms(
        &c, &m, &locker, &claimer, i.direction, i.amount, i.xmr_amount, i.t0_secs, i.window_secs, i.flags,
    )?;
    let _pay = logic::pay_shape(i.flags, i.direction)?;
    // Final round (reviewer #2): pay escrows get a claim window of at least MIN_PROOF_WINDOW.
    crate::final_logic::proof_window_floor(i.flags, i.window_secs)?;
    if i.claim_point == i.refund_point {
        return Err(HkError::BadPoint);
    }
    // point_is_prime_order(claim/refund/view) and the pay-link derivation are not modelled (curve
    // syscalls, sha256).
    logic::check_watchtowers(&i.watchtowers, &claimer, &locker, i.flags)?;
    let fee_bps = logic::effective_fee_bps(&c, &m);
    let (t0, t1) = logic::deadlines(i.t_lock, i.t0_secs, i.window_secs)?;
    logic::open_counters(&mut m, &mut c, i.amount, tvl)?;
    let escrow = i.rent.checked_add(i.amount).ok_or(HkError::Overflow)?;
    let e = Escrow {
        state: ST_LOCKED,
        direction: i.direction,
        locker,
        claimer,
        maker: m.authority,
        amount: i.amount,
        xmr_amount: i.xmr_amount,
        fee_bps,
        claim_point: i.claim_point,
        refund_point: i.refund_point,
        watchtowers: i.watchtowers,
        created_at: i.t_lock,
        t0,
        t1,
        flags: i.flags,
        ..Default::default()
    };
    Ok(World {
        e,
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
        ready_at: None,
        abort: None,
        proof_arg: None,
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

/// One instruction. `reveal(secret, point)` stands for `check_reveal` (Kani: arbitrary syscall
/// result; fuzz: the real curve code). On Err the caller discards `w` (transactions are atomic).
pub fn step<R>(w: &mut World, op: Op, signer: Pubkey, dest: Pubkey, t: i64, secret: [u8; 32], reveal: R) -> Result<(), HkError>
where
    R: Fn(&[u8; 32], &[u8; 32]) -> Result<(), HkError>,
{
    if w.closed {
        // A closed account has no data: load_escrow fails for every instruction.
        return Err(HkError::BadAccount);
    }
    match op {
        Op::Ready if w.e.flags & F_PAY != 0 => {
            // Final round (reviewer #2): the link owner (the recipient), until t1.
            if signer != key(RECIPIENT) {
                return Err(HkError::Unauthorized);
            }
            crate::final_logic::late_ready_window::<HkError>(w.e.state, w.e.t1, || Ok(t))?;
            w.e.state = ST_READY;
            w.ready_at = Some(t);
        }
        Op::Ready => {
            if w.e.locker != signer {
                return Err(HkError::Unauthorized);
            }
            logic::ready_window_late::<HkError>(w.e.state, w.e.t0, w.e.t1, w.e.flags, || Ok(t))?;
            w.e.state = ST_READY;
            w.ready_at = Some(t);
        }
        Op::Abort => {
            let before = w.e.state;
            let kind = logic::abort_check(&w.e, &signer, t)?;
            if let Some(o) = logic::abort_ext_outcome(kind, signer == w.e.claimer) {
                logic::ext_count(&w.e, &mut w.m, o)?;
            }
            logic::release(&mut w.e, &mut w.m, &mut w.c)?;
            w.e.state = ST_ABORTED;
            w.e.settled_at = t;
            w.abort = Some((signer, before, t));
        }
        Op::Claim => {
            if w.e.claimer != signer {
                return Err(HkError::Unauthorized);
            }
            logic::claim_window(w.e.state, t, w.e.t0, w.e.t1)?;
            // v1.5 gate (the handler passes the record only for a Locked proof-mode escrow; the
            // gate ignores it otherwise, so passing it always is equivalent).
            let rec = w.proof_arg.map(|(escrow, escrow_created, amount)| crate::zkproof::ProofRec { escrow, escrow_created, amount, ..Default::default() });
            crate::zkproof::claim_gate(&w.e, &key(ESCROW), rec.as_ref())?;
            reveal(&secret, &w.e.claim_point)?;
            let (to_claimer, fee) = logic::split_fee(w.e.amount, w.e.fee_bps)?;
            pay(&mut w.escrow, &mut w.claimer, to_claimer)?;
            pay(&mut w.escrow, &mut w.vault, fee)?;
            logic::release(&mut w.e, &mut w.m, &mut w.c)?;
            w.e.state = ST_CLAIMED;
            w.e.secret = secret;
            w.e.settled_at = t;
            logic::ext_count(&w.e, &mut w.m, logic::Outcome::Fill)?;
            w.claims += 1;
        }
        Op::Refund => {
            // Anyone may submit; `dest` is the account passed as the locker.
            if w.e.locker != dest {
                return Err(HkError::BadAccount);
            }
            logic::refund_window(w.e.state, t, w.e.t1)?;
            if w.e.flags & F_PAY != 0 {
                // Never consults the curve for a pay escrow (`mul_g` unused).
                logic::refund_secret_check(w.e.flags, &secret, &w.e.refund_point, |_| None)?;
            } else {
                reveal(&secret, &w.e.refund_point)?;
            }
            if !w.e.released {
                logic::release(&mut w.e, &mut w.m, &mut w.c)?;
                logic::ext_count(&w.e, &mut w.m, logic::Outcome::Failed)?;
            }
            let amount = w.e.amount;
            pay(&mut w.escrow, &mut w.locker, amount)?;
            w.e.state = ST_REFUNDED;
            w.e.secret = secret;
            w.e.settled_at = t;
            w.refunds += 1;
        }
        Op::Expire => {
            logic::expire_window::<HkError>(w.e.state, w.e.released, w.e.t1, || Ok(t))?;
            logic::release(&mut w.e, &mut w.m, &mut w.c)?;
            logic::ext_count(&w.e, &mut w.m, logic::Outcome::Failed)?;
        }
        Op::Close if w.e.flags & F_PAY != 0 => {
            // close_pay: signer = `signer`, the locker account (rent destination) is the locker.
            logic::close_pay_allowed::<HkError>(
                w.e.state, w.e.flags, signer == w.e.locker, signer == key(RECIPIENT), w.e.settled_at, || Ok(t),
            )?;
            let all = w.escrow;
            pay(&mut w.escrow, &mut w.locker, all)?;
            w.closed = true;
        }
        Op::Close => {
            if w.e.locker != signer {
                return Err(HkError::Unauthorized);
            }
            logic::close_allowed(w.e.state, w.e.flags)?;
            let all = w.escrow;
            pay(&mut w.escrow, &mut w.locker, all)?;
            w.closed = true;
        }
    }
    Ok(())
}

/// The safety properties checked after every successful instruction: `check_money` (P1 amounts
/// and destinations, P4) and `check_state` (P1 authorization, P2, P3, counters). Kani runs them in
/// separate harnesses so each instance only contains what it asserts.
pub fn check<R>(before: &World, after: &World, op: Op, signer: Pubkey, dest: Pubkey, t: i64, secret: &[u8; 32], total0: u128, reveal: R)
where
    R: Fn(&[u8; 32], &[u8; 32]) -> Result<(), HkError>,
{
    check_money(before, after, op, total0);
    check_state(before, after, op, signer, dest, t, secret, reveal);
}

/// P1 (what moves where) and P4 (conservation, exact split).
pub fn check_money(before: &World, after: &World, op: Op, total0: u128) {
    let (b, w) = (before, after);
    // P4: no lamport created or destroyed.
    assert!(w.total() == total0, "P4: lamports created or destroyed");
    // P1: the escrow only ever pays out; nobody's balance goes down.
    assert!(w.escrow <= b.escrow);
    let esc_out = b.escrow - w.escrow;
    assert!(w.vault >= b.vault && w.locker >= b.locker && w.claimer >= b.claimer);
    match op {
        Op::Claim => {
            assert!(esc_out == b.e.amount, "P1: claim moved more or less than the amount");
            let fee = w.vault - b.vault;
            assert!((w.claimer - b.claimer) as u128 + fee as u128 == b.e.amount as u128, "P4: split");
            // Exact value and the 1% bound: checked here only in the proptest walk and in
            // fuzz::split_fee_*. Under Kani the divider is replaced by its definition and SAT
            // cannot carry the 128-bit arithmetic implication (docs/FORMAL-VERIFICATION.md, P4).
            #[cfg(not(kani))]
            {
                assert!(fee as u128 == b.e.amount as u128 * b.e.fee_bps as u128 / 10_000);
                assert!(fee as u128 * 100 <= b.e.amount as u128, "fee above 1%");
            }
            assert!(w.locker == b.locker);
        }
        Op::Refund => {
            assert!(esc_out == b.e.amount && w.locker - b.locker == b.e.amount, "P1: refund amount");
            assert!(w.claimer == b.claimer && w.vault == b.vault);
        }
        Op::Close => {
            // Only after settlement, when the principal is gone: only the rent is left.
            assert!(b.escrow == b.rent, "P1: close took principal");
            assert!(w.locker - b.locker == b.rent);
        }
        _ => assert!(
            esc_out == 0 && w.vault == b.vault && w.locker == b.locker && w.claimer == b.claimer,
            "P1: a non-exit instruction moved lamports"
        ),
    }
}

/// P1 (who may trigger an exit and with what secret), P2, P3 and the counter invariant.
pub fn check_state<R>(before: &World, after: &World, op: Op, signer: Pubkey, dest: Pubkey, t: i64, secret: &[u8; 32], reveal: R)
where
    R: Fn(&[u8; 32], &[u8; 32]) -> Result<(), HkError>,
{
    let (b, w) = (before, after);
    match op {
        Op::Claim => {
            assert!(signer == b.e.claimer, "P1: claim not by the claimer");
            // P10 (v1.5): every SOL->XMR escrow (and a proof-mode XMR->SOL one) claimed without
            // the locker's Ready had a payment proof of THIS escrow for at least its XMR amount.
            if crate::zkproof::proof_gated(b.e.direction, b.e.flags) && b.e.state != ST_READY {
                assert!(
                    matches!(b.proof_arg, Some((k, cr, a)) if k == key(ESCROW) && cr == b.e.created_at && a >= b.e.xmr_amount),
                    "P10: proof-mode claim without a proof of this escrow and amount"
                );
            }
            assert!(reveal(secret, &b.e.claim_point).is_ok(), "P1: claim without a valid reveal");
            assert!(logic::scalar_is_canonical(secret));
            assert!(b.e.fee_bps <= MAX_FEE_BPS);
        }
        Op::Refund => {
            assert!(dest == b.e.locker, "P1: refund not to the locker");
            if b.e.flags & F_PAY != 0 {
                // A pay refund reveals nothing: the payer never had the recipient's key half.
                assert!(*secret == [0u8; 32], "P1: pay refund published a secret");
            } else {
                assert!(reveal(secret, &b.e.refund_point).is_ok());
            }
        }
        Op::Close => {
            assert!(b.e.state == ST_CLAIMED || b.e.state == ST_REFUNDED);
            if b.e.flags & F_PAY != 0 && b.e.state == ST_CLAIMED && signer != key(RECIPIENT) {
                // The maker's revealed half stays readable for the recipient for the grace period.
                assert!(t >= b.e.settled_at + PAY_CLOSE_GRACE, "P1: claimed pay escrow closed early");
            }
        }
        Op::Abort => {
            if b.e.flags & F_PAY != 0 && signer != b.e.claimer {
                assert!(signer != b.e.locker && b.e.watchtowers.contains(&signer), "P1: pay abort by a non-watchtower");
            }
        }
        _ => {}
    }
    // P2: claim and refund are mutually exclusive, each at most once.
    assert!(!(w.claims > 0 && w.refunds > 0), "P2: both claim and refund");
    assert!(w.claims <= 1 && w.refunds <= 1);
    // P3: windows.
    if op == Op::Claim {
        assert!(t < b.e.t1, "P3: claim at/after t1");
        assert!(t >= b.e.t0 || b.e.state == ST_READY, "P3: early claim without ready");
        if b.e.state == ST_READY {
            // Late finish: the locker's ready may come up to max(t0, t1 - LATE_READY_MARGIN); a pay recipient's until t1.
            let by = if b.e.flags & F_PAY != 0 { b.e.t1 } else { logic::late_deadline(b.e.t0, b.e.t1) };
            assert!(matches!(b.ready_at, Some(ra) if ra < by), "P3: ready not before the late deadline (t1 for a pay escrow)");
        }
    }
    if op == Op::Refund {
        assert!(b.e.state == ST_ABORTED || t >= b.e.t1, "P3: refund before abort/t1");
        if b.e.state == ST_ABORTED {
            let (who, st, at) = b.abort.expect("aborted without an abort");
            let pay = b.e.flags & F_PAY != 0;
            let listed = (who == b.e.locker && !pay) || (who != Pubkey::default() && b.e.watchtowers.contains(&who));
            assert!(
                (who == b.e.claimer && at < b.e.t1) || (listed && st == ST_LOCKED && at < b.e.t0),
                "P3: abort outside its window or by an unlisted signer"
            );
        }
    }
    if op == Op::Ready {
        if b.e.flags & F_PAY != 0 {
            // Only the recipient (link owner) may release a pay escrow early: never the payer.
            assert!(signer == key(RECIPIENT) && signer != b.e.locker && t < b.e.t1, "P1: pay ready not by the recipient");
        } else {
            assert!(signer == b.e.locker && t < logic::late_deadline(b.e.t0, b.e.t1), "P1: ready by the locker before the late deadline");
        }
        assert!(b.e.state == ST_LOCKED);
    }
    // Counters: released at the first exit (abort/claim/refund), or by expire at/after t1.
    let open = w.e.state == ST_LOCKED || w.e.state == ST_READY;
    if !open {
        assert!(w.e.released, "settled escrow still counted as open");
    } else if w.e.released {
        assert!(t >= w.e.t1, "released before t1 while still open");
    }
}

/// Inductive invariant of one escrow's world. `t_prev` is the clock at the last instruction.
/// `lock` establishes it (`proofs::sm_inv_base`); every instruction preserves it and satisfies
/// `check_state` / `check_money` (`proofs::sm_inv_step_*`). Together: P1-P4 hold in every
/// reachable state, for any number of instructions.
pub fn inv(w: &World, t_prev: i64) -> bool {
    let e = &w.e;
    let open = e.state == ST_LOCKED || e.state == ST_READY;
    let funded = open || e.state == ST_ABORTED;
    let known = funded || e.state == ST_CLAIMED || e.state == ST_REFUNDED;
    let pay = e.flags & F_PAY != 0;
    // Who may abort before t0: the locker (not of a pay escrow) or a listed watchtower.
    let listed = |k: &Pubkey| (*k == e.locker && !pay) || (*k != Pubkey::default() && e.watchtowers.contains(k));
    known
        // Flag shape fixed at lock: known bits only, vault only with pay, pay is SOL->XMR with a
        // watchtower that is not the locker.
        && e.flags & !F_ALL == 0
        && (e.flags & F_VAULT == 0 || pay)
        && (!pay
            || (e.direction == DIR_SOL_TO_XMR
                && e.watchtowers.iter().any(|w| *w != Pubkey::default())
                && !e.watchtowers.contains(&e.locker)))
        && e.locker != e.claimer
        && e.fee_bps <= MAX_FEE_BPS
        && e.t0 < e.t1
        && t_prev >= e.created_at
        // P2 bookkeeping: each exit at most once, and only the one matching the state.
        && w.claims == (e.state == ST_CLAIMED) as u32
        && w.refunds == (e.state == ST_REFUNDED) as u32
        // Money: the principal is in the escrow exactly while it is funded.
        && (if w.closed {
            w.escrow == 0 && (e.state == ST_CLAIMED || e.state == ST_REFUNDED)
        } else {
            w.escrow as u128 == w.rent as u128 + if funded { e.amount as u128 } else { 0 }
        })
        // Ready was signed by the locker before max(t0, t1 - margin) (late finish), or before t1 by a pay escrow's recipient.
        && (e.state != ST_READY || matches!(w.ready_at, Some(ra) if ra < if pay { e.t1 } else { logic::late_deadline(e.t0, e.t1) }))
        && w.ready_at.map_or(true, |ra| ra < if pay { e.t1 } else { logic::late_deadline(e.t0, e.t1) })
        // An abort happened in its window, by an allowed signer.
        && (e.state != ST_ABORTED
            || matches!(w.abort, Some((who, st, at))
                if (who == e.claimer && at < e.t1) || (listed(&who) && st == ST_LOCKED && at < e.t0)))
        // Counters: released at the first exit, or by expire at/after t1.
        && (open || e.released)
        && (!(open && e.released) || t_prev >= e.t1)
}
