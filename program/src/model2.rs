//! Executable models of the final-round money paths, shared by the Kani harnesses
//! (`proofs_final.rs`, all inputs) and the proptest walks (`fuzz_final.rs`, long runs, real curve
//! code). Each `step` follows its handler's checks and effects in the same order, calling the
//! same `final_logic` / `logic` / `zkproof` functions; account plumbing (owners, PDAs, signer and
//! writable flags) is assumed and covered by e2e/final.test.ts.
//!
//! * `World2`: one v2 escrow (lock3 / fill_deposit; ready, abort, claim_to, refund with the tip,
//!   expire, close). Lamports of the escrow, the four actors, the fee vault and the integrator
//!   account are tracked.
//! * `OWorld`: one open offer (open; take, release, cancel, forfeit), same bookkeeping.

use crate::final_logic::{self, OF_CANCELLED, OF_DONE, OF_OPEN, OF_RESERVED};
use crate::logic;
use crate::offer::Offer;
use crate::*;

pub const LOCKER: u8 = 1;
pub const CLAIMER: u8 = 2;
pub const WT: u8 = 3;
pub const RANDO: u8 = 4;
pub const ESCROW: u8 = 9;

pub fn key(id: u8) -> Pubkey {
    let mut b = [0u8; 32];
    b[0] = id;
    Pubkey::new_from_array(b)
}

/// Index of an actor's balance (1..=4), `None` for anyone else.
pub fn idx(k: &Pubkey) -> Option<usize> {
    let b = k.to_bytes();
    if b[1..] == [0u8; 31] && (1..=4).contains(&b[0]) {
        Some(b[0] as usize)
    } else {
        None
    }
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

// ---------------------------------------------------------------------------------------------
// v2 escrow
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct World2 {
    pub e: Escrow,
    pub m: Maker,
    pub c: Config,
    pub closed: bool,
    /// Escrow rent plus pre-funding plus a fill's dust: none of it is principal; back to the
    /// locker at close.
    pub rent: u64,
    pub escrow: u64,
    /// Balances of the actors key(1..=4); index 0 unused.
    pub bal: [u64; 5],
    pub vault: u64,
    pub integ: u64,
    pub claims: u32,
    pub refunds: u32,
    pub ready_at: Option<i64>,
    pub abort: Option<(Pubkey, u8, i64)>,
    /// The proof record a claim passes (record.escrow, record.escrow_created, record.amount).
    pub proof_arg: Option<(Pubkey, i64, u64)>,
}

impl World2 {
    pub fn total(&self) -> u128 {
        let mut s = self.escrow as u128 + self.vault as u128 + self.integ as u128;
        for i in 1..5 {
            s += self.bal[i] as u128;
        }
        s
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Op2 {
    Ready,
    Abort,
    ClaimTo,
    Refund,
    Expire,
    Close,
}
pub const OPS2: [Op2; 6] = [Op2::Ready, Op2::Abort, Op2::ClaimTo, Op2::Refund, Op2::Expire, Op2::Close];

pub struct LockIn2 {
    pub c: Config,
    pub m: Maker,
    pub direction: u8,
    pub flags: u8,
    pub amount: u64,
    pub xmr_amount: u64,
    pub t0_secs: i64,
    pub window_secs: i64,
    pub watchtowers: [Pubkey; 2],
    pub claim_point: [u8; 32],
    pub refund_point: [u8; 32],
    pub integrator: Pubkey,
    pub integrator_bps: u16,
    pub tip: u64,
    /// 1 = filled from a deposit order (then `order_deadline` is its deadline, and the fill
    /// happened before it).
    pub origin: u8,
    pub order_deadline: i64,
    pub t_lock: i64,
    pub rent: u64,
    pub bal: [u64; 5],
    pub vault: u64,
    pub integ: u64,
}

/// `lock3` / `fill_deposit` (`escrow2::open_v2`): locker key(LOCKER), claimer key(CLAIMER).
pub fn lock2(i: LockIn2) -> Result<World2, HkError> {
    let (locker, claimer) = (key(LOCKER), key(CLAIMER));
    let (mut c, mut m) = (i.c, i.m);
    if i.origin == 1 && !(i.t_lock < i.order_deadline) {
        return Err(HkError::Expired);
    }
    let legacy = final_logic::check_v2_terms(
        i.direction, i.flags, &i.integrator, i.integrator_bps, i.tip, i.amount, i.window_secs, &i.watchtowers,
    )?;
    let tvl = logic::check_lock_terms(&c, &m, &locker, &claimer, i.direction, i.amount, i.xmr_amount, i.t0_secs, i.window_secs, legacy)?;
    if i.claim_point == i.refund_point {
        return Err(HkError::BadPoint);
    }
    logic::check_watchtowers(&i.watchtowers, &claimer, &locker, legacy)?;
    let fee_bps = logic::effective_fee_bps(&c, &m);
    let (t0, t1) = logic::deadlines(i.t_lock, i.t0_secs, i.window_secs)?;
    logic::open_counters(&mut m, &mut c, i.amount, tvl)?;
    let principal = i.amount.checked_add(i.tip).ok_or(HkError::Overflow)?;
    let escrow = i.rent.checked_add(principal).ok_or(HkError::Overflow)?;
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
        v2: true,
        ext: EscrowExt {
            integrator: i.integrator,
            integrator_bps: i.integrator_bps,
            origin: i.origin,
            tip: i.tip,
            order_deadline: if i.origin == 1 { i.order_deadline } else { 0 },
        },
        ..Default::default()
    };
    Ok(World2 { e, m, c, closed: false, rent: i.rent, escrow, bal: i.bal, vault: i.vault, integ: i.integ, claims: 0, refunds: 0, ready_at: None, abort: None, proof_arg: None })
}

/// One instruction on a v2 escrow. `signer` = the transaction signer (submitter / payer),
/// `dest` = the account passed as the claimer (claim_to) or the locker (refund, direct close).
pub fn step2<R>(w: &mut World2, op: Op2, signer: Pubkey, dest: Pubkey, t: i64, secret: [u8; 32], reveal: R) -> Result<(), HkError>
where
    R: Fn(&[u8; 32], &[u8; 32]) -> Result<(), HkError>,
{
    if w.closed {
        return Err(HkError::BadAccount);
    }
    let direct = w.e.flags & F_DIRECT != 0;
    match op {
        Op2::Ready => {
            if w.e.locker != signer {
                return Err(HkError::Unauthorized);
            }
            if direct {
                final_logic::late_ready_window::<HkError>(w.e.state, w.e.t1, || Ok(t))?;
            } else {
                logic::ready_window_late::<HkError>(w.e.state, w.e.t0, w.e.t1, w.e.flags, || Ok(t))?;
            }
            w.e.state = ST_READY;
            w.ready_at = Some(t);
        }
        Op2::Abort => {
            let before = w.e.state;
            let kind = final_logic::abort_check_v2(&w.e, &signer, t)?;
            if let Some(o) = logic::abort_ext_outcome(kind, signer == w.e.claimer) {
                logic::ext_count(&w.e, &mut w.m, o)?;
            }
            logic::release(&mut w.e, &mut w.m, &mut w.c)?;
            w.e.state = ST_ABORTED;
            w.e.settled_at = t;
            w.abort = Some((signer, before, t));
        }
        Op2::ClaimTo => {
            if w.e.claimer != dest {
                return Err(HkError::BadAccount);
            }
            let sub = idx(&signer).ok_or(HkError::BadAccount)?;
            logic::claim_window(w.e.state, t, w.e.t0, w.e.t1)?;
            let rec = w.proof_arg.map(|(escrow, escrow_created, amount)| crate::zkproof::ProofRec { escrow, escrow_created, amount, ..Default::default() });
            crate::zkproof::claim_gate(&w.e, &key(ESCROW), rec.as_ref())?;
            reveal(&secret, &w.e.claim_point)?;
            let (to, fee, ifee) = final_logic::split3(w.e.amount, w.e.fee_bps, w.e.ext.integrator_bps)?;
            let ci = idx(&w.e.claimer).ok_or(HkError::BadAccount)?;
            pay(&mut w.escrow, &mut w.bal[ci], to)?;
            pay(&mut w.escrow, &mut w.vault, fee)?;
            if w.e.ext.integrator != Pubkey::default() {
                pay(&mut w.escrow, &mut w.integ, ifee)?;
            }
            let tip = w.e.ext.tip;
            pay(&mut w.escrow, &mut w.bal[sub], tip)?;
            logic::release(&mut w.e, &mut w.m, &mut w.c)?;
            w.e.state = ST_CLAIMED;
            w.e.secret = secret;
            w.e.settled_at = t;
            logic::ext_count(&w.e, &mut w.m, logic::Outcome::Fill)?;
            w.claims += 1;
        }
        Op2::Refund => {
            if w.e.locker != dest {
                return Err(HkError::BadAccount);
            }
            let sub = idx(&signer).ok_or(HkError::BadAccount)?;
            logic::refund_window(w.e.state, t, w.e.t1)?;
            if direct {
                final_logic::refund_secret_v2(w.e.flags, &secret, &w.e.refund_point, |_| None)?;
            } else {
                reveal(&secret, &w.e.refund_point)?;
            }
            if !w.e.released {
                logic::release(&mut w.e, &mut w.m, &mut w.c)?;
                logic::ext_count(&w.e, &mut w.m, logic::Outcome::Failed)?;
            }
            let li = idx(&w.e.locker).ok_or(HkError::BadAccount)?;
            let (amount, tip) = (w.e.amount, w.e.ext.tip);
            pay(&mut w.escrow, &mut w.bal[li], amount)?;
            pay(&mut w.escrow, &mut w.bal[sub], tip)?;
            w.e.state = ST_REFUNDED;
            w.e.secret = secret;
            w.e.settled_at = t;
            w.refunds += 1;
        }
        Op2::Expire => {
            logic::expire_window::<HkError>(w.e.state, w.e.released, w.e.t1, || Ok(t))?;
            logic::release(&mut w.e, &mut w.m, &mut w.c)?;
            logic::ext_count(&w.e, &mut w.m, logic::Outcome::Failed)?;
        }
        Op2::Close => {
            // Direct: anyone signs, `dest` is the locker account; otherwise the locker signs and
            // is the destination.
            let to = if direct { dest } else { signer };
            if w.e.locker != to {
                return Err(HkError::Unauthorized);
            }
            final_logic::close_v2_allowed::<HkError>(w.e.state, w.e.flags, signer == w.e.locker, w.e.ext.order_deadline, || Ok(t))?;
            let li = idx(&w.e.locker).ok_or(HkError::BadAccount)?;
            let all = w.escrow;
            pay(&mut w.escrow, &mut w.bal[li], all)?;
            w.closed = true;
        }
    }
    Ok(())
}

/// P1 / P4 for one v2 step: conservation, nobody loses lamports, and each exit moves exactly its
/// share to the right party.
pub fn check_money2(b: &World2, w: &World2, op: Op2, signer: Pubkey, total0: u128) {
    assert!(w.total() == total0, "P4: lamports created or destroyed");
    assert!(w.escrow <= b.escrow);
    let out = b.escrow - w.escrow;
    for i in 1..5 {
        assert!(w.bal[i] >= b.bal[i]);
    }
    assert!(w.vault >= b.vault && w.integ >= b.integ);
    let gain = |i: usize| (w.bal[i] - b.bal[i]) as u128;
    let sub = idx(&signer).unwrap_or(0);
    let tip_to = |i: usize| if i == sub { b.e.ext.tip as u128 } else { 0 };
    let principal = b.e.amount as u128 + b.e.ext.tip as u128;
    match op {
        Op2::ClaimTo => {
            assert!(out as u128 == principal, "claim_to moved more or less than amount + tip");
            // The claimer gets the amount minus the fee and the share; the tip goes to the
            // submitter; nobody else is paid.
            let fee = (w.vault - b.vault) as u128;
            let ifee = (w.integ - b.integ) as u128;
            assert!(fee + ifee <= b.e.amount as u128);
            assert!(gain(CLAIMER as usize) == b.e.amount as u128 - fee - ifee + tip_to(CLAIMER as usize), "claim_to: claimer share");
            for i in [LOCKER as usize, WT as usize, RANDO as usize] {
                assert!(gain(i) == tip_to(i));
            }
            if b.e.ext.integrator == Pubkey::default() {
                assert!(ifee == 0);
            }
            #[cfg(not(kani))]
            {
                assert!(fee == b.e.amount as u128 * b.e.fee_bps as u128 / 10_000);
                assert!(ifee == b.e.amount as u128 * b.e.ext.integrator_bps as u128 / 10_000);
                assert!(ifee * 50 <= b.e.amount as u128, "integrator share above 2%");
            }
        }
        Op2::Refund => {
            assert!(out as u128 == principal, "refund moved more or less than amount + tip");
            assert!(gain(LOCKER as usize) == b.e.amount as u128 + tip_to(LOCKER as usize), "refund: locker");
            for i in [CLAIMER as usize, WT as usize, RANDO as usize] {
                assert!(gain(i) == tip_to(i));
            }
            assert!(w.vault == b.vault && w.integ == b.integ);
        }
        Op2::Close => {
            assert!(b.escrow == b.rent, "close took principal");
            assert!(gain(LOCKER as usize) == b.rent as u128);
        }
        _ => {
            assert!(out == 0 && w.vault == b.vault && w.integ == b.integ, "non-exit moved lamports");
            for i in 1..5 {
                assert!(gain(i) == 0);
            }
        }
    }
}

/// P1 (who and with what), P2, P3, P10, and the v2 rules for one step.
pub fn check_state2<R>(b: &World2, w: &World2, op: Op2, signer: Pubkey, dest: Pubkey, t: i64, secret: &[u8; 32], reveal: R)
where
    R: Fn(&[u8; 32], &[u8; 32]) -> Result<(), HkError>,
{
    let direct = b.e.flags & F_DIRECT != 0;
    match op {
        Op2::ClaimTo => {
            assert!(dest == b.e.claimer, "claim_to paid someone else");
            if crate::zkproof::proof_gated(b.e.direction, b.e.flags) && b.e.state != ST_READY {
                assert!(
                    matches!(b.proof_arg, Some((k, cr, a)) if k == key(ESCROW) && cr == b.e.created_at && a >= b.e.xmr_amount),
                    "P10: claim without the locker's ready or a proof of this escrow"
                );
            }
            assert!(reveal(secret, &b.e.claim_point).is_ok() && logic::scalar_is_canonical(secret));
            assert!(t < b.e.t1 && (t >= b.e.t0 || b.e.state == ST_READY), "P3: claim window");
        }
        Op2::Refund => {
            assert!(dest == b.e.locker, "refund not to the locker");
            if direct {
                assert!(*secret == [0u8; 32], "direct refund published a secret");
            } else {
                assert!(reveal(secret, &b.e.refund_point).is_ok());
            }
            assert!(b.e.state == ST_ABORTED || t >= b.e.t1, "P3: refund before abort/t1");
        }
        Op2::Abort => {
            if direct {
                assert!(signer == b.e.claimer, "direct escrow aborted by someone other than the maker");
            }
        }
        Op2::Ready => {
            assert!(signer == b.e.locker && b.e.state == ST_LOCKED);
            assert!(t < if direct { b.e.t1 } else { logic::late_deadline(b.e.t0, b.e.t1) }, "ready before the late deadline (t1 for direct)");
        }
        Op2::Close => {
            assert!(b.e.state == ST_CLAIMED || b.e.state == ST_REFUNDED);
            if b.e.ext.order_deadline != 0 && direct {
                assert!(t >= b.e.ext.order_deadline, "order escrow closed before the order deadline");
            }
            if !direct {
                assert!(signer == b.e.locker);
            }
        }
        Op2::Expire => {}
    }
    assert!(!(w.claims > 0 && w.refunds > 0) && w.claims <= 1 && w.refunds <= 1, "P2");
    let open = w.e.state == ST_LOCKED || w.e.state == ST_READY;
    if !open {
        assert!(w.e.released);
    } else if w.e.released {
        assert!(t >= w.e.t1);
    }
}

/// Inductive invariant of a v2 escrow world (`proofs_final::fr_inv2_*`).
pub fn inv2(w: &World2, t_prev: i64) -> bool {
    let e = &w.e;
    let x = &e.ext;
    let open = e.state == ST_LOCKED || e.state == ST_READY;
    let funded = open || e.state == ST_ABORTED;
    let known = funded || e.state == ST_CLAIMED || e.state == ST_REFUNDED;
    let direct = e.flags & F_DIRECT != 0;
    let listed = |k: &Pubkey| *k == e.locker || (*k != Pubkey::default() && e.watchtowers.contains(k));
    let principal = e.amount as u128 + x.tip as u128;
    let ready_by = if direct { e.t1 } else { logic::late_deadline(e.t0, e.t1) };
    known
        && e.v2
        && e.locker == key(LOCKER)
        && e.claimer == key(CLAIMER)
        && e.flags & !(F_PROOF | F_DIRECT | F_OTC) == 0
        && (e.flags & F_OTC == 0 || e.direction == DIR_SOL_TO_XMR)
        && (!direct
            || (e.direction == DIR_SOL_TO_XMR
                && e.watchtowers == [Pubkey::default(); 2]
                && e.t1.checked_sub(e.t0).is_some_and(|wd| wd >= MIN_PROOF_WINDOW)))
        && (e.flags & F_PROOF == 0 || e.direction == DIR_XMR_TO_SOL)
        && (e.direction == DIR_SOL_TO_XMR || e.direction == DIR_XMR_TO_SOL)
        && !e.watchtowers.contains(&e.claimer)
        && x.integrator_bps <= MAX_INTEGRATOR_BPS
        && (x.integrator != Pubkey::default() || x.integrator_bps == 0)
        && x.tip <= MAX_TIP
        && x.tip <= e.amount / 10
        && (x.order_deadline == 0 || x.origin == 1)
        && e.fee_bps <= MAX_FEE_BPS
        && e.t0 < e.t1
        && t_prev >= e.created_at
        && w.claims == (e.state == ST_CLAIMED) as u32
        && w.refunds == (e.state == ST_REFUNDED) as u32
        && (if w.closed {
            w.escrow == 0 && (e.state == ST_CLAIMED || e.state == ST_REFUNDED)
        } else {
            w.escrow as u128 == w.rent as u128 + if funded { principal } else { 0 }
        })
        && (e.state != ST_READY || matches!(w.ready_at, Some(ra) if ra < ready_by))
        && w.ready_at.map_or(true, |ra| ra < ready_by)
        && (e.state != ST_ABORTED
            || matches!(w.abort, Some((who, st, at))
                if (who == e.claimer && at < e.t1) || (!direct && listed(&who) && st == ST_LOCKED && at < e.t0)))
        && (open || e.released)
        && (!(open && e.released) || t_prev >= e.t1)
}

// ---------------------------------------------------------------------------------------------
// Open offer
// ---------------------------------------------------------------------------------------------

pub const BIDDER: u8 = 1;

#[derive(Clone, Debug)]
pub struct OWorld {
    pub o: Offer,
    pub closed: bool,
    /// Account rent (+ pre-funding): back to the bidder at close.
    pub rent: u64,
    pub acct: u64,
    pub bal: [u64; 5],
    pub vault: u64,
    pub integ: u64,
    pub releases: u32,
    pub cancels: u32,
}

impl OWorld {
    pub fn total(&self) -> u128 {
        let mut s = self.acct as u128 + self.vault as u128 + self.integ as u128;
        for i in 1..5 {
            s += self.bal[i] as u128;
        }
        s
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OOp {
    Take,
    /// A release with a valid direct-pay proof to the bidder's address whose payment id is the
    /// one of fill number `proof_seq` (the proof cannot carry another offer's or fill's id).
    Release,
    Cancel,
    Forfeit,
}
pub const OOPS: [OOp; 4] = [OOp::Take, OOp::Release, OOp::Cancel, OOp::Forfeit];

/// `offer_open` (the config caps are checked by the handler; not modelled).
pub fn open_offer(o: Offer, t: i64, life: i64, rent: u64, bal: [u64; 5], vault: u64, integ: u64) -> Result<OWorld, HkError> {
    final_logic::offer_terms(o.amount, o.xmr_amount, &o.integrator, o.integrator_bps, o.tip, o.fill_window, life)?;
    if o.fee_bps > MAX_FEE_BPS {
        return Err(HkError::BadParam);
    }
    let o = Offer {
        state: OF_OPEN,
        bidder: key(BIDDER),
        created_at: t,
        expires_at: t.checked_add(life).ok_or(HkError::Overflow)?,
        fill_seq: 0,
        filler: Pubkey::default(),
        deposit: 0,
        reserved_at: 0,
        deadline: 0,
        forfeits: 0,
        ..o
    };
    let acct = rent.checked_add(o.amount).and_then(|x| x.checked_add(o.tip)).ok_or(HkError::Overflow)?;
    Ok(OWorld { o, closed: false, rent, acct, bal, vault, integ, releases: 0, cancels: 0 })
}

pub fn ostep(w: &mut OWorld, op: OOp, signer: Pubkey, t: i64, proof_seq: u64) -> Result<(), HkError> {
    if w.closed {
        return Err(HkError::BadAccount);
    }
    let s = idx(&signer).ok_or(HkError::BadAccount)?;
    let b = BIDDER as usize;
    match op {
        OOp::Take => {
            let (forfeit, dep) = final_logic::offer_take(&mut w.o, &signer, t)?;
            pay(&mut w.acct, &mut w.bal[b], forfeit)?;
            pay(&mut w.bal[s], &mut w.acct, dep)?;
        }
        OOp::Release => {
            final_logic::offer_release_check(&w.o, t)?;
            let f = idx(&w.o.filler).ok_or(HkError::BadAccount)?;
            if proof_seq != w.o.fill_seq {
                return Err(HkError::BadPaymentId);
            }
            let (to, fee, ifee) = final_logic::split3(w.o.amount, w.o.fee_bps, w.o.integrator_bps)?;
            let back = to.checked_add(w.o.deposit).ok_or(HkError::Overflow)?;
            pay(&mut w.acct, &mut w.bal[f], back)?;
            pay(&mut w.acct, &mut w.vault, fee)?;
            if w.o.integrator != Pubkey::default() {
                pay(&mut w.acct, &mut w.integ, ifee)?;
            }
            let tip = w.o.tip;
            pay(&mut w.acct, &mut w.bal[s], tip)?;
            let all = w.acct;
            pay(&mut w.acct, &mut w.bal[b], all)?;
            w.o.state = OF_DONE;
            w.closed = true;
            w.releases += 1;
        }
        OOp::Cancel => {
            let is_bidder = signer == w.o.bidder;
            let forfeit = final_logic::offer_cancel(&mut w.o, is_bidder, t)?;
            let back = w.o.amount.checked_add(forfeit).ok_or(HkError::Overflow)?;
            pay(&mut w.acct, &mut w.bal[b], back)?;
            let tip = w.o.tip;
            pay(&mut w.acct, &mut w.bal[s], tip)?;
            let all = w.acct;
            pay(&mut w.acct, &mut w.bal[b], all)?;
            w.closed = true;
            w.cancels += 1;
        }
        OOp::Forfeit => {
            let d = final_logic::offer_forfeit(&mut w.o, t)?;
            pay(&mut w.acct, &mut w.bal[b], d)?;
        }
    }
    Ok(())
}

/// Inductive invariant of an offer world (`proofs_final::of_inv_*`).
pub fn oinv(w: &OWorld, t_prev: i64) -> bool {
    let o = &w.o;
    let reserved = o.state == OF_RESERVED;
    o.bidder == key(BIDDER)
        && o.integrator_bps <= MAX_INTEGRATOR_BPS
        && (o.integrator != Pubkey::default() || o.integrator_bps == 0)
        && o.fee_bps <= MAX_FEE_BPS
        && o.tip <= MAX_TIP
        && o.fill_window >= MIN_PROOF_WINDOW
        && o.fill_window <= final_logic::MAX_FILL_WINDOW
        && t_prev >= o.created_at
        && w.releases as u64 + w.cancels as u64 == w.closed as u64
        && (if w.closed {
            w.acct == 0 && (o.state == OF_DONE || o.state == OF_CANCELLED)
        } else {
            (o.state == OF_OPEN || reserved)
                && w.acct as u128 == w.rent as u128 + o.amount as u128 + o.tip as u128 + if reserved { o.deposit as u128 } else { 0 }
        })
        && (!reserved
            || (o.filler != o.bidder
                && idx(&o.filler).is_some()
                && o.deposit >= final_logic::MIN_FILL_DEPOSIT
                && o.reserved_at.checked_add(o.fill_window) == Some(o.deadline)
                && o.reserved_at <= t_prev
                && o.reserved_at < o.expires_at
                && o.fill_seq >= 1))
        && (reserved || w.closed || (o.filler == Pubkey::default() && o.deposit == 0))
}

/// Per-step offer properties: conservation and exact payouts, who may do what, when.
pub fn ocheck(b: &OWorld, w: &OWorld, op: OOp, signer: Pubkey, t: i64, proof_seq: u64, total0: u128) {
    assert!(w.total() == total0, "offer: lamports created or destroyed");
    let s = idx(&signer).unwrap();
    let bi = BIDDER as usize;
    let delta = |i: usize| w.bal[i] as i128 - b.bal[i] as i128;
    let tip_to = |i: usize| if i == s { b.o.tip as i128 } else { 0 };
    match op {
        OOp::Take => {
            assert!(b.o.state == OF_OPEN || t >= b.o.deadline, "take during a live reservation");
            assert!(t < b.o.expires_at && signer != b.o.bidder);
            assert!(w.o.filler == signer && w.o.fill_seq == b.o.fill_seq + 1 && Some(w.o.deadline) == t.checked_add(b.o.fill_window));
            // The filler pays exactly the deposit; a lapsed one's deposit goes to the bidder.
            let forfeit = if b.o.state == OF_RESERVED { b.o.deposit as i128 } else { 0 };
            assert!(delta(s) == -(w.o.deposit as i128));
            #[cfg(not(kani))]
            assert!(w.o.deposit == final_logic::filler_deposit(b.o.amount));
            assert!(delta(bi) == forfeit);
            assert!(w.vault == b.vault && w.integ == b.integ);
        }
        OOp::Release => {
            assert!(b.o.state == OF_RESERVED && t < b.o.deadline, "release outside the live reservation");
            assert!(proof_seq == b.o.fill_seq, "release with another fill's payment");
            let f = idx(&b.o.filler).unwrap();
            assert!(f != bi);
            let fee = (w.vault - b.vault) as i128;
            let ifee = (w.integ - b.integ) as i128;
            assert!(fee + ifee <= b.o.amount as i128);
            assert!(delta(f) == b.o.amount as i128 - fee - ifee + b.o.deposit as i128 + tip_to(f), "release: filler share");
            assert!(delta(bi) == b.rent as i128 + tip_to(bi), "release: bidder gets the rent only");
            for i in 1..5 {
                if i != f && i != bi {
                    assert!(delta(i) == tip_to(i));
                }
            }
        }
        OOp::Cancel => {
            assert!(signer == b.o.bidder || t >= b.o.expires_at, "cancel by a stranger before expiry");
            assert!(b.o.state == OF_OPEN || t >= b.o.deadline, "cancel during a live reservation");
            let forfeit = if b.o.state == OF_RESERVED { b.o.deposit as i128 } else { 0 };
            assert!(delta(bi) == b.o.amount as i128 + forfeit + b.rent as i128 + tip_to(bi), "cancel: bidder");
            for i in 1..5 {
                if i != bi {
                    assert!(delta(i) == tip_to(i));
                }
            }
            assert!(w.vault == b.vault && w.integ == b.integ);
        }
        OOp::Forfeit => {
            assert!(b.o.state == OF_RESERVED && t >= b.o.deadline);
            assert!(delta(bi) == b.o.deposit as i128);
            for i in 1..5 {
                if i != bi {
                    assert!(delta(i) == 0);
                }
            }
            assert!(w.o.state == OF_OPEN);
        }
    }
}
