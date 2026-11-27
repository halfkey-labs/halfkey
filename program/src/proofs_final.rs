//! Kani harnesses for the final program round (v2 escrows, deposit orders, open offers,
//! reviewer decisions #2 and #5). Run with the rest:
//! `cargo kani --features no-entrypoint -Z stubbing -Z unstable-options --harness-timeout 600`.
//!
//!  * `fr_*`  single functions of `final_logic` (all inputs) and the v2 escrow lifecycle model
//!            (`model2::World2`): an inductive invariant that `lock3` / `fill_deposit` establish
//!            and every instruction preserves, with the per-step money and authorization checks;
//!  * `of_*`  the open-offer lifecycle model (`model2::OWorld`), same structure.

use crate::final_logic::{self, OF_OPEN, OF_RESERVED};
use crate::logic;
use crate::model2::{self, key, OOp, OWorld, Op2, World2};
use crate::offer::Offer;
use crate::*;

fn any_key() -> Pubkey {
    Pubkey::new_from_array(kani::any())
}

/// See proofs.rs: Rust's unsigned `/` is floor division; SAT does not finish through a 128-bit
/// divider, so harnesses that reach a fee use the definition instead (`-Z stubbing`).
/// Money harnesses: any fee value at all (conservation and destinations must hold whatever the
/// division returns; the exact value is tested by proptest), which keeps them inside 600 s.
fn any_bps_of(_amount: u64, _bps: u16) -> u64 {
    kani::any()
}

fn spec_bps_of(amount: u64, bps: u16) -> u64 {
    let prod = amount as u128 * bps as u128;
    let q: u128 = kani::any();
    let qm = q.checked_mul(10_000);
    kani::assume(matches!(qm, Some(x) if x <= prod && prod < x + 10_000));
    q as u64
}

// ---------------------------------------------------------------------------------------------
// Single functions
// ---------------------------------------------------------------------------------------------

/// The settlement split never panics and conserves the amount exactly, for any fee and share.
#[kani::proof]
#[kani::stub(logic::bps_of, spec_bps_of)]
fn fr_split3_conserves() {
    let (a, f, i): (u64, u16, u16) = (kani::any(), kani::any(), kani::any());
    if let Ok((to, fee, ifee)) = final_logic::split3(a, f, i) {
        assert!(to as u128 + fee as u128 + ifee as u128 == a as u128);
    }
}

/// Every v2 lock the terms check accepts: integrator share <= 200 bps and only with an
/// integrator, tip <= MAX_TIP and <= a tenth of the amount, F_DIRECT only SOL->XMR without
/// watchtowers and with a claim window >= MIN_PROOF_WINDOW, F_PROOF only XMR->SOL, nothing else.
#[kani::proof]
fn fr_v2_terms_bounds() {
    let (dir, flags, ibps, tip, amount, ws): (u8, u8, u16, u64, u64, i64) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    let integ = if kani::any() { Pubkey::default() } else { any_key() };
    let wt = [if kani::any() { Pubkey::default() } else { any_key() }, if kani::any() { Pubkey::default() } else { any_key() }];
    if let Ok(legacy) = final_logic::check_v2_terms(dir, flags, &integ, ibps, tip, amount, ws, &wt) {
        assert!(ibps <= MAX_INTEGRATOR_BPS && (integ != Pubkey::default() || ibps == 0));
        assert!(tip <= MAX_TIP && tip <= amount / 10);
        assert!(flags & !(F_PROOF | F_DIRECT | F_OTC) == 0 && legacy == flags & (F_PROOF | F_OTC));
        if flags & F_OTC != 0 {
            assert!(dir == DIR_SOL_TO_XMR);
        }
        if flags & F_DIRECT != 0 {
            assert!(dir == DIR_SOL_TO_XMR && wt == [Pubkey::default(); 2] && ws >= MIN_PROOF_WINDOW);
        }
        if flags & F_PROOF != 0 {
            assert!(dir == DIR_XMR_TO_SOL);
        }
    }
    // Reviewer #2 on v1 locks too: a pay escrow below the floor is refused.
    let f: u8 = kani::any();
    if final_logic::proof_window_floor(f, ws).is_ok() && f & (F_PAY | F_DIRECT) != 0 {
        assert!(ws >= MIN_PROOF_WINDOW);
    }
}

/// A fill takes at least what the escrow needs, never more than the order holds, and never
/// leaves the order address with a rent-paying balance; it fails exactly when underpaid.
#[kani::proof]
fn fr_fill_take() {
    let (bal, amount, tip, top, rmin): (u64, u64, u64, u64, u64) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    let need = amount as u128 + tip as u128 + top as u128;
    match final_logic::fill_take(bal, amount, tip, top, rmin) {
        Ok(take) => {
            assert!(take as u128 >= need && take <= bal);
            let left = bal - take;
            assert!(left == 0 || left >= rmin);
            assert!(take as u128 == need || take == bal);
        }
        Err(e) => assert!((e == HkError::Underpaid && (bal as u128) < need) || (e == HkError::Overflow && need > u64::MAX as u128)),
    }
}

/// An order refund pays out exactly the balance, all of it to R except at most the tip to the
/// caller (never after a fill), and leaves R rent-exempt when the caller is paid; it is allowed
/// exactly from the deadline or after the fill.
#[kani::proof]
fn fr_order_refund() {
    let (bal, tip, filled, rmin): (u64, u64, bool, u64) = (kani::any(), kani::any(), kani::any(), kani::any());
    let (to_r, to_c) = final_logic::order_refund_split(bal, tip, filled, rmin);
    assert!(to_r as u128 + to_c as u128 == bal as u128);
    assert!(to_c <= tip && (!filled || to_c == 0));
    assert!(to_c == 0 || to_r >= rmin);
    let (now, dl): (i64, i64) = (kani::any(), kani::any());
    let rs: bool = kani::any();
    let far = dl.checked_sub(now).map_or(true, |x| x > final_logic::MAX_ORDER_LIFE);
    assert!(final_logic::order_refund_allowed(now, dl, filled, rs).is_ok() == (now >= dl || filled || rs || far));
}

/// Legacy escrows (no F_DIRECT: lock / lock2 / vault_lock refuse the bit) see exactly the v1
/// abort and refund-secret rules; prove_lock refuses every direct escrow.
#[kani::proof]
#[kani::unwind(33)]
fn fr_v1_paths_unchanged() {
    let e = Escrow {
        state: kani::any(),
        direction: kani::any(),
        flags: kani::any(),
        locker: any_key(),
        claimer: any_key(),
        watchtowers: [any_key(), any_key()],
        t0: kani::any(),
        t1: kani::any(),
        ..Default::default()
    };
    let who = any_key();
    let t: i64 = kani::any();
    if e.flags & F_DIRECT == 0 {
        assert!(final_logic::abort_check_v2(&e, &who, t) == logic::abort_check(&e, &who, t));
        let s: [u8; 32] = kani::any();
        let img: Option<[u8; 32]> = kani::any();
        assert!(final_logic::refund_secret_v2(e.flags, &s, &e.refund_point, |_| img) == logic::refund_secret_check(e.flags, &s, &e.refund_point, |_| img));
    } else {
        // Direct: only the claimer aborts.
        if final_logic::abort_check_v2(&e, &who, t).is_ok() {
            assert!(who == e.claimer);
        }
        assert!(zkproof::prove_window(e.direction, e.flags, e.state, t, e.t1).is_err());
    }
}

/// Reviewer #5: every config init/update accepts only `unbond_secs >= MIN_UNBOND_SECS`.
#[kani::proof]
#[kani::unwind(33)]
fn fr_unbond_floor() {
    let buf: [u8; 140] = kani::any();
    let mut r = Rd::new(&buf);
    if let Ok(p) = read_config_params(&mut r) {
        assert!(p.unbond_secs >= MIN_UNBOND_SECS);
    }
}

/// The v3 consent is a fixed-length encoding under its own prefix: equal messages mean equal
/// terms, including the integrator, its share and the tip, so a maker's signature binds them.
#[kani::proof]
#[kani::unwind(470)]
fn fr_consent_v3_injective() {
    let pid = any_key();
    let (e1, e2) = (any_key(), any_key());
    let (l1, l2) = (any_key(), any_key());
    let (c1, c2) = (any_key(), any_key());
    let (a1, a2): (u64, u64) = (kani::any(), kani::any());
    let (x1, x2): (u64, u64) = (kani::any(), kani::any());
    let (cp1, cp2): ([u8; 32], [u8; 32]) = (kani::any(), kani::any());
    let (rp1, rp2): ([u8; 32], [u8; 32]) = (kani::any(), kani::any());
    let (g1, g2): (u8, u8) = (kani::any(), kani::any());
    let (k1, k2) = (any_key(), any_key());
    let (b1, b2): (u16, u16) = (kani::any(), kani::any());
    let (p1, p2): (u64, u64) = (kani::any(), kani::any());
    let x1e = EscrowExt { integrator: k1, integrator_bps: b1, tip: p1, ..Default::default() };
    let x2e = EscrowExt { integrator: k2, integrator_bps: b2, tip: p2, ..Default::default() };
    let wt = [Pubkey::default(); 2];
    let (v, q) = ([3u8; 32], [4u8; 32]);
    let m1 = escrow2::consent_message_v3(&pid, &e1, &l1, &c1, 1, a1, x1, &cp1, &rp1, &v, &q, 5, 6, 7, 50, g1, &wt, &x1e);
    let m2 = escrow2::consent_message_v3(&pid, &e2, &l2, &c2, 1, a2, x2, &cp2, &rp2, &v, &q, 5, 6, 7, 50, g2, &wt, &x2e);
    assert!(m1.len() == 456 && m2.len() == 456);
    assert!(m1[..escrow2::CONSENT_PREFIX_V3.len()] == *escrow2::CONSENT_PREFIX_V3);
    assert!(escrow2::CONSENT_PREFIX_V3 != CONSENT_PREFIX_V2 && escrow2::CONSENT_PREFIX_V3 != CONSENT_PREFIX);
    if m1 == m2 {
        assert!(e1 == e2 && l1 == l2 && c1 == c2 && a1 == a2 && x1 == x2 && cp1 == cp2 && rp1 == rp2 && g1 == g2);
        assert!(k1 == k2 && b1 == b2 && p1 == p2);
    }
}

// ---------------------------------------------------------------------------------------------
// v2 escrow lifecycle (model2::World2): inductive invariant
// ---------------------------------------------------------------------------------------------

fn any_actor() -> Pubkey {
    key(kani::any_where(|i: &u8| *i >= model2::LOCKER && *i <= model2::RANDO))
}
fn any_actor_or_default() -> Pubkey {
    if kani::any() { Pubkey::default() } else { any_actor() }
}

fn any_world2() -> World2 {
    let e = Escrow {
        state: kani::any(),
        direction: kani::any(),
        released: kani::any(),
        locker: key(model2::LOCKER),
        claimer: key(model2::CLAIMER),
        maker: any_key(),
        amount: kani::any(),
        xmr_amount: kani::any(),
        fee_bps: kani::any(),
        claim_point: kani::any(),
        refund_point: kani::any(),
        watchtowers: [any_actor_or_default(), any_actor_or_default()],
        created_at: kani::any(),
        t0: kani::any(),
        t1: kani::any(),
        settled_at: kani::any(),
        flags: kani::any(),
        v2: true,
        ext: EscrowExt {
            integrator: if kani::any() { Pubkey::default() } else { key(7) },
            integrator_bps: kani::any(),
            origin: kani::any(),
            tip: kani::any(),
            order_deadline: kani::any(),
        },
        ..Default::default()
    };
    World2 {
        e,
        m: Maker { open_swaps: kani::any(), open_lamports: kani::any(), v2: kani::any(), ..Default::default() },
        c: Config { open_tvl: kani::any(), ..Default::default() },
        closed: kani::any(),
        rent: kani::any(),
        escrow: kani::any(),
        bal: [0, kani::any(), kani::any(), kani::any(), kani::any()],
        vault: kani::any(),
        integ: kani::any(),
        claims: kani::any(),
        refunds: kani::any(),
        ready_at: kani::any(),
        abort: if kani::any() { Some((any_actor(), kani::any(), kani::any())) } else { None },
        proof_arg: if kani::any() { Some((if kani::any() { key(model2::ESCROW) } else { any_key() }, kani::any(), kani::any())) } else { None },
    }
}

/// Base case: every v2 escrow a lock or a fill creates satisfies the invariant.
#[kani::proof]
#[kani::unwind(34)]
fn fr_inv2_base() {
    let c = Config {
        fee_bps: kani::any_where(|f: &u16| *f <= MAX_FEE_BPS),
        holder_fee_bps: kani::any(),
        halfkey_mint: any_key(),
        holder_min: kani::any(),
        max_swap: kani::any(),
        max_open_tvl: kani::any(),
        open_tvl: kani::any(),
        min_t0: kani::any_where(|x: &i64| *x >= 1),
        max_t0: kani::any_where(|x: &i64| *x <= 30 * 86_400),
        min_window: kani::any_where(|x: &i64| *x >= 1),
        max_window: kani::any_where(|x: &i64| *x <= 30 * 86_400),
        ..Default::default()
    };
    kani::assume(c.holder_fee_bps <= c.fee_bps);
    let direction: u8 = kani::any();
    let m = Maker {
        active: kani::any(),
        directions: kani::any(),
        authority: key(if direction == DIR_SOL_TO_XMR { model2::CLAIMER } else { model2::LOCKER }),
        min: kani::any(),
        max: kani::any(),
        staked: kani::any(),
        stake_unlock_at: kani::any(),
        open_swaps: kani::any(),
        open_lamports: kani::any(),
        v2: kani::any(),
        ..Default::default()
    };
    let i = model2::LockIn2 {
        c,
        m,
        direction,
        flags: kani::any(),
        amount: kani::any(),
        xmr_amount: kani::any(),
        t0_secs: kani::any(),
        window_secs: kani::any(),
        watchtowers: [any_actor_or_default(), any_actor_or_default()],
        claim_point: kani::any(),
        refund_point: kani::any(),
        integrator: if kani::any() { Pubkey::default() } else { key(7) },
        integrator_bps: kani::any(),
        tip: kani::any(),
        origin: kani::any(),
        order_deadline: kani::any(),
        t_lock: kani::any_where(|t: &i64| *t >= 0 && *t <= i64::MAX - 60 * 86_400),
        rent: kani::any(),
        bal: [0, kani::any(), kani::any(), kani::any(), kani::any()],
        vault: kani::any(),
        integ: kani::any(),
    };
    let r = model2::lock2(i);
    kani::cover!(r.is_ok(), "a v2 lock succeeds");
    kani::cover!(matches!(&r, Ok(w) if w.e.flags & F_DIRECT != 0 && w.e.ext.origin == 1), "an order fill succeeds");
    if let Ok(w) = r {
        assert!(model2::inv2(&w, w.e.created_at));
    }
}

const STATE: u8 = 0;
const MONEY: u8 = 1;
/// `OP` = index into `model2::OPS2`, or `ANY` for every non-exit op (ready, abort, expire): one
/// harness per exit keeps each SAT instance small enough for the 600 s budget.
const ANY: usize = 99;

/// `S`: the signer's actor id, or 0 for any actor (see `of_step`).
fn inv2_step<const MODE: u8, const OP: usize, const S: u8>() {
    let w = any_world2();
    let t_prev: i64 = kani::any();
    kani::assume(model2::inv2(&w, t_prev));
    let t: i64 = kani::any_where(|t| *t >= t_prev);
    let op = if OP == ANY {
        [Op2::Ready, Op2::Abort, Op2::Expire][kani::any_where(|i: &usize| *i < 3)]
    } else {
        model2::OPS2[OP]
    };
    let (signer, dest) = (if S == 0 { any_actor() } else { key(S) }, any_actor());
    let secret: [u8; 32] = kani::any();
    let img: Option<[u8; 32]> = kani::any();
    let reveal = |s: &[u8; 32], p: &[u8; 32]| logic::check_reveal_with(s, p, |_| img);
    let mut next = w.clone();
    let ok = model2::step2(&mut next, op, signer, dest, t, secret, reveal).is_ok();
    let direct = w.e.flags & F_DIRECT != 0;
    if MODE == STATE {
        kani::cover!(ok && op == Op2::ClaimTo && signer != w.e.claimer, "claim_to by a relayer reachable");
        kani::cover!(ok && op == Op2::ClaimTo && direct && w.e.state == ST_LOCKED, "direct claim with a proof reachable");
        kani::cover!(ok && op == Op2::Ready && direct && t >= w.e.t0, "direct ready after t0 reachable");
        kani::cover!(ok && op == Op2::Refund && direct, "direct refund reachable");
        kani::cover!(ok && op == Op2::Refund && !direct && w.e.state == ST_ABORTED, "refund after abort reachable");
        kani::cover!(ok && op == Op2::Close && direct && w.e.ext.order_deadline != 0, "order escrow close reachable");
        kani::cover!(ok && op == Op2::Abort && direct, "direct maker decline reachable");
    }
    if ok {
        if MODE == MONEY {
            model2::check_money2(&w, &next, op, signer, w.total());
        } else {
            model2::check_state2(&w, &next, op, signer, dest, t, &secret, reveal);
            assert!(model2::inv2(&next, t), "v2 invariant broken");
        }
    }
}

#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(cadical)]
#[kani::stub(logic::bps_of, spec_bps_of)]
fn fr_inv2_step_state() {
    inv2_step::<STATE, ANY, 0>();
}
#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(cadical)]
#[kani::stub(logic::bps_of, spec_bps_of)]
fn fr_inv2_step_state_claim_to() {
    inv2_step::<STATE, 2, 0>();
}
#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(cadical)]
#[kani::stub(logic::bps_of, spec_bps_of)]
fn fr_inv2_step_state_refund() {
    inv2_step::<STATE, 3, 0>();
}
#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(cadical)]
#[kani::stub(logic::bps_of, spec_bps_of)]
fn fr_inv2_step_state_close() {
    inv2_step::<STATE, 5, 0>();
}
#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(cadical)]
#[kani::stub(logic::bps_of, any_bps_of)]
fn fr_inv2_step_money() {
    inv2_step::<MONEY, ANY, 0>();
}
#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(cadical)]
#[kani::stub(logic::bps_of, any_bps_of)]
fn fr_inv2_step_money_claim_to_1() {
    inv2_step::<MONEY, 2, 1>();
}
#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(cadical)]
#[kani::stub(logic::bps_of, any_bps_of)]
fn fr_inv2_step_money_claim_to_2() {
    inv2_step::<MONEY, 2, 2>();
}
#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(cadical)]
#[kani::stub(logic::bps_of, any_bps_of)]
fn fr_inv2_step_money_claim_to_3() {
    inv2_step::<MONEY, 2, 3>();
}
#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(cadical)]
#[kani::stub(logic::bps_of, any_bps_of)]
fn fr_inv2_step_money_claim_to_4() {
    inv2_step::<MONEY, 2, 4>();
}
#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(cadical)]
#[kani::stub(logic::bps_of, any_bps_of)]
fn fr_inv2_step_money_refund() {
    inv2_step::<MONEY, 3, 0>();
}
#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(cadical)]
#[kani::stub(logic::bps_of, any_bps_of)]
fn fr_inv2_step_money_close() {
    inv2_step::<MONEY, 5, 0>();
}

// ---------------------------------------------------------------------------------------------
// Open offers (model2::OWorld): inductive invariant
// ---------------------------------------------------------------------------------------------

fn any_offer_world() -> OWorld {
    let o = Offer {
        state: kani::any(),
        bidder: key(model2::BIDDER),
        amount: kani::any(),
        xmr_amount: kani::any(),
        fee_bps: kani::any(),
        integrator_bps: kani::any(),
        integrator: if kani::any() { Pubkey::default() } else { key(7) },
        tip: kani::any(),
        fill_window: kani::any(),
        expires_at: kani::any(),
        created_at: kani::any(),
        fill_seq: kani::any(),
        filler: any_actor_or_default(),
        deposit: kani::any(),
        reserved_at: kani::any(),
        deadline: kani::any(),
        forfeits: kani::any(),
        ..Default::default()
    };
    OWorld {
        o,
        closed: kani::any(),
        rent: kani::any(),
        acct: kani::any(),
        bal: [0, kani::any(), kani::any(), kani::any(), kani::any()],
        vault: kani::any(),
        integ: kani::any(),
        releases: kani::any(),
        cancels: kani::any(),
    }
}

/// Base case: every offer `open` creates satisfies the invariant.
#[kani::proof]
fn of_inv_base() {
    let o = Offer {
        amount: kani::any(),
        xmr_amount: kani::any(),
        fee_bps: kani::any(),
        integrator_bps: kani::any(),
        integrator: if kani::any() { Pubkey::default() } else { key(7) },
        tip: kani::any(),
        fill_window: kani::any(),
        ..Default::default()
    };
    let t: i64 = kani::any_where(|t: &i64| *t >= 0 && *t <= i64::MAX / 2);
    let r = model2::open_offer(o, t, kani::any(), kani::any(), [0, kani::any(), kani::any(), kani::any(), kani::any()], kani::any(), kani::any());
    kani::cover!(r.is_ok(), "an offer opens");
    if let Ok(w) = r {
        assert!(model2::oinv(&w, t));
    }
}

/// `S` = the signer's actor id (1..=4), or 0 for any actor: the money harnesses run one signer at a
/// time (a symbolic index into the balances makes the SAT instance too big for 600 s).
fn of_step<const MODE: u8, const OP: usize, const S: u8>() {
    let w = any_offer_world();
    let t_prev: i64 = kani::any();
    kani::assume(model2::oinv(&w, t_prev));
    let t: i64 = kani::any_where(|t| *t >= t_prev);
    let op = model2::OOPS[OP];
    let signer = if S == 0 { any_actor() } else { key(S) };
    let proof_seq: u64 = kani::any();
    let mut next = w.clone();
    let ok = model2::ostep(&mut next, op, signer, t, proof_seq).is_ok();
    if MODE == STATE {
        kani::cover!(ok && op == OOp::Take && w.o.state == OF_RESERVED, "take over a lapsed reservation reachable");
        kani::cover!(ok && op == OOp::Release, "release reachable");
        kani::cover!(ok && op == OOp::Cancel && signer != w.o.bidder, "expired cancel by anyone reachable");
        kani::cover!(ok && op == OOp::Forfeit, "forfeit reachable");
        kani::cover!(ok && op == OOp::Take && w.o.state == OF_OPEN, "take reachable");
    }
    if ok {
        if MODE == MONEY {
            model2::ocheck(&w, &next, op, signer, t, proof_seq, w.total());
        } else {
            assert!(model2::oinv(&next, t), "offer invariant broken");
        }
    }
}

macro_rules! of_harness {
    ($name:ident, STATE, $op:expr) => {
        #[kani::proof]
        #[kani::solver(cadical)]
        #[kani::stub(logic::bps_of, spec_bps_of)]
        fn $name() {
            of_step::<STATE, { $op }, 0>();
        }
    };
    ($name:ident, MONEY, $op:expr, $s:expr) => {
        #[kani::proof]
        #[kani::solver(cadical)]
        #[kani::stub(logic::bps_of, any_bps_of)]
        fn $name() {
            of_step::<MONEY, { $op }, { $s }>();
        }
    };
}
of_harness!(of_inv_step_state_take, STATE, 0);
of_harness!(of_inv_step_state_release, STATE, 1);
of_harness!(of_inv_step_state_cancel, STATE, 2);
of_harness!(of_inv_step_state_forfeit, STATE, 3);
// take by the bidder always fails (offer_take refuses it): fillers 2..=4
of_harness!(of_inv_step_money_take_2, MONEY, 0, 2);
of_harness!(of_inv_step_money_take_3, MONEY, 0, 3);
of_harness!(of_inv_step_money_take_4, MONEY, 0, 4);
of_harness!(of_inv_step_money_release_1, MONEY, 1, 1);
of_harness!(of_inv_step_money_release_2, MONEY, 1, 2);
of_harness!(of_inv_step_money_release_3, MONEY, 1, 3);
of_harness!(of_inv_step_money_release_4, MONEY, 1, 4);
of_harness!(of_inv_step_money_cancel_1, MONEY, 2, 1);
of_harness!(of_inv_step_money_cancel_2, MONEY, 2, 2);
of_harness!(of_inv_step_money_cancel_3, MONEY, 2, 3);
of_harness!(of_inv_step_money_cancel_4, MONEY, 2, 4);
of_harness!(of_inv_step_money_forfeit, MONEY, 3, 0);

/// The filler deposit is at least 1% of the amount and at least 0.01 SOL.
#[kani::proof]
#[kani::stub(logic::bps_of, spec_bps_of)]
fn of_filler_deposit_bounds() {
    let a: u64 = kani::any();
    let d = final_logic::filler_deposit(a);
    assert!(d >= final_logic::MIN_FILL_DEPOSIT && d as u128 * 10_000 + 10_000 > a as u128 * final_logic::FILL_DEPOSIT_BPS as u128);
}

// ---------------------------------------------------------------------------------------------
// Late finish
// ---------------------------------------------------------------------------------------------

/// Late finish is never stricter than the old rule: every `ready` the old window allowed, the new one allows.
#[kani::proof]
fn lf_ready_never_stricter() {
    let (state, t0, t1, flags, t): (u8, i64, i64, u8, i64) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    if logic::ready_window::<HkError>(state, t0, flags, || Ok(t)).is_ok() {
        assert!(logic::ready_window_late::<HkError>(state, t0, t1, flags, || Ok(t)).is_ok());
    }
}

/// A late `ready` is only ever: not a pay escrow, from Locked, strictly before max(t0, t1 - margin),
/// so with t1 - t0 >= margin the claiming side always keeps at least LATE_READY_MARGIN before t1.
#[kani::proof]
fn lf_ready_bounds() {
    let (state, t0, t1, flags, t): (u8, i64, i64, u8, i64) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    if logic::ready_window_late::<HkError>(state, t0, t1, flags, || Ok(t)).is_ok() {
        assert!(flags & F_PAY == 0);
        assert!(state == ST_LOCKED);
        assert!(t < t0 || t < t1.saturating_sub(LATE_READY_MARGIN));
        if t1.saturating_sub(t0) >= LATE_READY_MARGIN {
            assert!(t < t1.saturating_sub(LATE_READY_MARGIN));
        }
    }
}

/// After a late `ready`, a claim is still bounded by t1 and a refund still needs t1 (or an abort):
/// late finish moves no deadline that the refund towers or the refund path rely on.
#[kani::proof]
fn lf_claim_and_refund_deadlines_unchanged() {
    let (t0, t1, t): (i64, i64, i64) = (kani::any(), kani::any(), kani::any());
    if logic::claim_window(ST_READY, t, t0, t1).is_ok() {
        assert!(t < t1);
    }
    if logic::refund_window(ST_READY, t, t1).is_ok() {
        assert!(t >= t1);
    }
}
