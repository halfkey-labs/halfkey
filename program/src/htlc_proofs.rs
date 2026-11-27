//! Kani harnesses for the HTLC kind (SOL <-> transparent ZEC).
//! Run: `cd program && cargo kani --features no-entrypoint -Z stubbing --harness htlc_proofs::`.
//!
//! Money paths, for every input:
//!  * H1 no claim without the preimage: a claim succeeds only if sha256(secret) == hashlock, it is
//!    signed by the claimer, the escrow is Locked and t < t1; the claimer and the fee vault get
//!    exactly the escrowed amount.
//!  * H2 refund only to the locker, and only after t1 unless the claimer itself gave up first
//!    (abort is claimer-only); the locker gets exactly the amount; nothing else moves.
//!  * H3 no double spend: claim and refund are mutually exclusive, the swap amount leaves the
//!    escrow at most once (`claims + refunds <= 1`), and lamports are conserved.
//! Proved over the lifecycle model (`htlc_model.rs`, the handlers' sequence of `logic` calls) as an
//! inductive invariant: `lock` establishes it (htlc_inv_base) and every instruction preserves it
//! (htlc_inv_step_*), so H1-H3 hold in every reachable state after any number of instructions.
//! sha256 is an arbitrary function result (as the curve syscall is in proofs.rs).

use crate::htlc::Htlc;
use crate::htlc_model::{self as hm, HOp, HWorld};
use crate::logic;
use crate::*;

fn any_key() -> Pubkey {
    Pubkey::new_from_array(kani::any())
}

fn any_config() -> Config {
    Config {
        paused: kani::any(),
        bump: kani::any(),
        vault_bump: kani::any(),
        admin: any_key(),
        fee_recipient: any_key(),
        halfkey_mint: any_key(),
        fee_bps: kani::any(),
        holder_fee_bps: kani::any(),
        holder_min: kani::any(),
        min_bond: kani::any(),
        max_swap: kani::any(),
        max_open_tvl: kani::any(),
        open_tvl: kani::any(),
        min_t0: kani::any(),
        max_t0: kani::any(),
        min_window: kani::any(),
        max_window: kani::any(),
        unbond_secs: kani::any(),
        total_swaps: kani::any(),
        total_volume: kani::any(),
        total_fees: kani::any(),
        otc_max_swap: kani::any(),
        vault_min_delay: kani::any(),
        offer_tvl: kani::any(),
    }
}

/// Only the fields the HTLC logic reads are free (endpoint/extension are irrelevant here).
fn any_maker() -> Maker {
    Maker {
        active: kani::any(),
        directions: kani::any(),
        authority: any_key(),
        min: kani::any(),
        max: kani::any(),
        open_swaps: kani::any(),
        open_lamports: kani::any(),
        staked: kani::any(),
        stake_unlock_at: kani::any(),
        ..Default::default()
    }
}

fn any_actor() -> Pubkey {
    let id: u8 = kani::any_where(|i| *i >= hm::LOCKER && *i <= hm::RANDO);
    hm::key(id)
}

fn any_htlc() -> Htlc {
    Htlc {
        state: kani::any(),
        direction: kani::any(),
        bump: kani::any(),
        released: kani::any(),
        swap_id: [0; 32],
        locker: hm::key(hm::LOCKER),
        claimer: hm::key(hm::CLAIMER),
        maker: any_key(),
        amount: kani::any(),
        zec_amount: kani::any(),
        fee_bps: kani::any(),
        hashlock: kani::any(),
        quote_hash: [0; 32],
        created_at: kani::any(),
        t1: kani::any(),
        settled_at: kani::any(),
        secret: kani::any(),
    }
}

fn any_world() -> HWorld {
    HWorld {
        h: any_htlc(),
        m: any_maker(),
        c: any_config(),
        closed: kani::any(),
        rent: kani::any(),
        escrow: kani::any(),
        locker: kani::any(),
        claimer: kani::any(),
        vault: kani::any(),
        claims: kani::any(),
        refunds: kani::any(),
        aborted_by: if kani::any() { Some(any_actor()) } else { None },
        claimed_hash: kani::any(),
    }
}

/// `bps_of` with its 128-bit divider replaced by the definition of unsigned division (same stub
/// and justification as proofs::spec_bps_of; run with `-Z stubbing`).
fn spec_bps_of(amount: u64, bps: u16) -> u64 {
    let prod = amount as u128 * bps as u128;
    let q: u128 = kani::any();
    let qm = q.checked_mul(10_000);
    kani::assume(matches!(qm, Some(x) if x <= prod && prod < x + 10_000));
    q as u64
}

fn any_op() -> HOp {
    let i: usize = kani::any_where(|x| *x < hm::HOPS.len());
    hm::HOPS[i]
}

// ---------------------------------------------------------------------------------------------
// Single functions, all inputs
// ---------------------------------------------------------------------------------------------

/// H1 (function level): the claim checks pass only for the exact preimage, Locked, before t1.
#[kani::proof]
#[kani::unwind(33)]
fn htlc_claim_needs_preimage() {
    let (state, t, t1): (u8, i64, i64) = (kani::any(), kani::any(), kani::any());
    let (secret, hashlock, img): ([u8; 32], [u8; 32], [u8; 32]) = (kani::any(), kani::any(), kani::any());
    let ok = logic::htlc_claim_window(state, t, t1).is_ok() && logic::check_preimage_with(&secret, &hashlock, |_| img).is_ok();
    if ok {
        assert!(img == hashlock);
        assert!(state == ST_LOCKED && t < t1);
    }
    kani::cover!(ok, "a claim passes its checks");
}

/// H2 (function level): a refund window opens only after an abort or at/after t1 from Locked, and
/// only the claimer can abort (before t1, from Locked).
#[kani::proof]
#[kani::unwind(33)]
fn htlc_refund_only_after_timeout_or_claimer_abort() {
    let (state, t, t1): (u8, i64, i64) = (kani::any(), kani::any(), kani::any());
    if logic::htlc_refund_window(state, t, t1).is_ok() {
        assert!(state == ST_ABORTED || (state == ST_LOCKED && t >= t1));
    }
    let h = any_htlc();
    let who = any_key();
    let ta: i64 = kani::any();
    if logic::htlc_abort_check(&h, &who, ta).is_ok() {
        assert!(who == h.claimer && h.state == ST_LOCKED && ta < h.t1);
    }
}

/// H3 (function level): no (state, time) passes both the claim and the refund window.
#[kani::proof]
fn htlc_claim_refund_exclusive() {
    let (state, t, t1): (u8, i64, i64) = (kani::any(), kani::any(), kani::any());
    assert!(!(logic::htlc_claim_window(state, t, t1).is_ok() && logic::htlc_refund_window(state, t, t1).is_ok()));
}

/// The two kinds never cross: the XMR lock check rejects the HTLC directions, and the HTLC lock
/// check accepts nothing but them (the accounts are also disjoint by discriminator and seed).
#[kani::proof]
#[kani::unwind(33)]
fn htlc_kinds_disjoint() {
    let c = any_config();
    let m = any_maker();
    let (locker, claimer) = (any_key(), any_key());
    let d: u8 = kani::any();
    let xmr = logic::check_lock_terms(&c, &m, &locker, &claimer, d, kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    let htlc_dirs = [DIR_SOL_TO_ZEC, DIR_ZEC_TO_SOL, DIR_SOL_TO_ZEC_PT, DIR_ZEC_TO_SOL_PT];
    if htlc_dirs.contains(&d) {
        assert!(xmr.is_err());
    }
    let hl = logic::htlc_lock_terms(&c, &m, &locker, &claimer, d, kani::any(), kani::any(), &kani::any(), kani::any());
    if hl.is_ok() {
        assert!(htlc_dirs.contains(&d));
        assert!(m.directions & d != 0 && m.active && !c.paused);
        // The maker is the claimer of SOL->ZEC and the locker of ZEC->SOL (both lock kinds).
        let sol_to_zec = d == DIR_SOL_TO_ZEC || d == DIR_SOL_TO_ZEC_PT;
        assert!(if sol_to_zec { claimer == m.authority } else { locker == m.authority });
    }
}

/// H1 for the point lock (ZEC v2), function level, every input: `htlc_pt_claim` passes its secret
/// check only on a point-locked escrow, with a canonical scalar t whose t*G is the stored point;
/// `htlc_claim` passes only on a hash-locked escrow with sha256(x) == hashlock. The two kinds'
/// claims never cross (mul_g and sha256 are arbitrary functions here).
#[kani::proof]
#[kani::unwind(33)]
fn htlc_pt_claim_needs_scalar() {
    let d: u8 = kani::any();
    let point_ix: bool = kani::any();
    let (secret, lock, sha_img, g_img): ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) = (kani::any(), kani::any(), kani::any(), kani::any());
    let g_ok: bool = kani::any(); // the syscall may fail to multiply (None)
    let r = logic::htlc_check_secret(d, point_ix, &secret, &lock, |_| sha_img, |_| if g_ok { Some(g_img) } else { None });
    if r.is_ok() {
        let point_dir = d == DIR_SOL_TO_ZEC_PT || d == DIR_ZEC_TO_SOL_PT;
        assert!(point_dir == point_ix, "a claim of the wrong kind passed");
        if point_ix {
            assert!(logic::scalar_is_canonical(&secret) && g_ok && g_img == lock);
        } else {
            assert!(sha_img == lock);
        }
    }
    kani::cover!(r.is_ok() && point_ix, "a point claim passes");
    kani::cover!(r.is_ok() && !point_ix, "a hash claim passes");
}

/// A successful HTLC lock respects the per-swap and open-TVL caps and counts the swap exactly
/// once (counter induction step, like sm_lock_inductive).
#[kani::proof]
#[kani::unwind(33)]
fn htlc_lock_inductive() {
    let mut c = any_config();
    let mut m = any_maker();
    let (b_n, b_l, b_t) = (m.open_swaps, m.open_lamports, c.open_tvl);
    let amount: u64 = kani::any();
    let Ok(tvl) = logic::htlc_lock_terms(&c, &m, &any_key(), &any_key(), kani::any(), amount, kani::any(), &kani::any(), kani::any()) else { return };
    assert!(amount <= c.max_swap && amount >= m.min && amount <= m.max);
    if logic::open_counters(&mut m, &mut c, amount, tvl).is_ok() {
        assert!(m.open_swaps as u64 == b_n as u64 + 1);
        assert!(m.open_lamports as u128 == b_l as u128 + amount as u128);
        assert!(c.open_tvl as u128 == b_t as u128 + amount as u128);
        assert!(c.open_tvl <= c.max_open_tvl);
    }
}

/// htlc_release from "the others' contribution + this escrow's" leaves exactly the others'; a
/// second release is a no-op (so an exit never fails on the counters).
#[kani::proof]
fn htlc_release_inductive() {
    let mut h = any_htlc();
    let (b_n, b_l, b_t): (u32, u64, u64) = (kani::any(), kani::any(), kani::any());
    let (own_n, own_l) = if h.released { (0u32, 0u64) } else { (1u32, h.amount) };
    let mut m = any_maker();
    let mut c = any_config();
    let (Some(n), Some(l), Some(t)) = (b_n.checked_add(own_n), b_l.checked_add(own_l), b_t.checked_add(own_l)) else { return };
    m.open_swaps = n;
    m.open_lamports = l;
    c.open_tvl = t;
    assert!(logic::htlc_release(&mut h, &mut m, &mut c).is_ok());
    assert!(h.released && m.open_swaps == b_n && m.open_lamports == b_l && c.open_tvl == b_t);
    assert!(logic::htlc_release(&mut h, &mut m, &mut c).is_ok());
    assert!(m.open_swaps == b_n && m.open_lamports == b_l && c.open_tvl == b_t);
}

// ---------------------------------------------------------------------------------------------
// Lifecycle: inductive invariant (htlc_model::inv)
// ---------------------------------------------------------------------------------------------

/// Base: every escrow `lock` creates satisfies the invariant (config invariant assumed, as in
/// proofs::sm_inv_base: the config instructions bound fee and windows).
#[kani::proof]
#[kani::unwind(34)]
fn htlc_inv_base() {
    let c = any_config();
    kani::assume(c.fee_bps <= MAX_FEE_BPS && c.holder_fee_bps <= c.fee_bps);
    kani::assume(c.min_t0 >= 1 && c.max_t0 <= 30 * 86_400 && c.min_window >= 1 && c.max_window <= 30 * 86_400);
    let mut m = any_maker();
    let direction: u8 = kani::any();
    m.authority = hm::key(if logic::is_sol_to_zec(direction) { hm::CLAIMER } else { hm::LOCKER });
    let t_lock: i64 = kani::any_where(|t| *t >= 0 && *t <= i64::MAX - 61 * 86_400);
    let r = hm::lock(hm::HLockIn {
        c,
        m,
        direction,
        amount: kani::any(),
        zec_amount: kani::any(),
        hashlock: kani::any(),
        t1_secs: kani::any(),
        t_lock,
        rent: kani::any(),
        balances: (kani::any(), kani::any(), kani::any()),
    });
    kani::cover!(r.is_ok(), "an HTLC lock succeeds");
    if let Ok(w) = r {
        assert!(hm::inv(&w, t_lock));
        assert!(w.h.t1 > t_lock); // the claim window is never empty
    }
}

const STATE: u8 = 0;
const MONEY: u8 = 1;

/// Step: from ANY world satisfying the invariant, any instruction (op, signer, destination,
/// secret, hash result, pause flag, later time) that succeeds keeps the invariant and satisfies
/// H1-H3 for that step.
/// `OPS`: ALL_OPS, or one claim instruction / only the other ops (the money harness is split in
/// three so each part stays inside the per-harness timeout; together they cover every op).
const ALL_OPS: u8 = 0;
const HASH_CLAIM: u8 = 1;
const OTHER_OPS: u8 = 2;
const PT_CLAIM: u8 = 3;
fn inv_step<const MODE: u8, const OPS: u8>() {
    let w = any_world();
    let t_prev: i64 = kani::any();
    kani::assume(hm::inv(&w, t_prev));
    let t: i64 = kani::any_where(|t| *t >= t_prev); // the clock never goes backwards
    let op = any_op();
    let is_claim = op == HOp::Claim || op == HOp::PtClaim;
    if OPS == HASH_CLAIM {
        kani::assume(op == HOp::Claim);
    } else if OPS == PT_CLAIM {
        kani::assume(op == HOp::PtClaim);
    } else if OPS == OTHER_OPS {
        kani::assume(!is_claim);
    }
    let (signer, dest) = (any_actor(), any_actor());
    let secret: [u8; 32] = kani::any();
    let img: [u8; 32] = kani::any();
    let sha = |_: &[u8; 32]| img;
    let mut next = w.clone();
    next.c.paused = kani::any();
    let ok = hm::step(&mut next, op, signer, dest, t, secret, sha).is_ok();
    kani::cover!(ok && op == HOp::Claim, "claim reachable");
    kani::cover!(ok && op == HOp::PtClaim, "point claim reachable");
    kani::cover!(ok && op == HOp::Abort, "abort reachable");
    kani::cover!(ok && op == HOp::Refund && w.h.state == ST_ABORTED, "refund after abort reachable");
    kani::cover!(ok && op == HOp::Refund && w.h.state == ST_LOCKED, "refund after t1 reachable");
    kani::cover!(ok && op == HOp::Close, "close reachable");
    kani::cover!(ok && next.c.paused && op == HOp::Claim, "claim while paused reachable");
    kani::cover!(ok && next.c.paused && op == HOp::Refund, "refund while paused reachable");
    if !ok {
        return;
    }
    if MODE == STATE {
        assert!(hm::inv(&next, t), "invariant broken");
        match op {
            HOp::Claim | HOp::PtClaim => {
                // H1 (both lock kinds), and the instruction matches the escrow's kind.
                assert!(img == w.h.hashlock, "claim without the preimage");
                assert!(signer == w.h.claimer && w.h.state == ST_LOCKED && t < w.h.t1);
                assert!(logic::is_point_dir(w.h.direction) == (op == HOp::PtClaim));
            }
            HOp::Refund => {
                // H2
                assert!(dest == w.h.locker);
                assert!(w.h.state == ST_ABORTED || (w.h.state == ST_LOCKED && t >= w.h.t1));
                assert!(w.h.state != ST_ABORTED || w.aborted_by == Some(w.h.claimer));
            }
            HOp::Abort => assert!(signer == w.h.claimer && w.h.state == ST_LOCKED && t < w.h.t1),
            HOp::Close => assert!(signer == w.h.locker && (w.h.state == ST_CLAIMED || w.h.state == ST_REFUNDED)),
        }
        // H3: the swap amount leaves the escrow at most once, and settled states are terminal.
        assert!(next.claims + next.refunds <= 1);
        if w.h.state == ST_CLAIMED || w.h.state == ST_REFUNDED {
            assert!(next.h.state == w.h.state && next.claims == w.claims && next.refunds == w.refunds);
        }
    } else {
        // Lamports conserved across the four parties.
        assert!(next.total() == w.total(), "lamports created or destroyed");
        let amt = w.h.amount as u128;
        let (dl, dc, dv) = (
            next.locker as i128 - w.locker as i128,
            next.claimer as i128 - w.claimer as i128,
            next.vault as i128 - w.vault as i128,
        );
        match op {
            HOp::Claim | HOp::PtClaim => {
                // claimer + fee vault get exactly the amount; the locker gets nothing.
                assert!(dl == 0 && dc >= 0 && dv >= 0 && (dc + dv) as u128 == amt);
                assert!(dv as u128 * 10_000 <= amt * MAX_FEE_BPS as u128); // fee <= 1%
            }
            HOp::Refund => assert!(dl as u128 == amt && dc == 0 && dv == 0),
            HOp::Abort => assert!(dl == 0 && dc == 0 && dv == 0),
            HOp::Close => assert!(dc == 0 && dv == 0 && dl as u128 == w.rent as u128),
        }
    }
}

#[kani::proof]
#[kani::unwind(34)]
#[kani::stub(logic::bps_of, spec_bps_of)]
fn htlc_inv_step_state() {
    inv_step::<STATE, ALL_OPS>();
}

#[kani::proof]
#[kani::unwind(34)]
#[kani::stub(logic::bps_of, spec_bps_of)]
fn htlc_inv_step_money_claim() {
    inv_step::<MONEY, HASH_CLAIM>();
}

/// `scalar_is_canonical` replaced by an arbitrary answer: a sound over-approximation (every real
/// run is still covered), and the money property cannot depend on it. Keeps CBMC inside the timeout.
fn any_canonical(_s: &[u8; 32]) -> bool {
    kani::any()
}

#[kani::proof]
#[kani::unwind(34)]
#[kani::stub(logic::bps_of, spec_bps_of)]
#[kani::stub(logic::scalar_is_canonical, any_canonical)]
fn htlc_inv_step_money_pt_claim() {
    inv_step::<MONEY, PT_CLAIM>();
}

#[kani::proof]
#[kani::unwind(34)]
#[kani::stub(logic::bps_of, spec_bps_of)]
fn htlc_inv_step_money_others() {
    inv_step::<MONEY, OTHER_OPS>();
}

/// The SOL->ZEC consent is a fixed-length (250 byte) encoding under its own prefix: equal
/// messages mean equal terms, and it can never equal an XMR consent (v1 or v2), so a maker's
/// signature for one kind is useless for the other.
#[kani::proof]
#[kani::unwind(260)]
fn htlc_consent_message_injective() {
    let pid = any_key();
    let (e1, e2) = (any_key(), any_key());
    let (l1, l2) = (any_key(), any_key());
    let (c1, c2) = (any_key(), any_key());
    let (d1, d2): (u8, u8) = (kani::any(), kani::any());
    let (a1, a2): (u64, u64) = (kani::any(), kani::any());
    let (z1, z2): (u64, u64) = (kani::any(), kani::any());
    let (h1, h2): ([u8; 32], [u8; 32]) = (kani::any(), kani::any());
    let (q1, q2): ([u8; 32], [u8; 32]) = (kani::any(), kani::any());
    let (t1, t2): (i64, i64) = (kani::any(), kani::any());
    let (x1, x2): (i64, i64) = (kani::any(), kani::any());
    let (f1, f2): (u16, u16) = (kani::any(), kani::any());
    let m1 = crate::htlc::consent_message(&pid, &e1, &l1, &c1, d1, a1, z1, &h1, &q1, t1, x1, f1);
    let m2 = crate::htlc::consent_message(&pid, &e2, &l2, &c2, d2, a2, z2, &h2, &q2, t2, x2, f2);
    assert!(m1.len() == 250 && m2.len() == 250);
    // Differs from both XMR prefixes within their common length.
    assert!(m1[..CONSENT_PREFIX.len()] != *CONSENT_PREFIX && m1[..CONSENT_PREFIX_V2.len()] != *CONSENT_PREFIX_V2);
    if m1 == m2 {
        assert!(e1 == e2 && l1 == l2 && c1 == c2 && d1 == d2 && a1 == a2 && z1 == z2);
        assert!(h1 == h2 && q1 == q2 && t1 == t2 && x1 == x2 && f1 == f2);
    }
}
