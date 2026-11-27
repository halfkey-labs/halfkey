//! v1.5 Kani harnesses (docs/FORMAL-VERIFICATION.md section 4c).
//! Run with the rest: `cd program && cargo kani --features no-entrypoint -Z stubbing`.
//!
//! P9  burn auction: a take pays only the burner, at most the lot cap, never the rent reserve,
//!     only within the buyer's bounds; fees cannot be swept once the auction is on.
//! P10 payment proofs: a proof-mode claim without Ready needs a proof record of THIS escrow for
//!     at least its amount; the statement comes from the escrow only; the output check accepts
//!     only an output paying the escrow's spend key with a committed amount >= the minimum; the
//!     attestation parser counts only distinct listed keys signing exactly the header message.
//!
//! Curve and keccak are not modelled: the output-check harness replaces them by a stub that
//! returns arbitrary values and records what it was asked (so the result holds for ANY curve
//! and hash behaviour); the real curve/keccak code is tested in fuzz_v15.rs on real vectors.

use crate::burn::{self, BurnState, Take};
use crate::xmr::{self, Ops, Parsed, Statement};
use crate::zkproof::{self, ProofRec, XHeader};
use crate::*;
use core::cell::Cell;

fn any_key() -> Pubkey {
    Pubkey::new_from_array(kani::any())
}

fn any_escrow() -> Escrow {
    Escrow {
        state: kani::any(),
        direction: kani::any(),
        released: kani::any(),
        locker: any_key(),
        claimer: any_key(),
        amount: kani::any(),
        xmr_amount: kani::any(),
        claim_point: kani::any(),
        refund_point: kani::any(),
        view_pub: kani::any(),
        t0: kani::any(),
        t1: kani::any(),
        created_at: kani::any(),
        flags: kani::any(),
        ..Default::default()
    }
}

fn any_burn() -> BurnState {
    BurnState {
        mint: any_key(),
        start_price: kani::any(),
        floor_price: kani::any(),
        max_lot: kani::any(),
        start_at: kani::any(),
        takes: kani::any(),
        total_burned: kani::any(),
        total_lamports: kani::any(),
        last_price: kani::any(),
        pot: kani::any(),
    }
}

// ---------------------------------------------------------------------------------------------
// P10: payment proofs
// ---------------------------------------------------------------------------------------------

/// A claim of a proof-mode escrow passes the gate only if the locker marked it Ready, or the
/// record names this escrow and proves at least its XMR amount. Escrows without the flag are
/// never affected (the gate is a no-op for them, so phase-1 and platform escrows behave as before).
/// The gate is defined per XMR direction: SOL->XMR always, XMR->SOL with F_PROOF, nothing else
/// (the HTLC directions 4/8 are never XMR escrows, `htlc_kinds_disjoint`; their claim is the
/// preimage, `htlc_claim_needs_preimage`).
#[kani::proof]
fn p10_claim_gate_binds_escrow_and_amount() {
    let e = any_escrow();
    let key = any_key();
    let rec = ProofRec { escrow: any_key(), escrow_created: kani::any(), amount: kani::any(), ..Default::default() };
    let some: bool = kani::any();
    let r = zkproof::claim_gate(&e, &key, if some { Some(&rec) } else { None });
    let gated = e.direction == DIR_SOL_TO_XMR || (e.direction == DIR_XMR_TO_SOL && e.flags & F_PROOF != 0);
    assert_eq!(zkproof::proof_gated(e.direction, e.flags), gated);
    if e.direction == DIR_SOL_TO_ZEC || e.direction == DIR_ZEC_TO_SOL {
        assert!(!gated);
    }
    if !gated {
        assert!(r.is_ok());
    } else if r.is_ok() && e.state != ST_READY {
        assert!(e.flags & F_READY_ONLY == 0);
        // every SOL->XMR claim without Ready: a proof of THIS escrow instance and amount
        assert!(some && rec.escrow == key && rec.escrow_created == e.created_at && rec.amount >= e.xmr_amount);
    }
    let good = some && rec.escrow == key && rec.escrow_created == e.created_at && rec.amount >= e.xmr_amount;
    if e.direction == DIR_SOL_TO_XMR && e.state == ST_LOCKED && !good {
        assert!(r == Err(HkError::NotProven), "a SOL->XMR claim without ready or a valid proof of this instance");
    }
    kani::cover!(r.is_ok() && e.direction == DIR_SOL_TO_XMR && e.state == ST_LOCKED, "proven SOL->XMR claim passes");
}

/// The statement a proof is checked against is built from the escrow account alone: spend key
/// = claim_point + refund_point (as computed by the curve), view key = view_pub, minimum =
/// xmr_amount, message = the given escrow message. Nothing comes from the prover.
#[kani::proof]
fn p10_statement_from_escrow() {
    let e = any_escrow();
    let msg: [u8; 64] = kani::any();
    let sum: Option<[u8; 32]> = kani::any();
    let seen: Cell<Option<([u8; 32], [u8; 32])>> = Cell::new(None);
    let r = zkproof::statement_for(&e, &msg, |p, q| {
        seen.set(Some((*p, *q)));
        sum
    });
    assert!(seen.get() == Some((e.claim_point, e.refund_point)));
    match r {
        Ok(st) => {
            // the message is the very buffer passed in (identity, not a 64-byte compare)
            assert!(Some(st.spend) == sum && st.view == e.view_pub && st.min_amount == e.xmr_amount);
            assert!(core::ptr::eq(st.msg.as_ptr(), msg.as_ptr()) && st.msg.len() == 64);
        }
        Err(err) => assert!(sum.is_none() && err == HkError::BadPoint),
    }
}

/// prove_lock only on an open (Locked/Ready) proof-mode escrow before t1; the header must be
/// of the current epoch and network, deep enough, and the very block the proof folded to.
#[kani::proof]
fn p10_prove_window_and_header() {
    let (direction, flags, state, t, t1): (u8, u8, u8, i64, i64) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    if zkproof::prove_window(direction, flags, state, t, t1).is_ok() {
        assert!((direction == DIR_SOL_TO_XMR || flags & F_PROOF != 0) && (state == ST_LOCKED || state == ST_READY) && t < t1);
    }
    let h = XHeader { epoch: kani::any(), net: kani::any(), confirmations: kani::any(), block_id: kani::any(), ..Default::default() };
    let a = zkproof::Attesters { epoch: kani::any(), net: kani::any(), min_conf: kani::any(), ..Default::default() };
    let bid: [u8; 32] = kani::any();
    if zkproof::header_matches(&h, &a, &bid).is_ok() {
        assert!(h.epoch == a.epoch && h.net == a.net && h.confirmations >= a.min_conf && h.block_id == bid);
    }
}

/// A committee the program accepts has 1 <= threshold <= n distinct non-zero keys, a known
/// network and at least 10 confirmations (n up to 2 here; the loop is the same for 7).
// SLOW: did not finish within 600 s (32-byte key compares); opt-in with --cfg kani_slow.
// Routine coverage: fuzz_v15::attestation_rules (check_attesters cases), e2e set_attesters test.
#[cfg(kani_slow)]
#[kani::proof]
#[kani::unwind(34)]
fn p10_attester_set_rules() {
    // Keys differ in one symbolic byte over a fixed tail (32-byte symbolic compares do not finish
    // within 600 s); the rules checked are the same for any key bytes.
    let key = |b: u8, z: bool| { let mut k = [0x11u8; 32]; k[0] = b; if z { k = [0u8; 32]; } k };
    let keys: [[u8; 32]; 2] = [key(kani::any(), kani::any()), key(kani::any(), kani::any())];
    let n: usize = kani::any_where(|n| *n <= 2);
    let (net, threshold, min_conf): (u8, u8, u32) = (kani::any(), kani::any(), kani::any());
    if zkproof::check_attesters(net, threshold, n as u8, min_conf, &keys[..n]).is_ok() {
        assert!(n >= 1 && threshold >= 1 && threshold as usize <= n && net <= 2 && min_conf >= 10);
        for i in 0..n {
            assert!(keys[i] != [0u8; 32]);
            for j in 0..i {
                assert!(keys[i] != keys[j]);
            }
        }
    }
}

/// Bounded (instruction data <= 52 bytes: room for one full signature entry; 2 keys, a 2-byte
/// message): every key counted in the returned mask has a signature entry in this same instruction
/// whose public key is that key and whose message is exactly `msg`; at most `num` keys count.
/// SLOW (verified once in 2,250 s), so it is excluded from the routine run (10-minute budget per
/// harness) and opt-in: `RUSTFLAGS="--cfg kani_slow" cargo kani ... --harness
/// p10_attestation_counts_only_listed_signers`. Routine coverage: fuzz_v15::attestation_rules,
/// fuzz_v15::attestation_parser_never_panics, e2e/zk.test.ts attest_header.
#[cfg(kani_slow)]
#[kani::proof]
#[kani::unwind(53)]
fn p10_attestation_counts_only_listed_signers() {
    const N: usize = 52;
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any_where(|l| *l <= N);
    let d = &buf[..len];
    let keys: [[u8; 32]; 2] = kani::any();
    let msg: [u8; 2] = kani::any();
    if let Ok(mask) = zkproof::ed25519_signers(d, &keys, &msg) {
        let num = d[0] as usize;
        assert!(mask.count_ones() as usize <= num && mask < 4);
        let u = |i: usize| u16::from_le_bytes([d[i], d[i + 1]]) as usize;
        for j in 0..2 {
            if mask & (1 << j) != 0 {
                let mut found = false;
                for e in 0..num {
                    let b = 2 + 14 * e;
                    let (pk, mo, ml) = (u(b + 4), u(b + 8), u(b + 10));
                    if u(b + 2) == 0xffff && u(b + 6) == 0xffff && u(b + 12) == 0xffff && d[pk..pk + 32] == keys[j] && d[mo..mo + ml] == msg {
                        found = true;
                    }
                }
                assert!(found, "a counted key has no matching inline signature entry");
            }
        }
    }
}

/// Curve/keccak stub: arbitrary results; remembers the first two successful `msm2` calls.
struct Rec {
    calls: Cell<[Option<([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32])>; 2]>,
    n: Cell<usize>,
}
impl Ops for Rec {
    fn keccak(&self, _parts: &[&[u8]]) -> [u8; 32] {
        kani::any()
    }
    fn msm2(&self, a: &[u8; 32], p: &[u8; 32], b: &[u8; 32], q: &[u8; 32]) -> Option<[u8; 32]> {
        let r: Option<[u8; 32]> = kani::any();
        if let Some(x) = r {
            let mut c = self.calls.get();
            let i = self.n.get();
            if i < 2 {
                c[i] = Some((*a, *p, *b, *q, x));
                self.calls.set(c);
                self.n.set(i + 1);
            }
        }
        r
    }
    fn mul(&self, _a: &[u8; 32], _p: &[u8; 32]) -> Option<[u8; 32]> {
        kani::any()
    }
}

/// For ANY curve and hash behaviour: the output check accepts only if the curve said
/// `s*G + 1*B == P` for the statement's spend key B and the output's key P, and the curve said
/// `y*G + a*H == C` for the output's commitment C with `a` exactly the returned amount, and that
/// amount is at least the statement's minimum. So a proof can only count an output paying this
/// escrow, against this escrow's minimum, for the amount the commitment binds.
#[kani::proof]
#[kani::unwind(34)]
fn p10_output_check_binds_key_and_amount() {
    let st = Statement { spend: kani::any(), view: kani::any(), min_amount: kani::any(), msg: &[] };
    let t = Parsed { prefix_len: 0, out_key: kani::any(), view_tag: kani::any(), r_pub: kani::any(), enc: kani::any(), commit: kani::any() };
    let idx: u8 = kani::any_where(|i| (*i as usize) < xmr::MAX_OUTPUTS);
    let d: [u8; 32] = kani::any();
    let o = Rec { calls: Cell::new([None; 2]), n: Cell::new(0) };
    if let Ok(amount) = xmr::check_output(&o, &st, &t, idx, &d) {
        assert!(amount >= st.min_amount);
        let c = o.calls.get();
        let Some((_, p0, b0, q0, r0)) = c[0] else { panic!("no spend-key check") };
        assert!(p0 == xmr::G && b0 == xmr::SCALAR_ONE && q0 == st.spend && r0 == t.out_key);
        let Some((_, p1, a1, q1, r1)) = c[1] else { panic!("no commitment check") };
        assert!(p1 == xmr::G && q1 == xmr::H && r1 == t.commit);
        assert!(a1[..8] == amount.to_le_bytes() && a1[8..] == [0u8; 24]);
    }
}

// ---------------------------------------------------------------------------------------------
// P9: burn auction
// ---------------------------------------------------------------------------------------------

fn any_price(_start: u64, _floor: u64, _start_at: i64, _t: i64) -> u64 {
    kani::any()
}
fn any_cost(_price: u64, _lot: u64) -> Result<u64, HkError> {
    if kani::any() { Ok(kani::any()) } else { Err(HkError::Overflow) }
}

/// For ANY price curve and ANY cost rounding: a take moves 0 < lot <= max_lot lamports, never
/// below the rent reserve, at least the buyer's minimum, and burns between 1 and the buyer's
/// maximum.
#[kani::proof]
#[kani::unwind(34)]
#[kani::stub(burn::price_at, any_price)]
#[kani::stub(burn::cost, any_cost)]
fn p9_take_bounded() {
    let s = any_burn();
    let (vault, keep, t, max_burn, min_l): (u64, u64, i64, u64, u64) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    if let Ok(k) = burn::take_terms(&s, vault, keep, t, max_burn, min_l) {
        assert!(k.lot > 0 && k.lot <= s.max_lot && k.lot >= min_l && k.lot <= s.pot);
        assert!(vault >= keep && k.lot <= vault - keep);
        assert!(k.burn >= 1 && k.burn <= max_burn);
    }
}

/// The price is always within [floor, start] when floor <= start (as burn_init enforces), and
/// equals the start until time passes.
#[kani::proof]
fn p9_price_bounds() {
    let (start, floor, at, t): (u64, u64, i64, i64) = (kani::any(), kani::any(), kani::any(), kani::any());
    kani::assume(floor >= 1 && floor <= start);
    let p = burn::price_at(start, floor, at, t);
    assert!(p >= floor && p <= start);
    if t <= at {
        assert!(p == start);
    }
}

/// After a take the auction restarts at the take's time at `price * (1 + lot/max_lot)` (never below
/// the price or the floor; exactly twice the price, saturating, for a full lot), and the counters
/// grow by exactly the take; mint, cap and floor never change.
// SLOW: did not finish within 600 s even bounded (128-bit divider by a symbolic max_lot); opt-in
// with --cfg kani_slow. Routine coverage: fuzz_v15::burn_take_bounds (full-lot doubles, never
// above 2x, never below price or floor, counters), e2e burn_take test.
#[cfg(kani_slow)]
#[kani::proof]
fn p9_after_take_restarts_higher() {
    // Bounded (price < 2^20, lot and max_lot < 2^16): the restart contains a 128-bit divider by the
    // symbolic max_lot, which SAT does not finish at full width within 600 s.
    let mut s = any_burn();
    kani::assume(s.max_lot < 1 << 16);
    let before = s.clone();
    let k = Take { lot: kani::any_where(|l| *l < 1 << 16), burn: kani::any(), price: kani::any_where(|p| *p < 1 << 20) };
    let t: i64 = kani::any();
    if burn::after_take(&mut s, &k, t).is_ok() {
        assert!(s.start_at == t && s.start_price >= k.price && s.start_price >= before.floor_price);
        if k.lot == before.max_lot && before.max_lot > 0 {
            assert!(s.start_price == k.price.saturating_mul(2).max(before.floor_price));
        }
        if k.lot <= before.max_lot {
            assert!(s.start_price <= k.price.saturating_mul(2).max(before.floor_price));
        }
        assert!(s.total_burned == before.total_burned + k.burn && s.total_lamports == before.total_lamports + k.lot);
        assert!(s.pot == before.pot - k.lot);
        assert!(s.takes == before.takes + 1 && s.mint == before.mint && s.max_lot == before.max_lot && s.floor_price == before.floor_price);
    }
}

/// Once the fee vault holds the auction (any data), sweep_fees refuses.
#[kani::proof]
fn p9_sweep_blocked_once_burning() {
    let n: usize = kani::any();
    assert!(burn::sweep_allowed(n).is_ok() == (n == 0));
}

/// The take as the handler runs it (terms, burn from the signer's tokens, pay the signer, update),
/// over the fee vault, the signer and everyone else, for ANY price and cost: lamports are
/// conserved, the vault pays exactly the lot and only to the signer that burned, never below its
/// rent reserve, and the $HALFKEY supply drops by the burn.
#[kani::proof]
#[kani::unwind(34)]
#[kani::stub(burn::price_at, any_price)]
#[kani::stub(burn::cost, any_cost)]
fn p9_take_pays_only_the_burner() {
    let mut s = any_burn();
    let (mut vault, mut signer, other): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
    let (mut supply, mut tokens): (u64, u64) = (kani::any(), kani::any());
    kani::assume(tokens <= supply);
    let (keep, t, max_burn, min_l): (u64, i64, u64, u64) = (kani::any(), kani::any(), kani::any(), kani::any());
    let (v0, s0, sup0) = (vault, signer, supply);
    let total0 = vault as u128 + signer as u128 + other as u128;
    let mut step = || -> Result<Take, HkError> {
        let k = burn::take_terms(&s, vault, keep, t, max_burn, min_l)?;
        // BurnChecked: the token program fails the transaction unless the signer holds `burn`.
        if tokens < k.burn {
            return Err(HkError::BadState);
        }
        tokens -= k.burn;
        supply -= k.burn;
        let (v, b) = logic::pay_amounts(vault, signer, k.lot)?;
        vault = v;
        signer = b;
        burn::after_take(&mut s, &k, t)?;
        Ok(k)
    };
    if let Ok(k) = step() {
        assert!(vault as u128 + signer as u128 + other as u128 == total0);
        assert!(v0 - vault == k.lot && signer - s0 == k.lot && vault >= keep);
        assert!(sup0 - supply == k.burn && k.burn >= 1);
    }
}

// ---------------------------------------------------------------------------------------------
// v1.5 flag in lock terms
// ---------------------------------------------------------------------------------------------

/// The proof flag changes nothing about which locks are accepted except that, like every other
/// flag, it needs the maker extension: with F_PROOF set the lock check equals the check of the
/// same flags without it whenever the maker is upgraded or another flag is set.
#[kani::proof]
fn eq_lock_terms_proof() {
    let c = Config {
        paused: kani::any(),
        max_swap: kani::any(),
        max_open_tvl: kani::any(),
        open_tvl: kani::any(),
        otc_max_swap: kani::any(),
        min_t0: kani::any(),
        max_t0: kani::any(),
        min_window: kani::any(),
        max_window: kani::any(),
        ..Default::default()
    };
    let m = Maker {
        active: kani::any(),
        directions: kani::any(),
        authority: any_key(),
        min: kani::any(),
        max: kani::any(),
        v2: kani::any(),
        ext: MakerExt { otc_min: kani::any(), otc_max: kani::any(), ..Default::default() },
        ..Default::default()
    };
    let (locker, claimer) = (any_key(), any_key());
    let (direction, amount, xmr_amount, t0s, ws): (u8, u64, u64, i64, i64) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    let f: u8 = kani::any();
    let with = logic::check_lock_terms(&c, &m, &locker, &claimer, direction, amount, xmr_amount, t0s, ws, f | F_PROOF);
    let without = logic::check_lock_terms(&c, &m, &locker, &claimer, direction, amount, xmr_amount, t0s, ws, f & !F_PROOF);
    if m.v2 || f & !F_PROOF != 0 {
        assert!(with == without);
    }
}

// ---------------------------------------------------------------------------------------------
// P11: staking rewards (rewards.rs). The arithmetic runs at accumulator scale S = 8 with values
// bounded to 12-24 bits (128-bit multipliers and dividers are out of SAT's reach at full width);
// the code is the same generic code the program runs at S = 64, and the argument does not depend
// on S. Full-width behaviour: fuzz_v15::rewards_random_walk (2,000 runs, real S = 64).
// ---------------------------------------------------------------------------------------------

use crate::rewards::{self, Pool, Staker};
const S: u32 = 8;

fn small_pool() -> Pool {
    Pool { bump: 0, mint: Pubkey::default(), total_staked: kani::any_where(|x| *x < 1 << 12), acc: kani::any_where(|x| *x < 1 << 24), distributed: kani::any_where(|x| *x < 1 << 20), claimed: kani::any_where(|x| *x < 1 << 20) }
}
fn small_staker(acc: u128) -> Staker {
    Staker {
        staked: kani::any_where(|x| *x < 1 << 12),
        acc_at: kani::any_where(|x| *x <= acc),
        owed: kani::any_where(|x| *x < 1 << 20),
        unbonding: kani::any_where(|x| *x < 1 << 12),
        ..Default::default()
    }
}
/// I*: 2^S (claimed + owed_A + owed_B) + staked_A (acc - at_A) + staked_B (acc - at_B) <= 2^S distributed,
/// with total_staked = staked_A + staked_B. It implies claimed + all owed + all pending <= distributed.
fn inv_s<const T: u32>(p: &Pool, a: &Staker, b: &Staker) -> bool {
    if !(a.acc_at <= p.acc && b.acc_at <= p.acc && p.total_staked as u128 == a.staked as u128 + b.staked as u128) {
        return false;
    }
    let lhs = ((p.claimed as u128 + a.owed as u128 + b.owed as u128) << T)
        + a.staked as u128 * (p.acc - a.acc_at)
        + b.staked as u128 * (p.acc - b.acc_at);
    lhs <= (p.distributed as u128) << T
}
fn inv(p: &Pool, a: &Staker, b: &Staker) -> bool {
    inv_s::<S>(p, a, b)
}

/// Total claimed never exceeds total credited: I* holds after any stake, unstake or claim by
/// either staker, from any state where it held (induction; the empty pool satisfies it). The
/// credit step is tested, not proven (see the note below).
/// SLOW: verified once in 427 s alone, but over the 600 s budget on a loaded machine, so it is
/// opt-in (`--cfg kani_slow`). Routine coverage: fuzz_v15::rewards_random_walk, e2e staking tests.
#[cfg(kani_slow)]
#[kani::proof]
fn p11_claims_never_exceed_credits() {
    let mut p = small_pool();
    let mut a = small_staker(p.acc);
    let mut b = small_staker(p.acc);
    kani::assume(inv(&p, &a, &b));
    let op: u8 = kani::any_where(|o| *o < 4);
    let x: u64 = kani::any_where(|x| *x < 1 << 12);
    let r = match op {
        0 => rewards::stake_s::<S>(&mut p, &mut a, x),
        1 => rewards::unstake_s::<S>(&mut p, &mut a, x, 0).map(|_| ()),
        2 => rewards::claim_s::<S>(&mut p, &mut a).map(|_| ()),
        _ => rewards::claim_s::<S>(&mut p, &mut b).map(|_| ()),
    };
    if r.is_ok() {
        assert!(inv(&p, &a, &b));
        assert!(p.claimed <= p.distributed);
    }
}

// The credit step (acc += floor(x * 2^S / total)) is NOT a Kani harness: it contains a 128-bit
// divider by a symbolic total, and CBMC did not finish it in 10 hours even at scale 2^4 with
// 5-10-bit values. It is covered by fuzz_v15::credit_keeps_claims_within_credits (full 2^64 scale)
// and fuzz_v15::rewards_random_walk, and by the staking e2e tests. docs/FORMAL-VERIFICATION.md 4c.

/// One staker cannot take another's share: anything staker A does (stake, unstake, claim, settle)
/// leaves staker B's record and the accumulator untouched, so B's claimable amount is unchanged.
#[kani::proof]
fn p11_one_staker_cannot_touch_another() {
    let mut p = small_pool();
    let mut a = small_staker(p.acc);
    let b = small_staker(p.acc);
    let (acc0, b0) = (p.acc, b.clone());
    let before = rewards::pending_s::<S>(p.acc, &b);
    let op: u8 = kani::any_where(|o| *o < 4);
    let x: u64 = kani::any_where(|x| *x < 1 << 12);
    let r = match op {
        0 => rewards::stake_s::<S>(&mut p, &mut a, x),
        1 => rewards::unstake_s::<S>(&mut p, &mut a, x, 0).map(|_| ()),
        2 => rewards::claim_s::<S>(&mut p, &mut a).map(|_| ()),
        _ => rewards::settle_s::<S>(&p, &mut a),
    };
    if r.is_ok() {
        assert!(p.acc == acc0 && b == b0);
        assert!(rewards::pending_s::<S>(p.acc, &b) == before);
    }
}

/// Stake and unstake neither create nor destroy rewards: the staker's earned amount moves into
/// `owed` exactly, nothing is credited or paid, and afterwards it has nothing pending.
#[kani::proof]
fn p11_stake_unstake_conserve_rewards() {
    let mut p = small_pool();
    let mut a = small_staker(p.acc);
    let (p0, a0) = (p.clone(), a.clone());
    let earned = rewards::pending_s::<S>(p.acc, &a);
    let x: u64 = kani::any_where(|x| *x < 1 << 12);
    let r = if kani::any() { rewards::stake_s::<S>(&mut p, &mut a, x) } else { rewards::unstake_s::<S>(&mut p, &mut a, x, 0).map(|_| ()) };
    if r.is_ok() {
        let earned = earned.unwrap();
        assert!(a.owed == a0.owed + earned);
        assert!(rewards::pending_s::<S>(p.acc, &a) == Ok(0));
        assert!(p.acc == p0.acc && p.distributed == p0.distributed && p.claimed == p0.claimed);
        assert!(a.staked as u128 + a.unbonding as u128 == a0.staked as u128 + a0.unbonding as u128 + if a.staked > a0.staked { x as u128 } else { 0 });
    }
}

/// The crank's split is exact for every input: stakers get floor(u/2), the burn pot gets the rest
/// (the odd lamport of dust), the two add up to the unsplit fees; nobody staked -> all to burn.
#[kani::proof]
fn p11_split_exact() {
    let (u, t): (u64, u64) = (kani::any(), kani::any());
    let (a, b) = rewards::split(u, t);
    assert!(a as u128 + b as u128 == u as u128);
    if t == 0 {
        assert!(a == 0 && b == u);
    } else {
        assert!(a == u / 2 && (b == a || b == a + 1));
    }
}

/// Loose SOL in the pool counts only above rent and everything still owed to stakers.
#[kani::proof]
fn p11_pool_extra_never_touches_owed() {
    let p = Pool { distributed: kani::any(), claimed: kani::any(), ..Default::default() };
    kani::assume(p.claimed <= p.distributed);
    let (lamports, keep): (u64, u64) = (kani::any(), kani::any());
    let e = rewards::pool_extra(lamports, keep, &p);
    if e > 0 {
        assert!(lamports as u128 >= keep as u128 + (p.distributed - p.claimed) as u128 + e as u128);
    }
}
