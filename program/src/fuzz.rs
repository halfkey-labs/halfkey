//! Tests that complement the Kani proofs (`cargo test --features no-entrypoint`):
//!  * curve checks on the host build of `solana-curve25519`, the same crate (and dalek code)
//!    Agave's curve25519 syscalls run, including an exhaustive pass over every non-canonical
//!    point encoding;
//!  * a proptest random walk of the escrow model (`model.rs`) with long runs and the real
//!    `s*G` code instead of Kani's arbitrary syscall result.
//! More cases: `PROPTEST_CASES=20000 cargo test --release --features no-entrypoint`.

use crate::model::{self, Op, World};
use crate::*;
use proptest::prelude::*;
use solana_curve25519::edwards::{add_edwards, multiply_edwards, PodEdwardsPoint};
use solana_curve25519::scalar::PodScalar;

/// Case count: the default given, or `PROPTEST_CASES` when set (explicit configs ignore it).
fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn mul_g(s: &[u8; 32]) -> [u8; 32] {
    multiply_edwards(&PodScalar(*s), &PodEdwardsPoint(G)).unwrap().0
}

fn mul(s: &[u8; 32], p: &[u8; 32]) -> [u8; 32] {
    multiply_edwards(&PodScalar(*s), &PodEdwardsPoint(*p)).unwrap().0
}

fn add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    add_edwards(&PodEdwardsPoint(*a), &PodEdwardsPoint(*b)).unwrap().0
}

/// A canonical non-zero scalar from 32 random bytes (top 4 bits cleared: < 2^252 < L).
fn scalar(seed: [u8; 32]) -> [u8; 32] {
    let mut s = seed;
    s[31] &= 0x0f;
    if s == [0u8; 32] {
        s[0] = 1;
    }
    s
}

/// s + k*L over 256 bits, or None on overflow.
fn plus_kl(s: &[u8; 32], k: u64) -> Option<[u8; 32]> {
    let limb = |b: &[u8; 32], i: usize| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap());
    let mut a = [0u8; 32];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let v = limb(s, i) as u128 + limb(&L, i) as u128 * k as u128 + carry;
        a[8 * i..8 * i + 8].copy_from_slice(&(v as u64).to_le_bytes());
        carry = v >> 64;
    }
    (carry == 0).then_some(a)
}

fn real_reveal(s: &[u8; 32], p: &[u8; 32]) -> Result<(), HkError> {
    logic::check_reveal_with(s, p, |s| multiply_edwards(&PodScalar(*s), &PodEdwardsPoint(G)).map(|p| p.0))
}

/// An order-8 point (also used by e2e/program.test.ts).
const T8: [u8; 32] = [
    0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
    0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
];

fn small_order_points() -> Vec<[u8; 32]> {
    (0u8..8)
        .map(|k| {
            let mut s = [0u8; 32];
            s[0] = k;
            mul(&s, &T8)
        })
        .collect()
}

/// Every non-canonical 32-byte encoding of a curve point: y >= p (y = p + j, j < 19, either sign
/// bit) and x = 0 with the sign bit set (y = 1 and y = p - 1). 40 strings in total.
fn noncanonical_encodings() -> Vec<[u8; 32]> {
    let mut v = Vec::new();
    for j in 0u8..19 {
        // p = 2^255 - 19 = ed ff .. ff 7f (LE); p + j for j < 19 has the same upper bytes.
        let mut e = [0xffu8; 32];
        e[0] = 0xed + j;
        e[31] = 0x7f;
        v.push(e);
        let mut n = e;
        n[31] |= 0x80;
        v.push(n);
    }
    let mut one_neg = IDENTITY;
    one_neg[31] |= 0x80;
    v.push(one_neg);
    let mut pm1 = [0xffu8; 32];
    pm1[0] = 0xec;
    pm1[31] = 0xff; // y = p - 1, sign bit set
    v.push(pm1);
    v
}

// ---------------------------------------------------------------------------------------------
// P7: points and scalars on the real curve code
// ---------------------------------------------------------------------------------------------

#[test]
fn small_order_points_rejected() {
    let pts = small_order_points();
    assert!(pts.contains(&IDENTITY));
    for p in &pts {
        assert!(!point_is_prime_order(p), "small-order point accepted: {p:02x?}");
    }
}

#[test]
fn canonical_identity_rejected() {
    assert!(!point_is_prime_order(&IDENTITY));
}

/// Non-canonical encodings: before the BUG-1 fix the only ones accepted were encodings of the
/// identity point (docs/FORMAL-VERIFICATION.md); with the fix none are.
#[test]
fn noncanonical_encodings_audit() {
    for p in noncanonical_encodings() {
        if point_is_prime_order(&p) {
            assert_eq!(add(&p, &IDENTITY), IDENTITY, "non-identity non-canonical point accepted: {p:02x?}");
        }
    }
}

/// BUG-1: `point_is_prime_order` compares against the canonical identity bytes only, and the
/// syscalls decode non-canonical encodings, so 3 encodings of the identity pass as "prime order".
/// Fixed on this branch (canonical re-encoding check in point_is_prime_order).
#[test]
fn bug1_noncanonical_encodings_rejected() {
    let accepted: Vec<_> = noncanonical_encodings().into_iter().filter(point_is_prime_order).collect();
    assert!(accepted.is_empty(), "accepted non-canonical encodings: {accepted:02x?}");
}

/// s*G from the syscall is always a canonical encoding, so a non-canonical claim/refund point can
/// never be matched by any reveal: BUG-1 cannot be used to take funds, only to make a point
/// unclaimable.
#[test]
fn noncanonical_point_never_revealable() {
    for p in noncanonical_encodings() {
        for k in 0u8..=16 {
            let mut s = [0u8; 32];
            s[0] = k;
            assert_ne!(mul_g(&s), p);
        }
        // and the canonical form of the identity is what 0*G gives
        assert_eq!(mul_g(&[0u8; 32]), IDENTITY);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(256)))]

    /// A random s*G is accepted; adding any non-zero torsion component makes it rejected.
    #[test]
    fn prime_order_points_and_torsion(seed in any::<[u8; 32]>()) {
        let s = scalar(seed);
        let p = mul_g(&s);
        prop_assert!(point_is_prime_order(&p));
        prop_assert_eq!(add(&p, &IDENTITY), p, "s*G is canonical");
        for t in small_order_points().iter().skip(1) {
            prop_assert!(!point_is_prime_order(&add(&p, t)));
        }
    }

    /// check_reveal: the right scalar passes; every alias s + k*L is NonCanonicalScalar; a wrong
    /// scalar is WrongSecret.
    #[test]
    fn reveal_accepts_only_the_canonical_secret(seed in any::<[u8; 32]>(), other in any::<[u8; 32]>()) {
        let s = scalar(seed);
        let p = mul_g(&s);
        prop_assert!(check_reveal(&s, &p).is_ok());
        for k in 1..=15 {
            if let Some(a) = plus_kl(&s, k) {
                // Two layers: the program rejects the alias before any syscall (proved in Kani:
                // p7_*), and the current syscall code (solana-curve25519 3.1.14,
                // Scalar::from_canonical_bytes) refuses non-canonical scalars too.
                prop_assert_eq!(check_reveal(&a, &p), Err(HkError::NonCanonicalScalar.into()));
                prop_assert!(multiply_edwards(&PodScalar(a), &PodEdwardsPoint(G)).is_none());
            }
        }
        let o = scalar(other);
        if o != s {
            prop_assert_eq!(check_reveal(&o, &p), Err(HkError::WrongSecret.into()));
        }
    }

    /// Random 32-byte strings: anything accepted as a swap point is a canonical, non-identity,
    /// prime-order point.
    #[test]
    fn random_bytes_point_check(b in any::<[u8; 32]>()) {
        if point_is_prime_order(&b) {
            prop_assert_eq!(add(&b, &IDENTITY), b);
            prop_assert_ne!(b, IDENTITY);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Lifecycle random walk (P1-P4, P6) with the real curve code
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Setup {
    direction: u8,
    fee_bps: u16,
    holder: bool,
    amount: u64,
    t0_secs: i64,
    window_secs: i64,
    wt0: bool,
    wt1_locker: bool,
    claim_seed: [u8; 32],
    refund_seed: [u8; 32],
    open_before: u64,
}

fn setup() -> impl Strategy<Value = Setup> {
    (
        prop_oneof![Just(DIR_SOL_TO_XMR), Just(DIR_XMR_TO_SOL)],
        0u16..=MAX_FEE_BPS,
        any::<bool>(),
        1u64..=u64::MAX / 4,
        1i64..=50,
        1i64..=50,
        any::<bool>(),
        any::<bool>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        0u64..=u64::MAX / 4,
    )
        .prop_map(|(direction, fee_bps, holder, amount, t0_secs, window_secs, wt0, wt1_locker, claim_seed, refund_seed, open_before)| Setup {
            direction, fee_bps, holder, amount, t0_secs, window_secs, wt0, wt1_locker, claim_seed, refund_seed, open_before,
        })
}

/// (op, signer, refund destination, seconds to advance, secret kind)
fn steps() -> impl Strategy<Value = Vec<(usize, u8, u8, u8, u8)>> {
    prop::collection::vec((0usize..6, 1u8..=4, 1u8..=4, 0u8..40, 0u8..6), 1..40)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(512)))]

    #[test]
    fn lifecycle_random_walk(su in setup(), walk in steps(), junk in any::<[u8; 32]>()) {
        let (cs, rs) = (scalar(su.claim_seed), scalar(su.refund_seed));
        prop_assume!(cs != rs);
        let (cp, rp) = (mul_g(&cs), mul_g(&rs));
        let mint = model::key(9);
        let c = Config {
            halfkey_mint: mint,
            fee_bps: su.fee_bps,
            holder_fee_bps: su.fee_bps / 2,
            holder_min: 1000,
            max_swap: u64::MAX / 4,
            max_open_tvl: u64::MAX / 2,
            open_tvl: su.open_before,
            min_t0: 1,
            max_t0: 50,
            min_window: 1,
            max_window: 50,
            ..Default::default()
        };
        let m = Maker {
            active: true,
            directions: DIR_SOL_TO_XMR | DIR_XMR_TO_SOL,
            authority: model::key(if su.direction == DIR_SOL_TO_XMR { model::CLAIMER } else { model::LOCKER }),
            min: 1,
            max: u64::MAX / 4,
            open_lamports: su.open_before,
            open_swaps: 3,
            staked: if su.holder { 5000 } else { 0 },
            ..Default::default()
        };
        let wt = [
            if su.wt0 { model::key(model::WT) } else { Pubkey::default() },
            if su.wt1_locker { model::key(model::LOCKER) } else { model::key(model::RANDO) },
        ];
        let w0 = model::lock(model::LockIn {
            c, m, direction: su.direction, amount: su.amount, xmr_amount: 1, t0_secs: su.t0_secs,
            window_secs: su.window_secs, watchtowers: wt, claim_point: cp, refund_point: rp,
            t_lock: 1_700_000_000, rent: 2_039_280, balances: (5_000_000, 0, 890_880), flags: 0,
        });
        let mut w: World = w0.expect("valid lock rejected");
        prop_assert_eq!(w.e.fee_bps, if su.holder { su.fee_bps / 2 } else { su.fee_bps });
        let total0 = w.total();
        let mut t = w.e.created_at;
        prop_assert!(model::inv(&w, t));
        for (op_i, s_i, d_i, dt, kind) in walk {
            t += dt as i64;
            let op: Op = model::OPS[op_i];
            let secret = match kind {
                0 => cs,
                1 => rs,
                2 => plus_kl(&cs, 1).unwrap(),
                3 => plus_kl(&rs, 1).unwrap(),
                4 => scalar(junk),
                _ => junk,
            };
            let (signer, dest) = (model::key(s_i), model::key(d_i));
            for paused in [false, true] {
                let mut x = w.clone();
                x.c.paused = paused;
                let mut y = w.clone();
                y.c.paused = !paused;
                prop_assert_eq!(
                    model::step(&mut x, op, signer, dest, t, secret, real_reveal),
                    model::step(&mut y, op, signer, dest, t, secret, real_reveal),
                    "P6"
                );
            }
            let mut next = w.clone();
            if model::step(&mut next, op, signer, dest, t, secret, real_reveal).is_ok() {
                model::check(&w, &next, op, signer, dest, t, &secret, total0, real_reveal);
                prop_assert!(model::inv(&next, t), "invariant broken");
                // Only the true discrete logs ever pass on the real curve.
                if op == Op::Claim { prop_assert_eq!(secret, cs); }
                if op == Op::Refund { prop_assert_eq!(secret, rs); }
                w = next;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// split_fee vs the original inline expression (the divider Kani replaces by its definition)
// ---------------------------------------------------------------------------------------------

/// Verbatim pre-refactor claim fee code (d00f39f).
fn orig_split_fee(amount: u64, fee_bps: u16) -> Result<(u64, u64), ProgramError> {
    let fee = ((amount as u128) * (fee_bps as u128) / 10_000) as u64;
    let to_claimer = amount.checked_sub(fee).ok_or(ProgramError::from(HkError::Overflow))?;
    Ok((to_claimer, fee))
}

#[test]
fn split_fee_edges_match_original() {
    let amounts = [0u64, 1, 99, 100, 9_999, 10_000, 10_001, 1 << 32, u64::MAX / 10_000, u64::MAX / 100, u64::MAX - 1, u64::MAX];
    for a in amounts {
        for b in [0u16, 1, 25, 50, 99, 100, 101, 9_999, 10_000, 10_001, u16::MAX] {
            assert_eq!(logic::split_fee(a, b).map_err(ProgramError::from), orig_split_fee(a, b), "{a} {b}");
            if b <= MAX_FEE_BPS {
                let (to, f) = logic::split_fee(a, b).unwrap();
                assert!(f as u128 * 100 <= a as u128 && to as u128 + f as u128 == a as u128);
                assert_eq!(f as u128, a as u128 * b as u128 / 10_000);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(20_000)))]
    #[test]
    fn split_fee_matches_original(a in any::<u64>(), b in any::<u16>()) {
        prop_assert_eq!(logic::split_fee(a, b).map_err(ProgramError::from), orig_split_fee(a, b));
        let fee = logic::bps_of(a, b) as u128;
        let prod = a as u128 * b as u128;
        if prod / 10_000 <= u64::MAX as u128 {
            prop_assert!(fee * 10_000 <= prod && prod < fee * 10_000 + 10_000, "bps_of is floor division");
        }
        // P4 for every storable fee: never fails, fee <= 1%, exact split.
        let s = b.min(MAX_FEE_BPS);
        let (to, f) = logic::split_fee(a, s).expect("split failed at a storable fee");
        prop_assert!(f as u128 * 100 <= a as u128 && to as u128 + f as u128 == a as u128);
    }
}

// ---------------------------------------------------------------------------------------------
// P1 tripwire: the complete list of places that debit a program-owned account
// ---------------------------------------------------------------------------------------------

/// Lamports leave program accounts only through `pay` (directly or via `close_account`). This
/// pins every call site, by enclosing handler, so a new debit path fails the test and forces a
/// review of P1 (docs/FORMAL-VERIFICATION.md).
#[test]
fn lamport_debit_sites_unchanged() {
    let src = include_str!("lib.rs");
    let mut handler = "";
    let mut sites = Vec::new();
    for line in src.lines() {
        let l = line.trim_start();
        if let Some(rest) = l.strip_prefix("fn ").or_else(|| l.strip_prefix("pub fn ")) {
            handler = rest.split(['(', '<']).next().unwrap();
            continue;
        }
        if l.starts_with("//") {
            continue;
        }
        let is_pay = l.starts_with("pay(") || l.contains(" pay(");
        if is_pay || l.contains("close_account(") || l.contains("try_borrow_mut_lamports") {
            let what = if l.contains("close_account(") { "close_account" } else if is_pay { "pay" } else { "lamports" };
            sites.push(format!("{handler}:{what}"));
        }
    }
    assert_eq!(
        sites,
        [
            "pay:lamports", "pay:lamports",                // the one place balances are written
            "close_account:pay",                           // all lamports to dest, then closed
            "withdraw_maker:close_account",                // maker account -> its authority
            "open_escrow:pay",                             // vault_lock: cashout vault -> new escrow
                                                           //   (amount + rent; vault terms, logic::vault_*)
            "claim:pay", "claim:pay",                      // escrow -> claimer, escrow -> fee vault
            "refund:pay",                                  // escrow -> locker (a vault for vault escrows)
            "refund:pay",                                  // v2 only: the tip -> the submitter
            "close:close_account",                         // v2: settled escrow rent -> locker
            "close:close_account",                         // settled escrow rent -> locker
            "close_pay:close_account",                     // settled pay escrow rent -> locker
            "sweep_fees:pay",                              // fee vault -> configured recipient
            "vault_withdraw:pay",                          // cashout vault -> its owner, after the timelock
        ]
    );
}

// Lifecycle walk over (almost) unconstrained configs and makers, with an arbitrary s*G result:
// the random-input mirror of the Kani lifecycle harnesses (which cover all inputs, bounded).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(20000)))]
    #[test]
    fn lifecycle_unconstrained_walk(
        fee in 0u16..=100, hfee in 0u16..=100, min_t0 in 1i64..100, t0span in 0i64..100, min_w in 1i64..100, wspan in 0i64..100,
        open_tvl in any::<u64>(), max_tvl in any::<u64>(), max_swap in any::<u64>(), mint in any::<bool>(), holder_min in any::<u64>(),
        dirs in any::<u8>(), mmin in any::<u64>(), mmax in any::<u64>(), staked in any::<u64>(), unlock in any::<i64>(),
        osw in any::<u32>(), olam in any::<u64>(), direction in 0u8..4, amount in any::<u64>(), xmr in any::<u64>(),
        t0s in -5i64..200, ws in -5i64..200, wt0 in any::<bool>(), wt1 in any::<bool>(), cp in any::<[u8;32]>(), rp in any::<[u8;32]>(),
        t_lock in 0i64..(1i64<<40), rent in any::<u64>(), bl in any::<u64>(), bc in any::<u64>(), bv in any::<u64>(),
        flags in prop_oneof![Just(0u8), Just(F_OTC), Just(F_PAY), Just(F_PAY | F_OTC), Just(F_PAY | F_VAULT), any::<u8>()],
        v2 in any::<bool>(), otc_max_swap in any::<u64>(), otc_min in any::<u64>(), otc_max in any::<u64>(), zero_secret in any::<bool>(),
        walk in prop::collection::vec((0usize..6, 1u8..=4, 1u8..=4, any::<u32>(), any::<[u8;32]>(), any::<Option<[u8;32]>>(), any::<bool>()), 1..5),
    ) {
        let hfee = hfee.min(fee);
        let olam = olam.min(open_tvl);
        let (mmin, mmax, max_swap, dirs) = (mmin.min(amount), mmax.max(amount), max_swap.max(amount), dirs | direction);
        let max_tvl = max_tvl.max(open_tvl.saturating_add(amount));
        let t0s = min_t0 + t0s.rem_euclid(t0span + 1);
        // Pay escrows need a claim window of at least MIN_PROOF_WINDOW (final round): shift theirs.
        let lift = if flags & F_PAY != 0 { MIN_PROOF_WINDOW } else { 0 };
        let ws = min_w + ws.rem_euclid(wspan + 1) + lift;
        let xmr = xmr.max(1);
        prop_assume!(cp != rp);
        let c = Config { fee_bps: fee, holder_fee_bps: hfee, min_t0, max_t0: (min_t0 + t0span).min(30*86400), min_window: min_w, max_window: (min_w + wspan + lift).min(30*86400),
            open_tvl, max_open_tvl: max_tvl, max_swap, halfkey_mint: if mint { model::key(9) } else { Pubkey::default() }, holder_min,
            otc_max_swap: if otc_max_swap % 2 == 0 { 0 } else { otc_max_swap.max(amount) }, ..Default::default() };
        let mut m = Maker { active: true, directions: dirs, min: mmin, max: mmax, staked, stake_unlock_at: unlock, open_swaps: osw, open_lamports: olam,
            v2: v2 || flags != 0, ..Default::default() };
        if otc_max % 2 == 1 { m.ext.otc_min = otc_min.min(amount).max(1); m.ext.otc_max = otc_max.max(amount); }
        m.authority = model::key(if direction == DIR_SOL_TO_XMR { model::CLAIMER } else { model::LOCKER });
        let wt = [if wt0 { model::key(model::WT) } else { Pubkey::default() }, if wt1 { model::key(model::LOCKER) } else { model::key(model::RANDO) }];
        let lk = model::lock(model::LockIn { c, m, direction, amount, xmr_amount: xmr, t0_secs: t0s, window_secs: ws, watchtowers: wt,
            claim_point: cp, refund_point: rp, t_lock, rent, balances: (bl, bc, bv), flags });
        let Ok(mut w) = lk else { return Ok(()) };
        prop_assert!(w.e.t0 > w.e.created_at && w.e.t1 > w.e.t0, "deadlines");
        prop_assert!(model::inv(&w, w.e.created_at));
        let total0 = w.total();
        let mut t = w.e.created_at;
        for (op_i, s_i, d_i, dt, secret, img, paused) in walk {
            // Pay refunds need an all-zero secret: try it often enough to reach them.
            let secret = if zero_secret && w.e.flags & F_PAY != 0 { [0u8; 32] } else { secret };
            // A claimed pay escrow's grace period is 90 days: jump over it sometimes.
            t += if dt % 7 == 0 { PAY_CLOSE_GRACE } else { dt as i64 };
            let op = model::OPS[op_i];
            let (signer, dest) = (model::key(s_i), model::key(d_i));
            let reveal = |s: &[u8; 32], p: &[u8; 32]| logic::check_reveal_with(s, p, |_| img);
            let mut next = w.clone(); next.c.paused = paused;
            let r = model::step(&mut next, op, signer, dest, t, secret, reveal);
            let mut alt = w.clone(); alt.c.paused = !paused;
            prop_assert_eq!(r, model::step(&mut alt, op, signer, dest, t, secret, reveal));
            if r.is_ok() {
                let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| model::check(&w, &next, op, signer, dest, t, &secret, total0, reveal)));
                prop_assert!(res.is_ok(), "check failed: op {:?} state {} amount {} rent {} esc {} -> {}", op, w.e.state, w.e.amount, w.rent, w.escrow, next.escrow);
                prop_assert!(model::inv(&next, t), "invariant broken");
                w = next;
            }
        }
    }
}

/// P6 tripwire: the protocol pause flag is read only by `lock` (via logic::check_lock_terms),
/// `register_maker`, `update_maker` (re-activation) and `vault_create`. A cashout vault's own
/// pause flag is read by `logic::vault_lock_terms` (conversions) and `logic::vault_tighten`
/// (unpausing is timelocked); neither is an exit. A new reader fails this test and forces a
/// review of "pause never blocks an exit" (docs/FORMAL-VERIFICATION.md).
#[test]
fn paused_read_sites_unchanged() {
    fn readers(src: &str) -> Vec<String> {
        let mut f = "";
        let mut out = Vec::new();
        for line in src.lines() {
            let l = line.trim_start();
            if let Some(rest) = l.strip_prefix("fn ").or_else(|| l.strip_prefix("pub fn ")) {
                f = rest.split(['(', '<']).next().unwrap();
            }
            if !l.starts_with("//") && l.contains(".paused") && !l.contains(".paused =") && !l.contains("self.paused") {
                out.push(f.to_string());
            }
        }
        out
    }
    assert_eq!(readers(include_str!("lib.rs")), ["register_maker", "update_maker", "vault_create"]);
    assert_eq!(readers(include_str!("logic.rs")), ["check_lock_terms", "vault_tighten", "vault_tighten", "vault_lock_terms", "htlc_lock_terms"]);
}
