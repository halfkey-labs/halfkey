//! Proptests for the HTLC kind: a random walk of the lifecycle model (`htlc_model.rs`) with the
//! real sha256 (the same `solana_sha256_hasher` the program calls), checking the invariant, the
//! money properties and the preimage rule at every step. Complements `htlc_proofs.rs`.
//! More cases: `PROPTEST_CASES=20000 cargo test --release --features no-entrypoint htlc_fuzz`.

use crate::htlc_model::{self as hm, HOp, HWorld};
use crate::logic;
use crate::*;
use proptest::prelude::*;

fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn sha(s: &[u8; 32]) -> [u8; 32] {
    solana_sha256_hasher::hash(s).to_bytes()
}

fn config() -> Config {
    Config {
        fee_bps: 50,
        holder_fee_bps: 25,
        max_swap: 50_000_000_000,
        max_open_tvl: 400_000_000_000,
        min_t0: 60,
        max_t0: 3_600,
        min_window: 60,
        max_window: 7_200,
        ..Default::default()
    }
}

fn maker(authority: Pubkey) -> Maker {
    Maker { active: true, directions: ALL_DIRS, authority, min: 1, max: 50_000_000_000, ..Default::default() }
}

fn new_world(direction: u8, amount: u64, x: &[u8; 32], t1_secs: i64, rent: u64) -> Result<HWorld, HkError> {
    let auth = hm::key(if logic::is_sol_to_zec(direction) { hm::CLAIMER } else { hm::LOCKER });
    hm::lock(hm::HLockIn {
        c: config(),
        m: maker(auth),
        direction,
        amount,
        zec_amount: 150_000_000,
        hashlock: sha(x),
        t1_secs,
        t_lock: 1_000_000,
        rent,
        balances: (10_000_000_000, 0, 890_880),
    })
}

#[derive(Clone, Debug)]
struct Act {
    op: u8,
    signer: u8,
    dest: u8,
    dt: i64,
    /// 0 = the true preimage, 1 = a random 32 bytes, 2 = the preimage with one bit flipped.
    secret_kind: u8,
    noise: [u8; 32],
    bit: u8,
}

fn act() -> impl Strategy<Value = Act> {
    (0u8..5, 1u8..=4, 1u8..=4, 0i64..2_000, 0u8..3, any::<[u8; 32]>(), any::<u8>())
        .prop_map(|(op, signer, dest, dt, secret_kind, noise, bit)| Act { op, signer, dest, dt, secret_kind, noise, bit })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(4000)))]

    /// Random walks of up to 24 instructions from a fresh lock: the invariant holds after every
    /// step, lamports are conserved, a claim never succeeds without the exact preimage, a refund
    /// only pays the locker after t1 or after the claimer's abort, and at most one of them happens.
    #[test]
    fn htlc_walk(
        dir in prop_oneof![Just(DIR_SOL_TO_ZEC), Just(DIR_ZEC_TO_SOL), Just(DIR_SOL_TO_ZEC_PT), Just(DIR_ZEC_TO_SOL_PT)],
        amount in 1u64..50_000_000_000,
        x0 in any::<[u8; 32]>(),
        t1_secs in 120i64..10_800,
        rent in 0u64..3_000_000,
        acts in proptest::collection::vec(act(), 1..24),
    ) {
        // A point lock's secret is a canonical scalar (t < 2^252 here, as the DLEQ needs).
        let mut x = x0;
        if logic::is_point_dir(dir) { x[31] &= 0x0f; }
        let mut w = new_world(dir, amount, &x, t1_secs, rent).unwrap();
        let mut t = w.h.created_at;
        prop_assert!(hm::inv(&w, t));
        let total = w.total();
        for a in acts {
            t += a.dt;
            let op = hm::HOPS[a.op as usize];
            let secret = match a.secret_kind {
                0 => x,
                1 => a.noise,
                _ => { let mut s = x; s[(a.bit % 32) as usize] ^= 1 << (a.bit % 8); s }
            };
            let mut next = w.clone();
            let ok = hm::step(&mut next, op, hm::key(a.signer), hm::key(a.dest), t, secret, sha).is_ok();
            if !ok { continue; }
            prop_assert!(hm::inv(&next, t));
            prop_assert_eq!(next.total(), total);
            match op {
                HOp::Claim | HOp::PtClaim => {
                    prop_assert_eq!(op, hm::claim_op(dir));
                    prop_assert_eq!(sha(&secret), w.h.hashlock);
                    prop_assert_eq!(secret, x);
                    prop_assert!(t < w.h.t1);
                    prop_assert_eq!((next.claimer - w.claimer) + (next.vault - w.vault), w.h.amount);
                }
                HOp::Refund => {
                    prop_assert!(t >= w.h.t1 || w.aborted_by == Some(w.h.claimer));
                    prop_assert_eq!(next.locker - w.locker, w.h.amount);
                }
                _ => {}
            }
            prop_assert!(next.claims + next.refunds <= 1);
            w = next;
        }
    }

    /// Any 32 bytes other than x fail the preimage check (with the real sha256).
    #[test]
    fn htlc_wrong_preimage_rejected(x in any::<[u8; 32]>(), y in any::<[u8; 32]>()) {
        prop_assume!(x != y);
        let h = sha(&x);
        prop_assert!(logic::check_preimage_with(&x, &h, sha).is_ok());
        prop_assert_eq!(logic::check_preimage_with(&y, &h, sha), Err(HkError::WrongSecret));
    }

    /// Lock terms over arbitrary configs and makers: an accepted lock is an HTLC direction the
    /// maker takes, within the caps and the config's deadline bounds.
    #[test]
    fn htlc_lock_terms_bounds(
        dirs in any::<u8>(), dir in any::<u8>(), amount in any::<u64>(), min in any::<u64>(), max in any::<u64>(),
        max_swap in any::<u64>(), open in any::<u64>(), max_open in any::<u64>(), t1 in any::<i64>(), zec in any::<u64>(),
        locker_is_maker in any::<bool>(), paused in any::<bool>(), active in any::<bool>(), h0 in any::<bool>(),
    ) {
        let c = Config { paused, max_swap, open_tvl: open, max_open_tvl: max_open, ..config() };
        let (locker, claimer) = (hm::key(hm::LOCKER), hm::key(hm::CLAIMER));
        let m = Maker { active, directions: dirs, authority: if locker_is_maker { locker } else { claimer }, min, max, ..Default::default() };
        let hashlock = if h0 { [0u8; 32] } else { [1u8; 32] };
        if let Ok(tvl) = logic::htlc_lock_terms(&c, &m, &locker, &claimer, dir, amount, zec, &hashlock, t1) {
            prop_assert!(logic::is_htlc_dir(dir));
            prop_assert!(dirs & dir != 0 && active && !paused && !h0 && zec > 0);
            prop_assert!(amount >= min && amount <= max && amount <= max_swap);
            prop_assert_eq!(tvl as u128, open as u128 + amount as u128);
            prop_assert!(tvl <= max_open);
            prop_assert!(t1 >= c.min_t0 + c.min_window && t1 <= c.max_t0 + c.max_window);
            prop_assert_eq!(locker_is_maker, !logic::is_sol_to_zec(dir));
        }
    }
}

/// Fixed scenarios on the model (both directions): the happy path, the claimer's abort, the
/// timeout, and every exit refused once the escrow has settled.
#[test]
fn htlc_scenarios() {
    let x = [7u8; 32];
    for dir in [DIR_SOL_TO_ZEC, DIR_ZEC_TO_SOL, DIR_SOL_TO_ZEC_PT, DIR_ZEC_TO_SOL_PT] {
        let claim = hm::claim_op(dir);
        let other = if claim == HOp::Claim { HOp::PtClaim } else { HOp::Claim };
        let (lk, cl, wt, rando) = (hm::key(hm::LOCKER), hm::key(hm::CLAIMER), hm::key(hm::WT), hm::key(hm::RANDO));
        // Happy path: claim at once (no t0), then nothing else.
        let mut w = new_world(dir, 1_000_000_000, &x, 600, 2_000_000).unwrap();
        let t0 = w.h.created_at;
        assert_eq!(hm::step(&mut w.clone(), claim, cl, lk, t0, [8; 32], sha), Err(HkError::WrongSecret));
        // The other kind's claim instruction is refused even with the right secret.
        assert_eq!(hm::step(&mut w.clone(), other, cl, lk, t0, x, sha), Err(HkError::BadParam));
        if claim == HOp::PtClaim {
            let mut big = x;
            big[31] = 0xff; // not a canonical scalar: refused before the curve is touched
            assert_eq!(hm::step(&mut w.clone(), claim, cl, lk, t0, big, sha), Err(HkError::NonCanonicalScalar));
        }
        assert_eq!(hm::step(&mut w.clone(), claim, lk, lk, t0, x, sha), Err(HkError::Unauthorized));
        for who in [lk, wt, rando] {
            assert_eq!(hm::step(&mut w.clone(), HOp::Abort, who, lk, t0, [0; 32], sha), Err(HkError::Unauthorized));
        }
        assert_eq!(hm::step(&mut w.clone(), HOp::Refund, rando, lk, t0 + 599, [0; 32], sha), Err(HkError::TooEarly));
        hm::step(&mut w, claim, cl, lk, t0, x, sha).unwrap();
        assert_eq!(w.h.secret, x);
        assert_eq!(w.claimer, 1_000_000_000 - 5_000_000);
        assert_eq!(w.vault, 890_880 + 5_000_000);
        assert_eq!(hm::step(&mut w.clone(), HOp::Refund, rando, lk, t0 + 10_000, [0; 32], sha), Err(HkError::BadState));
        assert_eq!(hm::step(&mut w.clone(), claim, cl, lk, t0 + 1, x, sha), Err(HkError::BadState));
        hm::step(&mut w, HOp::Close, lk, lk, t0 + 1, [0; 32], sha).unwrap();
        assert_eq!(w.escrow, 0);

        // Claimer aborts: refund at once by anyone, to the locker only.
        let mut w = new_world(dir, 1_000_000_000, &x, 600, 2_000_000).unwrap();
        hm::step(&mut w, HOp::Abort, cl, lk, t0 + 5, [0; 32], sha).unwrap();
        assert_eq!(hm::step(&mut w.clone(), claim, cl, lk, t0 + 6, x, sha), Err(HkError::BadState));
        assert_eq!(hm::step(&mut w.clone(), HOp::Refund, rando, cl, t0 + 6, [0; 32], sha), Err(HkError::BadAccount));
        let before = w.locker;
        hm::step(&mut w, HOp::Refund, rando, lk, t0 + 6, [0; 32], sha).unwrap();
        assert_eq!(w.locker - before, 1_000_000_000);

        // Timeout: the claim closes at t1 exactly, the refund opens.
        let mut w = new_world(dir, 1_000_000_000, &x, 600, 2_000_000).unwrap();
        let t1 = w.h.t1;
        assert_eq!(hm::step(&mut w.clone(), claim, cl, lk, t1, x, sha), Err(HkError::TooLate));
        assert_eq!(hm::step(&mut w.clone(), HOp::Abort, cl, lk, t1, x, sha), Err(HkError::TooLate));
        hm::step(&mut w.clone(), claim, cl, lk, t1 - 1, x, sha).unwrap();
        hm::step(&mut w, HOp::Refund, wt, lk, t1, [0; 32], sha).unwrap();
        assert_eq!(w.refunds, 1);
        assert_eq!(w.m.open_swaps, 0);
        assert_eq!(w.c.open_tvl, 0);
    }
}

/// Integration of the HTLC kind with v1.5 (zk branch): the payment-proof claim rule is for the XMR
/// kinds only, and the XMR lock never takes an HTLC direction (nor the HTLC lock an XMR one), so
/// no escrow can be of one kind with the other's rules.
#[test]
fn kinds_stay_apart_under_v15() {
    use crate::zkproof::proof_gated;
    for f in 0..=u8::MAX {
        assert!(!proof_gated(DIR_SOL_TO_ZEC, f), "flags {f}");
        assert!(!proof_gated(DIR_ZEC_TO_SOL, f), "flags {f}");
        assert!(proof_gated(DIR_SOL_TO_XMR, f), "flags {f}");
        assert_eq!(proof_gated(DIR_XMR_TO_SOL, f), f & F_PROOF != 0, "flags {f}");
    }
    let c = config();
    let (locker, claimer) = (hm::key(hm::LOCKER), hm::key(hm::CLAIMER));
    for dir in [DIR_SOL_TO_ZEC, DIR_ZEC_TO_SOL] {
        for auth in [locker, claimer] {
            let m = Maker { v2: true, ..maker(auth) };
            for flags in [0, F_PROOF, F_PAY, F_OTC] {
                assert_eq!(
                    logic::check_lock_terms(&c, &m, &locker, &claimer, dir, 1_000_000, 1, 600, 600, flags),
                    Err(HkError::BadParam),
                    "XMR lock must refuse HTLC direction {dir}"
                );
            }
        }
    }
    for dir in [DIR_SOL_TO_XMR, DIR_XMR_TO_SOL] {
        for auth in [locker, claimer] {
            assert_eq!(
                logic::htlc_lock_terms(&c, &maker(auth), &locker, &claimer, dir, 1_000_000, 1, &[1; 32], 1_200),
                Err(HkError::BadParam),
                "HTLC lock must refuse XMR direction {dir}"
            );
        }
    }
}
