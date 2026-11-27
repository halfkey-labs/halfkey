//! Final-round host tests: the v2 escrow and offer lifecycles as long random walks (real curve
//! code for reveals), the settlement split against the plain formula, deposit-order arithmetic,
//! the payment-id parser and decryption on real Monero data, layouts, the production timelock
//! floors, legacy paths unchanged, and tripwires for every lamport debit and pause read in the
//! new modules.

use crate::deposit::{OrderTerms, ORDER_TERMS_LEN};
use crate::direct;
use crate::escrow2::{Integrator, INTEGRATOR_LEN};
use crate::final_logic::{self, MIN_FILL_DEPOSIT, OF_RESERVED};
use crate::fuzz_v15::{load, vectors, V};
use crate::logic;
use crate::model2::{self, key, OOp, OWorld, Op2, World2};
use crate::offer::{Offer, OFFER_LEN};
use crate::xmr::{self, ProofIn, Statement, Syscalls};
use crate::*;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use proptest::prelude::*;

fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}
fn scalar(seed: [u8; 32]) -> [u8; 32] {
    Scalar::from_bytes_mod_order(seed).to_bytes()
}
fn mul_g(s: &[u8; 32]) -> [u8; 32] {
    (ED25519_BASEPOINT_POINT * Scalar::from_bytes_mod_order(*s)).compress().to_bytes()
}
fn real_reveal(s: &[u8; 32], p: &[u8; 32]) -> Result<(), HkError> {
    logic::check_reveal_with(s, p, |x| Some(mul_g(x)))
}

// ---------------------------------------------------------------------------------------------
// Settlement split
// ---------------------------------------------------------------------------------------------

#[test]
fn split3_edges() {
    for a in [0u64, 1, 99, 10_000, 1_000_000_007, u64::MAX / 3, u64::MAX] {
        for f in [0u16, 1, 25, 50, 100] {
            for i in [0u16, 1, 100, 199, 200] {
                let (to, fee, ifee) = final_logic::split3(a, f, i).unwrap();
                assert_eq!(fee as u128, a as u128 * f as u128 / 10_000);
                assert_eq!(ifee as u128, a as u128 * i as u128 / 10_000);
                assert_eq!(to as u128 + fee as u128 + ifee as u128, a as u128);
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(20000)))]
    #[test]
    fn split3_matches_formula(a in any::<u64>(), f in 0u16..=MAX_FEE_BPS, i in 0u16..=MAX_INTEGRATOR_BPS) {
        let (to, fee, ifee) = final_logic::split3(a, f, i).unwrap();
        prop_assert_eq!(fee as u128, a as u128 * f as u128 / 10_000);
        prop_assert_eq!(ifee as u128, a as u128 * i as u128 / 10_000);
        prop_assert_eq!(to as u128 + fee as u128 + ifee as u128, a as u128);
        prop_assert!((fee as u128 + ifee as u128) * 10_000 <= a as u128 * 300);
    }

    #[test]
    fn fill_take_rules(bal in any::<u64>(), amount in any::<u64>(), tip in 0u64..=MAX_TIP, top in 0u64..10_000_000, rmin in 0u64..2_000_000) {
        match final_logic::fill_take(bal, amount, tip, top, rmin) {
            Ok(take) => {
                let need = amount as u128 + tip as u128 + top as u128;
                prop_assert!(take as u128 >= need && take <= bal);
                let left = bal - take;
                prop_assert!(left == 0 || left >= rmin, "would leave the order address rent-paying");
                prop_assert!(take as u128 == need || take == bal);
            }
            Err(e) => prop_assert!(e == HkError::Overflow || (e == HkError::Underpaid && (bal as u128) < amount as u128 + tip as u128 + top as u128)),
        }
    }

    #[test]
    fn order_refund_rules(bal in any::<u64>(), tip in 0u64..=MAX_TIP, filled in any::<bool>(), rmin in 0u64..2_000_000, now in any::<i64>(), dl in any::<i64>()) {
        let (to_r, to_c) = final_logic::order_refund_split(bal, tip, filled, rmin);
        prop_assert_eq!(to_r as u128 + to_c as u128, bal as u128);
        prop_assert!(to_c <= tip);
        if filled { prop_assert_eq!(to_c, 0); }
        if to_c > 0 { prop_assert!(to_r >= rmin); }
        let rs = now % 3 == 0;
        let far = dl.checked_sub(now).map_or(true, |x| x > final_logic::MAX_ORDER_LIFE);
        prop_assert_eq!(final_logic::order_refund_allowed(now, dl, filled, rs).is_ok(), now >= dl || filled || rs || far);
    }
}

// ---------------------------------------------------------------------------------------------
// v2 escrow lifecycle walk
// ---------------------------------------------------------------------------------------------

fn base_config() -> Config {
    Config {
        fee_bps: 50,
        holder_fee_bps: 25,
        holder_min: 1000,
        halfkey_mint: key(9),
        max_swap: u64::MAX / 4,
        max_open_tvl: u64::MAX / 2,
        min_t0: 1,
        max_t0: 30 * 86_400,
        min_window: 1,
        max_window: 30 * 86_400,
        ..Default::default()
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(1024)))]
    #[test]
    fn v2_lifecycle_walk(
        kind in 0u8..4, amount in 1u64..=u64::MAX / 8, fee in 0u16..=MAX_FEE_BPS, holder in any::<bool>(),
        ibps in 0u16..=MAX_INTEGRATOR_BPS, has_int in any::<bool>(), tipf in 0u64..=1000, origin in 0u8..2,
        t0s in 1i64..100, ws in 1i64..200, wt0 in any::<bool>(), cs in any::<[u8; 32]>(), rs in any::<[u8; 32]>(),
        rent in 0u64..5_000_000, proof_kind in 0u8..5, junk in any::<[u8; 32]>(),
        walk in prop::collection::vec((0usize..6, 1u8..=4, 1u8..=4, 0u32..40_000, 0u8..5), 1..30),
    ) {
        // kind 0: SOL->XMR 2-of-2, 1: XMR->SOL proof mode, 2: SOL->XMR direct payout.
        let (direction, flags) = match kind { 0 => (DIR_SOL_TO_XMR, 0), 1 => (DIR_XMR_TO_SOL, F_PROOF), 2 => (DIR_SOL_TO_XMR, F_DIRECT), _ => (DIR_SOL_TO_XMR, F_DIRECT | F_OTC) };
        let (cs, rs) = (scalar(cs), scalar(rs));
        prop_assume!(cs != rs);
        let (cp, rp) = (mul_g(&cs), mul_g(&rs));
        let c = Config { fee_bps: fee, holder_fee_bps: fee / 2, ..base_config() };
        let m = Maker {
            active: true, directions: DIR_SOL_TO_XMR | DIR_XMR_TO_SOL, v2: true, min: 1, max: u64::MAX / 4,
            authority: key(if direction == DIR_SOL_TO_XMR { model2::CLAIMER } else { model2::LOCKER }),
            staked: if holder { 5000 } else { 0 }, ..Default::default()
        };
        let integrator = if has_int { key(7) } else { Pubkey::default() };
        let ibps = if has_int { ibps } else { 0 };
        let tip = (amount / 10).min(MAX_TIP) * tipf / 1000;
        let window = if flags & F_DIRECT != 0 { MIN_PROOF_WINDOW + ws } else { ws };
        let wt = if flags & F_DIRECT != 0 || !wt0 { [Pubkey::default(); 2] } else { [key(model2::WT), Pubkey::default()] };
        let t_lock = 1_800_000_000i64;
        let w0 = model2::lock2(model2::LockIn2 {
            c, m, direction, flags, amount, xmr_amount: 7, t0_secs: t0s, window_secs: window, watchtowers: wt,
            claim_point: cp, refund_point: rp, integrator, integrator_bps: ibps, tip, origin,
            order_deadline: t_lock + 60, t_lock, rent, bal: [0, 1_000, 2_000, 3_000, 4_000], vault: 5_000, integ: 6_000,
        });
        let mut w: World2 = w0.expect("valid v2 lock rejected");
        w.proof_arg = match proof_kind {
            0 => None,
            1 => Some((key(model2::ESCROW), w.e.created_at, w.e.xmr_amount)),
            2 => Some((key(model2::ESCROW), w.e.created_at, w.e.xmr_amount - 1)),
            3 => Some((key(8), w.e.created_at, u64::MAX)),
            _ => Some((key(model2::ESCROW), w.e.created_at + 1, u64::MAX)),
        };
        let total0 = w.total();
        let mut t = w.e.created_at;
        prop_assert!(model2::inv2(&w, t));
        for (op_i, s_i, d_i, dt, sk) in walk {
            t += dt as i64;
            let op = model2::OPS2[op_i];
            let secret = match sk { 0 => cs, 1 => rs, 2 => [0u8; 32], 3 => scalar(junk), _ => junk };
            let (signer, dest) = (key(s_i), key(d_i));
            let mut next = w.clone();
            if model2::step2(&mut next, op, signer, dest, t, secret, real_reveal).is_ok() {
                model2::check_money2(&w, &next, op, signer, total0);
                model2::check_state2(&w, &next, op, signer, dest, t, &secret, real_reveal);
                prop_assert!(model2::inv2(&next, t), "v2 invariant broken after {:?}", op);
                if op == Op2::ClaimTo { prop_assert_eq!(secret, cs); }
                if op == Op2::Refund && flags & F_DIRECT == 0 { prop_assert_eq!(secret, rs); }
                w = next;
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Offer lifecycle walk
// ---------------------------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(2048)))]
    #[test]
    fn offer_walk(
        amount in 1u64..=u64::MAX / 8, fee in 0u16..=MAX_FEE_BPS, ibps in 0u16..=MAX_INTEGRATOR_BPS, has_int in any::<bool>(),
        tipf in 0u64..=1000, fw in 0i64..100, life in 1i64..400, rent in 0u64..3_000_000,
        walk in prop::collection::vec((0usize..4, 1u8..=4, 0u32..300, 0u64..4), 1..40),
    ) {
        let integrator = if has_int { key(7) } else { Pubkey::default() };
        let o = Offer {
            amount, xmr_amount: 5, spend: [1; 32], view: [2; 32], fee_bps: fee, integrator,
            integrator_bps: if has_int { ibps } else { 0 }, tip: (amount / 10).min(MAX_TIP) * tipf / 1000,
            fill_window: MIN_PROOF_WINDOW + fw, ..Default::default()
        };
        let rich = u64::MAX / 16;
        let mut w: OWorld = model2::open_offer(o, 1_800_000_000, life, rent, [0, rich, rich, rich, rich], 0, 0).expect("valid offer rejected");
        let total0 = w.total();
        let mut t = w.o.created_at;
        prop_assert!(model2::oinv(&w, t));
        for (op_i, s_i, dt, ps) in walk {
            t += dt as i64;
            let op = model2::OOPS[op_i];
            let signer = key(s_i);
            // The proof carries the live fill's id, an older or a later one.
            let proof_seq = match ps { 0 => w.o.fill_seq, 1 => w.o.fill_seq.wrapping_sub(1), 2 => w.o.fill_seq + 1, _ => 0 };
            let mut next = w.clone();
            if model2::ostep(&mut next, op, signer, t, proof_seq).is_ok() {
                model2::ocheck(&w, &next, op, signer, t, proof_seq, total0);
                prop_assert!(model2::oinv(&next, t), "offer invariant broken after {:?}", op);
                w = next;
            }
        }
    }
}

#[test]
fn offer_scenarios() {
    let rich = 1u64 << 50;
    let o = Offer { amount: 2_000_000_000, xmr_amount: 5, fee_bps: 50, tip: 1_000_000, fill_window: MIN_PROOF_WINDOW, ..Default::default() };
    let mut w = model2::open_offer(o, 100, 1_000_000, 3_000_000, [0, rich, rich, rich, rich], 0, 0).unwrap();
    let (f1, f2, bidder) = (key(2), key(3), key(1));
    // bidder cannot fill its own offer
    assert_eq!(model2::ostep(&mut w.clone(), OOp::Take, bidder, 101, 0), Err(HkError::BadParam));
    model2::ostep(&mut w, OOp::Take, f1, 101, 0).unwrap();
    assert_eq!(w.o.deposit, 20_000_000); // 1%
    assert_eq!(w.o.fill_seq, 1);
    // live reservation blocks a second taker, the bidder's cancel and a forfeit
    assert_eq!(model2::ostep(&mut w.clone(), OOp::Take, f2, 102, 0), Err(HkError::Reserved));
    assert_eq!(model2::ostep(&mut w.clone(), OOp::Cancel, bidder, 102, 0), Err(HkError::Reserved));
    assert_eq!(model2::ostep(&mut w.clone(), OOp::Forfeit, f2, 102, 0), Err(HkError::TooEarly));
    // a proof for another fill does not release
    assert_eq!(model2::ostep(&mut w.clone(), OOp::Release, f2, 102, 2), Err(HkError::BadPaymentId));
    // after the window: f2 takes, f1's deposit goes to the bidder
    let dl = w.o.deadline;
    let b0 = w.bal[1];
    model2::ostep(&mut w, OOp::Take, f2, dl, 0).unwrap();
    assert_eq!(w.bal[1] - b0, 20_000_000);
    assert_eq!((w.o.fill_seq, w.o.forfeits, w.o.filler), (2, 1, f2));
    // f1's old payment (fill 1) cannot release fill 2
    assert_eq!(model2::ostep(&mut w.clone(), OOp::Release, f1, dl + 1, 1), Err(HkError::BadPaymentId));
    let (fb, vb) = (w.bal[3], w.vault);
    model2::ostep(&mut w, OOp::Release, key(4), dl + 1, 2).unwrap();
    assert_eq!(w.vault - vb, 10_000_000); // 0.5%
    assert_eq!(w.bal[3] - fb, 2_000_000_000 - 10_000_000 + 20_000_000);
    assert!(w.closed);
    // a minimal offer's deposit floor
    assert_eq!(final_logic::filler_deposit(1), MIN_FILL_DEPOSIT);
}

// ---------------------------------------------------------------------------------------------
// Payment ids
// ---------------------------------------------------------------------------------------------

fn d_of(v: &V) -> ProofIn<'_> {
    ProofIn { kind: v.kind, unprunable: &v.unprunable, prunable_hash: v.prunable_hash, out_index: v.out_index, d: v.d, c: v.c, z: v.z, header: &v.header, ntx: v.ntx, branch: &v.branch }
}

/// What `enc` decrypts to under a proof's shared secret.
fn decrypt(v: &V) -> [u8; 8] {
    let enc = direct::encrypted_pid(direct::tx_extra(&v.unprunable).unwrap()).unwrap();
    let k = (curve25519_dalek::edwards::CompressedEdwardsY(v.d).decompress().unwrap() * Scalar::from(8u8)).compress().to_bytes();
    let mask = solana_keccak_hasher::hashv(&[&k, &[direct::PID_TAIL]]).to_bytes();
    let mut p = [0u8; 8];
    for i in 0..8 {
        p[i] = enc[i] ^ mask[i];
    }
    p
}

/// A real wallet-rpc transaction (the live stagenet run) carries wallet2's dummy payment id: the
/// all-zero id, encrypted. Decrypting it with the proven shared secret gives zeroes, which pins
/// the decryption to Monero's `encrypt_payment_id` (derivation 8rA, tail 0x8d).
#[test]
fn real_wallet_dummy_payment_id_decrypts_to_zero() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../e2e/fixtures/xmr-stagenet-proof.json");
    let Ok(json) = std::fs::read_to_string(path) else {
        eprintln!("no live stagenet fixture");
        return;
    };
    for v in load(&json) {
        assert_eq!(decrypt(&v), [0u8; 8]);
        let m = xmr::escrow_msg(&v.escrow);
        let st = Statement { spend: v.spend, view: v.view, min_amount: v.min, msg: &m };
        direct::verify_direct(&Syscalls, &st, &d_of(&v), &[0u8; 8]).unwrap();
        assert_eq!(direct::verify_direct(&Syscalls, &st, &d_of(&v), &[0, 0, 0, 0, 0, 0, 0, 1]).unwrap_err(), HkError::BadPaymentId);
    }
}

#[test]
fn direct_verify_binds_the_payment_id() {
    for v in &vectors() {
        let pid = decrypt(v);
        let m = xmr::escrow_msg(&v.escrow);
        let st = Statement { spend: v.spend, view: v.view, min_amount: v.min, msg: &m };
        let got = direct::verify_direct(&Syscalls, &st, &d_of(v), &pid).unwrap();
        assert_eq!(got.txid, v.txid);
        for bit in 0..64 {
            let mut p2 = pid;
            p2[bit / 8] ^= 1 << (bit % 8);
            assert_eq!(direct::verify_direct(&Syscalls, &st, &d_of(v), &p2).unwrap_err(), HkError::BadPaymentId);
        }
        // the v1.5 checks still come first
        let st2 = Statement { min_amount: v.min + 1, ..st.clone() };
        assert_eq!(direct::verify_direct(&Syscalls, &st2, &d_of(v), &pid).unwrap_err(), HkError::AmountTooLow);
    }
}

#[test]
fn encrypted_pid_parser_cases() {
    let r = [7u8; 32];
    let mut e = vec![0x01];
    e.extend_from_slice(&r);
    e.extend_from_slice(&[0x02, 0x09, 0x01, 1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(direct::encrypted_pid(&e), Ok([1, 2, 3, 4, 5, 6, 7, 8]));
    // nonce first, padding, additional keys before it
    let mut e2 = vec![0x00, 0x04, 0x01];
    e2.extend_from_slice(&r);
    e2.extend_from_slice(&[0x02, 0x09, 0x01, 9, 9, 9, 9, 9, 9, 9, 9, 0x01]);
    e2.extend_from_slice(&r);
    assert_eq!(direct::encrypted_pid(&e2), Ok([9; 8]));
    // the first nonce counts: an unencrypted (32-byte) id first is refused
    let mut e3 = vec![0x02, 33, 0x00];
    e3.extend_from_slice(&[5; 32]);
    e3.extend_from_slice(&[0x02, 0x09, 0x01, 1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(direct::encrypted_pid(&e3), Err(HkError::BadPaymentId));
    // none, truncated, unknown tag first
    assert_eq!(direct::encrypted_pid(&e[..33]), Err(HkError::BadPaymentId));
    assert_eq!(direct::encrypted_pid(&e[..40]), Err(HkError::BadPaymentId));
    assert_eq!(direct::encrypted_pid(&[0xde, 0x02, 0x09, 0x01, 1, 2, 3, 4, 5, 6, 7, 8]), Err(HkError::BadPaymentId));
    // payment ids differ per escrow instance and per fill
    let k = [3u8; 32];
    assert_ne!(direct::pid_for(direct::PID_DOMAIN_ESCROW, &k, 1, 0, &[]), direct::pid_for(direct::PID_DOMAIN_ESCROW, &k, 2, 0, &[]));
    assert_ne!(direct::pid_for(direct::PID_DOMAIN_OFFER, &k, 1, 1, &[1; 32]), direct::pid_for(direct::PID_DOMAIN_OFFER, &k, 1, 2, &[1; 32]));
    assert_ne!(direct::pid_for(direct::PID_DOMAIN_OFFER, &k, 1, 1, &[1; 32]), direct::pid_for(direct::PID_DOMAIN_OFFER, &k, 1, 1, &[2; 32]));
    assert_ne!(direct::pid_for(direct::PID_DOMAIN_OFFER, &k, 1, 0, &[]), direct::pid_for(direct::PID_DOMAIN_ESCROW, &k, 1, 0, &[]));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(20000)))]
    #[test]
    fn pid_parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = direct::encrypted_pid(&bytes);
        let _ = direct::tx_extra(&bytes);
    }
}

#[test]
fn tx_extra_matches_the_v15_parser() {
    for v in &vectors() {
        let x = direct::tx_extra(&v.unprunable).unwrap();
        let p = xmr::parse_tx(&v.unprunable, v.out_index as usize).unwrap();
        assert_eq!(xmr::tx_pub_key(x), Some(p.r_pub));
    }
}

// ---------------------------------------------------------------------------------------------
// Layouts, constants, legacy paths, tripwires
// ---------------------------------------------------------------------------------------------

#[test]
fn final_layouts_roundtrip() {
    let mut d = vec![0u8; ESCROW_LEN_V2];
    let e = Escrow {
        amount: 9, link: key(3), v2: true, flags: F_DIRECT,
        ext: EscrowExt { integrator: key(4), integrator_bps: 200, origin: 1, tip: 77, order_deadline: -5 },
        ..Default::default()
    };
    e.store(&mut d);
    let e2 = Escrow::load(&d).unwrap();
    assert!(e2.v2);
    assert_eq!(e2.ext, e.ext);
    assert_eq!((e2.amount, e2.link, e2.flags), (9, key(3), F_DIRECT));
    let mut d1 = vec![0u8; ESCROW_LEN];
    e.store(&mut d1); // a v1 account never gets the extension written past its end
    let e1 = Escrow::load(&d1).unwrap();
    assert!(!e1.v2 && e1.ext == EscrowExt::default());
    assert!(Escrow::load(&vec![0xE5u8; ESCROW_LEN_V2 + 1]).is_err());

    let mut d = vec![0u8; OFFER_LEN];
    let o = Offer { state: OF_RESERVED, offer_id: [5; 32], bidder: key(1), amount: 3, fee_bps: 50, integrator_bps: 9, tip: 4, deadline: -9, forfeits: 2, filler: key(2), ..Default::default() };
    o.store(&mut d);
    assert_eq!(Offer::load(&d).unwrap(), o);

    let mut d = vec![0u8; INTEGRATOR_LEN];
    let g = Integrator { bump: 3, owner: key(5), earned: 1, withdrawn: 2, swaps: 3, volume: 4, created_at: 5 };
    g.store(&mut d);
    assert_eq!(Integrator::load(&d).unwrap(), g);

    let t = OrderTerms { maker: key(1), amount: 2, xmr_amount: 3, claim_point: [4; 32], pay_spend: [5; 32], pay_view: [6; 32], refund: key(7), deadline: 8, t0_secs: 9, window_secs: 10, fee_bps: 11, integrator: key(12), integrator_bps: 13, tip: 14, quote_hash: [15; 32], flags: F_OTC };
    let raw = t.encode();
    assert_eq!(raw.len(), ORDER_TERMS_LEN);
    assert_eq!(OrderTerms::parse(&raw).unwrap(), t);
    assert!(OrderTerms::parse(&raw[1..]).is_err());
}

/// The constants a mainnet build ships with (host tests never enable `test-timelocks`).
#[cfg(not(feature = "test-timelocks"))]
#[test]
fn production_floors() {
    assert_eq!(MIN_UNBOND_SECS, 3 * 86_400);
    assert_eq!(MIN_PROOF_WINDOW, 6 * 3600);
    assert_eq!(crate::LATE_READY_MARGIN, 30 * 60); // late finish closes 30 min before t1 (e2e build: 2 s)
    assert_eq!(MAX_INTEGRATOR_BPS, 200);
    // update/init config: unbond below 3 days refused, 3 days accepted
    let p = |unbond: i64| {
        let mut b = Vec::new();
        b.extend_from_slice(&[1u8; 32]);
        b.extend_from_slice(&[2u8; 32]);
        b.extend_from_slice(&50u16.to_le_bytes());
        b.extend_from_slice(&25u16.to_le_bytes());
        for v in [1u64, 1, 10, 100] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        for v in [1i64, 3600, 1, 7200, unbond] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b
    };
    let d = p(3 * 86_400 - 1);
    assert!(read_config_params(&mut Rd::new(&d)).is_err());
    let d = p(3 * 86_400);
    assert!(read_config_params(&mut Rd::new(&d)).is_ok());
    // pay / direct windows below 6 h refused
    assert_eq!(final_logic::proof_window_floor(F_PAY, 6 * 3600 - 1), Err(HkError::WindowTooShort));
    assert_eq!(final_logic::proof_window_floor(F_DIRECT, 6 * 3600), Ok(()));
    assert_eq!(final_logic::proof_window_floor(0, 1), Ok(()));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases(20000)))]
    /// Every v1 escrow (no F_DIRECT bit: lock/lock2/vault_lock refuse it) sees the v1 rules.
    #[test]
    fn v1_paths_unchanged(state in 0u8..7, dir in 0u8..4, flags in any::<u8>(), t in any::<i64>(), t0 in any::<i64>(), t1 in any::<i64>(),
                          who in 0u8..6, secret in any::<[u8; 32]>(), img in any::<Option<[u8; 32]>>()) {
        let flags = flags & !F_DIRECT;
        let e = Escrow { state, direction: dir, flags, t0, t1, locker: key(1), claimer: key(2), watchtowers: [key(3), Pubkey::default()], ..Default::default() };
        prop_assert_eq!(final_logic::abort_check_v2(&e, &key(who), t), logic::abort_check(&e, &key(who), t));
        prop_assert_eq!(final_logic::refund_secret_v2(flags, &secret, &[9; 32], |_| img), logic::refund_secret_check(flags, &secret, &[9; 32], |_| img));
        // prove_lock's window: what it was, minus direct escrows
        let before = zkproof::proof_allowed(dir, flags) && (state == ST_LOCKED || state == ST_READY) && t < t1;
        prop_assert_eq!(zkproof::prove_window(dir, flags, state, t, t1).is_ok(), before);
        prop_assert!(zkproof::prove_window(dir, flags | F_DIRECT, state, t, t1).is_err());
    }
}

/// Every place the new modules debit a program-owned account, by handler, and no pause reads
/// outside the instructions that open something new.
#[test]
fn final_debit_sites_and_pause_reads() {
    for (name, src, want, pause) in [
        ("escrow2.rs", include_str!("escrow2.rs"), vec!["integrator:pay", "claim_to:pay", "claim_to:pay", "claim_to:pay", "claim_to:pay"], vec![]),
        ("deposit.rs", include_str!("deposit.rs"), vec![], vec![]),
        ("direct.rs", include_str!("direct.rs"), vec![], vec![]),
        ("final_logic.rs", include_str!("final_logic.rs"), vec![], vec![]),
        (
            "offer.rs",
            include_str!("offer.rs"),
            vec!["take:pay", "settle:pay", "settle:pay", "settle:pay", "settle:pay", "settle:close_account", "settle:pay", "settle:pay", "settle:close_account", "settle:pay"],
            vec!["open", "take"],
        ),
    ] {
        let mut f = "";
        let (mut sites, mut reads) = (Vec::new(), Vec::new());
        for line in src.lines() {
            let l = line.trim_start();
            if let Some(rest) = l.strip_prefix("pub fn ").or_else(|| l.strip_prefix("pub(crate) fn ")).or_else(|| l.strip_prefix("fn ")) {
                f = rest.split(['(', '<']).next().unwrap();
                continue;
            }
            if l.starts_with("//") {
                continue;
            }
            if l.contains(".paused") {
                reads.push(f.to_string());
            }
            if l.contains("close_account(") {
                sites.push(format!("{f}:close_account"));
            } else if l.starts_with("pay(") || l.contains(" pay(") || l.contains("try_borrow_mut_lamports") {
                sites.push(format!("{f}:pay"));
            }
        }
        assert_eq!(sites, want, "{name}: lamport debit sites changed");
        assert_eq!(reads, pause, "{name}: pause reads changed");
    }
}
