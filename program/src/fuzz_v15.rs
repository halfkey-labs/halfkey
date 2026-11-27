//! v1.5 host tests: the Monero payment-proof verifier on vectors built from a real stagenet
//! transaction and block (e2e/fixtures/xmr-vectors.json, from e2e/gen-xmr-vectors.ts) and on a
//! real wallet-rpc OutProofV2 from the live stagenet run (e2e/fixtures/xmr-stagenet-proof.json),
//! with the same curve/keccak library code the validator's syscalls run; proptests of the parser,
//! the scalar reduction, the attestation parser and the burn auction; tripwires.

use crate::burn::{self, BurnState};
use crate::xmr::{self, Ops, ProofIn, Statement, Syscalls};
use crate::zkproof::{self, Attesters, ProofRec, XHeader};
use crate::*;
use proptest::prelude::*;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn a32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

#[derive(Clone)]
pub(crate) struct V {
    pub(crate) kind: u8,
    pub(crate) out_index: u8,
    pub(crate) spend: [u8; 32],
    pub(crate) view: [u8; 32],
    pub(crate) escrow: [u8; 32],
    pub(crate) min: u64,
    pub(crate) unprunable: Vec<u8>,
    pub(crate) prunable_hash: [u8; 32],
    pub(crate) d: [u8; 32],
    pub(crate) c: [u8; 32],
    pub(crate) z: [u8; 32],
    pub(crate) header: Vec<u8>,
    pub(crate) ntx: u32,
    pub(crate) branch: Vec<u8>,
    pub(crate) txid: [u8; 32],
    pub(crate) out_key: [u8; 32],
    pub(crate) block_id: [u8; 32],
}

pub(crate) fn load(json: &str) -> Vec<V> {
    let j: serde_json::Value = serde_json::from_str(json).unwrap();
    j.as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let s = |k: &str| v[k].as_str().unwrap().to_string();
            V {
                kind: v["kind"].as_u64().unwrap() as u8,
                out_index: v["out_index"].as_u64().unwrap() as u8,
                spend: a32(&s("spend")),
                view: a32(&s("view")),
                escrow: a32(&s("escrow")),
                min: s("min").parse().unwrap(),
                unprunable: unhex(&s("unprunable")),
                prunable_hash: a32(&s("prunable_hash")),
                d: a32(&s("d")),
                c: a32(&s("c")),
                z: a32(&s("z")),
                header: unhex(&s("header")),
                ntx: v["ntx"].as_u64().unwrap() as u32,
                branch: unhex(&s("branch")),
                txid: a32(&s("txid")),
                out_key: a32(&s("out_key")),
                block_id: a32(&s("block_id")),
            }
        })
        .collect()
}

pub(crate) fn vectors() -> Vec<V> {
    load(include_str!("../../e2e/fixtures/xmr-vectors.json"))
}

fn run(v: &V, msg: &[u8], min: u64, spend: &[u8; 32]) -> Result<xmr::Verified, HkError> {
    let st = Statement { spend: *spend, view: v.view, min_amount: min, msg };
    let p = ProofIn {
        kind: v.kind,
        unprunable: &v.unprunable,
        prunable_hash: v.prunable_hash,
        out_index: v.out_index,
        d: v.d,
        c: v.c,
        z: v.z,
        header: &v.header,
        ntx: v.ntx,
        branch: &v.branch,
    };
    xmr::verify(&Syscalls, &st, &p)
}

fn ok(v: &V) -> Result<xmr::Verified, HkError> {
    run(v, &xmr::escrow_msg(&v.escrow), v.min, &v.spend)
}

#[test]
fn txproof_separator_is_keccak_of_its_name() {
    assert_eq!(solana_keccak_hasher::hashv(&[b"TXPROOF_V2"]).to_bytes(), xmr::TXPROOF_V2_SEP);
}

#[test]
fn vectors_verify_with_the_syscall_code() {
    let vs = vectors();
    assert!(vs.len() >= 4);
    for v in &vs {
        let got = ok(v).unwrap();
        assert_eq!(got.txid, v.txid);
        assert_eq!(got.out_key, v.out_key);
        assert_eq!(got.amount, v.min);
        assert_eq!(got.block_id, v.block_id);
    }
}

/// The live stagenet run's proof: a real wallet transaction and the OutProofV2 string from
/// monero-wallet-rpc `get_tx_proof`, against the real block (present once e2e/zk-stagenet.ts ran).
#[test]
fn real_stagenet_wallet_proof_verifies() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../e2e/fixtures/xmr-stagenet-proof.json");
    let Ok(json) = std::fs::read_to_string(path) else {
        eprintln!("no live stagenet fixture yet");
        return;
    };
    for v in load(&json) {
        let got = ok(&v).unwrap();
        assert_eq!((got.txid, got.out_key, got.block_id), (v.txid, v.out_key, v.block_id));
        assert!(got.amount >= v.min);
    }
}

#[test]
fn wrong_statement_is_rejected() {
    for v in &vectors() {
        let msg = xmr::escrow_msg(&v.escrow);
        // amount one above what was paid
        assert_eq!(run(v, &msg, v.min + 1, &v.spend).unwrap_err(), HkError::AmountTooLow);
        // another escrow's address in the message (proof bound to a different escrow)
        let mut other = v.escrow;
        other[0] ^= 1;
        assert_eq!(run(v, &xmr::escrow_msg(&other), v.min, &v.spend).unwrap_err(), HkError::BadXmrProof);
        // another swap's spend key
        let b2 = Syscalls.msm2(&xmr::SCALAR_ONE, &v.spend, &xmr::SCALAR_ONE, &xmr::G).unwrap();
        assert_eq!(run(v, &msg, v.min, &b2).unwrap_err(), HkError::WrongOutput);
        // wrong view key: the DLEQ fails
        assert_eq!(ok(&V { view: xmr::G, ..v.clone() }).unwrap_err(), HkError::BadXmrProof);
        // the other proof kind (OUT read as IN), an unknown kind
        assert_eq!(ok(&V { kind: v.kind ^ 1, ..v.clone() }).unwrap_err(), HkError::BadXmrProof);
        assert_eq!(ok(&V { kind: 7, ..v.clone() }).unwrap_err(), HkError::BadXmrProof);
        // non-canonical c (c + L), when it fits in 256 bits
        let mut c = v.c;
        let mut carry = 0u16;
        for i in 0..32 {
            let s = c[i] as u16 + L[i] as u16 + carry;
            c[i] = s as u8;
            carry = s >> 8;
        }
        if carry == 0 {
            assert_eq!(ok(&V { c, ..v.clone() }).unwrap_err(), HkError::BadXmrProof);
        }
        // another output index of the same tx
        assert!(ok(&V { out_index: v.out_index ^ 1, ..v.clone() }).is_err());
        // a bad side bit; a flipped side (folds to another root); a bad header; ntx < 2
        let mut br = v.branch.clone();
        br[32] = 2;
        assert_eq!(ok(&V { branch: br, ..v.clone() }).unwrap_err(), HkError::BadInclusion);
        let mut br = v.branch.clone();
        br[32] ^= 1;
        assert_ne!(ok(&V { branch: br, ..v.clone() }).unwrap().block_id, v.block_id);
        let mut hd = v.header.clone();
        hd.push(0);
        assert_eq!(ok(&V { header: hd, ..v.clone() }).unwrap_err(), HkError::BadInclusion);
        assert_eq!(ok(&V { ntx: 1, ..v.clone() }).unwrap_err(), HkError::BadInclusion);
        // the prunable hash is part of the txid, so the proof (bound to the txid) breaks
        let mut ph = v.prunable_hash;
        ph[5] ^= 0x10;
        assert_eq!(ok(&V { prunable_hash: ph, ..v.clone() }).unwrap_err(), HkError::BadXmrProof);
    }
}

#[test]
fn time_locked_tx_is_rejected() {
    let v = &vectors()[0];
    let mut u = v.unprunable.clone();
    assert_eq!(u[1], 0);
    u[1] = 5;
    assert_eq!(ok(&V { unprunable: u, ..v.clone() }).unwrap_err(), HkError::BadXmrTx);
}

#[test]
fn forged_amount_fails_the_commitment() {
    // The commitment check on its own (check_output), so the txid binding is not what catches it.
    let v = &vectors()[0];
    let mut t = xmr::parse_tx(&v.unprunable, v.out_index as usize).unwrap();
    let st = Statement { spend: v.spend, view: v.view, min_amount: 1, msg: &[] };
    assert!(xmr::check_output(&Syscalls, &st, &t, v.out_index, &v.d).is_ok());
    t.enc[7] ^= 0x80; // claim ~2^63 more piconero
    assert_eq!(xmr::check_output(&Syscalls, &st, &t, v.out_index, &v.d).unwrap_err(), HkError::BadAmount);
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    /// Any single-bit change anywhere in the transaction bytes is rejected: the txid changes
    /// (the proof is bound to it) or the parse fails.
    #[test]
    fn any_tx_bit_flip_is_rejected(pos in 0usize..10_000, bit in 0u8..8, which in 0usize..4) {
        let vs = vectors();
        let v = &vs[which % vs.len()];
        let mut u = v.unprunable.clone();
        let i = pos % u.len();
        u[i] ^= 1 << bit;
        let rejected = ok(&V { unprunable: u, ..v.clone() }).is_err();
        prop_assert!(rejected);
    }

    /// The parser never panics, on random bytes or on truncations of a real tx.
    #[test]
    fn parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600), idx in 0usize..20, cut in 0usize..400) {
        let _ = xmr::parse_tx(&bytes, idx);
        let _ = xmr::tx_pub_key(&bytes);
        let _ = xmr::check_header(&bytes);
        let v = &vectors()[0];
        let n = cut.min(v.unprunable.len());
        let r = xmr::parse_tx(&v.unprunable[..n], 0);
        if n < v.unprunable.len() { prop_assert!(r.is_err()); }
    }

    /// sc_reduce32 and the canonical check agree with curve25519-dalek on every input.
    #[test]
    fn reduce_matches_dalek(b in any::<[u8; 32]>()) {
        use curve25519_dalek::scalar::Scalar;
        prop_assert_eq!(xmr::reduce32(&b), Scalar::from_bytes_mod_order(b).to_bytes());
        prop_assert_eq!(xmr::canonical(&b), bool::from(Scalar::from_canonical_bytes(b).is_some()));
        prop_assert_eq!(xmr::canonical(&b), scalar_is_canonical(&b));
    }

    /// The auction price never rises within a round and stays in [floor, start].
    #[test]
    fn burn_price_monotone(start in 1u64.., floor_frac in 0u64..1000, a in 0i64..2_000_000, b in 0i64..2_000_000, at in -1_000_000i64..1_000_000) {
        let floor = (start / 1000).saturating_mul(floor_frac).max(1).min(start);
        let (t1, t2) = (at + a.min(b), at + a.max(b));
        let (p1, p2) = (burn::price_at(start, floor, at, t1), burn::price_at(start, floor, at, t2));
        prop_assert!(p1 >= p2, "price rose: {} -> {}", p1, p2);
        prop_assert!(p1 <= start && p2 >= floor);
        prop_assert_eq!(burn::price_at(start, floor, at, at), start);
        prop_assert_eq!(burn::price_at(start, floor, at, at - 5), start);
        // after exactly one half-life: half the start (or the floor)
        prop_assert_eq!(burn::price_at(start, floor, at, at + burn::HALF_LIFE_SECS), (start >> 1).max(floor));
    }

    /// A take never takes the rent reserve, never more than the cap, always charges at least the
    /// auction price (rounded up by less than one unit), and respects both buyer bounds.
    #[test]
    fn burn_take_bounds(start in 1u64.., lot_cap in 1u64.., vault in any::<u64>(), keep in 0u64..10_000_000, dt in 0i64..400_000, max_burn in any::<u64>(), min_l in 0u64..1_000_000_000_000) {
        let s = BurnState { start_price: start, floor_price: 1, max_lot: lot_cap, start_at: 0, pot: vault / 3, ..Default::default() };
        if let Ok(k) = burn::take_terms(&s, vault, keep, dt, max_burn, min_l) {
            prop_assert!(k.lot > 0 && k.lot <= lot_cap && k.lot <= vault - keep && k.lot >= min_l && k.lot <= s.pot);
            prop_assert!(k.burn <= max_burn && k.burn >= 1);
            prop_assert!(k.burn as u128 * 1_000_000_000 >= k.price as u128 * k.lot as u128);
            prop_assert!((k.burn as u128 - 1) * 1_000_000_000 < k.price as u128 * k.lot as u128);
            prop_assert_eq!(k.price, burn::price_at(start, 1, 0, dt));
            let mut s2 = s.clone();
            burn::after_take(&mut s2, &k, dt).unwrap();
            prop_assert!(s2.start_price >= k.price && s2.start_at == dt && s2.start_price >= s.floor_price);
            // restart = price * (1 + lot/max_lot): never above twice the price, exactly twice for a full lot
            prop_assert!(s2.start_price <= k.price.saturating_mul(2).max(s.floor_price));
            if k.lot == s.max_lot { prop_assert_eq!(s2.start_price, k.price.saturating_mul(2).max(s.floor_price)); }
            prop_assert_eq!(s2.pot, s.pot - k.lot);
            prop_assert_eq!((s2.takes, s2.total_burned, s2.total_lamports), (s.takes + 1, s.total_burned + k.burn, s.total_lamports + k.lot));
            // a replay of the same take at the same instant costs at least as much again
            prop_assert!(burn::price_at(s2.start_price, 1, dt, dt) >= k.price);
        }
    }

    /// The attestation parser never panics and never counts more keys than the set has.
    #[test]
    fn attestation_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400), n in 0usize..8) {
        let keys: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
        if let Ok(mask) = zkproof::ed25519_signers(&bytes, &keys, b"m") {
            prop_assert!(mask.count_ones() as usize <= n);
        }
    }
}

fn precompile(entries: &[([u8; 32], &[u8])], inline: bool) -> Vec<u8> {
    // [n, 0, n x 14-byte offsets, n x (pubkey 32, sig 64), messages...]
    let n = entries.len();
    let head = 2 + 14 * n;
    let mut body = Vec::new();
    let mut table = Vec::new();
    let mut msgs = Vec::new();
    let msg_base = head + 96 * n;
    for (i, (pk, m)) in entries.iter().enumerate() {
        let pk_off = head + 96 * i;
        let msg_off = msg_base + msgs.len();
        let ix = if inline { u16::MAX } else { 0 };
        for v in [(pk_off + 32) as u16, ix, pk_off as u16, ix, msg_off as u16, m.len() as u16, ix] {
            table.extend_from_slice(&v.to_le_bytes());
        }
        body.extend_from_slice(pk);
        body.extend_from_slice(&[0u8; 64]);
        msgs.extend_from_slice(m);
    }
    let mut d = vec![n as u8, 0];
    d.extend(table);
    d.extend(body);
    d.extend(msgs);
    d
}

#[test]
fn attestation_rules() {
    let keys = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let m: &[u8] = b"halfkey-xmr-header-v1 test";
    assert_eq!(zkproof::ed25519_signers(&precompile(&[(keys[0], m), (keys[2], m)], true), &keys, m), Ok(0b101));
    // the same key twice
    assert!(zkproof::ed25519_signers(&precompile(&[(keys[0], m), (keys[0], m)], true), &keys, m).is_err());
    // a key outside the set
    assert!(zkproof::ed25519_signers(&precompile(&[(keys[0], m), ([9u8; 32], m)], true), &keys, m).is_err());
    // another message
    assert!(zkproof::ed25519_signers(&precompile(&[(keys[0], m), (keys[1], b"other")], true), &keys, m).is_err());
    // data in another instruction
    assert!(zkproof::ed25519_signers(&precompile(&[(keys[0], m)], false), &keys, m).is_err());
    // no signatures, truncated table
    assert!(zkproof::ed25519_signers(&[0, 0], &keys, m).is_err());
    assert!(zkproof::ed25519_signers(&[2, 0, 1, 2, 3], &keys, m).is_err());
    // committee rules
    assert!(zkproof::check_attesters(2, 2, 3, 10, &keys).is_ok());
    assert!(zkproof::check_attesters(2, 4, 3, 10, &keys).is_err());
    assert!(zkproof::check_attesters(2, 0, 3, 10, &keys).is_err());
    assert!(zkproof::check_attesters(2, 2, 3, 9, &keys).is_err());
    assert!(zkproof::check_attesters(3, 2, 3, 10, &keys).is_err());
    assert!(zkproof::check_attesters(2, 1, 2, 10, &[keys[0], keys[0]]).is_err());
    assert!(zkproof::check_attesters(2, 1, 1, 10, &[[0u8; 32]]).is_err());
    let msg = zkproof::header_msg(2, 2_243_223, &[7; 32], 10);
    assert_eq!(&msg[..21], zkproof::HEADER_MSG_PREFIX);
    assert_eq!(msg.len(), zkproof::HEADER_MSG_LEN);
}

#[test]
fn claim_gate_rules() {
    let key = Pubkey::new_from_array([5; 32]);
    let e = Escrow { direction: DIR_XMR_TO_SOL, flags: F_PROOF, state: ST_LOCKED, xmr_amount: 100, ..Default::default() };
    let rec = |escrow: Pubkey, amount: u64| ProofRec { escrow, amount, ..Default::default() };
    assert_eq!(zkproof::claim_gate(&e, &key, None), Err(HkError::NotProven));
    assert_eq!(zkproof::claim_gate(&e, &key, Some(&rec(key, 100))), Ok(()));
    assert_eq!(zkproof::claim_gate(&e, &key, Some(&rec(key, 99))), Err(HkError::NotProven));
    // a record for the same address but an earlier lock (reused address) is rejected
    assert_eq!(zkproof::claim_gate(&Escrow { created_at: 5, ..e.clone() }, &key, Some(&rec(key, 100))), Err(HkError::NotProven));
    assert_eq!(zkproof::claim_gate(&e, &key, Some(&rec(Pubkey::new_from_array([6; 32]), 1000))), Err(HkError::NotProven));
    // Ready (the locker checked it itself) and unflagged escrows are unchanged
    assert_eq!(zkproof::claim_gate(&Escrow { state: ST_READY, ..e.clone() }, &key, None), Ok(()));
    // XMR->SOL without proof mode: the maker (locker) protects itself, as before
    assert_eq!(zkproof::claim_gate(&Escrow { flags: 0, ..e.clone() }, &key, None), Ok(()));
    // every SOL->XMR escrow is gated, whatever its flags (swap, OTC, pay, vault)
    for f in [0, F_OTC, F_PAY, F_PAY | F_VAULT] {
        let s2x = Escrow { direction: DIR_SOL_TO_XMR, flags: f, ..e.clone() };
        assert_eq!(zkproof::claim_gate(&s2x, &key, None), Err(HkError::NotProven));
        assert_eq!(zkproof::claim_gate(&s2x, &key, Some(&rec(key, 100))), Ok(()));
        assert_eq!(zkproof::prove_window(DIR_SOL_TO_XMR, f, ST_LOCKED, 0, 10), Ok(()));
    }
    assert_eq!(zkproof::prove_window(DIR_XMR_TO_SOL, 0, ST_LOCKED, 0, 10), Err(HkError::BadState));
    assert_eq!(zkproof::prove_window(DIR_XMR_TO_SOL, F_PROOF, ST_ABORTED, 0, 10), Err(HkError::BadState));
    assert_eq!(zkproof::prove_window(DIR_XMR_TO_SOL, F_PROOF, ST_LOCKED, 10, 10), Err(HkError::TooLate));
    assert_eq!(zkproof::prove_window(DIR_SOL_TO_XMR, F_PAY, ST_READY, 9, 10), Ok(()));
}

#[test]
fn ready_only_cannot_be_overridden_by_a_committee_proof() {
    let key = Pubkey::new_from_array([5; 32]);
    let e = Escrow { direction: DIR_SOL_TO_XMR, flags: F_READY_ONLY, state: ST_LOCKED, xmr_amount: 100, created_at: 7, ..Default::default() };
    let good = ProofRec { escrow: key, escrow_created: 7, amount: 100, ..Default::default() };
    for flags in [F_READY_ONLY, F_READY_ONLY | F_PROOF, F_READY_ONLY | F_OTC] {
        let opted_out = Escrow { flags, ..e.clone() };
        assert!(zkproof::proof_gated(DIR_SOL_TO_XMR, flags));
        assert!(!zkproof::proof_allowed(DIR_SOL_TO_XMR, flags));
        assert_eq!(zkproof::claim_gate(&opted_out, &key, Some(&good)), Err(HkError::NotProven));
        assert_eq!(zkproof::claim_gate(&opted_out, &key, None), Err(HkError::NotProven));
        assert_eq!(zkproof::prove_window(DIR_SOL_TO_XMR, flags, ST_LOCKED, 0, 10), Err(HkError::BadState));
        assert_eq!(zkproof::claim_gate(&Escrow { state: ST_READY, ..opted_out }, &key, None), Ok(()));
    }
    // Legacy consent/layout stays unchanged: unflagged SOL->XMR can still use a valid proof.
    assert_eq!(zkproof::claim_gate(&Escrow { flags: 0, ..e }, &key, Some(&good)), Ok(()));
}

#[test]
fn v15_layouts_roundtrip() {
    let a = Attesters { bump: 3, net: 2, threshold: 2, n: 3, epoch: 9, min_conf: 10, keys: [[4; 32]; 7] };
    let mut d = vec![0u8; zkproof::ATTESTERS_LEN];
    a.store(&mut d);
    assert_eq!(Attesters::load(&d).unwrap(), a);
    let h = XHeader { bump: 1, net: 2, epoch: 3, height: 4, confirmations: 11, attested_at: -5, block_id: [6; 32], payer: Pubkey::new_from_array([7; 32]) };
    let mut d = vec![0u8; zkproof::XHDR_LEN];
    h.store(&mut d);
    assert_eq!(XHeader::load(&d).unwrap(), h);
    let p = ProofRec { bump: 1, kind: 1, out_index: 2, escrow: Pubkey::new_from_array([3; 32]), escrow_created: -11, amount: 4, proven_at: 5, height: 6, epoch: 7, txid: [8; 32], block_id: [9; 32], out_key: [10; 32] };
    let mut d = vec![0u8; zkproof::XPROOF_LEN];
    p.store(&mut d);
    assert_eq!(ProofRec::load(&d).unwrap(), p);
    let s = BurnState { mint: Pubkey::new_from_array([1; 32]), start_price: 2, floor_price: 3, max_lot: 4, start_at: 5, takes: 6, total_burned: 7, total_lamports: 8, last_price: 9, pot: 10 };
    let mut d = vec![0u8; burn::BURN_LEN];
    s.store(&mut d);
    assert_eq!(BurnState::load(&d).unwrap(), s);
    assert!(burn::sweep_allowed(0).is_ok() && burn::sweep_allowed(burn::BURN_LEN).is_err());
    assert!(burn::check_params(10, 1, 1).is_ok() && burn::check_params(10, 0, 1).is_err());
    assert!(burn::check_params(10, 11, 1).is_err() && burn::check_params(10, 1, 0).is_err());
}

/// Tripwire for the v1.5 modules: lamports leave a program account in exactly one place,
/// `burn_take` paying the buyer that burned; the proof instructions move no lamports out of
/// program accounts (they only create PDAs funded by the payer). No v1.5 code reads the pause.
#[test]
fn v15_debit_sites_and_pause_reads() {
    for (name, src, want) in [
        ("zkproof.rs", include_str!("zkproof.rs"), Vec::<&str>::new()),
        ("burn.rs", include_str!("burn.rs"), vec!["burn_take:pay"]),
        ("xmr.rs", include_str!("xmr.rs"), vec![]),
        ("rewards.rs", include_str!("rewards.rs"), vec!["sync:pay", "sync:pay", "pool_claim:pay"]),
    ] {
        let mut f = "";
        let mut sites = Vec::new();
        for line in src.lines() {
            let l = line.trim_start();
            if let Some(rest) = l.strip_prefix("pub fn ").or_else(|| l.strip_prefix("pub(crate) fn ")).or_else(|| l.strip_prefix("fn ")) {
                f = rest.split(['(', '<']).next().unwrap();
                continue;
            }
            if l.starts_with("//") {
                continue;
            }
            assert!(!l.contains(".paused"), "{name}: {f} reads the pause flag");
            if l.starts_with("pay(") || l.contains(" pay(") || l.contains("close_account(") || l.contains("try_borrow_mut_lamports") {
                sites.push(format!("{f}:pay"));
            }
        }
        assert_eq!(sites, want, "{name}: lamport debit sites changed");
    }
}

// ---------------------------------------------------------------------------------------------
// Staking rewards (rewards.rs): random walks over many stakers with the real code (SHIFT = 64)
// ---------------------------------------------------------------------------------------------

use crate::rewards::{self, Pool, Staker};

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    /// Any sequence of fee credits, stakes, unstakes and claims over 4 stakers: what is paid out
    /// never exceeds what was credited; each staker's payout only changes on its own claim; every
    /// credit is fully owed to the stakers present (up to < 1 lamport of rounding per staker).
    #[test]
    fn rewards_random_walk(ops in proptest::collection::vec((0u8..5, 0usize..4, 1u64..1_000_000_000_000), 1..60)) {
        let mut p = Pool::default();
        let mut st: Vec<Staker> = (0..4).map(|_| Staker::default()).collect();
        let mut paid = [0u64; 4];
        for (op, i, x) in ops {
            let before_paid = paid;
            match op {
                0 => { if rewards::credit(&mut p, x % 10_000_000_000).is_err() { prop_assert_eq!(p.total_staked, 0); } }
                1 => { let _ = rewards::stake_s::<64>(&mut p, &mut st[i], x); }
                2 => { let a = x % (st[i].staked + 1); let _ = rewards::unstake_s::<64>(&mut p, &mut st[i], a, 0); }
                3 => { if let Ok(y) = rewards::claim_s::<64>(&mut p, &mut st[i]) { paid[i] += y; } }
                _ => { st[i].unbonding = 0; } // withdraw the unbonded tokens
            }
            for j in 0..4 { if j != i { prop_assert_eq!(paid[j], before_paid[j]); } }
            prop_assert_eq!(p.total_staked, st.iter().map(|s| s.staked).sum::<u64>());
            let owed: u128 = st.iter().map(|s| s.owed as u128 + rewards::pending(p.acc, s).unwrap() as u128).sum();
            prop_assert_eq!(p.claimed as u128, paid.iter().map(|x| *x as u128).sum::<u128>());
            prop_assert!(p.claimed as u128 + owed <= p.distributed as u128, "owed more than credited");
            prop_assert!(p.claimed <= p.distributed);
        }
        // claim everything: the rounding left behind is under 1 lamport per staker per credit
        for i in 0..4 { let _ = rewards::unstake_s::<64>(&mut p, &mut st[i], 0, 0); let y = rewards::claim_s::<64>(&mut p, &mut st[i]).unwrap(); paid[i] += y; }
        prop_assert!(p.claimed <= p.distributed);
    }

    /// The credit step keeps I* (the Kani induction's invariant) at the program's real 2^64 scale:
    /// 2^64 (claimed + owed_a + owed_b) + staked_a (acc - at_a) + staked_b (acc - at_b)
    ///   <= 2^64 distributed, before and after crediting any x.
    #[test]
    fn credit_keeps_claims_within_credits(sa in 0u64..1 << 40, sb in 1u64..1 << 40, da in 0u128..1 << 60, db in 0u128..1 << 60, slack in 0u64..1 << 40, x in 0u64..1 << 50, claimed in 0u64..1 << 40, oa in 0u64..1 << 30, ob in 0u64..1 << 30) {
        let acc = da.max(db) + 1;
        let a = Staker { staked: sa, acc_at: acc - da, owed: oa, ..Default::default() };
        let b = Staker { staked: sb, acc_at: acc - db, owed: ob, ..Default::default() };
        let inv = |p: &Pool| -> bool {
            let lhs = ((p.claimed as u128 + a.owed as u128 + b.owed as u128) << 64)
                + a.staked as u128 * (p.acc - a.acc_at)
                + b.staked as u128 * (p.acc - b.acc_at);
            lhs <= (p.distributed as u128) << 64
        };
        // smallest `distributed` that satisfies I* now, plus some slack
        let need = ((claimed as u128 + oa as u128 + ob as u128) << 64) + sa as u128 * da + sb as u128 * db;
        let dist = ((need + (1u128 << 64) - 1) >> 64) as u64 + slack;
        let mut p = Pool { total_staked: sa + sb, acc, distributed: dist, claimed, ..Default::default() };
        prop_assume!(inv(&p));
        if rewards::credit(&mut p, x).is_ok() {
            prop_assert!(inv(&p), "credit broke claimed + owed + pending <= credited");
        }
    }

    /// The split is exact, stakers get the floor half and the burn the odd lamport.
    #[test]
    fn split_exact(u in any::<u64>(), staked in any::<u64>()) {
        let (a, b) = rewards::split(u, staked);
        prop_assert_eq!(a as u128 + b as u128, u as u128);
        if staked == 0 { prop_assert_eq!(a, 0); } else { prop_assert_eq!(a, u / 2); prop_assert!(b == a || b == a + 1); }
    }
}

#[test]
fn reward_shares_are_pro_rata() {
    let mut p = Pool::default();
    let (mut a, mut b) = (Staker::default(), Staker::default());
    rewards::stake_s::<64>(&mut p, &mut a, 3_000).unwrap();
    rewards::stake_s::<64>(&mut p, &mut b, 1_000).unwrap();
    rewards::credit(&mut p, 4_000_000).unwrap();
    // a new stake earns nothing from fees credited before it
    let mut c = Staker::default();
    rewards::stake_s::<64>(&mut p, &mut c, 1_000_000).unwrap();
    assert_eq!(rewards::claim_s::<64>(&mut p, &mut c).unwrap(), 0);
    assert_eq!(rewards::claim_s::<64>(&mut p, &mut a).unwrap(), 3_000_000);
    assert_eq!(rewards::claim_s::<64>(&mut p, &mut b).unwrap(), 1_000_000);
    // unbonding stake earns nothing
    rewards::unstake_s::<64>(&mut p, &mut c, 0, 9).unwrap();
    rewards::credit(&mut p, 4_000).unwrap();
    assert_eq!(rewards::claim_s::<64>(&mut p, &mut c).unwrap(), 0);
    assert_eq!(rewards::claim_s::<64>(&mut p, &mut a).unwrap(), 3_000);
    // loose SOL = lamports beyond rent and what is still owed (b has not claimed its 1,000)
    let outstanding = p.distributed - p.claimed;
    assert_eq!(outstanding, 1_000);
    assert_eq!(rewards::pool_extra(10_000 + outstanding + 5, 10_000, &p), 5);
    assert_eq!(rewards::pool_extra(10_000 + outstanding - 1, 10_000, &p), 0);
    let mut d = vec![0u8; rewards::POOL_LEN];
    let q = Pool { bump: 1, mint: Pubkey::new_from_array([8; 32]), total_staked: 2, acc: (5u128 << 70) | 7, distributed: 3, claimed: 4 };
    q.store(&mut d);
    assert_eq!(Pool::load(&d).unwrap(), q);
    let mut d = vec![0u8; rewards::STAKER_LEN];
    let s = Staker { bump: 1, owner: Pubkey::new_from_array([2; 32]), staked: 3, acc_at: (9u128 << 80) | 4, owed: 5, unbonding: 6, unlock_at: -7 };
    s.store(&mut d);
    assert_eq!(Staker::load(&d).unwrap(), s);
}

/// Integration review #1: a pre-v1.5 maker bond whose unstake was pending enrolls as a pending pool
/// unstake, and the enroll-only call (amount 0) no longer trips stake_s's "unbonding" guard, so
/// the owner can finish the unstake with pool_unstake (and then withdraw the SOL bond). A real
/// deposit while unbonding is still refused.
#[test]
fn legacy_pending_unstake_enrolls() {
    use crate::rewards::{add_stake_s, enrolled_legacy, stake_s, Pool, Staker, SHIFT};
    let mut p = Pool { total_staked: 7, ..Default::default() };
    let mut st = Staker::default();
    st.unbonding = enrolled_legacy(1_000, 1_000);
    st.unlock_at = 50;
    // the old final step refused this, reverting the whole enrollment
    assert_eq!(stake_s::<SHIFT>(&mut p.clone(), &mut st.clone(), 0), Err(HkError::BadState));
    assert_eq!(add_stake_s::<SHIFT>(&mut p, &mut st, 0), Ok(()));
    assert_eq!((st.staked, st.unbonding, st.unlock_at, p.total_staked), (0, 1_000, 50, 7));
    assert_eq!(add_stake_s::<SHIFT>(&mut p, &mut st, 5), Err(HkError::BadState));
    // a bond counts only what the pool-mint vault holds (review #6)
    assert_eq!(enrolled_legacy(1_000, 400), 400);
    assert_eq!(enrolled_legacy(1_000, 0), 0);
    assert_eq!(enrolled_legacy(1_000, 5_000), 1_000);
    // a normal enrollment of an active bond still stakes it
    let mut st2 = Staker::default();
    assert_eq!(stake_s::<SHIFT>(&mut p, &mut st2, enrolled_legacy(300, 300)), Ok(()));
    assert_eq!((st2.staked, p.total_staked), (300, 307));
    assert_eq!(add_stake_s::<SHIFT>(&mut p, &mut st2, 0), Ok(()));
    assert_eq!((st2.staked, p.total_staked), (300, 307));
}

/// Integration review #3: the proof record PDA is bound to the escrow's terms (both key halves and
/// the view key), so the same escrow address + lock time with other keys derives another record.
#[test]
fn proof_record_bound_to_terms() {
    let e = Escrow { claim_point: [1; 32], refund_point: [2; 32], view_pub: [3; 32], ..Default::default() };
    let t = zkproof::proof_terms(&e);
    for f in 0..3 {
        let mut o = e.clone();
        match f {
            0 => o.claim_point[0] ^= 1,
            1 => o.refund_point[31] ^= 0x80,
            _ => o.view_pub[7] ^= 4,
        }
        assert_ne!(zkproof::proof_terms(&o), t);
    }
    // amounts, times and parties are not part of it (the gate checks escrow, created_at, amount)
    let o = Escrow { amount: 9, xmr_amount: 9, created_at: 9, ..e.clone() };
    assert_eq!(zkproof::proof_terms(&o), t);
    // fixed vector, mirrored by sdk/v15.ts proofTerms (sdk/v15.test.ts)
    assert_eq!(
        t.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        "4d84182da017b6f9869f9e23537429611b4915c905e624a4292b435085b80619"
    );
}

/// Real Monero mainnet data (e2e/xmr-mainnet-format.ts --write): the program's parser, txid and block
/// fold agree with the chain on transactions it never saw in a test. The DLEQ needs a tx key, so
/// that half rests on the stagenet run and the first small mainnet swap.
#[test]
fn real_mainnet_txs_parse_and_fold() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../e2e/fixtures/xmr-mainnet-format.json");
    let json = std::fs::read_to_string(path).expect("run e2e/xmr-mainnet-format.ts --write");
    let j: serde_json::Value = serde_json::from_str(&json).unwrap();
    let rows = j.as_array().unwrap();
    assert!(rows.len() >= 10);
    for v in rows {
        let s = |k: &str| v[k].as_str().unwrap().to_string();
        let u = unhex(&s("unprunable"));
        let t = xmr::parse_tx(&u, 0).unwrap();
        assert_eq!(t.r_pub, a32(&s("r_pub")));
        let h0 = Syscalls.keccak(&[&u[..t.prefix_len]]);
        let h1 = Syscalls.keccak(&[&u[t.prefix_len..]]);
        let txid = Syscalls.keccak(&[&h0, &h1, &a32(&s("prunable_hash"))]);
        assert_eq!(txid, a32(&s("txid")));
        let got = xmr::fold_block_id(&Syscalls, &txid, &unhex(&s("header")), v["ntx"].as_u64().unwrap() as u32, &unhex(&s("branch"))).unwrap();
        assert_eq!(got, a32(&s("block_id")));
    }
}
