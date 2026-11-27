//! Native round trip: build + prove a shielded HTLC claim, re-read it, verify the proof and the
//! bundle signatures, decrypt the note with the recipient's key. Run: cargo test --release --features testkit
use halfkey_zecwasm::shielded::*;

const NU7: u32 = 0x77190ad9;

#[test]
fn shielded_claim_round_trip() {
    let seed = "11".repeat(32);
    let (ua, recv) = testkit::wallet(&seed, "regtest").unwrap();
    assert_eq!(ua_receiver(&ua, "regtest").unwrap(), recv);
    assert!(ua_receiver(&ua, "mainnet").is_err());
    let anchor = hex::encode(orchard::Anchor::empty_tree().to_bytes());
    // A dummy P2SH prevout (the script is never executed here).
    let req = SpendRequest {
        branch: NU7, lock_time: 0, sequence: 0xffffffff,
        prev_txid: "ab".repeat(32), vout: 1, value: 150_000_000,
        script_pubkey: format!("a914{}87", "00".repeat(20)), script_code: "51".into(),
        recipient: recv.clone(), fee: 20_000, anchor, memo: None,
    };
    let t0 = std::time::Instant::now();
    let pk_ms = { let t = std::time::Instant::now(); proving_key(); t.elapsed().as_millis() };
    let t = build_spend(&req).unwrap();
    eprintln!("proving key {pk_ms} ms, build+prove {} ms (prove {:.0} ms), raw {} bytes, proof {} bytes, actions {}",
        t0.elapsed().as_millis() - pk_ms, t.prove_ms, t.raw.len() / 2, t.proof_bytes, t.actions);
    assert_eq!(t.actions, 2);
    assert_eq!(t.out_value, 150_000_000 - 20_000);
    let ins = inspect(&InspectRequest { raw: t.raw.clone(), branch: NU7, value: req.value, script_pubkey: req.script_pubkey.clone(), script_code: req.script_code.clone(), verify_proof: true }).unwrap();
    assert_eq!(ins.txid, t.txid);
    assert_eq!(ins.sighash, t.sighash, "inspect recomputes the same transparent sighash");
    assert_eq!(ins.proof_ok, Some(true));
    assert_eq!(ins.ironwood_value_in, 150_000_000 - 20_000);
    assert_eq!(ins.inputs[0].script_sig, "");
    assert_eq!(ins.version, 6);
    // Only the recipient can read it.
    assert_eq!(testkit::decrypt(&t.raw, NU7, &seed).unwrap(), vec![(150_000_000 - 20_000, 0xF6)]);
    assert!(testkit::decrypt(&t.raw, NU7, &"22".repeat(32)).unwrap().is_empty());
    // A different value for the prevout changes the sighash (ZIP 244 commits to the amounts).
    let other = inspect(&InspectRequest { raw: t.raw.clone(), branch: NU7, value: req.value + 1, script_pubkey: req.script_pubkey.clone(), script_code: req.script_code.clone(), verify_proof: false }).unwrap();
    assert_ne!(other.sighash, t.sighash);
}
