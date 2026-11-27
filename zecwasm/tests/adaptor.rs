//! Adaptor signatures + cross-curve DLEQ round trips and negatives (native).
use halfkey_zecwasm::adaptor::*;

fn t_hex(seed: u8) -> String {
    let mut t = [seed; 32];
    t[31] &= 0x0f;
    hex::encode(t)
}

#[test]
fn dleq_and_adaptor_round_trip() {
    let t = t_hex(0x5a);
    let t0 = std::time::Instant::now();
    let d = dleq_prove(&t).unwrap();
    eprintln!("dleq prove {} ms, proof {} bytes", t0.elapsed().as_millis(), d.proof.len() / 2);
    let t0 = std::time::Instant::now();
    assert!(dleq_verify(&d.t_secp, &d.t_ed, &d.proof).unwrap());
    eprintln!("dleq verify {} ms", t0.elapsed().as_millis());
    let p = points(&t).unwrap();
    assert_eq!((p.t_secp.clone(), p.t_ed.clone()), (d.t_secp.clone(), d.t_ed.clone()));

    // The proof binds the PAIR: another t's ed25519 point with this secp point fails.
    let other = points(&t_hex(0x33)).unwrap();
    assert!(!dleq_verify(&d.t_secp, &other.t_ed, &d.proof).unwrap());
    assert!(!dleq_verify(&other.t_secp, &d.t_ed, &d.proof).unwrap());
    // A tampered proof fails or is refused.
    let mut bad = hex::decode(&d.proof).unwrap();
    let n = bad.len();
    bad[n / 2] ^= 1;
    assert!(!dleq_verify(&d.t_secp, &d.t_ed, &hex::encode(&bad)).unwrap_or(false));
    // Truncated / trailing bytes are refused.
    assert!(dleq_verify(&d.t_secp, &d.t_ed, &d.proof[..d.proof.len() - 2]).is_err() || !dleq_verify(&d.t_secp, &d.t_ed, &d.proof[..d.proof.len() - 2]).unwrap());
    assert!(dleq_verify(&d.t_secp, &d.t_ed, &format!("{}00", d.proof)).is_err());

    // t out of range.
    let mut big = [0x11u8; 32];
    big[31] = 0x10; // 2^252 bit set
    assert!(dleq_prove(&hex::encode(big)).is_err());
    assert!(dleq_prove(&"00".repeat(32)).is_err());

    // Adaptor: sign under T_secp, verify, decrypt with t, recover t.
    let sk = "11".repeat(32);
    let pk = {
        use ecdsa_fun::fun::{g, marker::*, Scalar, G};
        let s: Scalar<Secret, NonZero> = Scalar::<Secret, Zero>::from_bytes([0x11; 32]).unwrap().non_zero().unwrap();
        hex::encode(g!(s * G).normalize().to_bytes())
    };
    let msg = "42".repeat(32);
    let enc = enc_sign(&sk, &d.t_secp, &msg).unwrap();
    assert_eq!(enc.len(), 324);
    assert!(enc_verify(&pk, &d.t_secp, &msg, &enc).unwrap());
    assert!(!enc_verify(&pk, &other.t_secp, &msg, &enc).unwrap());
    assert!(!enc_verify(&pk, &d.t_secp, &"43".repeat(32), &enc).unwrap());
    let sig = decrypt(&t, &enc).unwrap();
    // low-S
    let s_hi = u8::from_str_radix(&sig[64..66], 16).unwrap();
    assert!(s_hi < 0x80);
    assert_eq!(recover(&d.t_secp, &sig, &enc).unwrap(), t);
    // Decrypting with the wrong t gives a signature that recovers nothing.
    let wrong = decrypt(&t_hex(0x33), &enc).unwrap();
    assert!(recover(&d.t_secp, &wrong, &enc).is_err());
}

#[test]
fn generators_are_fixed() {
    let (hp, hq) = generators();
    // Pin the generators: changing the derivation would silently break every stored proof.
    assert_eq!(hex::encode(hp.to_bytes()), "03309eebe6ddc0ba02fded1320486ab56a067ba7d2f755f6d40c3d46c6944a0fd9");
    assert_eq!(hex::encode(hq.compress().to_bytes()), "8b7cdc59b1bef67a96edadedc1cad68e58226111e6c9e920475e215b772e5226");
    assert!(!hq.is_small_order() && hq.is_torsion_free());
}
