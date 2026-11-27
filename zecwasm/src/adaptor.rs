//! ZEC v2 (unlinkable swaps): the secret t behind both locks, without a shared hash.
//!
//!  * Solana side: the escrow is locked to T_ed = t*G (ed25519); the claim reveals t (program,
//!    `htlc_pt_claim`).
//!  * Zcash side: a P2SH 2-of-2 (user + maker) with a CLTV refund branch. The counterparty's
//!    signature on the claim is an ECDSA adaptor signature encrypted to T_secp = t*G (secp256k1):
//!    anyone who learns t (from the Solana claim) decrypts it into an ordinary ECDSA signature.
//!  * A cross-curve DLEQ proof shows that T_secp and T_ed have the same 252-bit discrete log, so
//!    revealing t on Solana is exactly what completes the Zcash claim.
//!
//! On chain nothing links the legs: the Zcash spend carries two ordinary ECDSA signatures, the
//! Solana claim an ed25519 scalar. Only the two parties (who hold the encrypted signature) can
//! connect them. Timing and amounts still correlate.
//!
//! Libraries: ecdsa_fun 0.12 (adaptor) and sigma_fun 0.9 (cross-curve DLEQ, the MRL-0010-style
//! bit-commitment proof), both from LLFourn/secp256kfun; sigma_fun's ed25519 side is
//! curve25519-dalek-ng 4.1.1 (a fork that is no longer maintained). Not audited.
//!
//! Byte conventions (all hex in the JSON API):
//!  * t: 32 bytes LITTLE-endian (the ed25519 scalar encoding Solana checks), t < 2^252, t != 0.
//!  * T_ed: 32-byte compressed Edwards point. T_secp: 33-byte compressed SEC1 point.
//!  * secp256k1 secret keys: 32 bytes big-endian (as everywhere else in the SDK).
//!  * Adaptor signature: 162 bytes (ecdsa_fun's encoding). Decrypted signature: 64 bytes r||s,
//!    low-S (the SDK DER-encodes it).
use sigma_fun::ed25519::curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar as Ed,
};
use ecdsa_fun::{
    adaptor::{Adaptor, EncryptedSignature, HashTranscript},
    fun::{g, nonce, Point, Scalar, G},
};
use std::str::FromStr;
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256, Sha512};
use sigma_fun::ext::dl_secp256k1_ed25519_eq::{CrossCurveDLEQ, CrossCurveDLEQProof};
use std::sync::OnceLock;

pub type Res<T> = Result<T, String>;
type Transcript = HashTranscript<Sha256, ChaCha20Rng>;
type NonceGen = nonce::Synthetic<Sha256, nonce::GlobalRng<OsRng06>>;

/// rand_core 0.6 system RNG for secp256kfun (crypto.getRandomValues in the browser).
#[derive(Clone, Copy, Default)]
pub struct OsRng06;
impl rand_core06::RngCore for OsRng06 {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, d: &mut [u8]) {
        getrandom02::getrandom(d).expect("system randomness")
    }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core06::Error> {
        self.fill_bytes(d);
        Ok(())
    }
}
impl rand_core06::CryptoRng for OsRng06 {}

fn adaptor() -> Adaptor<Transcript, NonceGen> {
    Adaptor::<Transcript, NonceGen>::default()
}

// ------------------------------------------------------------------ the DLEQ's Pedersen generators
/// Domain tag for the generators. Changing it invalidates every proof.
const H_TAG: &[u8] = b"halfkey/zec-v2/dleq-H/v1";

/// Nothing-up-my-sleeve second generators, one per curve, whose discrete logs relative to G are
/// unknown to everyone: secp256k1 by secp256kfun's try-and-increment hash-to-curve, ed25519 by
/// try-and-increment decompression of SHA-512 output, cofactor-cleared (prime-order subgroup).
pub fn generators() -> &'static (Point, EdwardsPoint) {
    static H: OnceLock<(Point, EdwardsPoint)> = OnceLock::new();
    H.get_or_init(|| {
        use ecdsa_fun::fun::hash::HashAdd;
        let hp = Point::hash_to_curve(Sha256::default().add(H_TAG).add(&b"secp256k1"[..]));
        let mut hq = None;
        for ctr in 0u32..1000 {
            let d = Sha512::new().chain_update(H_TAG).chain_update(b"ed25519").chain_update(ctr.to_le_bytes()).finalize();
            let mut y = [0u8; 32];
            y.copy_from_slice(&d[..32]);
            if let Some(p) = CompressedEdwardsY(y).decompress() {
                let p = p.mul_by_cofactor();
                if !p.is_small_order() {
                    hq = Some(p);
                    break;
                }
            }
        }
        (hp, hq.expect("a point within 1000 tries"))
    })
}
fn dleq_system() -> CrossCurveDLEQ<Transcript> {
    let (hp, hq) = generators();
    CrossCurveDLEQ::<Transcript>::new(*hp, *hq)
}

// ------------------------------------------------------------------ parsing
fn unhex<const N: usize>(h: &str, what: &'static str) -> Res<[u8; N]> {
    let v = hex::decode(h).map_err(|e| format!("{what}: {e}"))?;
    v.try_into().map_err(|_| format!("{what}: expected {N} bytes"))
}
/// t from 32 little-endian bytes: canonical, below 2^252 (the DLEQ's bit length), non-zero.
fn t_ed(h: &str) -> Res<Ed> {
    let b: [u8; 32] = unhex(h, "t")?;
    if b[31] & 0xf0 != 0 {
        return Err("t must be below 2^252".into());
    }
    let s = Ed::from_canonical_bytes(b).ok_or("t is not a canonical scalar")?;
    if s == Ed::zero() {
        return Err("t must not be zero".into());
    }
    Ok(s)
}
/// The same integer on secp256k1 (big-endian; t < 2^252 < n, so no reduction).
fn t_secp(t: &Ed) -> Res<Scalar> {
    let mut be = t.to_bytes();
    be.reverse();
    Scalar::from_bytes(be).and_then(|s| s.non_zero()).ok_or_else(|| "t out of range".to_string())
}
fn secp_point(h: &str, what: &'static str) -> Res<Point> {
    Point::from_bytes(unhex::<33>(h, what)?).ok_or_else(|| format!("{what}: not a secp256k1 point"))
}
fn ed_point(h: &str, what: &'static str) -> Res<EdwardsPoint> {
    let b: [u8; 32] = unhex(h, what)?;
    let p = CompressedEdwardsY(b).decompress().ok_or_else(|| format!("{what}: not an ed25519 point"))?;
    // Canonical encoding, prime-order subgroup, not small order (same rules as the program).
    if p.compress().to_bytes() != b || p.is_small_order() || !p.is_torsion_free() {
        return Err(format!("{what}: not a canonical prime-order ed25519 point"));
    }
    Ok(p)
}
fn secp_secret(h: &str) -> Res<Scalar> {
    Scalar::from_bytes(unhex::<32>(h, "secret key")?)
        .and_then(|s| s.non_zero())
        .ok_or_else(|| "secret key out of range".to_string())
}

// ------------------------------------------------------------------ API
#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Points {
    pub t_secp: String,
    pub t_ed: String,
}

/// T_secp and T_ed for t (no proof).
pub fn points(t_hex: &str) -> Res<Points> {
    let t = t_ed(t_hex)?;
    let ts = t_secp(&t)?;
    let ted = &t * &ED25519_BASEPOINT_TABLE;
    Ok(Points { t_secp: hex::encode(g!(ts * G).normalize().to_bytes()), t_ed: hex::encode(ted.compress().to_bytes()) })
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DleqOut {
    pub t_secp: String,
    pub t_ed: String,
    /// bincode (legacy config) of sigma_fun's CrossCurveDLEQProof, hex.
    pub proof: String,
}

/// Prove that T_secp = t*G_secp and T_ed = t*G_ed share t.
pub fn dleq_prove(t_hex: &str) -> Res<DleqOut> {
    let t = t_ed(t_hex)?;
    let (proof, (tp, tq)) = dleq_system().prove(&t, &mut OsRng06);
    let bytes = bincode::serde::encode_to_vec(&proof, bincode::config::legacy()).map_err(|e| format!("encode proof: {e}"))?;
    // Self-check: the claim is the one t gives.
    let p = points(t_hex)?;
    if hex::encode(tp.to_bytes()) != p.t_secp || hex::encode(tq.compress().to_bytes()) != p.t_ed {
        return Err("DLEQ prover returned other points".into());
    }
    Ok(DleqOut { t_secp: p.t_secp, t_ed: p.t_ed, proof: hex::encode(bytes) })
}

/// Largest proof we accept (252 commitment pairs + responses; ~48 kB).
const MAX_PROOF: usize = 64 * 1024;

pub fn dleq_verify(t_secp: &str, t_ed: &str, proof_hex: &str) -> Res<bool> {
    let tp = secp_point(t_secp, "T_secp")?;
    let tq = ed_point(t_ed, "T_ed")?;
    let raw = hex::decode(proof_hex).map_err(|e| format!("proof: {e}"))?;
    if raw.len() > MAX_PROOF {
        return Err("proof too large".into());
    }
    let (proof, used): (CrossCurveDLEQProof, usize) =
        bincode::serde::decode_from_slice(&raw, bincode::config::legacy()).map_err(|e| format!("proof: {e}"))?;
    if used != raw.len() {
        return Err("trailing bytes after the proof".into());
    }
    Ok(dleq_system().verify(&proof, (tp, tq)))
}

/// Encrypted (adaptor) ECDSA signature by `sk` on the 32-byte `msg`, encrypted to T_secp.
pub fn enc_sign(sk_hex: &str, t_secp: &str, msg_hex: &str) -> Res<String> {
    let sk = secp_secret(sk_hex)?;
    let y = secp_point(t_secp, "T_secp")?;
    let m: [u8; 32] = unhex(msg_hex, "message")?;
    Ok(adaptor().encrypted_sign(&sk, &y, &m).to_string())
}

fn enc_sig(h: &str) -> Res<EncryptedSignature> {
    unhex::<162>(h, "adaptor signature")?;
    EncryptedSignature::from_str(h).map_err(|_| "not an adaptor signature".to_string())
}

/// Would `enc` decrypt (with the t behind T_secp) to a valid signature by `pk` on `msg`?
pub fn enc_verify(pk_hex: &str, t_secp: &str, msg_hex: &str, enc_hex: &str) -> Res<bool> {
    let pk = secp_point(pk_hex, "public key")?;
    let y = secp_point(t_secp, "T_secp")?;
    let m: [u8; 32] = unhex(msg_hex, "message")?;
    Ok(adaptor().verify_encrypted_signature(&pk, &y, &m, &enc_sig(enc_hex)?))
}

/// Decrypt with t: 64-byte r||s ECDSA signature (low-S).
pub fn decrypt(t_hex: &str, enc_hex: &str) -> Res<String> {
    let t = t_ed(t_hex)?;
    let y = t_secp(&t)?;
    Ok(hex::encode(adaptor().decrypt_signature(&y, enc_sig(enc_hex)?).to_bytes()))
}

/// t (little-endian hex) from a decrypted signature and its adaptor signature, or an error if the
/// signature is not the one decrypted from `enc`. (Not needed by the protocol, where t is public on
/// Solana; used by tests and by a party checking what the other side broadcast.)
pub fn recover(t_secp: &str, sig64_hex: &str, enc_hex: &str) -> Res<String> {
    let y = secp_point(t_secp, "T_secp")?;
    let sig = ecdsa_fun::Signature::from_bytes(unhex::<64>(sig64_hex, "signature")?).ok_or("bad signature")?;
    let k = adaptor().recover_decryption_key(&y, &sig, &enc_sig(enc_hex)?).ok_or("not the decryption of this adaptor signature")?;
    let mut le = k.to_bytes();
    le.reverse();
    Ok(hex::encode(le))
}
