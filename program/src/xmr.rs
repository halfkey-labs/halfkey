//! Monero payment proofs, checked on chain (HALFKEY v1.5).
//!
//! What `verify` establishes, from the bytes it is given:
//!   1. The unprunable part of a Monero transaction (prefix + RingCT base) and the hash of its
//!      prunable part hash to `txid` (Monero's own txid rule). Every field used below is read
//!      from those exact bytes: no field is taken from the prover.
//!   2. Monero's TXPROOF_V2 payment proof (the `OutProofV2` of `get_tx_proof` from the sending
//!      wallet, or the `InProofV2` from the view key) is valid for this txid and the message:
//!      a Schnorr/DLEQ proof that the shared secret `D` belongs to the tx key `R` and the
//!      escrow's view key `A`. Not zero-knowledge, and needs no trusted setup.
//!   3. Output `i` pays the escrow's shared spend key `B`: `P_i == Hs(8D || i)*G + B`, and its
//!      view tag matches, so a normal Monero wallet with the view key sees it.
//!   4. The encrypted amount decodes to `a`, and `a` is the amount in the output's Pedersen
//!      commitment (`C_i == y*G + a*H`), so it cannot be inflated. `a >= min_amount`.
//!   5. `unlock_time == 0`, version 2, RingCT type CLSAG (5) or BulletproofPlus (6), key inputs
//!      only (no coinbase).
//!   6. A Merkle path folds `txid` into the transaction tree root of a block header, giving the
//!      Monero block id.
//! What it does NOT establish: that the block is in the canonical Monero chain. Proof of work
//! (RandomX) cannot be checked on chain. The caller compares the block id with a header
//! attested by the k-of-n committee (`zkproof.rs`).
//!
//! The curve and hash operations go through `Ops`: the program uses the curve25519 and keccak
//! syscalls (`Syscalls`); the Kani harnesses use a recording stub.

use crate::HkError;

/// ed25519 basepoint.
pub const G: [u8; 32] = {
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    b
};
/// Monero's second Pedersen generator H (rctTypes.h).
pub const H: [u8; 32] = [
    0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea, 0x6c, 0x72,
    0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94,
];
pub const SCALAR_ONE: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
};
pub const SCALAR_EIGHT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 8;
    b
};
/// keccak("TXPROOF_V2"), the domain separator of Monero's v2 tx proofs (cryptonote_config.h).
pub const TXPROOF_V2_SEP: [u8; 32] = [
    0x23, 0x69, 0x2b, 0x68, 0xdb, 0xec, 0x0a, 0x2e, 0x32, 0x83, 0x40, 0x96, 0xeb, 0xbd, 0x28, 0x65, 0xe4, 0x7a,
    0xf7, 0xb4, 0x67, 0x10, 0x7f, 0x0c, 0x65, 0x96, 0x81, 0x95, 0x41, 0xc9, 0x12, 0x13,
];

/// Proof kinds: who produced the DLEQ.
/// OUT: the sender, from the tx secret key r (`R = r*G`, `D = r*A`): wallet-rpc `get_tx_proof`.
/// IN: the receiver, from the view secret v (`A = v*G`, `D = v*R`): the same call on a wallet
/// that holds the view key, or the SDK.
pub const KIND_OUT: u8 = 0;
pub const KIND_IN: u8 = 1;

/// Monero allows at most 16 outputs per transaction.
pub const MAX_OUTPUTS: usize = 16;
/// Longest Merkle path accepted (2^32 transactions per block is far beyond Monero's limits).
pub const MAX_DEPTH: usize = 32;

/// Curve and hash primitives.
pub trait Ops {
    /// Original (pre-NIST) Keccak-256 of the concatenation, Monero's `cn_fast_hash`.
    fn keccak(&self, parts: &[&[u8]]) -> [u8; 32];
    /// `a*P + b*Q`. None if a point does not decode or a scalar is not canonical.
    fn msm2(&self, a: &[u8; 32], p: &[u8; 32], b: &[u8; 32], q: &[u8; 32]) -> Option<[u8; 32]>;
    /// `a*P`. None if the point does not decode or the scalar is not canonical.
    fn mul(&self, a: &[u8; 32], p: &[u8; 32]) -> Option<[u8; 32]>;
}

/// The curve25519 and keccak syscalls (on the host: the same library code the validator runs).
pub struct Syscalls;

impl Ops for Syscalls {
    fn keccak(&self, parts: &[&[u8]]) -> [u8; 32] {
        solana_keccak_hasher::hashv(parts).to_bytes()
    }
    fn msm2(&self, a: &[u8; 32], p: &[u8; 32], b: &[u8; 32], q: &[u8; 32]) -> Option<[u8; 32]> {
        use solana_curve25519::edwards::{multiscalar_multiply_edwards, PodEdwardsPoint};
        use solana_curve25519::scalar::PodScalar;
        multiscalar_multiply_edwards(&[PodScalar(*a), PodScalar(*b)], &[PodEdwardsPoint(*p), PodEdwardsPoint(*q)])
            .map(|r| r.0)
    }
    fn mul(&self, a: &[u8; 32], p: &[u8; 32]) -> Option<[u8; 32]> {
        use solana_curve25519::edwards::{multiply_edwards, PodEdwardsPoint};
        use solana_curve25519::scalar::PodScalar;
        multiply_edwards(&PodScalar(*a), &PodEdwardsPoint(*p)).map(|r| r.0)
    }
}

// ---------------------------------------------------------------------------------------------
// Scalars
// ---------------------------------------------------------------------------------------------

const L_LIMBS: [u64; 4] = [0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000];

fn limbs(b: &[u8; 32]) -> [u64; 4] {
    let mut l = [0u64; 4];
    for (i, x) in l.iter_mut().enumerate() {
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[i * 8..i * 8 + 8]);
        *x = u64::from_le_bytes(w);
    }
    l
}
fn ge_l(a: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != L_LIMBS[i] {
            return a[i] > L_LIMBS[i];
        }
    }
    true
}
fn sub_l(a: &mut [u64; 4]) {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (x, o1) = a[i].overflowing_sub(L_LIMBS[i]);
        let (y, o2) = x.overflowing_sub(borrow);
        a[i] = y;
        borrow = (o1 | o2) as u64;
    }
}

/// `sc_reduce32`: a 256-bit little-endian value mod L. With q = a >> 252 (<= 15), (q-1)*L <= a,
/// so subtracting L (q-1) times first leaves less than 2L + 2^252, then at most two more steps.
pub fn reduce32(h: &[u8; 32]) -> [u8; 32] {
    let mut a = limbs(h);
    let q = a[3] >> 60;
    let mut i = 1;
    while i < q {
        sub_l(&mut a);
        i += 1;
    }
    while ge_l(&a) {
        sub_l(&mut a);
    }
    let mut o = [0u8; 32];
    for i in 0..4 {
        o[i * 8..i * 8 + 8].copy_from_slice(&a[i].to_le_bytes());
    }
    o
}

/// `s < L`.
pub fn canonical(s: &[u8; 32]) -> bool {
    !ge_l(&limbs(s))
}

/// Monero `hash_to_scalar`: keccak then reduce mod L.
pub fn hs<O: Ops>(o: &O, parts: &[&[u8]]) -> [u8; 32] {
    reduce32(&o.keccak(parts))
}

/// Monero varint (7-bit LEB128) of `n`; returns the bytes used.
pub fn varint(mut n: u64, out: &mut [u8; 10]) -> usize {
    let mut i = 0;
    while n >= 0x80 {
        out[i] = (n as u8 & 0x7f) | 0x80;
        n >>= 7;
        i += 1;
    }
    out[i] = n as u8;
    i + 1
}

// ---------------------------------------------------------------------------------------------
// Transaction parsing
// ---------------------------------------------------------------------------------------------

struct Rd<'a> {
    b: &'a [u8],
    o: usize,
}
impl<'a> Rd<'a> {
    fn u8(&mut self) -> Result<u8, HkError> {
        let v = *self.b.get(self.o).ok_or(HkError::BadXmrTx)?;
        self.o += 1;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], HkError> {
        let end = self.o.checked_add(n).ok_or(HkError::BadXmrTx)?;
        let s = self.b.get(self.o..end).ok_or(HkError::BadXmrTx)?;
        self.o = end;
        Ok(s)
    }
    fn a32(&mut self) -> Result<[u8; 32], HkError> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }
    /// Varint; at most 10 bytes, no bits past 64.
    fn v(&mut self) -> Result<u64, HkError> {
        let mut n = 0u64;
        let mut s = 0u32;
        loop {
            let x = self.u8()?;
            if s == 63 && x > 1 {
                return Err(HkError::BadXmrTx);
            }
            n |= ((x & 0x7f) as u64) << s;
            if x & 0x80 == 0 {
                return Ok(n);
            }
            s += 7;
            if s > 63 {
                return Err(HkError::BadXmrTx);
            }
        }
    }
    fn done(&self) -> bool {
        self.o == self.b.len()
    }
}

/// The fields of one output that the proof needs, read from the serialized transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parsed {
    /// Length of the tx prefix; the rest of the unprunable bytes is the RingCT base.
    pub prefix_len: usize,
    pub out_key: [u8; 32],
    pub view_tag: Option<u8>,
    /// The tx public key `R`: the first tag-0x01 field of tx_extra (what wallet2 tries first).
    pub r_pub: [u8; 32],
    /// ecdhInfo amount of the output (8 bytes, XOR-encrypted).
    pub enc: [u8; 8],
    /// outPk commitment of the output.
    pub commit: [u8; 32],
}

/// Parse `prefix || rct base` of a version-2 RingCT transaction and pick output `idx`.
/// Rejects time-locked transactions, coinbase/non-key inputs, unknown output types, RingCT
/// types other than CLSAG (5) / BulletproofPlus (6), and trailing bytes.
pub fn parse_tx(u: &[u8], idx: usize) -> Result<Parsed, HkError> {
    let mut r = Rd { b: u, o: 0 };
    if r.v()? != 2 {
        return Err(HkError::BadXmrTx);
    }
    if r.v()? != 0 {
        return Err(HkError::BadXmrTx); // unlock_time: the output must be spendable like any other
    }
    let nin = r.v()?;
    if nin == 0 {
        return Err(HkError::BadXmrTx);
    }
    for _ in 0..nin {
        if r.u8()? != 0x02 {
            return Err(HkError::BadXmrTx); // txin_to_key only (no coinbase)
        }
        r.v()?; // amount (0 for RingCT)
        let k = r.v()?;
        for _ in 0..k {
            r.v()?;
        }
        r.take(32)?; // key image
    }
    let nout = r.v()? as usize;
    if nout == 0 || nout > MAX_OUTPUTS || idx >= nout {
        return Err(HkError::BadXmrTx);
    }
    let (mut out_key, mut view_tag) = ([0u8; 32], None);
    for i in 0..nout {
        if r.v()? != 0 {
            return Err(HkError::BadXmrTx); // RingCT outputs carry amount 0 in the clear
        }
        let tag = r.u8()?;
        let k = r.a32()?;
        let vt = match tag {
            0x02 => None,
            0x03 => Some(r.u8()?),
            _ => return Err(HkError::BadXmrTx),
        };
        if i == idx {
            out_key = k;
            view_tag = vt;
        }
    }
    let elen = r.v()? as usize;
    let extra = r.take(elen)?;
    let r_pub = tx_pub_key(extra).ok_or(HkError::BadXmrTx)?;
    let prefix_len = r.o;
    let t = r.u8()?;
    if t != 5 && t != 6 {
        return Err(HkError::BadXmrTx);
    }
    r.v()?; // fee
    let ecdh = r.take(8 * nout)?;
    let outpk = r.take(32 * nout)?;
    if !r.done() {
        return Err(HkError::BadXmrTx);
    }
    let mut enc = [0u8; 8];
    enc.copy_from_slice(&ecdh[8 * idx..8 * idx + 8]);
    let mut commit = [0u8; 32];
    commit.copy_from_slice(&outpk[32 * idx..32 * idx + 32]);
    Ok(Parsed { prefix_len, out_key, view_tag, r_pub, enc, commit })
}

/// The first tag-0x01 (tx public key) field of tx_extra. Walks padding (0x00), nonces (0x02)
/// and additional keys (0x04); stops at anything else.
pub fn tx_pub_key(extra: &[u8]) -> Option<[u8; 32]> {
    let mut x = Rd { b: extra, o: 0 };
    while x.o < extra.len() {
        match x.u8().ok()? {
            0x01 => return x.a32().ok(),
            0x02 => {
                let n = x.u8().ok()? as usize;
                x.take(n).ok()?;
            }
            0x04 => {
                let n = x.v().ok()? as usize;
                x.take(n.checked_mul(32)?).ok()?;
            }
            0x00 => {}
            _ => return None,
        }
    }
    None
}

/// Block header (major, minor, timestamp varints, prev id, nonce): must be exactly these fields.
pub fn check_header(h: &[u8]) -> Result<(), HkError> {
    let mut r = Rd { b: h, o: 0 };
    r.v().map_err(|_| HkError::BadInclusion)?;
    r.v().map_err(|_| HkError::BadInclusion)?;
    r.v().map_err(|_| HkError::BadInclusion)?;
    r.take(36).map_err(|_| HkError::BadInclusion)?;
    if !r.done() {
        return Err(HkError::BadInclusion);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The checks
// ---------------------------------------------------------------------------------------------

/// What the program requires of the Monero side, all from the escrow account.
#[derive(Clone, Debug)]
pub struct Statement<'a> {
    /// Shared spend key `B = claim_point + refund_point`.
    pub spend: [u8; 32],
    /// Shared view key `A = view_pub`.
    pub view: [u8; 32],
    /// The escrow's `xmr_amount` (piconero).
    pub min_amount: u64,
    /// The proof message: the escrow address as 64 lowercase hex characters.
    pub msg: &'a [u8],
}

/// A proof as submitted.
#[derive(Clone, Debug)]
pub struct ProofIn<'a> {
    pub kind: u8,
    /// prefix || RingCT base, exactly as serialized on the Monero chain.
    pub unprunable: &'a [u8],
    /// keccak of the prunable RingCT part (the BP+/CLSAG bytes stay off chain).
    pub prunable_hash: [u8; 32],
    pub out_index: u8,
    /// Shared secret `D` and the TXPROOF_V2 signature (c, z).
    pub d: [u8; 32],
    pub c: [u8; 32],
    pub z: [u8; 32],
    /// Block header (major, minor, timestamp, prev_id, nonce).
    pub header: &'a [u8],
    /// Number of transactions in the block, miner tx included.
    pub ntx: u32,
    /// Merkle path: depth x (sibling[32] || side u8), side 1 = our node is the right child.
    pub branch: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    pub txid: [u8; 32],
    pub out_key: [u8; 32],
    pub amount: u64,
    pub block_id: [u8; 32],
}

/// Everything except the canonical-chain fact (see the module docs).
pub fn verify<O: Ops>(o: &O, st: &Statement, p: &ProofIn) -> Result<Verified, HkError> {
    let t = parse_tx(p.unprunable, p.out_index as usize)?;
    let h0 = o.keccak(&[&p.unprunable[..t.prefix_len]]);
    let h1 = o.keccak(&[&p.unprunable[t.prefix_len..]]);
    let txid = o.keccak(&[&h0, &h1, &p.prunable_hash]);
    check_dleq(o, st, p.kind, &txid, &t.r_pub, &p.d, &p.c, &p.z)?;
    let amount = check_output(o, st, &t, p.out_index, &p.d)?;
    let block_id = fold_block_id(o, &txid, p.header, p.ntx, p.branch)?;
    Ok(Verified { txid, out_key: t.out_key, amount, block_id })
}

/// TXPROOF_V2 (crypto.cpp `check_tx_proof`, no subaddress, so the B slot is 32 zero bytes),
/// with `prefix_hash = keccak(txid || msg)` (wallet2 `check_tx_proof`).
///   OUT (sender, R = rG, D = rA):   X = zG + cR, Y = zA + cD, c == Hs(m||D||X||Y||sep||R||A||0)
///   IN  (receiver, A = vG, D = vR): X = zG + cA, Y = zR + cD, c == Hs(m||D||X||Y||sep||A||R||0)
pub fn check_dleq<O: Ops>(
    o: &O,
    st: &Statement,
    kind: u8,
    txid: &[u8; 32],
    r_pub: &[u8; 32],
    d: &[u8; 32],
    c: &[u8; 32],
    z: &[u8; 32],
) -> Result<(), HkError> {
    if !canonical(c) || !canonical(z) {
        return Err(HkError::BadXmrProof);
    }
    let (first, second) = match kind {
        KIND_OUT => (r_pub, &st.view),
        KIND_IN => (&st.view, r_pub),
        _ => return Err(HkError::BadXmrProof),
    };
    let m = o.keccak(&[txid, st.msg]);
    let x = o.msm2(z, &G, c, first).ok_or(HkError::BadXmrProof)?;
    let y = o.msm2(z, second, c, d).ok_or(HkError::BadXmrProof)?;
    let c2 = hs(o, &[&m, d, &x, &y, &TXPROOF_V2_SEP, first, second, &[0u8; 32]]);
    if c2 != *c {
        return Err(HkError::BadXmrProof);
    }
    Ok(())
}

/// The output pays the escrow, with a real amount of at least the minimum:
///   K = 8D, s = Hs(K || varint(i)), view tag == keccak("view_tag" || K || varint(i))[0],
///   P == s*G + B, a = enc XOR keccak("amount" || s)[..8], y = Hs("commitment_mask" || s),
///   C == y*G + a*H, a >= min. Returns `a`.
pub fn check_output<O: Ops>(o: &O, st: &Statement, t: &Parsed, idx: u8, d: &[u8; 32]) -> Result<u64, HkError> {
    let k = o.mul(&SCALAR_EIGHT, d).ok_or(HkError::BadXmrProof)?;
    let mut vb = [0u8; 10];
    let vl = varint(idx as u64, &mut vb);
    if let Some(vt) = t.view_tag {
        if o.keccak(&[b"view_tag", &k, &vb[..vl]])[0] != vt {
            return Err(HkError::WrongOutput);
        }
    }
    let s = hs(o, &[&k, &vb[..vl]]);
    if o.msm2(&s, &G, &SCALAR_ONE, &st.spend).ok_or(HkError::WrongOutput)? != t.out_key {
        return Err(HkError::WrongOutput);
    }
    let mask = o.keccak(&[b"amount", &s]);
    let mut a8 = [0u8; 8];
    for i in 0..8 {
        a8[i] = t.enc[i] ^ mask[i];
    }
    let amount = u64::from_le_bytes(a8);
    let y = hs(o, &[b"commitment_mask", &s]);
    let mut a_scalar = [0u8; 32];
    a_scalar[..8].copy_from_slice(&a8);
    if o.msm2(&y, &G, &a_scalar, &H).ok_or(HkError::BadAmount)? != t.commit {
        return Err(HkError::BadAmount);
    }
    if amount < st.min_amount {
        return Err(HkError::AmountTooLow);
    }
    Ok(amount)
}

/// Fold the Merkle path from `txid` to the tree root (Monero `tree_hash`: plain keccak of the
/// two children), then the block id: `keccak(varint(|hb|) || hb)` with
/// `hb = header || root || varint(ntx)`.
pub fn fold_block_id<O: Ops>(o: &O, txid: &[u8; 32], header: &[u8], ntx: u32, branch: &[u8]) -> Result<[u8; 32], HkError> {
    check_header(header)?;
    if branch.len() % 33 != 0 || branch.len() / 33 > MAX_DEPTH || ntx < 2 {
        return Err(HkError::BadInclusion); // >= 2: the miner tx plus ours
    }
    let mut h = *txid;
    for step in branch.chunks_exact(33) {
        let sib = &step[..32];
        h = match step[32] {
            0 => o.keccak(&[&h, sib]),
            1 => o.keccak(&[sib, &h]),
            _ => return Err(HkError::BadInclusion),
        };
    }
    let mut nb = [0u8; 10];
    let nl = varint(ntx as u64, &mut nb);
    let mut lb = [0u8; 10];
    let ll = varint((header.len() + 32 + nl) as u64, &mut lb);
    Ok(o.keccak(&[&lb[..ll], header, &h, &nb[..nl]]))
}

/// The proof message for an escrow: its address as 64 lowercase hex characters (what the
/// maker passes as `message` to wallet-rpc `get_tx_proof`).
pub fn escrow_msg(escrow: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut m = [0u8; 64];
    for (i, b) in escrow.iter().enumerate() {
        m[2 * i] = HEX[(b >> 4) as usize];
        m[2 * i + 1] = HEX[(b & 15) as usize];
    }
    m
}
