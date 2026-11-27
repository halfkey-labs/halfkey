//! Direct-pay proofs (final round): a Monero payment to someone's OWN standard address, proven on
//! chain, released only for one specific escrow or offer fill.
//!
//! The v1.5 proof (`xmr::verify`: txid, TXPROOF_V2 DLEQ, output key, view tag, amount against its
//! commitment, `unlock_time == 0`, Merkle path; block attested by the committee) is checked
//! against the payee's address `(B, A)` instead of a 2-of-2 shared key. Because anyone may have
//! paid that address before, two more checks bind the payment to this release:
//!
//! 1. **Payment id.** The transaction's first tx_extra nonce must be an encrypted payment id
//!    (`02 09 01 <8 bytes>`, what wallets write for an integrated address) that decrypts, with
//!    the proven shared secret (`K = 8D`, Monero's `encrypt_payment_id`), to this release's id:
//!    `sha256(domain || escrow-or-offer || created_at || fill_seq)[..8]`. It exists only once the
//!    escrow or the reservation does, so no older payment can carry it.
//! 2. **One output, one release.** Each proven output key creates ["xmrused", out_key]: an output
//!    backs at most one escrow or offer fill, whatever the payment ids.
//!
//! Subaddresses cannot be paid this way (an integrated address is built on a standard address,
//! and the proof checks the standard derivation): clients refuse them before quoting.
//!
//! `prove_direct` (tag 46, anyone) writes the same proof record `claim_gate` reads, for a
//! direct-payout escrow (`F_DIRECT`); `prove_lock` refuses those (`zkproof::prove_window`).

use crate::xmr::{self, Ops, ProofIn, Statement, Syscalls, SCALAR_EIGHT};
use crate::zkproof::{self, ProofRec, XOUT_SEED, XPROOF_LEN};
use crate::*;

pub const XUSED_SEED: &[u8] = b"xmrused";
pub const DISC_XUSED: u8 = 0x9E;
pub const XUSED_LEN: usize = 48;
pub const PID_DOMAIN_ESCROW: &[u8] = b"halfkey-pid-v1";
pub const PID_DOMAIN_OFFER: &[u8] = b"halfkey-offer-pid-v1";
/// Monero's ENCRYPTED_PAYMENT_ID_TAIL.
pub const PID_TAIL: u8 = 0x8d;
pub const KIND_ESCROW: u8 = 1;
pub const KIND_OFFER: u8 = 2;

/// The payment id of one release: `sha256(domain || key || created_at || seq || who)[..8]`
/// (`who`: an offer fill's filler, so a payment made before one's own reservation landed can
/// never be credited to someone else's; empty for an escrow).
pub fn pid_for(domain: &[u8], key: &[u8; 32], created_at: i64, seq: u64, who: &[u8]) -> [u8; 8] {
    let h = solana_sha256_hasher::hashv(&[domain, key, &created_at.to_le_bytes(), &seq.to_le_bytes(), who]).to_bytes();
    let mut p = [0u8; 8];
    p.copy_from_slice(&h[..8]);
    p
}

struct Rd2<'a> {
    b: &'a [u8],
    o: usize,
}
impl<'a> Rd2<'a> {
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
    /// Varint, the same rule as `xmr.rs` (at most 10 bytes, no bits past 64).
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
}

/// tx_extra of a serialized transaction prefix (the walk of `xmr::parse_tx` up to the extra;
/// `xmr::verify` has already accepted the same bytes).
pub fn tx_extra(u: &[u8]) -> Result<&[u8], HkError> {
    let mut r = Rd2 { b: u, o: 0 };
    r.v()?; // version
    r.v()?; // unlock_time
    let nin = r.v()?;
    for _ in 0..nin {
        if r.u8()? != 0x02 {
            return Err(HkError::BadXmrTx);
        }
        r.v()?;
        let k = r.v()?;
        for _ in 0..k {
            r.v()?;
        }
        r.take(32)?;
    }
    let nout = r.v()? as usize;
    if nout > xmr::MAX_OUTPUTS {
        return Err(HkError::BadXmrTx);
    }
    for _ in 0..nout {
        r.v()?;
        let tag = r.u8()?;
        r.take(32)?;
        match tag {
            0x02 => {}
            0x03 => {
                r.u8()?;
            }
            _ => return Err(HkError::BadXmrTx),
        }
    }
    let elen = r.v()? as usize;
    r.take(elen)
}

/// The encrypted payment id: the first nonce field (tag 0x02) of tx_extra, which must be exactly
/// `09 01 <8 bytes>`. The walk is `xmr::tx_pub_key`'s (padding, tx key, nonce, additional keys;
/// anything else ends it).
pub fn encrypted_pid(extra: &[u8]) -> Result<[u8; 8], HkError> {
    let mut x = Rd2 { b: extra, o: 0 };
    while x.o < extra.len() {
        match x.u8().map_err(|_| HkError::BadPaymentId)? {
            0x00 => {}
            0x01 => {
                x.take(32).map_err(|_| HkError::BadPaymentId)?;
            }
            0x02 => {
                let n = x.u8().map_err(|_| HkError::BadPaymentId)? as usize;
                let nonce = x.take(n).map_err(|_| HkError::BadPaymentId)?;
                if n != 9 || nonce[0] != 0x01 {
                    return Err(HkError::BadPaymentId);
                }
                let mut p = [0u8; 8];
                p.copy_from_slice(&nonce[1..]);
                return Ok(p);
            }
            0x04 => {
                let n = x.v().map_err(|_| HkError::BadPaymentId)? as usize;
                x.take(n.checked_mul(32).ok_or(HkError::BadPaymentId)?).map_err(|_| HkError::BadPaymentId)?;
            }
            _ => return Err(HkError::BadPaymentId),
        }
    }
    Err(HkError::BadPaymentId)
}

/// `enc XOR keccak(8D || 0x8d)[..8] == pid` (Monero `encrypt_payment_id` with the derivation the
/// DLEQ proved).
pub fn check_pid<O: Ops>(o: &O, d: &[u8; 32], enc: &[u8; 8], pid: &[u8; 8]) -> Result<(), HkError> {
    let k = o.mul(&SCALAR_EIGHT, d).ok_or(HkError::BadXmrProof)?;
    let mask = o.keccak(&[&k, &[PID_TAIL]]);
    for i in 0..8 {
        if enc[i] ^ mask[i] != pid[i] {
            return Err(HkError::BadPaymentId);
        }
    }
    Ok(())
}

/// The v1.5 checks against `st` plus the payment id.
pub fn verify_direct<O: Ops>(o: &O, st: &Statement, p: &ProofIn, pid: &[u8; 8]) -> Result<xmr::Verified, HkError> {
    let v = xmr::verify(o, st, p)?;
    let enc = encrypted_pid(tx_extra(p.unprunable)?)?;
    check_pid(o, &p.d, &enc, pid)?;
    Ok(v)
}

/// The proof payload, laid out as `prove_lock`'s data.
pub(crate) fn read_proof<'a>(r: &mut Rd<'a>) -> Result<ProofIn<'a>, ProgramError> {
    let kind = r.u8()?;
    let n = r.u16()? as usize;
    let unprunable = r.take(n)?;
    let prunable_hash = r.b32()?;
    let out_index = r.u8()?;
    let d = r.b32()?;
    let c = r.b32()?;
    let z = r.b32()?;
    let hl = r.u8()? as usize;
    let header = r.take(hl)?;
    let ntx = r.u32()?;
    let depth = r.u8()? as usize;
    let branch = r.take(depth.checked_mul(33).ok_or(HkError::BadInstruction)?)?;
    r.done()?;
    Ok(ProofIn { kind, unprunable, prunable_hash, out_index, d, c, z, header, ntx, branch })
}

/// Verify a direct payment against the attested header and burn its output key.
/// Accounts read from `it`: attesters, header, used marker (w). Returns the verified payment and
/// the header's height and epoch.
pub(crate) fn prove_and_burn<'a, 'b>(
    pid: &Pubkey,
    payer: &'b AccountInfo<'a>,
    system: &'b AccountInfo<'a>,
    att: &'b AccountInfo<'a>,
    hdr: &'b AccountInfo<'a>,
    used: &'b AccountInfo<'a>,
    st: &Statement,
    p: &ProofIn,
    release_pid: &[u8; 8],
    kind: u8,
    by: &Pubkey,
) -> Result<(xmr::Verified, u64, u64), ProgramError> {
    writable(used)?;
    let a = zkproof::load_attesters(att, pid)?;
    let h = zkproof::load_header(hdr, pid)?;
    let v = verify_direct(&Syscalls, st, p, release_pid)?;
    zkproof::header_matches(&h, &a, &v.block_id)?;
    let (uk, ub) = Pubkey::find_program_address(&[XUSED_SEED, &v.out_key], pid);
    req!(uk == *used.key, HkError::BadPda);
    // Fails (AlreadyInitialized) if this output already backed a release.
    create_pda(payer, used, system, pid, XUSED_LEN, &[XUSED_SEED, &v.out_key, &[ub]])?;
    {
        let mut d = used.try_borrow_mut_data()?;
        let mut w = Wr::new(&mut d);
        w.u8(DISC_XUSED);
        w.u8(1);
        w.u8(kind);
        w.u8(ub);
        w.pad(4);
        w.put(by.as_ref());
        w.i64(now()?);
    }
    Ok((v, h.height, h.epoch))
}

/// `prove_direct` window: an open (Locked/Ready) direct-payout escrow, before t1.
pub fn direct_prove_window(flags: u8, state: u8, t: i64, t1: i64) -> Result<(), HkError> {
    if flags & F_DIRECT == 0 {
        return Err(HkError::BadState);
    }
    if !(state == ST_LOCKED || state == ST_READY) {
        return Err(HkError::BadState);
    }
    if !(t < t1) {
        return Err(HkError::TooLate);
    }
    Ok(())
}

/// Accounts: [payer (signer, w), escrow, attesters, header, proof (w), used marker (w), system].
/// Data: the `prove_lock` payload. Verifies that the Monero transaction pays the escrow's payout
/// address (`refund_point`, `view_pub`) at least `xmr_amount` with this escrow's payment id, and
/// records it in the escrow instance's proof record (the one `claim_gate` reads).
pub(crate) fn prove_direct(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let payer = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let att = next_account_info(it)?;
    let hdr = next_account_info(it)?;
    let proof = next_account_info(it)?;
    let used = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(payer)?;
    writable(proof)?;
    let p = read_proof(r)?;
    let e = load_escrow(escrow, pid)?;
    let t = now()?;
    direct_prove_window(e.flags, e.state, t, e.t1)?;
    let m = xmr::escrow_msg(&escrow.key.to_bytes());
    let st = Statement { spend: e.refund_point, view: e.view_pub, min_amount: e.xmr_amount, msg: &m };
    let rp = pid_for(PID_DOMAIN_ESCROW, &escrow.key.to_bytes(), e.created_at, 0, &[]);
    let (v, height, epoch) = prove_and_burn(pid, payer, system, att, hdr, used, &st, &p, &rp, KIND_ESCROW, escrow.key)?;
    let ec = e.created_at.to_le_bytes();
    let terms = zkproof::proof_terms(&e);
    let (pk, pb) = Pubkey::find_program_address(&[XOUT_SEED, escrow.key.as_ref(), &ec, &terms], pid);
    req!(pk == *proof.key, HkError::BadPda);
    create_pda(payer, proof, system, pid, XPROOF_LEN, &[XOUT_SEED, escrow.key.as_ref(), &ec, &terms, &[pb]])?;
    ProofRec {
        bump: pb,
        kind: p.kind,
        out_index: p.out_index,
        escrow: *escrow.key,
        escrow_created: e.created_at,
        amount: v.amount,
        proven_at: t,
        height,
        epoch,
        txid: v.txid,
        block_id: v.block_id,
        out_key: v.out_key,
    }
    .store(&mut proof.try_borrow_mut_data()?);
    msg!("halfkey: direct payment proven ({} piconero, block {})", v.amount, height);
    Ok(())
}
