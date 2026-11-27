//! HALFKEY v1.5: on-chain Monero payment proofs.
//!
//! The claim rule (`claim_gate`): every SOL->XMR escrow (swap, OTC tranche, pay link, cashout
//! vault), and any XMR->SOL escrow locked with `F_PROOF`, can be claimed only after the locker's
//! `ready` or against a payment proof that this program verified (`prove_lock`). There is no
//! claim at `t0` on the claimer's word any more: a maker that never delivers can never claim, and
//! the locker gets everything back at `t1` whether or not anyone aborted. The proof says: the Monero transaction pays at
//! least the escrow's `xmr_amount` to the escrow's own shared address (spend key
//! `claim_point + refund_point`, view key `view_pub`), with no time lock, and it is in a
//! Monero block that a k-of-n committee attested as canonical with at least 10 confirmations.
//!
//! Trust, stated plainly:
//!  * checked here, by this program: the transaction bytes and txid, the TXPROOF_V2 DLEQ, the
//!    output key, the view tag, the amount against its Pedersen commitment, the minimum,
//!    `unlock_time == 0`, the Merkle path to the block id (`xmr.rs`);
//!  * resting on the committee: that the attested block is in the canonical Monero chain and
//!    10 deep (Monero's RandomX proof of work cannot be checked on chain);
//!  * watchtowers (and the locker) can still abort before `t0`: no longer needed for safety, only
//!    to refund early; with a watchtower online, stealing needs the committee to lie AND the
//!    watchtower to miss it.
//!
//! Accounts:
//!   ["attesters"]                       the committee: up to 7 ed25519 keys, threshold, network,
//!                                       minimum confirmations, epoch (bumped on every change)
//!   ["xmrhdr", epoch u64 LE, block_id]  a Monero block attested under that epoch
//!   ["xmrout", escrow, created_at]      the proof record of one escrow instance; the lock time is
//!                                       in the seed, so a reused escrow address gets a fresh slot
//!                                       and a "twin" escrow with the same shared key writes its
//!                                       own record instead of blocking the honest one

use crate::xmr::{self, ProofIn, Statement, Syscalls};
use crate::*;

pub const ATTESTERS_SEED: &[u8] = b"attesters";
pub const XHDR_SEED: &[u8] = b"xmrhdr";
pub const XOUT_SEED: &[u8] = b"xmrout";

pub const DISC_ATTESTERS: u8 = 0xAE;
pub const DISC_XHDR: u8 = 0x8D;
pub const DISC_XPROOF: u8 = 0x9F;

pub const ATTESTERS_LEN: usize = 248;
pub const XHDR_LEN: usize = 104;
pub const XPROOF_LEN: usize = 176;

pub const MAX_ATTESTERS: usize = 7;
/// Monero's spendable age (CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE): the floor for `min_conf`.
pub const MIN_XMR_CONF: u32 = 10;
/// Monero network types (cryptonote_config.h): MAINNET 0, TESTNET 1, STAGENET 2.
pub const MAX_NET: u8 = 2;
/// What an attester signs: prefix || net u8 || height u64 LE || block_id 32 || confirmations u32 LE.
pub const HEADER_MSG_PREFIX: &[u8] = b"halfkey-xmr-header-v1";
pub const HEADER_MSG_LEN: usize = 21 + 1 + 8 + 32 + 4;

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attesters {
    pub bump: u8,
    pub net: u8,
    pub threshold: u8,
    pub n: u8,
    pub epoch: u64,
    pub min_conf: u32,
    pub keys: [[u8; 32]; MAX_ATTESTERS],
}

impl Attesters {
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!(d.len() == ATTESTERS_LEN && d[0] == DISC_ATTESTERS, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let bump = r.u8()?;
        let net = r.u8()?;
        let threshold = r.u8()?;
        let n = r.u8()?;
        r.skip(2)?;
        let epoch = r.u64()?;
        let min_conf = r.u32()?;
        r.skip(4)?;
        let mut keys = [[0u8; 32]; MAX_ATTESTERS];
        for k in keys.iter_mut() {
            *k = r.b32()?;
        }
        req!(n as usize <= MAX_ATTESTERS, HkError::BadAccount);
        Ok(Self { bump, net, threshold, n, epoch, min_conf, keys })
    }
    pub fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_ATTESTERS);
        w.u8(1);
        w.u8(self.bump);
        w.u8(self.net);
        w.u8(self.threshold);
        w.u8(self.n);
        w.pad(2);
        w.u64(self.epoch);
        w.u32(self.min_conf);
        w.pad(4);
        for k in self.keys.iter() {
            w.put(k);
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XHeader {
    pub bump: u8,
    pub net: u8,
    pub epoch: u64,
    pub height: u64,
    pub confirmations: u32,
    pub attested_at: i64,
    pub block_id: [u8; 32],
    pub payer: Pubkey,
}

impl XHeader {
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!(d.len() == XHDR_LEN && d[0] == DISC_XHDR, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let bump = r.u8()?;
        let net = r.u8()?;
        r.skip(4)?;
        let epoch = r.u64()?;
        let height = r.u64()?;
        let confirmations = r.u32()?;
        r.skip(4)?;
        Ok(Self { bump, net, epoch, height, confirmations, attested_at: r.i64()?, block_id: r.b32()?, payer: r.key()? })
    }
    pub fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_XHDR);
        w.u8(1);
        w.u8(self.bump);
        w.u8(self.net);
        w.pad(4);
        w.u64(self.epoch);
        w.u64(self.height);
        w.u32(self.confirmations);
        w.pad(4);
        w.i64(self.attested_at);
        w.put(&self.block_id);
        w.put(self.payer.as_ref());
    }
}

/// The on-chain receipt of a verified Monero payment.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProofRec {
    pub bump: u8,
    pub kind: u8,
    pub out_index: u8,
    pub escrow: Pubkey,
    /// The escrow's lock time, so a record cannot be reused for a later escrow at the same
    /// (reusable) address (addresses free up at close; a fresh lock has a new `created_at`).
    pub escrow_created: i64,
    /// Piconero, decoded from the output and proven against its commitment.
    pub amount: u64,
    pub proven_at: i64,
    pub height: u64,
    pub epoch: u64,
    pub txid: [u8; 32],
    pub block_id: [u8; 32],
    pub out_key: [u8; 32],
}

impl ProofRec {
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!(d.len() == XPROOF_LEN && d[0] == DISC_XPROOF, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let bump = r.u8()?;
        let kind = r.u8()?;
        let out_index = r.u8()?;
        r.skip(3)?;
        Ok(Self {
            bump,
            kind,
            out_index,
            escrow: r.key()?,
            escrow_created: r.i64()?,
            amount: r.u64()?,
            proven_at: r.i64()?,
            height: r.u64()?,
            epoch: r.u64()?,
            txid: r.b32()?,
            block_id: r.b32()?,
            out_key: r.b32()?,
        })
    }
    pub fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_XPROOF);
        w.u8(1);
        w.u8(self.bump);
        w.u8(self.kind);
        w.u8(self.out_index);
        w.pad(3);
        w.put(self.escrow.as_ref());
        w.i64(self.escrow_created);
        w.u64(self.amount);
        w.i64(self.proven_at);
        w.u64(self.height);
        w.u64(self.epoch);
        w.put(&self.txid);
        w.put(&self.block_id);
        w.put(&self.out_key);
    }
}

// ---------------------------------------------------------------------------------------------
// Pure rules (Kani: proofs_v15.rs)
// ---------------------------------------------------------------------------------------------

/// `set_attesters`: 1 <= threshold <= n <= 7, distinct non-zero keys, a known network, and at
/// least Monero's 10-block spendable age.
pub fn check_attesters(net: u8, threshold: u8, n: u8, min_conf: u32, keys: &[[u8; 32]]) -> Result<(), HkError> {
    if !(n >= 1 && n as usize <= MAX_ATTESTERS && keys.len() == n as usize) {
        return Err(HkError::BadParam);
    }
    if !(threshold >= 1 && threshold <= n) {
        return Err(HkError::BadParam);
    }
    if net > MAX_NET || min_conf < MIN_XMR_CONF {
        return Err(HkError::BadParam);
    }
    for i in 0..keys.len() {
        if keys[i] == [0u8; 32] {
            return Err(HkError::BadParam);
        }
        for j in 0..i {
            if keys[i] == keys[j] {
                return Err(HkError::BadParam);
            }
        }
    }
    Ok(())
}

/// The message an attester signs for a Monero block.
pub fn header_msg(net: u8, height: u64, block_id: &[u8; 32], confirmations: u32) -> [u8; HEADER_MSG_LEN] {
    let mut m = [0u8; HEADER_MSG_LEN];
    m[..21].copy_from_slice(HEADER_MSG_PREFIX);
    m[21] = net;
    m[22..30].copy_from_slice(&height.to_le_bytes());
    m[30..62].copy_from_slice(block_id);
    m[62..66].copy_from_slice(&confirmations.to_le_bytes());
    m
}

/// Parse an Ed25519 precompile instruction carrying several signatures. Every entry must point
/// inside this same instruction, sign exactly `msg`, and be by one of `keys`, each key at most
/// once. Returns the bitmask of the keys that signed. (The precompile verifies every signature;
/// the transaction fails if one does not verify.)
pub fn ed25519_signers(d: &[u8], keys: &[[u8; 32]], msg: &[u8]) -> Result<u8, HkError> {
    if d.len() < 2 || keys.len() > 8 {
        return Err(HkError::NotAttested);
    }
    let num = d[0] as usize;
    if num == 0 || num > keys.len() {
        return Err(HkError::NotAttested);
    }
    let table_end = 2 + 14 * num;
    if d.len() < table_end {
        return Err(HkError::NotAttested);
    }
    let u = |i: usize| u16::from_le_bytes([d[i], d[i + 1]]);
    let mut mask = 0u8;
    for e in 0..num {
        let b = 2 + 14 * e;
        let (sig_off, sig_ix, pk_off, pk_ix, msg_off, msg_len, msg_ix) =
            (u(b) as usize, u(b + 2), u(b + 4) as usize, u(b + 6), u(b + 8) as usize, u(b + 10) as usize, u(b + 12));
        if !(sig_ix == u16::MAX && pk_ix == u16::MAX && msg_ix == u16::MAX) {
            return Err(HkError::NotAttested);
        }
        if !(sig_off + 64 <= d.len() && pk_off + 32 <= d.len() && msg_off + msg_len <= d.len()) {
            return Err(HkError::NotAttested);
        }
        if d[msg_off..msg_off + msg_len] != *msg {
            return Err(HkError::NotAttested);
        }
        let pk = &d[pk_off..pk_off + 32];
        let j = keys.iter().position(|k| k[..] == *pk).ok_or(HkError::NotAttested)?;
        if mask & (1u8 << j) != 0 {
            return Err(HkError::NotAttested);
        }
        mask |= 1u8 << j;
    }
    Ok(mask)
}

/// Whether a claim of this escrow needs the locker's Ready or a payment proof: every SOL->XMR
/// escrow, and XMR->SOL escrows locked in proof mode. XMR kinds only: the hash-locked SOL<->ZEC
/// kind (directions 4/8, `htlc.rs`) settles on the preimage of its hashlock, lives in its own
/// accounts and its own claim instruction, and never reaches this gate; it is `false` for those
/// directions (and any other) so the rule cannot be read as covering them.
pub fn proof_gated(direction: u8, flags: u8) -> bool {
    match direction {
        DIR_SOL_TO_XMR => true,
        DIR_XMR_TO_SOL => flags & F_PROOF != 0,
        _ => false,
    }
}

/// Whether the immutable lock terms allow a committee-backed proof instead of Ready.
pub fn proof_allowed(direction: u8, flags: u8) -> bool {
    proof_gated(direction, flags) && flags & F_READY_ONLY == 0
}

/// `prove_lock` window: a proof-gated escrow that is still open (Locked or Ready), before t1.
pub fn prove_window(direction: u8, flags: u8, state: u8, t: i64, t1: i64) -> Result<(), HkError> {
    if !proof_allowed(direction, flags) {
        return Err(HkError::BadState);
    }
    // A direct-payout escrow pays the user's own address, not `claim_point + refund_point`: it is
    // proven only by `direct::prove_direct` (which also checks the payment id).
    if flags & F_DIRECT != 0 {
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

/// The attested header a proof is checked against: current epoch and network, enough
/// confirmations, and the block id the proof folded to.
pub fn header_matches(h: &XHeader, a: &Attesters, block_id: &[u8; 32]) -> Result<(), HkError> {
    if !(h.epoch == a.epoch && h.net == a.net && h.confirmations >= a.min_conf && h.block_id == *block_id) {
        return Err(HkError::NotAttested);
    }
    Ok(())
}

/// The statement for an escrow, read from the escrow account only: spend key `B` (the sum
/// of the two halves, computed by `add`), view key, minimum amount, and the message (escrow
/// address). A prover chooses none of these.
pub fn statement_for<'a, F>(e: &Escrow, msg: &'a [u8; 64], add: F) -> Result<Statement<'a>, HkError>
where
    F: FnOnce(&[u8; 32], &[u8; 32]) -> Option<[u8; 32]>,
{
    let spend = add(&e.claim_point, &e.refund_point).ok_or(HkError::BadPoint)?;
    Ok(Statement { spend, view: e.view_pub, min_amount: e.xmr_amount, msg })
}

/// `claim` gate (after `claim_window`): a proof-gated escrow that the locker did not mark Ready
/// claims only with a proof record of THIS escrow for at least its amount.
pub fn claim_gate(e: &Escrow, escrow_key: &Pubkey, rec: Option<&ProofRec>) -> Result<(), HkError> {
    if !proof_gated(e.direction, e.flags) || e.state == ST_READY {
        return Ok(());
    }
    if e.flags & F_READY_ONLY != 0 {
        return Err(HkError::NotProven);
    }
    match rec {
        Some(r) if r.escrow == *escrow_key && r.escrow_created == e.created_at && r.amount >= e.xmr_amount => Ok(()),
        _ => Err(HkError::NotProven),
    }
}

// ---------------------------------------------------------------------------------------------
// Account loading
// ---------------------------------------------------------------------------------------------

pub fn attesters_pda(pid: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[ATTESTERS_SEED], pid)
}

pub(crate) fn load_attesters(a: &AccountInfo, pid: &Pubkey) -> Result<Attesters, ProgramError> {
    owned(a, pid)?;
    let s = Attesters::load(&a.try_borrow_data()?)?;
    let k = Pubkey::create_program_address(&[ATTESTERS_SEED, &[s.bump]], pid).map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(s)
}

pub(crate) fn load_header(a: &AccountInfo, pid: &Pubkey) -> Result<XHeader, ProgramError> {
    owned(a, pid)?;
    let h = XHeader::load(&a.try_borrow_data()?)?;
    let k = Pubkey::create_program_address(&[XHDR_SEED, &h.epoch.to_le_bytes(), &h.block_id, &[h.bump]], pid)
        .map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(h)
}

/// A proof record, checked against its PDA (so only `prove_lock` can have written it). The PDA is
/// seeded by the escrow and its lock time: one record per escrow instance.
/// The escrow terms a proof record is bound to (its PDA seed): the two key halves and the view
/// key, i.e. the Monero address the proven output had to pay. A record therefore belongs to one
/// escrow instance AND its terms: an escrow closed and re-locked at the same address in the same
/// second with other keys gets its own record slot and cannot use the old one.
pub fn proof_terms(e: &Escrow) -> [u8; 32] {
    let mut m = Vec::with_capacity(PROOF_TERMS_PREFIX.len() + 96);
    m.extend_from_slice(PROOF_TERMS_PREFIX);
    m.extend_from_slice(&e.claim_point);
    m.extend_from_slice(&e.refund_point);
    m.extend_from_slice(&e.view_pub);
    // Final round: a direct-payout escrow's record proves a payment to another statement (the
    // payee's own address), so it lives under other seeds: a v1.5 record of an earlier instance
    // with the same three points can never pass for it, nor the reverse. v1 seeds unchanged.
    if e.flags & F_DIRECT != 0 {
        m.push(F_DIRECT);
    }
    solana_sha256_hasher::hash(&m).to_bytes()
}
pub const PROOF_TERMS_PREFIX: &[u8] = b"halfkey-proof-terms-v1";

/// Load the proof record of the escrow instance `e` at `escrow_key`: owner, layout, and the PDA
/// re-derived from the record's escrow, lock time and bump plus `e`'s terms.
pub fn load_proof(a: &AccountInfo, pid: &Pubkey, e: &Escrow) -> Result<ProofRec, ProgramError> {
    owned(a, pid)?;
    let p = ProofRec::load(&a.try_borrow_data()?)?;
    let terms = proof_terms(e);
    let k = Pubkey::create_program_address(&[XOUT_SEED, p.escrow.as_ref(), &p.escrow_created.to_le_bytes(), &terms, &[p.bump]], pid)
        .map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(p)
}

// ---------------------------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------------------------

/// Accounts: [admin (signer, w), config, attesters (w), system].
/// Data: net u8, threshold u8, min_conf u32, n u8, n x key[32].
/// Creates or replaces the committee; every call bumps the epoch, so headers attested under an
/// earlier set stop counting for new proofs (recorded proofs stand).
pub(crate) fn set_attesters(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let admin = next_account_info(it)?;
    let config = next_account_info(it)?;
    let att = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(admin)?;
    writable(att)?;
    let net = r.u8()?;
    let threshold = r.u8()?;
    let min_conf = r.u32()?;
    let n = r.u8()?;
    req!(n as usize <= MAX_ATTESTERS, HkError::BadParam);
    let mut keys = [[0u8; 32]; MAX_ATTESTERS];
    for k in keys.iter_mut().take(n as usize) {
        *k = r.b32()?;
    }
    r.done()?;
    let c = load_config(config, pid)?;
    req!(c.admin == *admin.key, HkError::Unauthorized);
    check_attesters(net, threshold, n, min_conf, &keys[..n as usize])?;
    let (ak, ab) = attesters_pda(pid);
    req!(ak == *att.key, HkError::BadPda);
    let epoch = if att.data_len() == 0 {
        create_pda(admin, att, system, pid, ATTESTERS_LEN, &[ATTESTERS_SEED, &[ab]])?;
        1
    } else {
        add(load_attesters(att, pid)?.epoch, 1)?
    };
    Attesters { bump: ab, net, threshold, n, epoch, min_conf, keys }.store(&mut att.try_borrow_mut_data()?);
    msg!("halfkey: attesters epoch {} ({} of {})", epoch, threshold, n);
    Ok(())
}

/// Accounts: [payer (signer, w), attesters, header (w), system, instructions sysvar].
/// Data: height u64, block_id 32, confirmations u32.
/// The instruction right before must be an Ed25519 precompile carrying signatures of at least
/// `threshold` distinct attesters over `header_msg`. Anyone may submit (it is a fact about
/// Monero, the same for every swap); the payer funds the header account.
pub(crate) fn attest_header(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let payer = next_account_info(it)?;
    let att = next_account_info(it)?;
    let hdr = next_account_info(it)?;
    let system = next_account_info(it)?;
    let ixs = next_account_info(it)?;
    signer(payer)?;
    writable(hdr)?;
    let height = r.u64()?;
    let block_id = r.b32()?;
    let confirmations = r.u32()?;
    r.done()?;
    let a = load_attesters(att, pid)?;
    req!(confirmations >= a.min_conf, HkError::NotAttested);
    let msg = header_msg(a.net, height, &block_id, confirmations);
    req!(*ixs.key == SYSVAR_INSTRUCTIONS, HkError::BadAccount);
    let cur = load_current_index_checked(ixs)? as usize;
    req!(cur > 0, HkError::NotAttested);
    let ix = load_instruction_at_checked(cur - 1, ixs)?;
    req!(ix.program_id == ED25519_PROGRAM, HkError::NotAttested);
    let mask = ed25519_signers(&ix.data, &a.keys[..a.n as usize], &msg)?;
    req!(mask.count_ones() >= a.threshold as u32, HkError::NotAttested);
    let ep = a.epoch.to_le_bytes();
    let (hk, hb) = Pubkey::find_program_address(&[XHDR_SEED, &ep, &block_id], pid);
    req!(hk == *hdr.key, HkError::BadPda);
    create_pda(payer, hdr, system, pid, XHDR_LEN, &[XHDR_SEED, &ep, &block_id, &[hb]])?;
    XHeader { bump: hb, net: a.net, epoch: a.epoch, height, confirmations, attested_at: now()?, block_id, payer: *payer.key }
        .store(&mut hdr.try_borrow_mut_data()?);
    msg!("halfkey: monero block {} attested ({} sigs, {} conf)", height, mask.count_ones(), confirmations);
    Ok(())
}

/// Accounts: [payer (signer, w), escrow, attesters, header, proof (w), system].
/// Data: kind u8, n u16, unprunable[n], prunable_hash 32, out_index u8, D 32, c 32, z 32,
///       hl u8, header[hl], ntx u32, depth u8, depth x (sibling 32 || side u8).
/// Verifies the Monero payment proof against the escrow (xmr.rs) and the attested header, and
/// records it in ["xmrout", escrow, created_at]. Permissionless: a proof is a proof, whoever sends it.
pub(crate) fn prove_lock(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let payer = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let att = next_account_info(it)?;
    let hdr = next_account_info(it)?;
    let proof = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(payer)?;
    writable(proof)?;
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

    let e = load_escrow(escrow, pid)?;
    let t = now()?;
    prove_window(e.direction, e.flags, e.state, t, e.t1)?;
    let a = load_attesters(att, pid)?;
    let h = load_header(hdr, pid)?;

    let m = xmr::escrow_msg(&escrow.key.to_bytes());
    let st = statement_for(&e, &m, |p, q| add_edwards(&PodEdwardsPoint(*p), &PodEdwardsPoint(*q)).map(|x| x.0))?;
    let p = ProofIn { kind, unprunable, prunable_hash, out_index, d, c, z, header, ntx, branch };
    let v = xmr::verify(&Syscalls, &st, &p)?;
    header_matches(&h, &a, &v.block_id)?;

    // One record per escrow instance (escrow + its lock time). A twin escrow with the same shared
    // key writes its own record, never the honest escrow's; a reused address gets a fresh slot.
    // ... and its terms (proof_terms), so a same-second re-lock at a reused address with other keys
    // cannot inherit this record.
    let ec = e.created_at.to_le_bytes();
    let terms = proof_terms(&e);
    let (pk, pb) = Pubkey::find_program_address(&[XOUT_SEED, escrow.key.as_ref(), &ec, &terms], pid);
    req!(pk == *proof.key, HkError::BadPda);
    create_pda(payer, proof, system, pid, XPROOF_LEN, &[XOUT_SEED, escrow.key.as_ref(), &ec, &terms, &[pb]])?;
    ProofRec {
        bump: pb,
        kind,
        out_index,
        escrow: *escrow.key,
        escrow_created: e.created_at,
        amount: v.amount,
        proven_at: t,
        height: h.height,
        epoch: h.epoch,
        txid: v.txid,
        block_id: v.block_id,
        out_key: v.out_key,
    }
    .store(&mut proof.try_borrow_mut_data()?);
    msg!("halfkey: monero payment proven ({} piconero, block {})", v.amount, h.height);
    Ok(())
}
