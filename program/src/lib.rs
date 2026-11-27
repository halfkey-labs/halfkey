//! HALFKEY: the Solana side of a trustless SOL <-> XMR atomic swap.
//!
//! Clean-room implementation. AthanorLabs `docs/protocol.md` and Suture's SECURITY.md were read as
//! the spec only; no code was copied.
//!
//! One escrow, two directions:
//!   * SOL -> XMR: the user is the `locker` (locks SOL), the maker is the `claimer`.
//!   * XMR -> SOL: the maker is the `locker` (locks SOL), the user is the `claimer`.
//!
//! The claimer gets the SOL only by revealing the scalar `s` with `s*G == claim_point`. That scalar
//! is the claimer's half of the Monero spend key, so claiming the SOL hands the locker the missing
//! half of the XMR. A refund pays only the locker and reveals the locker's half (`refund_point`),
//! which hands the XMR back to whoever locked it.
//!
//! Windows (unix seconds, fixed at lock):
//!   [lock, t0)   claim only after `ready` (locker-signed). `abort` allowed (locker or watchtower).
//!   [t0, t1)     claim allowed. No abort by locker/watchtowers. v1.5: a SOL->XMR (or proof-mode
//!                XMR->SOL) claim without `ready` also needs an on-chain Monero payment proof.
//!   [t1, inf)    refund only.
//!   Aborted      refund only, any time, no deadline. Abort never reveals a secret.
//! `claim` and `refund` can never both succeed: they need disjoint states/times and each one
//! moves the escrow to a terminal state.

#![allow(clippy::too_many_arguments)]
// solana-curve25519 is pinned (=3.1.14); its deprecation notes refer to the v4 feature gate.
#![allow(deprecated, unexpected_cfgs)]

use solana_account_info::{next_account_info, AccountInfo};
use solana_cpi::invoke_signed;
use solana_curve25519::edwards::{add_edwards, multiply_edwards, validate_edwards, PodEdwardsPoint};
use solana_curve25519::scalar::PodScalar;
use solana_msg::msg;
use solana_program_error::{ProgramError, ProgramResult};
use solana_pubkey::Pubkey;
use solana_sysvar::{clock::Clock, rent::Rent, Sysvar};
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};

#[cfg(not(feature = "no-entrypoint"))]
solana_program_entrypoint::entrypoint!(process_instruction);

pub mod logic;
pub use logic::scalar_is_canonical;
use logic::release;

// ---------------------------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------------------------

pub const CONFIG_SEED: &[u8] = b"config";
pub const FEE_VAULT_SEED: &[u8] = b"fee_vault";
pub const MAKER_SEED: &[u8] = b"maker";
pub const SWAP_SEED: &[u8] = b"swap";
pub const STAKE_SEED: &[u8] = b"stake";
pub const LINK_SEED: &[u8] = b"link";
pub const VAULT_SEED: &[u8] = b"vault";

pub const DISC_CONFIG: u8 = 0xC1;
pub const DISC_MAKER: u8 = 0xA7;
pub const DISC_ESCROW: u8 = 0xE5;
pub const DISC_LINK: u8 = 0x1C;
pub const DISC_VAULT: u8 = 0x5A;

pub const CONFIG_LEN: usize = 248;
pub const MAKER_LEN: usize = 296;
pub const ESCROW_LEN: usize = 448;
/// Maker account with the platform extension (OTC/pay reputation + OTC size range).
pub const MAKER_LEN_V2: usize = 392;
pub const LINK_LEN: usize = 128;
pub const VAULT_LEN: usize = 448;
/// Escrow v2 (final round, `escrow2.rs`): the v1 layout plus a 96-byte extension (integrator
/// share, finisher tip, order deadline). v1 escrows keep working unchanged.
pub const ESCROW_LEN_V2: usize = 544;

/// Hard ceiling on the protocol fee the admin can ever set (1%).
pub const MAX_FEE_BPS: u16 = 100;
pub const MAX_ENDPOINT: usize = 128;

pub const DIR_SOL_TO_XMR: u8 = 1;
pub const DIR_XMR_TO_SOL: u8 = 2;
/// Hash-locked kinds (SOL <-> transparent ZEC HTLC). They live in their own accounts and
/// instructions (`htlc.rs`); the XMR instructions never accept them. See `htlc.rs`.
pub const DIR_SOL_TO_ZEC: u8 = 4;
pub const DIR_ZEC_TO_SOL: u8 = 8;
/// Point-locked kinds (ZEC v2, unlinkable): the same HTLC accounts and rules, but the lock is an
/// ed25519 point T (stored in `hashlock`) and the claim reveals the scalar t with t*G == T
/// (`htlc_pt_claim`, tag 52). The Zcash side is a 2-of-2 whose claim signature is an ECDSA adaptor
/// signature encrypted to t on secp256k1 (cross-curve DLEQ): the legs share no hash.
pub const DIR_SOL_TO_ZEC_PT: u8 = 16;
pub const DIR_ZEC_TO_SOL_PT: u8 = 32;
/// Every direction bit a maker may register.
pub const ALL_DIRS: u8 = DIR_SOL_TO_XMR | DIR_XMR_TO_SOL | DIR_SOL_TO_ZEC | DIR_ZEC_TO_SOL | DIR_SOL_TO_ZEC_PT | DIR_ZEC_TO_SOL_PT;

pub const ST_LOCKED: u8 = 1;
pub const ST_READY: u8 = 2;
pub const ST_ABORTED: u8 = 3;
pub const ST_CLAIMED: u8 = 4;
pub const ST_REFUNDED: u8 = 5;

/// Escrow flags (header byte 6; zero on every phase-1 escrow).
/// PAY: the XMR goes to a pay-link one-time key (refund_point holds S_i, derived on chain from the
///   link's master point). The locker never learns that key, so a refund reveals nothing and the
///   locker cannot abort (an abort after the maker locked XMR would strand the maker's XMR).
/// OTC: settles one tranche of an OTC trade (separate reputation counters, OTC size range/cap).
/// VAULT: the locker is an auto-cashout vault PDA (always together with PAY).
pub const F_PAY: u8 = 1;
pub const F_OTC: u8 = 2;
pub const F_VAULT: u8 = 4;
/// v1.5 proof mode for XMR->SOL escrows: the claimer (user) needs the maker's ready or a verified
/// Monero payment proof of its deposit (zkproof.rs). SOL->XMR escrows are always proof-gated.
pub const F_PROOF: u8 = 8;
/// Per-swap opt-out of committee proofs. Ordinary SOL->XMR locks with this immutable bit
/// can only be claimed after the locker's signed Ready, even if a payment proof exists.
pub const F_READY_ONLY: u8 = 32;
const F_ALL: u8 = F_PAY | F_OTC | F_VAULT | F_PROOF | F_READY_ONLY;
/// Final round, v2 escrows only: SOL->XMR with the XMR paid straight to the user's own standard
/// Monero address (`refund_point` = its spend key, `view_pub` = its view key), released only by
/// the user's `ready` or a direct payment proof with this escrow's payment id (`direct.rs`).
/// The refund reveals nothing, and only the claimer (maker) may abort.
pub const F_DIRECT: u8 = 16;
/// Ceiling on an integrator's share of a settlement (2%).
pub const MAX_INTEGRATOR_BPS: u16 = 200;
/// Ceiling on a finisher tip (0.02 SOL; also at most a tenth of the amount).
pub const MAX_TIP: u64 = 20_000_000;
/// Floor for `config.unbond_secs` (staking and maker bonds): 3 days, so a stake cannot be
/// flash-farmed around one large fee split. The e2e build (`test-timelocks`) uses 10 s.
#[cfg(not(feature = "test-timelocks"))]
pub const MIN_UNBOND_SECS: i64 = 3 * 86_400;
#[cfg(feature = "test-timelocks")]
pub const MIN_UNBOND_SECS: i64 = 10;
/// Floor for the claim window (t1 - t0) of escrows whose refund cannot hand the maker its XMR
/// back (pay links, cashout vaults, direct payout) and for an offer's proof window: time for
/// 10 confirmations plus a committee outage. 6 hours; the e2e build uses 3 s.
#[cfg(not(feature = "test-timelocks"))]
pub const MIN_PROOF_WINDOW: i64 = 6 * 3600;
#[cfg(feature = "test-timelocks")]
pub const MIN_PROOF_WINDOW: i64 = 3;
/// Late finish: `ready` stays open until t1 - LATE_READY_MARGIN (never earlier than t0), so a user who
/// comes back after t0 (SOL->XMR) or a deposit that confirms late (XMR->SOL) can still finish. The
/// margin leaves the claiming side time to claim before t1. The e2e build uses 2 s.
#[cfg(not(feature = "test-timelocks"))]
pub const LATE_READY_MARGIN: i64 = 30 * 60;
#[cfg(feature = "test-timelocks")]
pub const LATE_READY_MARGIN: i64 = 2;
/// A claimed pay escrow holds the maker's revealed half that the recipient needs to collect, so
/// only the recipient may close it early; the payer may reclaim the rent after this grace.
pub const PAY_CLOSE_GRACE: i64 = 90 * 86_400;
pub const PAY_SPEND_DOMAIN: &[u8] = b"halfkey-pay-spend-v1";
pub const PAY_VIEW_DOMAIN: &[u8] = b"halfkey-pay-view-v1";

const SYSTEM_PROGRAM: Pubkey = Pubkey::from_str_const("11111111111111111111111111111111");
const BPF_UPGRADEABLE_LOADER: Pubkey =
    Pubkey::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
const TOKEN_PROGRAM: Pubkey = Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const TOKEN_2022_PROGRAM: Pubkey =
    Pubkey::from_str_const("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"); // canonical (was a P7 typo); pinned by tests::program_ids_match_crates
const ATA_PROGRAM: Pubkey = Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const ED25519_PROGRAM: Pubkey = Pubkey::from_str_const("Ed25519SigVerify111111111111111111111111111");
const SYSVAR_INSTRUCTIONS: Pubkey =
    Pubkey::from_str_const("Sysvar1nstructions1111111111111111111111111");
pub const CONSENT_PREFIX: &[u8] = b"halfkey-consent-v1";
pub const CONSENT_PREFIX_V2: &[u8] = b"halfkey-consent-v2";

/// ed25519 basepoint, compressed.
const G: [u8; 32] = {
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    b
};
/// Compressed identity point.
const IDENTITY: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 1;
    b
};
/// Group order L, little-endian.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];
/// L - 1, little-endian (canonical, so the syscall does not reduce it).
const L_MINUS_1: [u8; 32] = [
    0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

// ---------------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------------

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HkError {
    BadInstruction = 1,
    NotSigner = 2,
    BadAccount = 3,
    BadPda = 4,
    AlreadyInitialized = 5,
    Unauthorized = 6,
    Paused = 7,
    BadParam = 8,
    NonCanonicalScalar = 9,
    BadPoint = 10,
    WrongSecret = 11,
    BadState = 12,
    TooEarly = 13,
    TooLate = 14,
    AmountOutOfRange = 15,
    CapExceeded = 16,
    MakerInactive = 17,
    DirectionUnsupported = 18,
    OpenSwaps = 19,
    BondLocked = 20,
    Overflow = 21,
    BondTooSmall = 22,
    NoConsent = 23,
    Staked = 24,
    NotUpgraded = 25,
    RateTooLow = 26,
    NotDue = 27,
    NoWatchtower = 28,
    Timelocked = 29,
    NothingPending = 30,
    // v1.5 (payment proofs, burn auction). 40+ so they stay clear of other branches' codes.
    /// A proof-mode escrow claimed without `ready` and without a proof of this escrow.
    NotProven = 40,
    /// The Monero transaction bytes are malformed or of an unsupported kind.
    BadXmrTx = 41,
    /// The TXPROOF_V2 signature (or the shared secret) does not verify.
    BadXmrProof = 42,
    /// The output does not pay the escrow's shared key (or its view tag is wrong).
    WrongOutput = 43,
    /// The decoded amount does not open the output's commitment.
    BadAmount = 44,
    /// The proven amount is below the escrow's `xmr_amount`.
    AmountTooLow = 45,
    /// Header or Merkle path malformed.
    BadInclusion = 46,
    /// Not enough attester signatures, or the block is not the attested one.
    NotAttested = 47,
    /// Burn auction: above the buyer's max burn, or below its min lamports.
    Slippage = 48,
    // Final round (deposit orders, direct pay, offers, integrators, tips): 49-59.
    /// The deposit address holds less than the order needs.
    Underpaid = 49,
    /// The order's deposit deadline or the offer's expiry has passed.
    Expired = 50,
    /// The offer is reserved by a filler whose proof window is still open.
    Reserved = 51,
    /// The Monero transaction carries no encrypted payment id, or not this fill's.
    BadPaymentId = 52,
    /// Integrator share above 200 bps, or a tip above its cap.
    FeeTooHigh = 53,
    /// Claim or proof window below MIN_PROOF_WINDOW.
    WindowTooShort = 54,
}

impl From<HkError> for ProgramError {
    fn from(e: HkError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

macro_rules! req {
    ($cond:expr, $err:expr) => {
        if !($cond) {
            return Err($err.into());
        }
    };
}

// ---------------------------------------------------------------------------------------------
// Byte helpers
// ---------------------------------------------------------------------------------------------

struct Rd<'a> {
    d: &'a [u8],
    o: usize,
}
impl<'a> Rd<'a> {
    fn new(d: &'a [u8]) -> Self {
        Self { d, o: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProgramError> {
        let end = self.o.checked_add(n).ok_or(HkError::BadInstruction)?;
        req!(end <= self.d.len(), HkError::BadInstruction);
        let s = &self.d[self.o..end];
        self.o = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProgramError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, ProgramError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, ProgramError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn i64(&mut self) -> Result<i64, ProgramError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn b32(&mut self) -> Result<[u8; 32], ProgramError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn key(&mut self) -> Result<Pubkey, ProgramError> {
        Ok(Pubkey::new_from_array(self.b32()?))
    }
    fn skip(&mut self, n: usize) -> Result<(), ProgramError> {
        self.take(n).map(|_| ())
    }
    fn done(&self) -> ProgramResult {
        req!(self.o == self.d.len(), HkError::BadInstruction);
        Ok(())
    }
}

struct Wr<'a> {
    d: &'a mut [u8],
    o: usize,
}
impl<'a> Wr<'a> {
    fn new(d: &'a mut [u8]) -> Self {
        Self { d, o: 0 }
    }
    fn put(&mut self, b: &[u8]) {
        self.d[self.o..self.o + b.len()].copy_from_slice(b);
        self.o += b.len();
    }
    fn u8(&mut self, v: u8) {
        self.put(&[v])
    }
    fn u16(&mut self, v: u16) {
        self.put(&v.to_le_bytes())
    }
    fn u32(&mut self, v: u32) {
        self.put(&v.to_le_bytes())
    }
    fn u64(&mut self, v: u64) {
        self.put(&v.to_le_bytes())
    }
    fn i64(&mut self, v: i64) {
        self.put(&v.to_le_bytes())
    }
    fn pad(&mut self, n: usize) {
        for _ in 0..n {
            self.u8(0)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub paused: bool,
    pub bump: u8,
    pub vault_bump: u8,
    pub admin: Pubkey,
    pub fee_recipient: Pubkey,
    pub halfkey_mint: Pubkey,
    pub fee_bps: u16,
    pub holder_fee_bps: u16,
    pub holder_min: u64,
    pub min_bond: u64,
    pub max_swap: u64,
    pub max_open_tvl: u64,
    pub open_tvl: u64,
    pub min_t0: i64,
    pub max_t0: i64,
    pub min_window: i64,
    pub max_window: i64,
    pub unbond_secs: i64,
    pub total_swaps: u64,
    pub total_volume: u64,
    pub total_fees: u64,
    /// Per-escrow cap for OTC tranches (0 = same as max_swap). Bytes 216..224.
    pub otc_max_swap: u64,
    /// Smallest timelock a cashout vault may use for its config changes. Bytes 224..232.
    pub vault_min_delay: i64,
    /// Final round: lamports locked in open offers (bytes 232..240). A bucket of its own, capped
    /// at `max_open_tvl` like the escrows' `open_tvl`, so offers can never crowd out swaps.
    pub offer_tvl: u64,
}

impl Config {
    fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!(d.len() == CONFIG_LEN && d[0] == DISC_CONFIG, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let paused = r.u8()? != 0;
        let bump = r.u8()?;
        let vault_bump = r.u8()?;
        r.skip(3)?;
        Ok(Self {
            paused,
            bump,
            vault_bump,
            admin: r.key()?,
            fee_recipient: r.key()?,
            halfkey_mint: r.key()?,
            fee_bps: r.u16()?,
            holder_fee_bps: {
                let v = r.u16()?;
                r.skip(4)?;
                v
            },
            holder_min: r.u64()?,
            min_bond: r.u64()?,
            max_swap: r.u64()?,
            max_open_tvl: r.u64()?,
            open_tvl: r.u64()?,
            min_t0: r.i64()?,
            max_t0: r.i64()?,
            min_window: r.i64()?,
            max_window: r.i64()?,
            unbond_secs: r.i64()?,
            total_swaps: r.u64()?,
            total_volume: r.u64()?,
            total_fees: r.u64()?,
            otc_max_swap: r.u64()?,
            vault_min_delay: r.i64()?,
            offer_tvl: r.u64()?,
        })
    }
    fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_CONFIG);
        w.u8(1);
        w.u8(self.paused as u8);
        w.u8(self.bump);
        w.u8(self.vault_bump);
        w.pad(3);
        w.put(self.admin.as_ref());
        w.put(self.fee_recipient.as_ref());
        w.put(self.halfkey_mint.as_ref());
        w.u16(self.fee_bps);
        w.u16(self.holder_fee_bps);
        w.pad(4);
        w.u64(self.holder_min);
        w.u64(self.min_bond);
        w.u64(self.max_swap);
        w.u64(self.max_open_tvl);
        w.u64(self.open_tvl);
        w.i64(self.min_t0);
        w.i64(self.max_t0);
        w.i64(self.min_window);
        w.i64(self.max_window);
        w.i64(self.unbond_secs);
        w.u64(self.total_swaps);
        w.u64(self.total_volume);
        w.u64(self.total_fees);
        w.u64(self.otc_max_swap);
        w.i64(self.vault_min_delay);
        w.u64(self.offer_tvl);
    }
}

#[derive(Clone, Debug, Default)]
pub struct Maker {
    pub active: bool,
    pub directions: u8,
    pub bump: u8,
    pub authority: Pubkey,
    pub bond: u64,
    pub min: u64,
    pub max: u64,
    pub open_swaps: u32,
    pub open_lamports: u64,
    pub completed: u64,
    pub aborted: u64,
    pub expired: u64,
    pub volume: u64,
    pub created_at: i64,
    pub withdraw_after: i64,
    pub spread_bps: u16,
    pub endpoint: Vec<u8>,
    /// Locker cancelled before t0 (user's free option, not the maker's fault).
    pub cancelled: u64,
    /// The maker itself gave up a swap (claimer abort).
    pub declined: u64,
    /// $HALFKEY bonded in the maker's stake vault (the holder perk), and the unstake unlock time
    /// (0 = no unstake pending; while pending the discount is off).
    pub staked: u64,
    pub stake_unlock_at: i64,
    /// Platform extension present (account is MAKER_LEN_V2 bytes).
    pub v2: bool,
    pub ext: MakerExt,
}

/// Reputation for OTC and pay-link fills, kept apart from the swap counters, plus the size range a
/// maker takes for OTC tranches. `failed` = watchtower abort or expiry (maker no-show),
/// `declined` = the maker gave up the tranche itself.
#[derive(Clone, Debug, Default)]
pub struct MakerExt {
    pub otc_fills: u64,
    pub otc_volume: u64,
    pub otc_failed: u64,
    pub otc_declined: u64,
    pub pay_fills: u64,
    pub pay_volume: u64,
    pub pay_failed: u64,
    pub pay_declined: u64,
    pub otc_min: u64,
    pub otc_max: u64,
}

impl Maker {
    fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!((d.len() == MAKER_LEN || d.len() == MAKER_LEN_V2) && d[0] == DISC_MAKER, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let active = r.u8()? != 0;
        let directions = r.u8()?;
        let bump = r.u8()?;
        let elen = r.u8()? as usize;
        r.skip(2)?;
        let authority = r.key()?;
        let bond = r.u64()?;
        let min = r.u64()?;
        let max = r.u64()?;
        let open_swaps = r.u32()?;
        r.skip(4)?;
        let open_lamports = r.u64()?;
        let completed = r.u64()?;
        let aborted = r.u64()?;
        let expired = r.u64()?;
        let volume = r.u64()?;
        let created_at = r.i64()?;
        let withdraw_after = r.i64()?;
        let spread_bps = r.u16()?;
        r.skip(6)?;
        req!(elen <= MAX_ENDPOINT, HkError::BadAccount);
        let endpoint = r.take(MAX_ENDPOINT)?[..elen].to_vec();
        let cancelled = r.u64()?;
        let declined = r.u64()?;
        let staked = r.u64()?;
        let stake_unlock_at = r.i64()?;
        let v2 = d.len() == MAKER_LEN_V2;
        let ext = if v2 {
            MakerExt {
                otc_fills: r.u64()?,
                otc_volume: r.u64()?,
                otc_failed: r.u64()?,
                otc_declined: r.u64()?,
                pay_fills: r.u64()?,
                pay_volume: r.u64()?,
                pay_failed: r.u64()?,
                pay_declined: r.u64()?,
                otc_min: r.u64()?,
                otc_max: r.u64()?,
            }
        } else {
            MakerExt::default()
        };
        Ok(Self {
            v2,
            ext,
            cancelled,
            declined,
            staked,
            stake_unlock_at,
            active,
            directions,
            bump,
            authority,
            bond,
            min,
            max,
            open_swaps,
            open_lamports,
            completed,
            aborted,
            expired,
            volume,
            created_at,
            withdraw_after,
            spread_bps,
            endpoint,
        })
    }
    fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_MAKER);
        w.u8(1);
        w.u8(self.active as u8);
        w.u8(self.directions);
        w.u8(self.bump);
        w.u8(self.endpoint.len() as u8);
        w.pad(2);
        w.put(self.authority.as_ref());
        w.u64(self.bond);
        w.u64(self.min);
        w.u64(self.max);
        w.u32(self.open_swaps);
        w.pad(4);
        w.u64(self.open_lamports);
        w.u64(self.completed);
        w.u64(self.aborted);
        w.u64(self.expired);
        w.u64(self.volume);
        w.i64(self.created_at);
        w.i64(self.withdraw_after);
        w.u16(self.spread_bps);
        w.pad(6);
        let mut ep = [0u8; MAX_ENDPOINT];
        ep[..self.endpoint.len()].copy_from_slice(&self.endpoint);
        w.put(&ep);
        w.u64(self.cancelled);
        w.u64(self.declined);
        w.u64(self.staked);
        w.i64(self.stake_unlock_at);
        if d_len_is_v2(w.d.len()) {
            let x = &self.ext;
            for v in [x.otc_fills, x.otc_volume, x.otc_failed, x.otc_declined, x.pay_fills, x.pay_volume, x.pay_failed, x.pay_declined, x.otc_min, x.otc_max] {
                w.u64(v);
            }
        }
    }
}

fn d_len_is_v2(n: usize) -> bool {
    n == MAKER_LEN_V2
}

#[derive(Clone, Debug, Default)]
pub struct Escrow {
    pub state: u8,
    pub direction: u8,
    pub bump: u8,
    /// Open-swap counters (maker + global TVL) already released (abort/expire/claim/refund).
    pub released: bool,
    pub swap_id: [u8; 32],
    pub locker: Pubkey,
    pub claimer: Pubkey,
    pub maker: Pubkey,
    pub amount: u64,
    pub xmr_amount: u64,
    pub fee_bps: u16,
    pub claim_point: [u8; 32],
    pub refund_point: [u8; 32],
    pub view_pub: [u8; 32],
    pub quote_hash: [u8; 32],
    pub watchtowers: [Pubkey; 2],
    pub created_at: i64,
    pub t0: i64,
    pub t1: i64,
    pub settled_at: i64,
    pub secret: [u8; 32],
    /// F_PAY | F_OTC | F_VAULT (header byte 6).
    pub flags: u8,
    /// PAY: the pay-link account the one-time key is derived from (bytes 416..448).
    pub link: Pubkey,
    /// v2 escrow (ESCROW_LEN_V2 bytes): `ext` is stored at 448..544.
    pub v2: bool,
    pub ext: EscrowExt,
}

/// The v2 extension (bytes 448..544).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EscrowExt {
    /// Integrator paid `integrator_bps` of the amount at settlement (default = none), into its
    /// program-owned account ["integrator", key] so a claim can never fail on the recipient.
    pub integrator: Pubkey,
    pub integrator_bps: u16,
    /// 0 = locked by a wallet (lock3), 1 = filled from a deposit order.
    pub origin: u8,
    /// Lamports held on top of the amount, paid to whoever submits the claim or the refund.
    pub tip: u64,
    /// Order escrows: the order's deposit deadline (close waits for it, so an order is filled at
    /// most once). 0 otherwise.
    pub order_deadline: i64,
}

impl Escrow {
    fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!((d.len() == ESCROW_LEN || d.len() == ESCROW_LEN_V2) && d[0] == DISC_ESCROW, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let state = r.u8()?;
        let direction = r.u8()?;
        let bump = r.u8()?;
        let released = r.u8()? != 0;
        let flags = r.u8()?;
        r.skip(1)?;
        Ok(Self {
            flags,
            state,
            direction,
            bump,
            released,
            swap_id: r.b32()?,
            locker: r.key()?,
            claimer: r.key()?,
            maker: r.key()?,
            amount: r.u64()?,
            xmr_amount: r.u64()?,
            fee_bps: {
                let v = r.u16()?;
                r.skip(6)?;
                v
            },
            claim_point: r.b32()?,
            refund_point: r.b32()?,
            view_pub: r.b32()?,
            quote_hash: r.b32()?,
            watchtowers: [r.key()?, r.key()?],
            created_at: r.i64()?,
            t0: r.i64()?,
            t1: r.i64()?,
            settled_at: r.i64()?,
            secret: r.b32()?,
            link: r.key()?,
            v2: d.len() == ESCROW_LEN_V2,
            ext: if d.len() == ESCROW_LEN_V2 {
                EscrowExt {
                    integrator: r.key()?,
                    integrator_bps: r.u16()?,
                    origin: r.u8()?,
                    tip: {
                        r.skip(5)?;
                        r.u64()?
                    },
                    order_deadline: r.i64()?,
                }
            } else {
                EscrowExt::default()
            },
        })
    }
    fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_ESCROW);
        w.u8(1);
        w.u8(self.state);
        w.u8(self.direction);
        w.u8(self.bump);
        w.u8(self.released as u8);
        w.u8(self.flags);
        w.pad(1);
        w.put(&self.swap_id);
        w.put(self.locker.as_ref());
        w.put(self.claimer.as_ref());
        w.put(self.maker.as_ref());
        w.u64(self.amount);
        w.u64(self.xmr_amount);
        w.u16(self.fee_bps);
        w.pad(6);
        w.put(&self.claim_point);
        w.put(&self.refund_point);
        w.put(&self.view_pub);
        w.put(&self.quote_hash);
        w.put(self.watchtowers[0].as_ref());
        w.put(self.watchtowers[1].as_ref());
        w.i64(self.created_at);
        w.i64(self.t0);
        w.i64(self.t1);
        w.i64(self.settled_at);
        w.put(&self.secret);
        w.put(self.link.as_ref());
        if w.d.len() == ESCROW_LEN_V2 {
            let x = &self.ext;
            w.put(x.integrator.as_ref());
            w.u16(x.integrator_bps);
            w.u8(x.origin);
            w.pad(5);
            w.u64(x.tip);
            w.i64(x.order_deadline);
        }
    }
}

/// A pay link: `/pay/<name>` -> the recipient's master public point. Immutable once registered,
/// so nobody (not even the owner) can redirect payments already in flight.
#[derive(Clone, Debug, Default)]
pub struct Link {
    pub bump: u8,
    /// One-way: a retired link takes no new payments (open ones settle as usual).
    pub retired: bool,
    pub name: Vec<u8>,
    pub owner: Pubkey,
    pub master: [u8; 32],
    pub created_at: i64,
    pub payments: u64,
    pub locked_lamports: u64,
}

impl Link {
    fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!(d.len() == LINK_LEN && d[0] == DISC_LINK, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let bump = r.u8()?;
        let n = r.u8()? as usize;
        let retired = r.u8()? != 0;
        r.skip(3)?;
        req!(n <= 32, HkError::BadAccount);
        let name = r.take(32)?[..n].to_vec();
        Ok(Self { bump, retired, name, owner: r.key()?, master: r.b32()?, created_at: r.i64()?, payments: r.u64()?, locked_lamports: r.u64()? })
    }
    fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_LINK);
        w.u8(1);
        w.u8(self.bump);
        w.u8(self.name.len() as u8);
        w.u8(self.retired as u8);
        w.pad(3);
        let mut nm = [0u8; 32];
        nm[..self.name.len()].copy_from_slice(&self.name);
        w.put(&nm);
        w.put(self.owner.as_ref());
        w.put(&self.master);
        w.i64(self.created_at);
        w.u64(self.payments);
        w.u64(self.locked_lamports);
    }
}

/// The part of a vault's config that can only change through the timelock.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct VaultParams {
    /// Who may trigger a conversion (Pubkey::default() = anyone; the owner always may).
    pub keeper: Pubkey,
    /// The owner's watchtowers, copied into every escrow (the keeper cannot pick its own).
    pub watchtowers: [Pubkey; 2],
    /// Destination link (owned by the vault owner): XMR keys derive from its master point.
    pub link: Pubkey,
    pub min_lamports: u64,
    pub max_lamports: u64,
    pub interval: i64,
    /// Floor price in piconero per SOL, enforced on chain for every conversion.
    pub min_rate: u64,
    /// Timelock for changes to these params and for withdrawals.
    pub delay: i64,
}

/// Auto-cashout vault ["vault", owner]: receives SOL (plain transfers, pump.fun fee sharing) and a
/// keeper converts it into pay-mode escrows to the owner's link. Refunds come back here.
#[derive(Clone, Debug, Default)]
pub struct Vault {
    pub bump: u8,
    pub paused: bool,
    /// Unpausing is a loosening, so it goes through the timelock with the pending proposal.
    pub pending_unpause: bool,
    pub owner: Pubkey,
    pub p: VaultParams,
    pub next_at: i64,
    pub created_at: i64,
    pub pending_at: i64,
    pub pending: VaultParams,
    pub withdraw_at: i64,
    pub withdraw_amount: u64,
    pub conversions: u64,
    pub locked_lamports: u64,
    pub refunds: u64,
    pub refunded_lamports: u64,
}

fn read_vp(r: &mut Rd) -> Result<VaultParams, ProgramError> {
    Ok(VaultParams {
        keeper: r.key()?,
        watchtowers: [r.key()?, r.key()?],
        link: r.key()?,
        min_lamports: r.u64()?,
        max_lamports: r.u64()?,
        interval: r.i64()?,
        min_rate: r.u64()?,
        delay: r.i64()?,
    })
}
fn write_vp(w: &mut Wr, p: &VaultParams) {
    w.put(p.keeper.as_ref());
    w.put(p.watchtowers[0].as_ref());
    w.put(p.watchtowers[1].as_ref());
    w.put(p.link.as_ref());
    w.u64(p.min_lamports);
    w.u64(p.max_lamports);
    w.i64(p.interval);
    w.u64(p.min_rate);
    w.i64(p.delay);
}

impl Vault {
    fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!(d.len() == VAULT_LEN && d[0] == DISC_VAULT, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let bump = r.u8()?;
        let paused = r.u8()? != 0;
        let pending_unpause = r.u8()? != 0;
        r.skip(3)?;
        let owner = r.key()?;
        let p = read_vp(&mut r)?;
        let next_at = r.i64()?;
        let created_at = r.i64()?;
        let pending_at = r.i64()?;
        let pending = read_vp(&mut r)?;
        Ok(Self {
            bump, paused, pending_unpause, owner, p, next_at, created_at, pending_at, pending,
            withdraw_at: r.i64()?,
            withdraw_amount: r.u64()?,
            conversions: r.u64()?,
            locked_lamports: r.u64()?,
            refunds: r.u64()?,
            refunded_lamports: r.u64()?,
        })
    }
    fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_VAULT);
        w.u8(1);
        w.u8(self.bump);
        w.u8(self.paused as u8);
        w.u8(self.pending_unpause as u8);
        w.pad(3);
        w.put(self.owner.as_ref());
        write_vp(&mut w, &self.p);
        w.i64(self.next_at);
        w.i64(self.created_at);
        w.i64(self.pending_at);
        write_vp(&mut w, &self.pending);
        w.i64(self.withdraw_at);
        w.u64(self.withdraw_amount);
        w.u64(self.conversions);
        w.u64(self.locked_lamports);
        w.u64(self.refunds);
        w.u64(self.refunded_lamports);
    }
}

// ---------------------------------------------------------------------------------------------
// Curve checks
// ---------------------------------------------------------------------------------------------

/// A point is usable as a swap key iff it decompresses, is canonically encoded, is not the
/// identity, and lies in the prime-order subgroup (L*P == O, computed as (L-1)*P + P since L
/// itself reduces to 0).
pub fn point_is_prime_order(p: &[u8; 32]) -> bool {
    if *p == IDENTITY {
        return false;
    }
    let pt = PodEdwardsPoint(*p);
    if !validate_edwards(&pt) {
        return false;
    }
    // The syscalls decode non-canonical encodings (y >= p, or x = 0 with the sign bit set), so
    // without this the identity check above misses 3 encodings of the identity. P + O is
    // re-encoded canonically by the syscall, so it equals the input bytes only if they were
    // canonical.
    match add_edwards(&pt, &PodEdwardsPoint(IDENTITY)) {
        Some(c) if c.0 == *p => {}
        _ => return false,
    }
    let Some(q) = multiply_edwards(&PodScalar(L_MINUS_1), &pt) else {
        return false;
    };
    match add_edwards(&q, &pt) {
        Some(r) => r.0 == IDENTITY,
        None => false,
    }
}

/// `secret` is canonical and `secret*G == point`.
pub fn check_reveal(secret: &[u8; 32], point: &[u8; 32]) -> ProgramResult {
    logic::check_reveal_with(secret, point, |s| {
        multiply_edwards(&PodScalar(*s), &PodEdwardsPoint(G)).map(|p| p.0)
    })?;
    Ok(())
}

/// Pay-link tweak: sha256(domain || master || escrow || quote_hash) with the top 4 bits cleared, so
/// it is a canonical scalar (< 2^252 < L) by construction; no reduction needed on chain. Binding
/// the escrow address and the maker's quote hash makes every escrow's one-time key distinct, so
/// one XMR output can never satisfy two pay escrows (same invoice paid twice, or a reused id).
pub fn pay_tweak(domain: &[u8], master: &[u8; 32], escrow: &[u8; 32], quote_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = solana_sha256_hasher::hashv(&[domain, master, escrow, quote_hash]).to_bytes();
    h[31] &= 0x0f;
    h
}

/// One-time keys of a pay-link payment, derived additively from the link's master point S:
///   S_i = S + t_i*G   (spend half; the recipient's s_i = s + t_i)
///   V_i = v_i*G       (view key; public-derivable, so watchtowers get it per payment)
/// with t_i = pay_tweak(spend, S, escrow, quote_hash), v_i = pay_tweak(view, S, escrow, quote_hash).
fn derive_pay(master: &[u8; 32], escrow: &Pubkey, quote_hash: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), ProgramError> {
    let e = escrow.to_bytes();
    let t = pay_tweak(PAY_SPEND_DOMAIN, master, &e, quote_hash);
    let v = pay_tweak(PAY_VIEW_DOMAIN, master, &e, quote_hash);
    req!(t != [0u8; 32] && v != [0u8; 32], HkError::BadPoint);
    let tg = multiply_edwards(&PodScalar(t), &PodEdwardsPoint(G)).ok_or(HkError::BadPoint)?;
    let si = add_edwards(&PodEdwardsPoint(*master), &tg).ok_or(HkError::BadPoint)?;
    let vg = multiply_edwards(&PodScalar(v), &PodEdwardsPoint(G)).ok_or(HkError::BadPoint)?;
    Ok((si.0, vg.0))
}

// ---------------------------------------------------------------------------------------------
// Account helpers
// ---------------------------------------------------------------------------------------------

fn signer(a: &AccountInfo) -> ProgramResult {
    req!(a.is_signer, HkError::NotSigner);
    Ok(())
}

fn owned(a: &AccountInfo, pid: &Pubkey) -> ProgramResult {
    req!(a.owner == pid, HkError::BadAccount);
    Ok(())
}

fn writable(a: &AccountInfo) -> ProgramResult {
    req!(a.is_writable, HkError::BadAccount);
    Ok(())
}

fn now() -> Result<i64, ProgramError> {
    Ok(Clock::get()?.unix_timestamp)
}

fn config_pda(pid: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[CONFIG_SEED], pid)
}

fn load_config(a: &AccountInfo, pid: &Pubkey) -> Result<Config, ProgramError> {
    owned(a, pid)?;
    let c = Config::load(&a.try_borrow_data()?)?;
    let k = Pubkey::create_program_address(&[CONFIG_SEED, &[c.bump]], pid)
        .map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(c)
}

fn load_maker(a: &AccountInfo, pid: &Pubkey) -> Result<Maker, ProgramError> {
    owned(a, pid)?;
    let m = Maker::load(&a.try_borrow_data()?)?;
    let k = Pubkey::create_program_address(&[MAKER_SEED, m.authority.as_ref(), &[m.bump]], pid)
        .map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(m)
}

fn load_escrow(a: &AccountInfo, pid: &Pubkey) -> Result<Escrow, ProgramError> {
    owned(a, pid)?;
    let e = Escrow::load(&a.try_borrow_data()?)?;
    let k = Pubkey::create_program_address(
        &[SWAP_SEED, e.locker.as_ref(), &e.swap_id, &[e.bump]],
        pid,
    )
    .map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(e)
}

fn load_link(a: &AccountInfo, pid: &Pubkey) -> Result<Link, ProgramError> {
    owned(a, pid)?;
    let l = Link::load(&a.try_borrow_data()?)?;
    let k = Pubkey::create_program_address(&[LINK_SEED, &l.name, &[l.bump]], pid).map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(l)
}

fn load_vault(a: &AccountInfo, pid: &Pubkey) -> Result<Vault, ProgramError> {
    owned(a, pid)?;
    let v = Vault::load(&a.try_borrow_data()?)?;
    let k = Pubkey::create_program_address(&[VAULT_SEED, v.owner.as_ref(), &[v.bump]], pid).map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(v)
}

/// Create a program-owned PDA. Works even if someone pre-funded the address (a known DoS on a
/// plain `create_account`).
fn create_pda<'a>(
    payer: &AccountInfo<'a>,
    target: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    pid: &Pubkey,
    space: usize,
    seeds: &[&[u8]],
) -> ProgramResult {
    req!(*system.key == SYSTEM_PROGRAM, HkError::BadAccount);
    req!(target.data_len() == 0 && *target.owner == SYSTEM_PROGRAM, HkError::AlreadyInitialized);
    let need = Rent::get()?.minimum_balance(space);
    let have = target.lamports();
    if have == 0 {
        invoke_signed(
            &solana_system_interface::instruction::create_account(
                payer.key,
                target.key,
                need,
                space as u64,
                pid,
            ),
            &[payer.clone(), target.clone(), system.clone()],
            &[seeds],
        )?;
    } else {
        if have < need {
            invoke_signed(
                &solana_system_interface::instruction::transfer(payer.key, target.key, need - have),
                &[payer.clone(), target.clone(), system.clone()],
                &[],
            )?;
        }
        invoke_signed(
            &solana_system_interface::instruction::allocate(target.key, space as u64),
            &[target.clone(), system.clone()],
            &[seeds],
        )?;
        invoke_signed(
            &solana_system_interface::instruction::assign(target.key, pid),
            &[target.clone(), system.clone()],
            &[seeds],
        )?;
    }
    Ok(())
}

fn transfer_in<'a>(
    from: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    lamports: u64,
) -> ProgramResult {
    if lamports == 0 {
        return Ok(());
    }
    req!(*system.key == SYSTEM_PROGRAM, HkError::BadAccount);
    invoke_signed(
        &solana_system_interface::instruction::transfer(from.key, to.key, lamports),
        &[from.clone(), to.clone(), system.clone()],
        &[],
    )
}

/// Move lamports out of a program-owned account.
fn pay(from: &AccountInfo, to: &AccountInfo, lamports: u64) -> ProgramResult {
    if lamports == 0 {
        return Ok(());
    }
    req!(from.key != to.key, HkError::BadAccount);
    let (f, t) = logic::pay_amounts(from.lamports(), to.lamports(), lamports)?;
    **from.try_borrow_mut_lamports()? = f;
    **to.try_borrow_mut_lamports()? = t;
    Ok(())
}

/// Close a program-owned account: all lamports to `dest`, data zeroed, handed back to System.
fn close_account(acc: &AccountInfo, dest: &AccountInfo) -> ProgramResult {
    let l = acc.lamports();
    pay(acc, dest, l)?;
    acc.try_borrow_mut_data()?.fill(0);
    acc.resize(0)?;
    acc.assign(&SYSTEM_PROGRAM);
    Ok(())
}

fn add(a: u64, b: u64) -> Result<u64, ProgramError> {
    a.checked_add(b).ok_or_else(|| HkError::Overflow.into())
}

// ---------------------------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------------------------

pub mod ix {
    pub const INIT_CONFIG: u8 = 0;
    pub const UPDATE_CONFIG: u8 = 1;
    pub const REGISTER_MAKER: u8 = 2;
    pub const UPDATE_MAKER: u8 = 3;
    pub const REQUEST_UNBOND: u8 = 4;
    pub const WITHDRAW_MAKER: u8 = 5;
    pub const LOCK: u8 = 6;
    pub const READY: u8 = 7;
    pub const ABORT: u8 = 8;
    pub const CLAIM: u8 = 9;
    pub const REFUND: u8 = 10;
    pub const CLOSE: u8 = 11;
    pub const SWEEP_FEES: u8 = 12;
    pub const EXPIRE: u8 = 13;
    pub const STAKE: u8 = 14;
    pub const UNSTAKE_REQUEST: u8 = 15;
    pub const UNSTAKE: u8 = 16;
    pub const LOCK2: u8 = 17;
    pub const CLOSE_PAY: u8 = 18;
    pub const SET_CONFIG_EXT: u8 = 19;
    pub const UPGRADE_MAKER: u8 = 20;
    pub const REGISTER_LINK: u8 = 21;
    pub const VAULT_CREATE: u8 = 22;
    pub const VAULT_PROPOSE: u8 = 23;
    pub const VAULT_APPLY: u8 = 24;
    pub const VAULT_CANCEL: u8 = 25;
    pub const VAULT_TIGHTEN: u8 = 26;
    pub const VAULT_LOCK: u8 = 27;
    pub const VAULT_WITHDRAW_REQUEST: u8 = 28;
    pub const VAULT_WITHDRAW: u8 = 29;
    pub const RETIRE_LINK: u8 = 30;
    // v1.5 (31-41). The HTLC (SOL <-> ZEC) block starts at 47; 42-46 are the final round's.
    pub const SET_ATTESTERS: u8 = 31;
    pub const ATTEST_HEADER: u8 = 32;
    pub const PROVE_LOCK: u8 = 33;
    pub const BURN_INIT: u8 = 34;
    pub const BURN_TAKE: u8 = 35;
    pub const POOL_STAKE: u8 = 36;
    pub const POOL_UNSTAKE_REQUEST: u8 = 37;
    pub const POOL_UNSTAKE: u8 = 38;
    pub const POOL_CLAIM: u8 = 39;
    pub const SPLIT_FEES: u8 = 40;
    pub const DEPOSIT_STAKERS: u8 = 41;
    // HTLC kind (SOL <-> ZEC, htlc.rs). Tags start 16 above the platform's next free tag (31), so
    // other branches can keep allocating 31.. without colliding.
    pub const HTLC_LOCK: u8 = 47;
    pub const HTLC_CLAIM: u8 = 48;
    pub const HTLC_ABORT: u8 = 49;
    pub const HTLC_REFUND: u8 = 50;
    pub const HTLC_CLOSE: u8 = 51;
    // Point-locked HTLC kind (ZEC v2). 52-55 are this kind's block; only 52 is used: lock, abort,
    // refund and close are the HTLC instructions above (the direction selects the kind), and the
    // claim is separate so a hash claim can never be applied to a point lock or the reverse.
    pub const HTLC_PT_CLAIM: u8 = 52;
    // Final round (escrow2.rs, deposit.rs, direct.rs, offer.rs): 42-46 and 56-59. 52-55 belong
    // to the point-locked HTLC kind, 60+ to ZK v1.
    pub const LOCK3: u8 = 42;
    pub const CLAIM_TO: u8 = 43;
    pub const FILL_DEPOSIT: u8 = 44;
    pub const ORDER_REFUND: u8 = 45;
    pub const PROVE_DIRECT: u8 = 46;
    pub const INTEGRATOR: u8 = 56;
    pub const OFFER_OPEN: u8 = 57;
    pub const OFFER_TAKE: u8 = 58;
    pub const OFFER_SETTLE: u8 = 59;
}

pub fn process_instruction(pid: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let (&tag, rest) = data.split_first().ok_or(HkError::BadInstruction)?;
    let mut r = Rd::new(rest);
    match tag {
        ix::INIT_CONFIG => init_config(pid, accounts, &mut r),
        ix::UPDATE_CONFIG => update_config(pid, accounts, &mut r),
        ix::REGISTER_MAKER => register_maker(pid, accounts, &mut r),
        ix::UPDATE_MAKER => update_maker(pid, accounts, &mut r),
        ix::REQUEST_UNBOND => request_unbond(pid, accounts, &mut r),
        ix::WITHDRAW_MAKER => withdraw_maker(pid, accounts, &mut r),
        ix::LOCK => lock(pid, accounts, &mut r),
        ix::READY => ready(pid, accounts, &mut r),
        ix::ABORT => abort(pid, accounts, &mut r),
        ix::CLAIM => claim(pid, accounts, &mut r),
        ix::REFUND => refund(pid, accounts, &mut r),
        ix::CLOSE => close(pid, accounts, &mut r),
        ix::SWEEP_FEES => sweep_fees(pid, accounts, &mut r),
        ix::EXPIRE => expire(pid, accounts, &mut r),
        // v1.5: the maker bond is a $HALFKEY stake in the reward pool (rewards.rs, tags 36-39:
        // same vault, same unbond delay, open to anyone). The old maker-only entry points are
        // retired so no token can leave the shared vault without the pool's bookkeeping.
        ix::STAKE | ix::UNSTAKE_REQUEST | ix::UNSTAKE => Err(HkError::BadInstruction.into()),
        ix::LOCK2 => lock2(pid, accounts, &mut r),
        ix::CLOSE_PAY => close_pay(pid, accounts, &mut r),
        ix::SET_CONFIG_EXT => set_config_ext(pid, accounts, &mut r),
        ix::UPGRADE_MAKER => upgrade_maker(pid, accounts, &mut r),
        ix::REGISTER_LINK => register_link(pid, accounts, &mut r),
        ix::VAULT_CREATE => vault_create(pid, accounts, &mut r),
        ix::VAULT_PROPOSE => vault_propose(pid, accounts, &mut r),
        ix::VAULT_APPLY => vault_apply(pid, accounts, &mut r),
        ix::VAULT_CANCEL => vault_cancel(pid, accounts, &mut r),
        ix::VAULT_TIGHTEN => vault_tighten(pid, accounts, &mut r),
        ix::VAULT_LOCK => vault_lock(pid, accounts, &mut r),
        ix::VAULT_WITHDRAW_REQUEST => vault_withdraw_request(pid, accounts, &mut r),
        ix::VAULT_WITHDRAW => vault_withdraw(pid, accounts, &mut r),
        ix::RETIRE_LINK => retire_link(pid, accounts, &mut r),
        ix::SET_ATTESTERS => zkproof::set_attesters(pid, accounts, &mut r),
        ix::ATTEST_HEADER => zkproof::attest_header(pid, accounts, &mut r),
        ix::PROVE_LOCK => zkproof::prove_lock(pid, accounts, &mut r),
        ix::BURN_INIT => burn::burn_init(pid, accounts, &mut r),
        ix::BURN_TAKE => burn::burn_take(pid, accounts, &mut r),
        ix::POOL_STAKE => rewards::pool_stake(pid, accounts, &mut r),
        ix::POOL_UNSTAKE_REQUEST => rewards::pool_unstake_request(pid, accounts, &mut r),
        ix::POOL_UNSTAKE => rewards::pool_unstake(pid, accounts, &mut r),
        ix::POOL_CLAIM => rewards::pool_claim(pid, accounts, &mut r),
        ix::SPLIT_FEES => rewards::split_fees(pid, accounts, &mut r),
        ix::DEPOSIT_STAKERS => rewards::deposit_stakers(pid, accounts, &mut r),
        ix::HTLC_LOCK => htlc::lock(pid, accounts, &mut r),
        ix::HTLC_CLAIM => htlc::claim(pid, accounts, &mut r, false),
        ix::HTLC_PT_CLAIM => htlc::claim(pid, accounts, &mut r, true),
        ix::HTLC_ABORT => htlc::abort(pid, accounts, &mut r),
        ix::HTLC_REFUND => htlc::refund(pid, accounts, &mut r),
        ix::HTLC_CLOSE => htlc::close(pid, accounts, &mut r),
        ix::LOCK3 => escrow2::lock3(pid, accounts, &mut r),
        ix::CLAIM_TO => escrow2::claim_to(pid, accounts, &mut r),
        ix::FILL_DEPOSIT => deposit::fill_deposit(pid, accounts, &mut r),
        ix::ORDER_REFUND => deposit::order_refund(pid, accounts, &mut r),
        ix::PROVE_DIRECT => direct::prove_direct(pid, accounts, &mut r),
        ix::INTEGRATOR => escrow2::integrator(pid, accounts, &mut r),
        ix::OFFER_OPEN => offer::open(pid, accounts, &mut r),
        ix::OFFER_TAKE => offer::take(pid, accounts, &mut r),
        ix::OFFER_SETTLE => offer::settle(pid, accounts, &mut r),
        _ => Err(HkError::BadInstruction.into()),
    }
}

/// Shared parameter block of init/update config.
struct ConfigParams {
    fee_recipient: Pubkey,
    halfkey_mint: Pubkey,
    fee_bps: u16,
    holder_fee_bps: u16,
    holder_min: u64,
    min_bond: u64,
    max_swap: u64,
    max_open_tvl: u64,
    min_t0: i64,
    max_t0: i64,
    min_window: i64,
    max_window: i64,
    unbond_secs: i64,
}

fn read_config_params(r: &mut Rd) -> Result<ConfigParams, ProgramError> {
    let p = ConfigParams {
        fee_recipient: r.key()?,
        halfkey_mint: r.key()?,
        fee_bps: r.u16()?,
        holder_fee_bps: r.u16()?,
        holder_min: r.u64()?,
        min_bond: r.u64()?,
        max_swap: r.u64()?,
        max_open_tvl: r.u64()?,
        min_t0: r.i64()?,
        max_t0: r.i64()?,
        min_window: r.i64()?,
        max_window: r.i64()?,
        unbond_secs: r.i64()?,
    };
    req!(p.fee_bps <= MAX_FEE_BPS, HkError::BadParam);
    req!(p.holder_fee_bps <= p.fee_bps, HkError::BadParam);
    req!(p.min_t0 >= 1 && p.min_t0 <= p.max_t0, HkError::BadParam);
    req!(p.min_window >= 1 && p.min_window <= p.max_window, HkError::BadParam);
    // t0/t1 must stay far from i64 overflow.
    req!(p.max_t0 <= 30 * 86_400 && p.max_window <= 30 * 86_400, HkError::BadParam);
    req!(p.unbond_secs >= 0, HkError::BadParam);
    // Final round (reviewer #5): an on-chain floor, so the stake pool and the holder discount
    // cannot be flash-farmed whatever the admin sets.
    req!(p.unbond_secs >= MIN_UNBOND_SECS, HkError::BadParam);
    req!(p.max_swap > 0 && p.max_open_tvl >= p.max_swap, HkError::BadParam);
    Ok(p)
}

fn apply_params(c: &mut Config, p: ConfigParams) {
    c.fee_recipient = p.fee_recipient;
    c.halfkey_mint = p.halfkey_mint;
    c.fee_bps = p.fee_bps;
    c.holder_fee_bps = p.holder_fee_bps;
    c.holder_min = p.holder_min;
    c.min_bond = p.min_bond;
    c.max_swap = p.max_swap;
    c.max_open_tvl = p.max_open_tvl;
    c.min_t0 = p.min_t0;
    c.max_t0 = p.max_t0;
    c.min_window = p.min_window;
    c.max_window = p.max_window;
    c.unbond_secs = p.unbond_secs;
}

/// Accounts: [admin (signer, w), config (w), fee_vault (w), program_data, system]
/// Only the program's upgrade authority can initialize (blocks a front-run of the first init).
fn init_config(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let admin = next_account_info(it)?;
    let config = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let program_data = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(admin)?;
    let p = read_config_params(r)?;
    r.done()?;

    // Upgrade authority check: ProgramData = [u32 tag=3][u64 slot][u8 is_some][32 authority].
    let (pd, _) = Pubkey::find_program_address(&[pid.as_ref()], &BPF_UPGRADEABLE_LOADER);
    req!(*program_data.key == pd && *program_data.owner == BPF_UPGRADEABLE_LOADER, HkError::BadAccount);
    {
        let d = program_data.try_borrow_data()?;
        req!(d.len() >= 45 && d[0..4] == [3, 0, 0, 0] && d[12] == 1, HkError::Unauthorized);
        req!(d[13..45] == *admin.key.as_ref(), HkError::Unauthorized);
    }

    let (ck, cb) = config_pda(pid);
    req!(ck == *config.key, HkError::BadPda);
    let (vk, vb) = Pubkey::find_program_address(&[FEE_VAULT_SEED], pid);
    req!(vk == *vault.key, HkError::BadPda);
    create_pda(admin, config, system, pid, CONFIG_LEN, &[CONFIG_SEED, &[cb]])?;
    create_pda(admin, vault, system, pid, 0, &[FEE_VAULT_SEED, &[vb]])?;

    let mut c = Config { bump: cb, vault_bump: vb, admin: *admin.key, ..Default::default() };
    apply_params(&mut c, p);
    c.store(&mut config.try_borrow_mut_data()?);
    msg!("halfkey: config initialized");
    Ok(())
}

/// Accounts: [admin (signer), config (w)]. Data: params + paused u8 + new_admin.
/// Never touches open escrows: fee bps and windows are copied into each escrow at lock.
fn update_config(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let admin = next_account_info(it)?;
    let config = next_account_info(it)?;
    signer(admin)?;
    writable(config)?;
    let mut c = load_config(config, pid)?;
    req!(c.admin == *admin.key, HkError::Unauthorized);
    let p = read_config_params(r)?;
    let paused = r.u8()?;
    let new_admin = r.key()?;
    r.done()?;
    req!(paused <= 1, HkError::BadParam);
    req!(new_admin != Pubkey::default(), HkError::BadParam);
    // The mint is NOT frozen here: the staking pool pins its own mint at creation (rewards.rs,
    // Pool::mint) and the burn auction fixes its mint in BurnState, so changing config.halfkey_mint
    // cannot strand stakers' tokens or let a swapped mint be staked into the pool.
    apply_params(&mut c, p);
    c.paused = paused == 1;
    c.admin = new_admin;
    c.store(&mut config.try_borrow_mut_data()?);
    Ok(())
}

fn read_endpoint(r: &mut Rd) -> Result<Vec<u8>, ProgramError> {
    let n = r.u8()? as usize;
    req!(n > 0 && n <= MAX_ENDPOINT, HkError::BadParam);
    let ep = r.take(n)?.to_vec();
    req!(ep.iter().all(|b| (0x21..0x7f).contains(b)), HkError::BadParam);
    Ok(ep)
}

fn check_maker_params(min: u64, max: u64, directions: u8, spread_bps: u16) -> ProgramResult {
    req!(min > 0 && min <= max, HkError::BadParam);
    req!(directions != 0 && directions & !ALL_DIRS == 0, HkError::BadParam);
    req!(spread_bps <= 2_000, HkError::BadParam);
    Ok(())
}

/// Accounts: [authority (signer, w), maker (w), config, system]
/// Data: bond u64, min u64, max u64, directions u8, spread_bps u16, endpoint_len u8, endpoint.
fn register_maker(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let auth = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(auth)?;
    writable(maker)?;
    let c = load_config(config, pid)?;
    req!(!c.paused, HkError::Paused);
    let bond = r.u64()?;
    let min = r.u64()?;
    let max = r.u64()?;
    let directions = r.u8()?;
    let spread_bps = r.u16()?;
    let endpoint = read_endpoint(r)?;
    r.done()?;
    check_maker_params(min, max, directions, spread_bps)?;
    req!(bond >= c.min_bond, HkError::BondTooSmall);

    let (mk, mb) = Pubkey::find_program_address(&[MAKER_SEED, auth.key.as_ref()], pid);
    req!(mk == *maker.key, HkError::BadPda);
    create_pda(auth, maker, system, pid, MAKER_LEN, &[MAKER_SEED, auth.key.as_ref(), &[mb]])?;
    transfer_in(auth, maker, system, bond)?;
    let m = Maker {
        active: true,
        directions,
        bump: mb,
        authority: *auth.key,
        bond,
        min,
        max,
        created_at: now()?,
        spread_bps,
        endpoint,
        ..Default::default()
    };
    m.store(&mut maker.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [authority (signer, w), maker (w), config, system]
/// Data: add_bond u64, min u64, max u64, directions u8, spread_bps u16, active u8, endpoint_len u8, endpoint.
fn update_maker(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let auth = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(auth)?;
    writable(maker)?;
    let c = load_config(config, pid)?;
    let mut m = load_maker(maker, pid)?;
    req!(m.authority == *auth.key, HkError::Unauthorized);
    let add_bond = r.u64()?;
    let min = r.u64()?;
    let max = r.u64()?;
    let directions = r.u8()?;
    let spread_bps = r.u16()?;
    let active = r.u8()?;
    let endpoint = read_endpoint(r)?;
    r.done()?;
    check_maker_params(min, max, directions, spread_bps)?;
    req!(active <= 1, HkError::BadParam);
    transfer_in(auth, maker, system, add_bond)?;
    m.bond = add(m.bond, add_bond)?;
    if active == 1 {
        req!(!c.paused, HkError::Paused);
        req!(m.bond >= c.min_bond, HkError::BondTooSmall);
        m.withdraw_after = 0; // re-activating cancels a pending unbond
    }
    m.active = active == 1;
    m.min = min;
    m.max = max;
    m.directions = directions;
    m.spread_bps = spread_bps;
    m.endpoint = endpoint;
    m.store(&mut maker.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [authority (signer), maker (w), config]
fn request_unbond(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let auth = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    signer(auth)?;
    writable(maker)?;
    r.done()?;
    let c = load_config(config, pid)?;
    let mut m = load_maker(maker, pid)?;
    req!(m.authority == *auth.key, HkError::Unauthorized);
    m.active = false;
    m.withdraw_after = now()?.checked_add(c.unbond_secs).ok_or(HkError::Overflow)?;
    m.store(&mut maker.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [authority (signer, w), maker (w)]. Closes the maker account; bond + rent to authority.
fn withdraw_maker(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let auth = next_account_info(it)?;
    let maker = next_account_info(it)?;
    signer(auth)?;
    writable(maker)?;
    writable(auth)?;
    r.done()?;
    let m = load_maker(maker, pid)?;
    req!(m.authority == *auth.key, HkError::Unauthorized);
    req!(m.open_swaps == 0 && m.open_lamports == 0, HkError::OpenSwaps);
    req!(m.staked == 0, HkError::Staked); // unstake first, or the tokens would be stranded
    req!(!m.active && m.withdraw_after != 0 && now()? >= m.withdraw_after, HkError::BondLocked);
    close_account(maker, auth)
}

/// The exact bytes a maker signs to consent to one SOL->XMR lock. Binding every economic field
/// (and the escrow address) means a user cannot lock against a maker that never agreed, and a
/// maker cannot change terms after the fact.
pub fn consent_message(
    pid: &Pubkey,
    escrow: &Pubkey,
    locker: &Pubkey,
    claimer: &Pubkey,
    direction: u8,
    amount: u64,
    xmr_amount: u64,
    claim_point: &[u8; 32],
    refund_point: &[u8; 32],
    view_pub: &[u8; 32],
    quote_hash: &[u8; 32],
    t0_secs: i64,
    window_secs: i64,
    expiry: i64,
    fee_bps: u16,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(CONSENT_PREFIX.len() + 32 * 8 + 1 + 8 * 5);
    m.extend_from_slice(CONSENT_PREFIX);
    m.extend_from_slice(pid.as_ref());
    m.extend_from_slice(escrow.as_ref());
    m.extend_from_slice(locker.as_ref());
    m.extend_from_slice(claimer.as_ref());
    m.push(direction);
    m.extend_from_slice(&amount.to_le_bytes());
    m.extend_from_slice(&xmr_amount.to_le_bytes());
    m.extend_from_slice(claim_point);
    m.extend_from_slice(refund_point);
    m.extend_from_slice(view_pub);
    m.extend_from_slice(quote_hash);
    m.extend_from_slice(&t0_secs.to_le_bytes());
    m.extend_from_slice(&window_secs.to_le_bytes());
    m.extend_from_slice(&expiry.to_le_bytes());
    m.extend_from_slice(&fee_bps.to_le_bytes());
    m
}

/// v2 consent (flagged locks): the v1 fields plus flags, the pay link and both watchtowers.
pub fn consent_message_v2(
    pid: &Pubkey,
    escrow: &Pubkey,
    locker: &Pubkey,
    claimer: &Pubkey,
    direction: u8,
    amount: u64,
    xmr_amount: u64,
    claim_point: &[u8; 32],
    refund_point: &[u8; 32],
    view_pub: &[u8; 32],
    quote_hash: &[u8; 32],
    t0_secs: i64,
    window_secs: i64,
    expiry: i64,
    fee_bps: u16,
    flags: u8,
    link: &Pubkey,
    wt: &[Pubkey; 2],
) -> Vec<u8> {
    let mut m = consent_message(
        pid, escrow, locker, claimer, direction, amount, xmr_amount, claim_point, refund_point, view_pub,
        quote_hash, t0_secs, window_secs, expiry, fee_bps,
    );
    m.splice(0..CONSENT_PREFIX.len(), CONSENT_PREFIX_V2.iter().copied());
    m.push(flags);
    m.extend_from_slice(link.as_ref());
    m.extend_from_slice(wt[0].as_ref());
    m.extend_from_slice(wt[1].as_ref());
    m
}

/// The instruction right before this one must be an Ed25519 precompile check of exactly one
/// signature by `signer_key` over `msg`, with all data inline (no cross-instruction offsets).
fn require_ed25519(ixs: &AccountInfo, signer_key: &Pubkey, msg: &[u8]) -> ProgramResult {
    req!(*ixs.key == SYSVAR_INSTRUCTIONS, HkError::BadAccount);
    let cur = load_current_index_checked(ixs)? as usize;
    req!(cur > 0, HkError::NoConsent);
    let ix = load_instruction_at_checked(cur - 1, ixs)?;
    req!(ix.program_id == ED25519_PROGRAM, HkError::NoConsent);
    logic::ed25519_ix_binds(&ix.data, &signer_key.to_bytes(), msg)?;
    Ok(())
}

/// Load maker + config for an escrow and check they belong to it.
fn load_pair(e: &Escrow, maker: &AccountInfo, config: &AccountInfo, pid: &Pubkey) -> Result<(Maker, Config), ProgramError> {
    writable(maker)?;
    writable(config)?;
    let m = load_maker(maker, pid)?;
    req!(m.authority == e.maker, HkError::BadAccount);
    let c = load_config(config, pid)?;
    Ok((m, c))
}

/// Every term of a lock. `lock` (v1), `lock2` (flags) and `vault_lock` all parse into this.
struct LockReq {
    swap_id: [u8; 32],
    claimer: Pubkey,
    direction: u8,
    amount: u64,
    xmr_amount: u64,
    claim_point: [u8; 32],
    refund_point: [u8; 32],
    view_pub: [u8; 32],
    quote_hash: [u8; 32],
    t0_secs: i64,
    window_secs: i64,
    wt: [Pubkey; 2],
    consent_expiry: i64,
    flags: u8,
}

fn read_lock_req(r: &mut Rd, with_flags: bool) -> Result<LockReq, ProgramError> {
    let mut q = LockReq {
        swap_id: r.b32()?,
        claimer: r.key()?,
        direction: r.u8()?,
        amount: r.u64()?,
        xmr_amount: r.u64()?,
        claim_point: r.b32()?,
        refund_point: r.b32()?,
        view_pub: r.b32()?,
        quote_hash: r.b32()?,
        t0_secs: r.i64()?,
        window_secs: r.i64()?,
        wt: [r.key()?, r.key()?],
        consent_expiry: r.i64()?,
        flags: 0,
    };
    if with_flags {
        q.flags = r.u8()?;
    }
    r.done()?;
    Ok(q)
}

/// How the escrow is funded: a signing wallet (system transfer), or a vault PDA's lamports.
enum Funding<'a, 'b> {
    Wallet { locker: &'b AccountInfo<'a> },
    Vault { vault: &'b AccountInfo<'a> },
}

/// The checks and state changes shared by every lock. `locker_key` is the escrow's locker (a
/// wallet, or the vault PDA). The caller has already authorized the locker.
fn open_escrow<'a, 'b>(
    pid: &Pubkey,
    q: &LockReq,
    locker_key: &Pubkey,
    funding: Funding<'a, 'b>,
    escrow: &'b AccountInfo<'a>,
    maker: &'b AccountInfo<'a>,
    config: &'b AccountInfo<'a>,
    system: &'b AccountInfo<'a>,
    ixs: &'b AccountInfo<'a>,
    link: Option<&'b AccountInfo<'a>>,
) -> ProgramResult {
    writable(escrow)?;
    writable(maker)?;
    writable(config)?;
    let mut c = load_config(config, pid)?;
    let mut m = load_maker(maker, pid)?;
    // Pause, maker status/direction, who is locker/claimer, flags (extension required, OTC size
    // range and cap), open-TVL cap, windows.
    let tvl = logic::check_lock_terms(
        &c, &m, locker_key, &q.claimer, q.direction, q.amount, q.xmr_amount, q.t0_secs, q.window_secs, q.flags,
    )?;

    // PAY: the one-time spend half and view key are derived on chain from the link, so a payer
    // (or keeper) can never point the XMR anywhere but the link owner's key.
    let mut link_key = Pubkey::default();
    let mut link_state: Option<Link> = None;
    if logic::pay_shape(q.flags, q.direction)? {
        let la = link.ok_or(HkError::BadAccount)?;
        let l = load_link(la, pid)?;
        req!(!l.retired, HkError::BadState);
        let (ek, _) = Pubkey::find_program_address(&[SWAP_SEED, locker_key.as_ref(), &q.swap_id], pid);
        let (si, vi) = derive_pay(&l.master, &ek, &q.quote_hash)?;
        req!(q.refund_point == si && q.view_pub == vi, HkError::BadPoint);
        link_key = *la.key;
        link_state = Some(l);
    }
    // Reviewer #2: a pay escrow's refund reveals nothing, so a committee outage until t1 would
    // strand the maker's XMR; its claim window has an on-chain floor (and the link owner may say
    // `ready`, see `ready`).
    final_logic::proof_window_floor(q.flags, q.window_secs)?;
    req!(q.claim_point != q.refund_point, HkError::BadPoint);
    req!(point_is_prime_order(&q.claim_point), HkError::BadPoint);
    req!(point_is_prime_order(&q.refund_point), HkError::BadPoint);
    req!(point_is_prime_order(&q.view_pub), HkError::BadPoint);
    // A claimer must not be able to abort-then-race; a pay escrow needs a watchtower (the payer
    // cannot abort it) and the locker cannot be one.
    logic::check_watchtowers(&q.wt, &q.claimer, locker_key, q.flags)?;

    let (ek, eb) = Pubkey::find_program_address(&[SWAP_SEED, locker_key.as_ref(), &q.swap_id], pid);
    req!(ek == *escrow.key, HkError::BadPda);

    // Holder perk: a maker with >= holder_min $HALFKEY bonded (and no unstake pending) pays the
    // lower protocol fee. Bonded in a program vault, so it cannot be flash-borrowed for one tx.
    let fee_bps = logic::effective_fee_bps(&c, &m);

    let t = now()?;
    if q.direction == DIR_SOL_TO_XMR {
        req!(t <= q.consent_expiry, HkError::NoConsent);
        // The effective fee is part of the consent: omitting the holder account (or an admin fee
        // change between consent and lock) makes the signature not match. v2 also binds the
        // flags, the link and the watchtowers (a pay-mode maker trusts the watchtowers not to
        // abort a delivered swap, so it must agree to them).
        let msg = if q.flags == 0 {
            consent_message(
                pid, &ek, locker_key, &q.claimer, q.direction, q.amount, q.xmr_amount, &q.claim_point,
                &q.refund_point, &q.view_pub, &q.quote_hash, q.t0_secs, q.window_secs, q.consent_expiry, fee_bps,
            )
        } else {
            consent_message_v2(
                pid, &ek, locker_key, &q.claimer, q.direction, q.amount, q.xmr_amount, &q.claim_point,
                &q.refund_point, &q.view_pub, &q.quote_hash, q.t0_secs, q.window_secs, q.consent_expiry, fee_bps,
                q.flags, &link_key, &q.wt,
            )
        };
        // The maker signs sha256(consent_message): 32 bytes keeps the lock small enough to share a
        // transaction with a Jupiter route (sell any coin -> XMR in one signature).
        let digest = solana_sha256_hasher::hash(&msg).to_bytes();
        require_ed25519(ixs, &m.authority, &digest)?;
    }

    let seeds: &[&[u8]] = &[SWAP_SEED, locker_key.as_ref(), &q.swap_id, &[eb]];
    match funding {
        Funding::Wallet { locker } => {
            create_pda(locker, escrow, system, pid, ESCROW_LEN, seeds)?;
            transfer_in(locker, escrow, system, q.amount)?;
        }
        Funding::Vault { vault } => {
            // Rent and amount both come out of the vault (it gets the rent back at close).
            req!(*system.key == SYSTEM_PROGRAM, HkError::BadAccount);
            req!(escrow.data_len() == 0 && *escrow.owner == SYSTEM_PROGRAM, HkError::AlreadyInitialized);
            let need = Rent::get()?.minimum_balance(ESCROW_LEN);
            let top = need.saturating_sub(escrow.lamports());
            let keep = Rent::get()?.minimum_balance(VAULT_LEN);
            let total = logic::vault_funding(q.amount, top, vault.lamports(), keep)?;
            // Allocate + assign first (no lamports move through a CPI), then move the lamports
            // between two accounts this program owns.
            invoke_signed(
                &solana_system_interface::instruction::allocate(escrow.key, ESCROW_LEN as u64),
                &[escrow.clone(), system.clone()],
                &[seeds],
            )?;
            invoke_signed(
                &solana_system_interface::instruction::assign(escrow.key, pid),
                &[escrow.clone(), system.clone()],
                &[seeds],
            )?;
            pay(vault, escrow, total)?;
        }
    }

    let (t0, t1) = logic::deadlines(t, q.t0_secs, q.window_secs)?;
    let e = Escrow {
        state: ST_LOCKED,
        direction: q.direction,
        bump: eb,
        released: false,
        swap_id: q.swap_id,
        locker: *locker_key,
        claimer: q.claimer,
        maker: m.authority,
        amount: q.amount,
        xmr_amount: q.xmr_amount,
        fee_bps,
        claim_point: q.claim_point,
        refund_point: q.refund_point,
        view_pub: q.view_pub,
        quote_hash: q.quote_hash,
        watchtowers: q.wt,
        created_at: t,
        t0,
        t1,
        settled_at: 0,
        secret: [0; 32],
        flags: q.flags,
        link: link_key,
        v2: false,
        ext: EscrowExt::default(),
    };
    e.store(&mut escrow.try_borrow_mut_data()?);

    if let (Some(mut l), Some(la)) = (link_state, link) {
        l.payments = add(l.payments, 1)?;
        l.locked_lamports = add(l.locked_lamports, q.amount)?;
        l.store(&mut la.try_borrow_mut_data()?);
    }

    logic::open_counters(&mut m, &mut c, q.amount, tvl)?;
    m.store(&mut maker.try_borrow_mut_data()?);
    c.store(&mut config.try_borrow_mut_data()?);
    msg!("halfkey: locked");
    Ok(())
}

/// Accounts: [locker (signer, w), escrow (w), maker (w), config (w), system, instructions sysvar]
/// Data: swap_id 32, claimer 32, direction u8, amount u64, xmr_amount u64, claim_point 32,
///       refund_point 32, view_pub 32, quote_hash 32, t0_secs i64, window_secs i64, wt0 32, wt1 32,
///       consent_expiry i64.
/// SOL->XMR needs the maker's ed25519 consent over `consent_message` in the previous instruction.
/// XMR->SOL is locked by the maker itself, so its signature is the consent.
fn lock(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let locker = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    let system = next_account_info(it)?;
    let ixs = next_account_info(it)?;
    signer(locker)?;
    let q = read_lock_req(r, false)?;
    open_escrow(pid, &q, locker.key, Funding::Wallet { locker }, escrow, maker, config, system, ixs, None)
}

/// Accounts: [locker (signer, w), escrow (w), maker (w), config (w), system, instructions sysvar,
///            link (w; PAY only)]
/// Data: the `lock` data + flags u8. Flagged SOL->XMR locks need the maker's v2 consent.
fn lock2(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let locker = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    let system = next_account_info(it)?;
    let ixs = next_account_info(it)?;
    signer(locker)?;
    let q = read_lock_req(r, true)?;
    req!(q.flags & F_VAULT == 0, HkError::BadParam); // only vault_lock creates vault escrows
    let link = if q.flags & F_PAY != 0 {
        let l = next_account_info(it)?;
        writable(l)?;
        Some(l)
    } else {
        None
    };
    open_escrow(pid, &q, locker.key, Funding::Wallet { locker }, escrow, maker, config, system, ixs, link)
}

/// Accounts: [locker (signer), escrow (w)], or for a pay escrow [link owner (signer), escrow (w),
/// link]. Only the side that receives the XMR, having checked it, can shorten the wait. Nobody
/// else gets this power (it would need trust in their honesty).
fn ready(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let locker = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    signer(locker)?;
    writable(escrow)?;
    r.done()?;
    let mut e = load_escrow(escrow, pid)?;
    if e.flags & F_PAY != 0 {
        // A pay escrow's XMR belongs to the recipient: a payer saying "ready" could let a
        // colluding maker claim without delivering while the recipient sees "paid". The link
        // owner (the recipient) may, until t1, so a committee outage cannot strand the maker's
        // XMR when the recipient has it (reviewer #2).
        req!(e.locker != *locker.key, HkError::Unauthorized);
        let link = next_account_info(it)?;
        req!(*link.key == e.link, HkError::BadAccount);
        let l = load_link(link, pid)?;
        req!(l.owner == *locker.key, HkError::Unauthorized);
        final_logic::late_ready_window(e.state, e.t1, now)?;
    } else if e.flags & F_DIRECT != 0 {
        // Direct payout: the locker is the user whose own address receives the XMR; its word
        // releases the claim at any time before t1 (no refund could return the maker's XMR).
        req!(e.locker == *locker.key, HkError::Unauthorized);
        final_logic::late_ready_window(e.state, e.t1, now)?;
    } else {
        req!(e.locker == *locker.key, HkError::Unauthorized);
        logic::ready_window_late(e.state, e.t0, e.t1, e.flags, now)?; // late finish: until max(t0, t1 - margin)
    }
    e.state = ST_READY;
    e.store(&mut escrow.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [signer, escrow (w), maker (w), config (w)]. Freezes the escrow into refund-only
/// mode. Reveals nothing. Releases the open-swap counters.
///  * locker or a listed watchtower: only while Locked (not Ready) and before t0.
///  * claimer: any time before t1 while Locked/Ready (it only gives up its own claim).
fn abort(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let who = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    signer(who)?;
    writable(escrow)?;
    r.done()?;
    let mut e = load_escrow(escrow, pid)?;
    let (mut m, mut c) = load_pair(&e, maker, config, pid)?;
    let t = now()?;
    // Stats are about the MAKER: `declined` = the maker gave up, `cancelled` = the user did,
    // `aborted` = a watchtower did (maker no-show; the UI shows it separately because a locker
    // can list its own key as a watchtower).
    // A pay-mode locker never holds the XMR key, so its refund cannot hand the maker its XMR back:
    // only the (maker-consented) watchtowers may abort a pay escrow (logic::abort_check).
    // Direct payout (v2): only the claimer may abort (see final_logic::abort_check_v2).
    let kind = final_logic::abort_check_v2(&e, who.key, t)?;
    match kind {
        logic::AbortKind::Declined => m.declined = add(m.declined, 1)?,
        logic::AbortKind::Cancelled => m.cancelled = add(m.cancelled, 1)?,
        logic::AbortKind::Watchtower => m.aborted = add(m.aborted, 1)?,
    }
    // OTC / pay reputation: the maker declining as claimer, or a watchtower abort (no-show). An
    // XMR->SOL maker aborting as locker (the taker never deposited) does not count against it.
    if let Some(o) = logic::abort_ext_outcome(kind, *who.key == e.claimer) {
        logic::ext_count(&e, &mut m, o)?;
    }
    release(&mut e, &mut m, &mut c)?;
    e.state = ST_ABORTED;
    e.settled_at = t;
    e.store(&mut escrow.try_borrow_mut_data()?);
    m.store(&mut maker.try_borrow_mut_data()?);
    c.store(&mut config.try_borrow_mut_data()?);
    msg!("halfkey: aborted");
    Ok(())
}

/// Accounts: [claimer (signer, w), escrow (w), maker (w), config (w), fee_vault (w),
///            proof record (proof-mode escrow claimed without `ready` only)]. Data: secret.
/// Signer binding: only the claimer can submit the reveal, so it cannot be front-run.
fn claim(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let claimer = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    let vault = next_account_info(it)?;
    signer(claimer)?;
    writable(claimer)?;
    writable(escrow)?;
    writable(vault)?;
    let secret = r.b32()?;
    r.done()?;

    let mut e = load_escrow(escrow, pid)?;
    // v2 escrows settle through claim_to, which pays the integrator share and the tip.
    req!(!e.v2, HkError::BadAccount);
    let (mut m, mut c) = load_pair(&e, maker, config, pid)?;
    req!(e.claimer == *claimer.key, HkError::Unauthorized);
    let vk = Pubkey::create_program_address(&[FEE_VAULT_SEED, &[c.vault_bump]], pid)
        .map_err(|_| HkError::BadPda)?;
    req!(vk == *vault.key, HkError::BadPda);
    owned(vault, pid)?;
    let t = now()?;
    logic::claim_window(e.state, t, e.t0, e.t1)?;
    // v1.5: a SOL->XMR (or proof-mode) escrow the locker did not mark Ready needs a recorded
    // Monero payment proof of this escrow for at least its amount. No claim on the maker's word.
    let rec = if zkproof::proof_allowed(e.direction, e.flags) && e.state == ST_LOCKED {
        Some(zkproof::load_proof(next_account_info(it)?, pid, &e)?)
    } else {
        None
    };
    zkproof::claim_gate(&e, escrow.key, rec.as_ref())?;
    check_reveal(&secret, &e.claim_point)?;

    let (to_claimer, fee) = logic::split_fee(e.amount, e.fee_bps)?;
    pay(escrow, claimer, to_claimer)?;
    pay(escrow, vault, fee)?;

    release(&mut e, &mut m, &mut c)?;
    e.state = ST_CLAIMED;
    e.secret = secret;
    e.settled_at = t;
    e.store(&mut escrow.try_borrow_mut_data()?);

    m.completed = add(m.completed, 1)?;
    m.volume = add(m.volume, e.amount)?;
    logic::ext_count(&e, &mut m, logic::Outcome::Fill)?;
    m.store(&mut maker.try_borrow_mut_data()?);

    c.total_swaps = add(c.total_swaps, 1)?;
    c.total_volume = add(c.total_volume, e.amount)?;
    c.total_fees = add(c.total_fees, fee)?;
    c.store(&mut config.try_borrow_mut_data()?);
    msg!("halfkey: claimed");
    Ok(())
}

/// Accounts: [anyone (signer), escrow (w), maker (w), config (w)].
/// Permissionless bookkeeping after t1: releases the counters of a swap nobody claimed (so an
/// absent locker cannot pin the maker's bond or the global cap) and marks the maker expired.
/// The escrow stays refund-only; the SOL can still only go to the locker.
fn expire(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let who = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    signer(who)?;
    writable(escrow)?;
    r.done()?;
    let mut e = load_escrow(escrow, pid)?;
    logic::expire_window(e.state, e.released, e.t1, now)?;
    let (mut m, mut c) = load_pair(&e, maker, config, pid)?;
    release(&mut e, &mut m, &mut c)?;
    m.expired = add(m.expired, 1)?;
    logic::ext_count(&e, &mut m, logic::Outcome::Failed)?;
    e.store(&mut escrow.try_borrow_mut_data()?);
    m.store(&mut maker.try_borrow_mut_data()?);
    c.store(&mut config.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [payer (signer), escrow (w), locker (w), maker (w), config (w)]. Data: secret.
/// Anyone may submit (gasless relay); the SOL can only go to the locker. Reveals the locker's
/// half so the other side can take its XMR back. When the counters were already released
/// (abort/expire), the maker and config accounts are not read, so a refund never depends on the
/// maker account still existing.
fn refund(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let payer = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let locker = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    signer(payer)?;
    writable(escrow)?;
    writable(locker)?;
    let secret = r.b32()?;
    r.done()?;

    let mut e = load_escrow(escrow, pid)?;
    req!(e.locker == *locker.key, HkError::BadAccount);
    let t = now()?;
    logic::refund_window(e.state, t, e.t1)?;
    // Pay mode: the locker never knew the XMR key half (it is the recipient's), so nothing is
    // revealed. Passing a secret is an error, so no client can leak one by mistake. The same for
    // direct payout (the "refund point" is the user's own address key).
    final_logic::refund_secret_v2(e.flags, &secret, &e.refund_point, |s| {
        multiply_edwards(&PodScalar(*s), &PodEdwardsPoint(G)).map(|p| p.0)
    })?;

    if !e.released {
        let (mut m, mut c) = load_pair(&e, maker, config, pid)?;
        release(&mut e, &mut m, &mut c)?;
        m.expired = add(m.expired, 1)?;
        logic::ext_count(&e, &mut m, logic::Outcome::Failed)?;
        m.store(&mut maker.try_borrow_mut_data()?);
        c.store(&mut config.try_borrow_mut_data()?);
    }
    if e.flags & F_VAULT != 0 {
        let mut v = load_vault(locker, pid)?;
        v.refunds = add(v.refunds, 1)?;
        v.refunded_lamports = add(v.refunded_lamports, e.amount)?;
        v.store(&mut locker.try_borrow_mut_data()?);
    }
    pay(escrow, locker, e.amount)?;
    if e.v2 {
        // Finisher tip: whoever submits the refund (permissionless) is paid for it.
        writable(payer)?;
        pay(escrow, payer, e.ext.tip)?;
    }
    e.state = ST_REFUNDED;
    e.secret = secret;
    e.settled_at = t;
    e.store(&mut escrow.try_borrow_mut_data()?);
    msg!("halfkey: refunded");
    Ok(())
}


/// Accounts: [locker (signer, w), escrow (w)]. Reclaims the escrow rent after settlement.
/// The revealed secret stays readable in the transaction history.
/// v2 escrows: [anyone (signer), escrow (w), locker (w)] for direct payout (nothing to keep
/// readable; an order escrow only after the order's deadline), else the locker as above.
fn close(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let locker = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    signer(locker)?;
    writable(escrow)?;
    r.done()?;
    let e = load_escrow(escrow, pid)?;
    if e.v2 {
        let dest = if e.flags & F_DIRECT != 0 { next_account_info(it)? } else { locker };
        writable(dest)?;
        req!(e.locker == *dest.key, HkError::Unauthorized);
        final_logic::close_v2_allowed(e.state, e.flags, *locker.key == e.locker, e.ext.order_deadline, now)?;
        return close_account(escrow, dest);
    }
    writable(locker)?;
    req!(e.locker == *locker.key, HkError::Unauthorized);
    logic::close_allowed(e.state, e.flags)?; // pay escrows close via close_pay
    close_account(escrow, locker)
}

/// Accounts: [who (signer), escrow (w), locker (w, rent destination), link].
/// A claimed pay escrow carries the maker's revealed half, which the recipient needs to collect
/// from any device, so early close is the recipient's call (the link owner, after collecting).
/// The locker (anyone, for a vault) may reclaim the rent after PAY_CLOSE_GRACE, or at once when
/// refunded (nothing to collect). Rent always goes to the locker.
fn close_pay(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let who = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let locker = next_account_info(it)?;
    let link = next_account_info(it)?;
    signer(who)?;
    writable(escrow)?;
    writable(locker)?;
    r.done()?;
    let e = load_escrow(escrow, pid)?;
    req!(e.flags & F_PAY != 0, HkError::BadState);
    req!(e.locker == *locker.key, HkError::BadAccount);
    req!(e.link == *link.key, HkError::BadAccount);
    let l = load_link(link, pid)?;
    logic::close_pay_allowed(e.state, e.flags, *who.key == e.locker, *who.key == l.owner, e.settled_at, now)?;
    close_account(escrow, locker)
}

/// Accounts: [anyone (signer), config, fee_vault (w), fee_recipient (w)].
/// Moves accumulated protocol fees to the configured buyback-and-burn wallet. Permissionless:
/// the destination is fixed in config.
fn sweep_fees(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let who = next_account_info(it)?;
    let config = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let dest = next_account_info(it)?;
    signer(who)?;
    writable(vault)?;
    writable(dest)?;
    r.done()?;
    let c = load_config(config, pid)?;
    let vk = Pubkey::create_program_address(&[FEE_VAULT_SEED, &[c.vault_bump]], pid)
        .map_err(|_| HkError::BadPda)?;
    req!(vk == *vault.key, HkError::BadPda);
    owned(vault, pid)?;
    // Once the burn auction is on (burn.rs), fees leave the vault only by being burned.
    burn::sweep_allowed(vault.data_len())?;
    req!(*dest.key == c.fee_recipient, HkError::BadAccount);
    let keep = Rent::get()?.minimum_balance(0);
    let amt = vault.lamports().saturating_sub(keep);
    pay(vault, dest, amt)
}

// ---------------------------------------------------------------------------------------------
// Platform: config extension, maker extension, pay links, cashout vaults
// ---------------------------------------------------------------------------------------------

/// Accounts: [admin (signer), config (w)]. Data: otc_max_swap u64, vault_min_delay i64.
fn set_config_ext(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let admin = next_account_info(it)?;
    let config = next_account_info(it)?;
    signer(admin)?;
    writable(config)?;
    let otc_max_swap = r.u64()?;
    let vault_min_delay = r.i64()?;
    r.done()?;
    let mut c = load_config(config, pid)?;
    req!(c.admin == *admin.key, HkError::Unauthorized);
    logic::check_config_ext(&c, otc_max_swap, vault_min_delay)?;
    c.otc_max_swap = otc_max_swap;
    c.vault_min_delay = vault_min_delay;
    c.store(&mut config.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [authority (signer, w), maker (w), system]. Data: otc_min u64, otc_max u64.
/// Grows the maker account to MAKER_LEN_V2 on first use (the authority pays the extra rent) and
/// sets the OTC tranche range (otc_max = 0: OTC uses the normal min/max).
fn upgrade_maker(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let auth = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(auth)?;
    writable(auth)?;
    writable(maker)?;
    let otc_min = r.u64()?;
    let otc_max = r.u64()?;
    r.done()?;
    logic::check_otc_range(otc_min, otc_max)?;
    let mut m = load_maker(maker, pid)?;
    req!(m.authority == *auth.key, HkError::Unauthorized);
    if !m.v2 {
        // Rent for the extra bytes, on top of what the account holds (bond included).
        let rent = Rent::get()?;
        let extra = rent.minimum_balance(MAKER_LEN_V2).saturating_sub(rent.minimum_balance(MAKER_LEN));
        transfer_in(auth, maker, system, extra)?;
        maker.resize(MAKER_LEN_V2)?;
        m.v2 = true;
    }
    m.ext.otc_min = otc_min;
    m.ext.otc_max = otc_max;
    m.store(&mut maker.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [owner (signer, w), link (w), system]. Data: name_len u8, name, master 32.
/// `/pay/<name>` -> master point S. First come, first served; immutable afterwards.
fn register_link(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let link = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(owner)?;
    writable(link)?;
    let n = r.u8()? as usize;
    let name = r.take(n)?.to_vec();
    let master = r.b32()?;
    r.done()?;
    logic::check_link_name(&name)?;
    req!(point_is_prime_order(&master), HkError::BadPoint);
    let (lk, lb) = Pubkey::find_program_address(&[LINK_SEED, &name], pid);
    req!(lk == *link.key, HkError::BadPda);
    create_pda(owner, link, system, pid, LINK_LEN, &[LINK_SEED, &name, &[lb]])?;
    let l = Link { bump: lb, name, owner: *owner.key, master, created_at: now()?, ..Default::default() };
    l.store(&mut link.try_borrow_mut_data()?);
    msg!("halfkey: link registered");
    Ok(())
}

/// Accounts: [owner (signer), link (w)]. One-way: the link takes no new payments or vault
/// conversions (if the wallet root ever leaks). Payments already open settle as usual.
fn retire_link(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let link = next_account_info(it)?;
    signer(owner)?;
    writable(link)?;
    r.done()?;
    let mut l = load_link(link, pid)?;
    req!(l.owner == *owner.key, HkError::Unauthorized);
    l.retired = true;
    l.store(&mut link.try_borrow_mut_data()?);
    Ok(())
}

/// The link must exist and belong to the vault owner (payments can only ever reach the owner).
fn check_vault_link(pid: &Pubkey, owner: &Pubkey, p: &VaultParams, link: &AccountInfo) -> ProgramResult {
    req!(*link.key == p.link, HkError::BadAccount);
    let l = load_link(link, pid)?;
    req!(l.owner == *owner, HkError::Unauthorized);
    for w in p.watchtowers.iter() {
        req!(w != owner, HkError::BadParam);
    }
    Ok(())
}

/// Accounts: [owner (signer, w), vault (w), link, config, system]. Data: VaultParams.
fn vault_create(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let link = next_account_info(it)?;
    let config = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(owner)?;
    writable(vault)?;
    let p = read_vp(r)?;
    r.done()?;
    let c = load_config(config, pid)?;
    req!(!c.paused, HkError::Paused);
    logic::check_vault_params(&c, &p)?;
    check_vault_link(pid, owner.key, &p, link)?;
    let (vk, vb) = Pubkey::find_program_address(&[VAULT_SEED, owner.key.as_ref()], pid);
    req!(vk == *vault.key, HkError::BadPda);
    create_pda(owner, vault, system, pid, VAULT_LEN, &[VAULT_SEED, owner.key.as_ref(), &[vb]])?;
    let t = now()?;
    let v = Vault { bump: vb, owner: *owner.key, p, next_at: t, created_at: t, ..Default::default() };
    v.store(&mut vault.try_borrow_mut_data()?);
    msg!("halfkey: vault created");
    Ok(())
}

fn owner_vault(pid: &Pubkey, owner: &AccountInfo, vault: &AccountInfo) -> Result<Vault, ProgramError> {
    signer(owner)?;
    writable(vault)?;
    let v = load_vault(vault, pid)?;
    req!(v.owner == *owner.key, HkError::Unauthorized);
    Ok(v)
}

/// Accounts: [owner (signer), vault (w), link (the proposed one), config]. Data: VaultParams.
/// Starts the timelock; replaces any earlier proposal.
fn vault_propose(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let link = next_account_info(it)?;
    let config = next_account_info(it)?;
    let mut v = owner_vault(pid, owner, vault)?;
    let p = read_vp(r)?;
    let unpause = r.u8()?;
    r.done()?;
    req!(unpause <= 1, HkError::BadParam);
    let c = load_config(config, pid)?;
    logic::check_vault_params(&c, &p)?;
    check_vault_link(pid, owner.key, &p, link)?;
    // The CURRENT delay applies (a proposal cannot shorten its own wait).
    logic::vault_propose(&mut v, p, unpause == 1, now()?)?;
    v.store(&mut vault.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [anyone (signer), vault (w)]. Applies a proposal once its timelock has passed.
fn vault_apply(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let who = next_account_info(it)?;
    let vault = next_account_info(it)?;
    signer(who)?;
    writable(vault)?;
    r.done()?;
    let mut v = load_vault(vault, pid)?;
    logic::vault_apply(&mut v, now)?;
    v.store(&mut vault.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [owner (signer), vault (w)]. Drops a pending proposal and a pending withdrawal.
fn vault_cancel(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let mut v = owner_vault(pid, owner, vault)?;
    r.done()?;
    logic::vault_cancel(&mut v);
    v.store(&mut vault.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [owner (signer), vault (w)]. Data: paused u8, min_rate u64, max_lamports u64, interval i64.
/// Instant, but only in the safe direction: pause, raise the price floor, lower the size cap, slow
/// the schedule. Anything else (unpausing included) goes through the timelock.
fn vault_tighten(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let mut v = owner_vault(pid, owner, vault)?;
    let paused = r.u8()?;
    let min_rate = r.u64()?;
    let max_lamports = r.u64()?;
    let interval = r.i64()?;
    r.done()?;
    logic::vault_tighten(&mut v, paused, min_rate, max_lamports, interval)?;
    v.store(&mut vault.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [keeper (signer), vault (w), escrow (w), maker (w), config (w), link (w), system,
///            instructions sysvar]
/// Data: swap_id 32, amount u64, xmr_amount u64, claim_point 32, quote_hash 32, t0_secs i64,
///       window_secs i64, consent_expiry i64.
/// Converts vault SOL into a pay-mode escrow. Everything that decides where value goes is fixed by
/// the vault, not the keeper: the XMR key derives from the owner's link, the watchtowers are the
/// owner's, the price is at or above the owner's floor, refunds return to the vault.
fn vault_lock(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let keeper = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let escrow = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let config = next_account_info(it)?;
    let link = next_account_info(it)?;
    let system = next_account_info(it)?;
    let ixs = next_account_info(it)?;
    signer(keeper)?;
    writable(vault)?;
    writable(link)?;
    let swap_id = r.b32()?;
    let amount = r.u64()?;
    let xmr_amount = r.u64()?;
    let claim_point = r.b32()?;
    let quote_hash = r.b32()?;
    let t0_secs = r.i64()?;
    let window_secs = r.i64()?;
    let consent_expiry = r.i64()?;
    r.done()?;
    let mut v = load_vault(vault, pid)?;
    // Not paused, a named keeper (or the owner), due, size range, price floor (piconero per SOL).
    let t = logic::vault_lock_terms(&v, keeper.key, now, amount, xmr_amount)?;
    req!(*link.key == v.p.link, HkError::BadAccount);
    let l = load_link(link, pid)?;
    req!(l.owner == v.owner, HkError::Unauthorized);
    let (ek, _) = Pubkey::find_program_address(&[SWAP_SEED, vault.key.as_ref(), &swap_id], pid);
    let (si, vi) = derive_pay(&l.master, &ek, &quote_hash)?;
    let m = load_maker(maker, pid)?;
    let q = LockReq {
        swap_id,
        claimer: m.authority,
        direction: DIR_SOL_TO_XMR,
        amount,
        xmr_amount,
        claim_point,
        refund_point: si,
        view_pub: vi,
        quote_hash,
        t0_secs,
        window_secs,
        wt: v.p.watchtowers,
        consent_expiry,
        flags: F_PAY | F_VAULT,
    };
    drop(m);
    open_escrow(pid, &q, vault.key, Funding::Vault { vault }, escrow, maker, config, system, ixs, Some(link))?;
    // open_escrow moved lamports out of the vault (its data is unchanged).
    logic::vault_converted(&mut v, t, amount)?;
    v.store(&mut vault.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [owner (signer), vault (w)]. Data: amount u64. Starts the withdrawal timelock.
fn vault_withdraw_request(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let mut v = owner_vault(pid, owner, vault)?;
    let amount = r.u64()?;
    r.done()?;
    logic::vault_withdraw_request(&mut v, amount, now)?;
    v.store(&mut vault.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [owner (signer, w), vault (w)]. Pays the requested amount (or what is free) to the
/// owner itself, never anywhere else.
fn vault_withdraw(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let vault = next_account_info(it)?;
    writable(owner)?;
    let mut v = owner_vault(pid, owner, vault)?;
    r.done()?;
    logic::vault_withdraw_due(&v, now)?;
    let keep = Rent::get()?.minimum_balance(VAULT_LEN);
    let amt = logic::vault_withdraw_take(&mut v, vault.lamports(), keep);
    v.store(&mut vault.try_borrow_mut_data()?);
    pay(vault, owner, amt)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical() {
        assert!(!scalar_is_canonical(&L));
        assert!(scalar_is_canonical(&L_MINUS_1));
        let mut over = L;
        over[0] += 1;
        assert!(!scalar_is_canonical(&over));
        assert!(scalar_is_canonical(&[0u8; 32]));
    }
    #[test]
    fn layouts_roundtrip() {
        let mut d = vec![0u8; ESCROW_LEN];
        let e = Escrow { state: 2, direction: 1, amount: 7, t1: -3, ..Default::default() };
        e.store(&mut d);
        let e2 = Escrow::load(&d).unwrap();
        assert_eq!(e2.amount, 7);
        assert_eq!(e2.t1, -3);
        let mut d = vec![0u8; MAKER_LEN];
        let m = Maker { endpoint: b"https://x".to_vec(), spread_bps: 5, ..Default::default() };
        m.store(&mut d);
        assert_eq!(Maker::load(&d).unwrap().endpoint, b"https://x");
        let mut d = vec![0u8; CONFIG_LEN];
        let c = Config { fee_bps: 50, total_fees: 9, ..Default::default() };
        c.store(&mut d);
        let c2 = Config::load(&d).unwrap();
        assert_eq!(c2.fee_bps, 50);
        assert_eq!(c2.total_fees, 9);
        // platform layouts
        let mut d = vec![0u8; ESCROW_LEN];
        let e = Escrow { flags: F_PAY | F_VAULT, link: Pubkey::new_from_array([7; 32]), secret: [1; 32], ..Default::default() };
        e.store(&mut d);
        let e2 = Escrow::load(&d).unwrap();
        assert_eq!(e2.flags, F_PAY | F_VAULT);
        assert_eq!(e2.link, Pubkey::new_from_array([7; 32]));
        assert_eq!(e2.secret, [1; 32]);
        let mut d = vec![0u8; MAKER_LEN_V2];
        let m = Maker { v2: true, ext: MakerExt { otc_fills: 3, pay_declined: 4, otc_max: 9, ..Default::default() }, endpoint: b"e".to_vec(), ..Default::default() };
        m.store(&mut d);
        let m2 = Maker::load(&d).unwrap();
        assert!(m2.v2);
        assert_eq!((m2.ext.otc_fills, m2.ext.pay_declined, m2.ext.otc_max), (3, 4, 9));
        let mut d = vec![0u8; MAKER_LEN];
        m.store(&mut d); // a v1 account never gets the extension written past its end
        assert!(!Maker::load(&d).unwrap().v2);
        let mut d = vec![0u8; VAULT_LEN];
        let v = Vault { owner: Pubkey::new_from_array([2; 32]), refunded_lamports: 5, pending: VaultParams { delay: 7, ..Default::default() }, ..Default::default() };
        v.store(&mut d);
        let v2 = Vault::load(&d).unwrap();
        assert_eq!(v2.refunded_lamports, 5);
        assert_eq!(v2.pending.delay, 7);
        let mut d = vec![0u8; LINK_LEN];
        let l = Link { name: b"shop".to_vec(), master: [9; 32], payments: 2, ..Default::default() };
        l.store(&mut d);
        let l2 = Link::load(&d).unwrap();
        assert_eq!(l2.name, b"shop");
        assert_eq!(l2.payments, 2);
    }
    /// Every hand-typed program / sysvar id equals its crate constant (a Token-2022 typo, "P7"
    /// instead of "P5", shipped in the base and would have rejected every Token-2022 mint).
    #[test]
    fn program_ids_match_crates() {
        let b = |k: &Pubkey| k.to_bytes();
        assert_eq!(b(&SYSTEM_PROGRAM), solana_sdk_ids::system_program::ID.to_bytes());
        assert_eq!(b(&BPF_UPGRADEABLE_LOADER), solana_sdk_ids::bpf_loader_upgradeable::ID.to_bytes());
        assert_eq!(b(&ED25519_PROGRAM), solana_sdk_ids::ed25519_program::ID.to_bytes());
        assert_eq!(b(&SYSVAR_INSTRUCTIONS), solana_sdk_ids::sysvar::instructions::ID.to_bytes());
        assert_eq!(b(&TOKEN_PROGRAM), spl_generic_token::token::ID.to_bytes());
        assert_eq!(b(&TOKEN_2022_PROGRAM), spl_generic_token::token_2022::ID.to_bytes());
        assert_eq!(b(&ATA_PROGRAM), spl_generic_token::associated_token_account::ID.to_bytes());
    }
    /// The same ids hand-typed in the clients (SDK, e2e, web): any base58 literal that starts like
    /// a well-known id must be exactly that id. JUP v6, Memo v2 and USDC match the live Jupiter
    /// API fixtures in sdk/fixtures (checked here as literals).
    #[test]
    fn client_program_ids_match() {
        use spl_generic_token::{associated_token_account as ata, token, token_2022};
        let canon: Vec<(&str, String)> = vec![
            ("Tokenz", token_2022::ID.to_string()),
            ("Tokenkeg", token::ID.to_string()),
            ("ATokenG", ata::ID.to_string()),
            ("So1111", token::native_mint::ID.to_string()),
            ("Ed25519Sig", solana_sdk_ids::ed25519_program::ID.to_string()),
            ("BPFLoaderUpgradeab", solana_sdk_ids::bpf_loader_upgradeable::ID.to_string()),
            ("Sysvar1nstr", solana_sdk_ids::sysvar::instructions::ID.to_string()),
            ("SysvarC1ock", solana_sdk_ids::sysvar::clock::ID.to_string()),
            ("ComputeBudget", solana_sdk_ids::compute_budget::ID.to_string()),
            ("JUP6", "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4".to_string()),
            ("MemoSq", "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr".to_string()),
            ("EPjFWdd5", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v".to_string()),
        ];
        let files = [
            ("sdk/program.ts", include_str!("../../sdk/program.ts")),
            ("sdk/jupiter.ts", include_str!("../../sdk/jupiter.ts")),
            ("sdk/jupiter.test.ts", include_str!("../../sdk/jupiter.test.ts")),
            ("sdk/v15.ts", include_str!("../../sdk/v15.ts")),
            ("sdk/taker.ts", include_str!("../../sdk/taker.ts")),
            ("sdk/final.ts", include_str!("../../sdk/final.ts")),
            ("sdk/stealth.ts", include_str!("../../sdk/stealth.ts")),
            ("e2e/bootstrap.ts", include_str!("../../e2e/bootstrap.ts")),
            ("e2e/anytoken.test.ts", include_str!("../../e2e/anytoken.test.ts")),
            ("e2e/immutability.ts", include_str!("../../e2e/immutability.ts")),
            ("e2e/program.test.ts", include_str!("../../e2e/program.test.ts")),
            ("web/src/client/env.ts", include_str!("../../web/src/client/env.ts")),
            ("program/src/lib.rs", include_str!("lib.rs")),
        ];
        let b58 = |c: char| c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l');
        let mut seen = 0;
        for (name, src) in files {
            for w in src.split(|c: char| !b58(c)).filter(|w| (32..=44).contains(&w.len())) {
                for (prefix, c) in &canon {
                    if w.starts_with(prefix) {
                        assert_eq!(w, c, "{name}: {w} is not the canonical {prefix}... id");
                        seen += 1;
                    }
                }
            }
        }
        assert!(seen >= 15, "id scan found only {seen} literals");
    }
    #[test]
    fn tweak_is_canonical() {
        for i in 0..64u8 {
            let t = pay_tweak(PAY_SPEND_DOMAIN, &[i; 32], &[i.wrapping_mul(7); 32], &[i ^ 0x5a; 32]);
            assert!(scalar_is_canonical(&t));
            assert!(t[31] < 0x10);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// $HALFKEY maker bond (stake)
// ---------------------------------------------------------------------------------------------

/// The vault is the associated token account of the per-maker stake PDA ["stake", authority].
/// Works for SPL Token and Token-2022 mints (TransferChecked; ATA program sizes the account).
struct StakeAccounts<'a, 'b> {
    mint: &'b AccountInfo<'a>,
    token_program: &'b AccountInfo<'a>,
    owner_bump: u8,
    decimals: u8,
}

fn stake_accounts<'a, 'b>(
    pid: &Pubkey,
    expected_mint: &Pubkey,
    authority: &Pubkey,
    mint: &'b AccountInfo<'a>,
    vault: &'b AccountInfo<'a>,
    owner: &'b AccountInfo<'a>,
    token_program: &'b AccountInfo<'a>,
) -> Result<StakeAccounts<'a, 'b>, ProgramError> {
    req!(*expected_mint != Pubkey::default() && *mint.key == *expected_mint, HkError::BadAccount);
    req!(*token_program.key == TOKEN_PROGRAM || *token_program.key == TOKEN_2022_PROGRAM, HkError::BadAccount);
    req!(mint.owner == token_program.key, HkError::BadAccount);
    let (ok, ob) = Pubkey::find_program_address(&[STAKE_SEED, authority.as_ref()], pid);
    req!(ok == *owner.key, HkError::BadPda);
    let (vk, _) = Pubkey::find_program_address(
        &[ok.as_ref(), token_program.key.as_ref(), mint.key.as_ref()],
        &ATA_PROGRAM,
    );
    req!(vk == *vault.key, HkError::BadPda);
    let decimals = {
        let d = mint.try_borrow_data()?;
        req!(d.len() >= 82, HkError::BadAccount);
        d[44]
    };
    Ok(StakeAccounts { mint, token_program, owner_bump: ob, decimals })
}

fn token_amount(a: &AccountInfo) -> Result<u64, ProgramError> {
    let d = a.try_borrow_data()?;
    req!(d.len() >= 72, HkError::BadAccount);
    Ok(u64::from_le_bytes(d[64..72].try_into().unwrap()))
}

fn transfer_checked<'a>(
    sa: &StakeAccounts<'a, '_>,
    from: &AccountInfo<'a>,
    to: &AccountInfo<'a>,
    authority: &AccountInfo<'a>,
    amount: u64,
    seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = Vec::with_capacity(10);
    data.push(12u8); // TransferChecked
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(sa.decimals);
    let ix = solana_instruction::Instruction {
        program_id: *sa.token_program.key,
        accounts: vec![
            solana_instruction::AccountMeta::new(*from.key, false),
            solana_instruction::AccountMeta::new_readonly(*sa.mint.key, false),
            solana_instruction::AccountMeta::new(*to.key, false),
            solana_instruction::AccountMeta::new_readonly(*authority.key, true),
        ],
        data,
    };
    let infos = [from.clone(), sa.mint.clone(), to.clone(), authority.clone(), sa.token_program.clone()];
    if seeds.is_empty() { invoke_signed(&ix, &infos, &[]) } else { invoke_signed(&ix, &infos, &[seeds]) }
}

// Kani proof harnesses (declared last so `req!` is in scope). `cargo kani --features no-entrypoint`.
// v1.5: Monero payment proofs and the burn auction.
pub mod xmr;
pub mod zkproof;
pub mod burn;
pub mod rewards;

#[cfg(kani)]
mod proofs;
#[cfg(kani)]
mod proofs_v15;
#[cfg(any(kani, test))]
mod model;
#[cfg(test)]
mod fuzz;
#[cfg(test)]
mod fuzz_v15;

// Final round: v2 escrows (integrator share, tips, claim_to, direct payout), deposit orders,
// direct payment proofs with a payment id, open offers. Pure rules in final_logic.rs.
pub mod final_logic;
pub mod escrow2;
pub mod deposit;
pub mod direct;
pub mod offer;
#[cfg(any(kani, test))]
mod model2;
#[cfg(kani)]
mod proofs_final;
#[cfg(test)]
mod fuzz_final;

// HTLC kind (SOL <-> transparent ZEC): handlers, its lifecycle model, Kani harnesses, proptests.
pub mod htlc;
#[cfg(any(kani, test))]
mod htlc_model;
#[cfg(kani)]
mod htlc_proofs;
#[cfg(test)]
mod htlc_fuzz;
