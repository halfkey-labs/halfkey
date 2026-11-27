//! Pure decision and accounting logic of the HALFKEY escrow, extracted from the instruction
//! handlers so it can be model-checked (Kani) and fuzzed (proptest) without a Solana runtime.
//!
//! Every function here is called by the handlers in `lib.rs`, in the same order as the inline
//! checks it replaced, and returns the same error codes. The handlers keep everything that
//! touches accounts, sysvars, CPIs and curve syscalls. `src/proofs.rs` proves each function
//! equivalent to a verbatim copy of the pre-refactor inline code: the phase-1 code (git d00f39f)
//! for unflagged escrows, and the platform branch's inline code (git 3f2d99e) for pay links, OTC
//! tranches and cashout vaults.

use crate::{
    Config, Escrow, HkError, Maker, Vault, VaultParams, DIR_SOL_TO_XMR, DIR_XMR_TO_SOL, F_ALL,
    F_OTC, F_PAY, F_VAULT, F_READY_ONLY, L, PAY_CLOSE_GRACE, ST_ABORTED, ST_CLAIMED, ST_LOCKED, ST_READY,
    ST_REFUNDED,
};
use solana_pubkey::Pubkey;

/// `s < L` (little-endian). The syscall reduces scalars mod L, so this must be checked first or
/// `s + L` would be accepted as an alias of `s`.
pub fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if s[i] != L[i] {
            return s[i] < L[i];
        }
    }
    false
}

/// `secret` is canonical and `mul_g(secret) == point`, where `mul_g` is `s*G` (the curve25519
/// syscall in the program). The canonical check runs first and short-circuits.
pub fn check_reveal_with<F>(secret: &[u8; 32], point: &[u8; 32], mul_g: F) -> Result<(), HkError>
where
    F: FnOnce(&[u8; 32]) -> Option<[u8; 32]>,
{
    if !scalar_is_canonical(secret) {
        return Err(HkError::NonCanonicalScalar);
    }
    let got = mul_g(secret).ok_or(HkError::BadPoint)?;
    if got != *point {
        return Err(HkError::WrongSecret);
    }
    Ok(())
}

/// Lamports moved by `pay`: new (from, to) balances. Checked on both sides.
pub fn pay_amounts(from: u64, to: u64, lamports: u64) -> Result<(u64, u64), HkError> {
    let f = from.checked_sub(lamports).ok_or(HkError::Overflow)?;
    let t = to.checked_add(lamports).ok_or(HkError::Overflow)?;
    Ok((f, t))
}

/// `floor(amount * bps / 10_000)`, truncated to u64: the original inline fee expression,
/// unchanged. A separate function so Kani harnesses can replace the 128-bit divider by the
/// definition of unsigned division (`proofs::spec_bps_of`).
pub fn bps_of(amount: u64, bps: u16) -> u64 {
    ((amount as u128) * (bps as u128) / 10_000) as u64
}

/// Claim payout split: (to_claimer, fee). `fee = floor(amount * fee_bps / 10_000)`.
pub fn split_fee(amount: u64, fee_bps: u16) -> Result<(u64, u64), HkError> {
    let fee = bps_of(amount, fee_bps);
    let to_claimer = amount.checked_sub(fee).ok_or(HkError::Overflow)?;
    Ok((to_claimer, fee))
}

/// Fee copied into the escrow at lock: the holder fee while the maker has `holder_min` $HALFKEY
/// bonded with no unstake pending, otherwise the base fee.
pub fn effective_fee_bps(c: &Config, m: &Maker) -> u16 {
    if c.halfkey_mint != Pubkey::default() && m.staked >= c.holder_min && m.stake_unlock_at == 0 {
        c.holder_fee_bps
    } else {
        c.fee_bps
    }
}

/// Per-escrow cap: OTC tranches use `otc_max_swap` when the admin set one.
pub fn cap_for(c: &Config, flags: u8) -> u64 {
    if flags & F_OTC != 0 && c.otc_max_swap > 0 {
        c.otc_max_swap
    } else {
        c.max_swap
    }
}

/// Size range the maker takes: its OTC range for OTC tranches (when set), else min..max.
pub fn amount_range(m: &Maker, flags: u8) -> (u64, u64) {
    if flags & F_OTC != 0 && m.ext.otc_max > 0 {
        (m.ext.otc_min, m.ext.otc_max)
    } else {
        (m.min, m.max)
    }
}

/// Lock checks that need no curve math: pause, maker status and direction, flags (known bits
/// only; a flagged escrow needs the maker extension), who may be locker and claimer, amount range,
/// per-swap and open-TVL caps, windows. Returns the new open TVL. With `flags == 0` this is the
/// phase-1 check unchanged.
pub fn check_lock_terms(
    c: &Config,
    m: &Maker,
    locker: &Pubkey,
    claimer: &Pubkey,
    direction: u8,
    amount: u64,
    xmr_amount: u64,
    t0_secs: i64,
    window_secs: i64,
    flags: u8,
) -> Result<u64, HkError> {
    if c.paused {
        return Err(HkError::Paused);
    }
    if !m.active {
        return Err(HkError::MakerInactive);
    }
    if flags & !F_ALL != 0 {
        return Err(HkError::BadParam);
    }
    // Pay/vault funds belong to another recipient; that recipient's release rules are separate.
    if flags & F_READY_ONLY != 0 && (direction != DIR_SOL_TO_XMR || flags & (F_PAY | F_VAULT) != 0) {
        return Err(HkError::BadParam);
    }
    if m.directions & direction == 0 {
        return Err(HkError::DirectionUnsupported);
    }
    match direction {
        DIR_SOL_TO_XMR => {
            if *claimer != m.authority {
                return Err(HkError::BadParam);
            }
        }
        DIR_XMR_TO_SOL => {
            if *locker != m.authority {
                return Err(HkError::BadParam);
            }
        }
        _ => return Err(HkError::BadParam),
    }
    if !(*claimer != *locker && *claimer != Pubkey::default()) {
        return Err(HkError::BadParam);
    }
    // Flagged escrows feed the extended reputation counters: the maker must have them.
    if flags != 0 && !m.v2 {
        return Err(HkError::NotUpgraded);
    }
    let (lo, hi) = amount_range(m, flags);
    if !(amount >= lo && amount <= hi) {
        return Err(HkError::AmountOutOfRange);
    }
    if amount > cap_for(c, flags) {
        return Err(HkError::CapExceeded);
    }
    let tvl = c.open_tvl.checked_add(amount).ok_or(HkError::Overflow)?;
    if tvl > c.max_open_tvl {
        return Err(HkError::CapExceeded);
    }
    if xmr_amount == 0 {
        return Err(HkError::BadParam);
    }
    if !(t0_secs >= c.min_t0 && t0_secs <= c.max_t0) {
        return Err(HkError::BadParam);
    }
    if !(window_secs >= c.min_window && window_secs <= c.max_window) {
        return Err(HkError::BadParam);
    }
    Ok(tvl)
}

/// Pay-mode shape: a pay escrow is SOL->XMR, and only pay escrows may carry the vault flag.
/// Returns whether the escrow is a pay escrow (the handler then derives its keys from the link).
pub fn pay_shape(flags: u8, direction: u8) -> Result<bool, HkError> {
    if flags & F_PAY != 0 {
        if direction != DIR_SOL_TO_XMR {
            return Err(HkError::BadParam);
        }
        Ok(true)
    } else {
        if flags & F_VAULT != 0 {
            return Err(HkError::BadParam);
        }
        Ok(false)
    }
}

/// A claimer must not be able to abort-then-race, so it can never be a watchtower. A pay escrow's
/// payer cannot abort, so it needs at least one watchtower, and the locker cannot be one.
pub fn check_watchtowers(wt: &[Pubkey; 2], claimer: &Pubkey, locker: &Pubkey, flags: u8) -> Result<(), HkError> {
    for w in wt.iter() {
        if *w == *claimer {
            return Err(HkError::BadParam);
        }
    }
    if flags & F_PAY != 0 {
        if !wt.iter().any(|w| *w != Pubkey::default()) {
            return Err(HkError::NoWatchtower);
        }
        for w in wt.iter() {
            if *w == *locker {
                return Err(HkError::BadParam);
            }
        }
    }
    Ok(())
}

/// Absolute deadlines from the lock time: (t0, t1).
pub fn deadlines(t: i64, t0_secs: i64, window_secs: i64) -> Result<(i64, i64), HkError> {
    let t0 = t.checked_add(t0_secs).ok_or(HkError::Overflow)?;
    let t1 = t0.checked_add(window_secs).ok_or(HkError::Overflow)?;
    Ok((t0, t1))
}

/// Count a new open swap against the maker and the global open TVL (`tvl` from
/// `check_lock_terms`).
pub fn open_counters(m: &mut Maker, c: &mut Config, amount: u64, tvl: u64) -> Result<(), HkError> {
    m.open_swaps = m.open_swaps.checked_add(1).ok_or(HkError::Overflow)?;
    m.open_lamports = m.open_lamports.checked_add(amount).ok_or(HkError::Overflow)?;
    c.open_tvl = tvl;
    Ok(())
}

/// Release the escrow's share of the maker's open counters and the global open TVL. Idempotent.
/// Called at the first of abort / claim / expire / refund, so an abandoned escrow can never pin
/// a maker's bond or the global cap.
pub fn release(e: &mut Escrow, m: &mut Maker, c: &mut Config) -> Result<(), HkError> {
    if e.released {
        return Ok(());
    }
    m.open_swaps = m.open_swaps.checked_sub(1).ok_or(HkError::Overflow)?;
    m.open_lamports = m.open_lamports.checked_sub(e.amount).ok_or(HkError::Overflow)?;
    c.open_tvl = c.open_tvl.checked_sub(e.amount).ok_or(HkError::Overflow)?;
    e.released = true;
    Ok(())
}

/// `ready`: never on a pay escrow (its XMR belongs to the recipient, not the payer), only from
/// Locked and strictly before t0 (the caller check is `e.locker == signer`). The clock is read
/// only after the flag and state checks, as in the original handler.
pub fn ready_window<E: From<HkError>>(
    state: u8,
    t0: i64,
    flags: u8,
    now: impl FnOnce() -> Result<i64, E>,
) -> Result<(), E> {
    if flags & F_PAY != 0 {
        return Err(HkError::Unauthorized.into());
    }
    if state != ST_LOCKED {
        return Err(HkError::BadState.into());
    }
    if !(now()? < t0) {
        return Err(HkError::TooLate.into());
    }
    Ok(())
}

/// The last moment (exclusive) for a late `ready`: max(t0, t1 - LATE_READY_MARGIN).
pub fn late_deadline(t0: i64, t1: i64) -> i64 {
    let late = t1.saturating_sub(crate::LATE_READY_MARGIN);
    if late > t0 { late } else { t0 }
}

/// Late finish (`ready` of a plain escrow): like `ready_window`, but open until
/// max(t0, t1 - LATE_READY_MARGIN), so it is never stricter than `ready_window`.
pub fn ready_window_late<E: From<HkError>>(
    state: u8,
    t0: i64,
    t1: i64,
    flags: u8,
    now: impl FnOnce() -> Result<i64, E>,
) -> Result<(), E> {
    if flags & F_PAY != 0 {
        return Err(HkError::Unauthorized.into());
    }
    if state != ST_LOCKED {
        return Err(HkError::BadState.into());
    }
    if !(now()? < late_deadline(t0, t1)) {
        return Err(HkError::TooLate.into());
    }
    Ok(())
}

/// Who aborted, for the maker's stats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbortKind {
    /// The maker side gave up (`declined`).
    Declined,
    /// The user side cancelled (`cancelled`).
    Cancelled,
    /// A listed watchtower aborted (`aborted`).
    Watchtower,
}

/// `abort` authorization and window:
///  * claimer: Locked or Ready, before t1 (it only gives up its own claim);
///  * locker (not of a pay escrow) or a listed (non-default) watchtower: Locked only, before t0.
pub fn abort_check(e: &Escrow, who: &Pubkey, t: i64) -> Result<AbortKind, HkError> {
    let maker_side = if e.direction == DIR_SOL_TO_XMR { e.claimer } else { e.locker };
    if *who == e.claimer {
        if !(e.state == ST_LOCKED || e.state == ST_READY) {
            return Err(HkError::BadState);
        }
        if !(t < e.t1) {
            return Err(HkError::TooLate);
        }
        if *who == maker_side {
            Ok(AbortKind::Declined)
        } else {
            Ok(AbortKind::Cancelled)
        }
    } else {
        let is_wt = e.watchtowers.iter().any(|w| *w != Pubkey::default() && w == who);
        // A pay-mode locker never holds the XMR key, so its refund cannot hand the maker its XMR
        // back: only the (maker-consented) watchtowers may abort a pay escrow.
        let locker_may = *who == e.locker && e.flags & F_PAY == 0;
        if !(locker_may || is_wt) {
            return Err(HkError::Unauthorized);
        }
        if e.state != ST_LOCKED {
            return Err(HkError::BadState);
        }
        if !(t < e.t0) {
            return Err(HkError::TooLate);
        }
        if locker_may {
            if *who == maker_side {
                Ok(AbortKind::Declined)
            } else {
                Ok(AbortKind::Cancelled)
            }
        } else {
            Ok(AbortKind::Watchtower)
        }
    }
}

/// `claim` window: before t1, and either Ready or (Locked and at/after t0).
pub fn claim_window(state: u8, t: i64, t0: i64, t1: i64) -> Result<(), HkError> {
    if !(t < t1) {
        return Err(HkError::TooLate);
    }
    match state {
        ST_READY => Ok(()),
        ST_LOCKED => {
            if t >= t0 {
                Ok(())
            } else {
                Err(HkError::TooEarly)
            }
        }
        _ => Err(HkError::BadState),
    }
}

/// `refund` window: Aborted (any time), or Locked/Ready at/after t1.
pub fn refund_window(state: u8, t: i64, t1: i64) -> Result<(), HkError> {
    match state {
        ST_ABORTED => Ok(()),
        ST_LOCKED | ST_READY => {
            if t >= t1 {
                Ok(())
            } else {
                Err(HkError::TooEarly)
            }
        }
        _ => Err(HkError::BadState),
    }
}

/// `expire`: unreleased Locked/Ready escrow at/after t1 (bookkeeping only, state unchanged).
/// The clock is read only after the state checks, as in the original handler.
pub fn expire_window<E: From<HkError>>(
    state: u8,
    released: bool,
    t1: i64,
    now: impl FnOnce() -> Result<i64, E>,
) -> Result<(), E> {
    if !(state == ST_LOCKED || state == ST_READY) {
        return Err(HkError::BadState.into());
    }
    if released {
        return Err(HkError::BadState.into());
    }
    if !(now()? >= t1) {
        return Err(HkError::TooEarly.into());
    }
    Ok(())
}

/// `close`: only a settled (Claimed/Refunded) escrow, never a pay escrow (those close through
/// `close_pay_allowed`). The caller check is `e.locker == signer`.
pub fn close_allowed(state: u8, flags: u8) -> Result<(), HkError> {
    if flags & F_PAY != 0 {
        return Err(HkError::BadState);
    }
    if !(state == ST_CLAIMED || state == ST_REFUNDED) {
        return Err(HkError::BadState);
    }
    Ok(())
}

/// Parse an Ed25519 precompile instruction's data and check it carries exactly one signature,
/// with every offset pointing into this same instruction, whose public key is `signer_key` and
/// whose message is `msg`. (The precompile itself verifies the signature; the transaction fails
/// if it does not.)
pub fn ed25519_ix_binds(d: &[u8], signer_key: &[u8; 32], msg: &[u8]) -> Result<(), HkError> {
    if !(d.len() >= 16 && d[0] == 1) {
        return Err(HkError::NoConsent);
    }
    let u = |i: usize| u16::from_le_bytes([d[i], d[i + 1]]);
    let (sig_off, sig_ix, pk_off, pk_ix, msg_off, msg_len, msg_ix) =
        (u(2) as usize, u(4), u(6) as usize, u(8), u(10) as usize, u(12) as usize, u(14));
    if !(sig_ix == u16::MAX && pk_ix == u16::MAX && msg_ix == u16::MAX) {
        return Err(HkError::NoConsent);
    }
    if !sig_off.checked_add(64).is_some_and(|e| e <= d.len()) {
        return Err(HkError::NoConsent);
    }
    if !pk_off.checked_add(32).is_some_and(|e| e <= d.len()) {
        return Err(HkError::NoConsent);
    }
    if !msg_off.checked_add(msg_len).is_some_and(|e| e <= d.len()) {
        return Err(HkError::NoConsent);
    }
    if d[pk_off..pk_off + 32] != *signer_key {
        return Err(HkError::NoConsent);
    }
    if d[msg_off..msg_off + msg_len] != *msg {
        return Err(HkError::NoConsent);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Platform: OTC / pay reputation, pay escrows, cashout vaults, config and maker extensions
// ---------------------------------------------------------------------------------------------

/// Outcome of a flagged escrow for the maker's OTC / pay reputation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Fill,
    Failed,
    Declined,
}

/// Which reputation outcome an abort counts: the maker declining as claimer, or a watchtower
/// abort (maker no-show). An XMR->SOL maker aborting as locker (the taker never deposited) and a
/// user cancelling count nothing.
pub fn abort_ext_outcome(kind: AbortKind, by_claimer: bool) -> Option<Outcome> {
    match kind {
        AbortKind::Declined if by_claimer => Some(Outcome::Declined),
        AbortKind::Watchtower => Some(Outcome::Failed),
        _ => None,
    }
}

/// OTC / pay-link reputation (only flagged escrows; their makers always have the extension).
/// XMR->SOL: the taker deposits last, so an expiry is as likely the taker's no-show as the
/// maker's; only fills count there. Touches only `m.ext`.
pub fn ext_count(e: &Escrow, m: &mut Maker, o: Outcome) -> Result<(), HkError> {
    if e.flags == 0 || !m.v2 {
        return Ok(());
    }
    if e.direction == DIR_XMR_TO_SOL && o != Outcome::Fill {
        return Ok(());
    }
    let x = &mut m.ext;
    let bump = |fills: &mut u64, vol: &mut u64, failed: &mut u64, declined: &mut u64| -> Result<(), HkError> {
        match o {
            Outcome::Fill => {
                *fills = fills.checked_add(1).ok_or(HkError::Overflow)?;
                *vol = vol.checked_add(e.amount).ok_or(HkError::Overflow)?;
            }
            Outcome::Failed => *failed = failed.checked_add(1).ok_or(HkError::Overflow)?,
            Outcome::Declined => *declined = declined.checked_add(1).ok_or(HkError::Overflow)?,
        }
        Ok(())
    };
    if e.flags & F_OTC != 0 {
        bump(&mut x.otc_fills, &mut x.otc_volume, &mut x.otc_failed, &mut x.otc_declined)?;
    }
    if e.flags & F_PAY != 0 {
        bump(&mut x.pay_fills, &mut x.pay_volume, &mut x.pay_failed, &mut x.pay_declined)?;
    }
    Ok(())
}

/// Refund secret: a pay escrow reveals nothing (the locker never knew the recipient's key half),
/// so it must pass all zeroes and `mul_g` is never called; any other escrow reveals its refund
/// secret through `check_reveal_with`.
pub fn refund_secret_check<F>(flags: u8, secret: &[u8; 32], point: &[u8; 32], mul_g: F) -> Result<(), HkError>
where
    F: FnOnce(&[u8; 32]) -> Option<[u8; 32]>,
{
    if flags & F_PAY != 0 {
        if *secret != [0u8; 32] {
            return Err(HkError::BadParam);
        }
        Ok(())
    } else {
        check_reveal_with(secret, point, mul_g)
    }
}

/// `close_pay` (the caller checked the pay flag, the locker and the link accounts). A refunded
/// pay escrow holds nothing to collect: the locker side may close it. A claimed one carries the
/// maker's revealed half the recipient needs, so the link owner may close it at once and the
/// locker side only after PAY_CLOSE_GRACE. A vault escrow's locker side is anyone (rent goes back
/// to the vault). The clock is read only for a claimed escrow, as in the original handler.
pub fn close_pay_allowed<E: From<HkError>>(
    state: u8,
    flags: u8,
    who_is_locker: bool,
    who_is_owner: bool,
    settled_at: i64,
    now: impl FnOnce() -> Result<i64, E>,
) -> Result<(), E> {
    let locker_side = who_is_locker || flags & F_VAULT != 0;
    match state {
        ST_REFUNDED => {
            if !locker_side {
                return Err(HkError::Unauthorized.into());
            }
        }
        ST_CLAIMED => {
            let t = now()?;
            let late = t >= settled_at.checked_add(PAY_CLOSE_GRACE).ok_or(HkError::Overflow)?;
            if !(who_is_owner || (locker_side && late)) {
                return Err(HkError::Unauthorized.into());
            }
        }
        _ => return Err(HkError::BadState.into()),
    }
    Ok(())
}

/// `set_config_ext`: the OTC cap is off (0) or between the swap cap and the open-TVL cap; the
/// vault timelock floor is at most 30 days.
pub fn check_config_ext(c: &Config, otc_max_swap: u64, vault_min_delay: i64) -> Result<(), HkError> {
    if !(otc_max_swap == 0 || (otc_max_swap >= c.max_swap && otc_max_swap <= c.max_open_tvl)) {
        return Err(HkError::BadParam);
    }
    if !(0..=30 * 86_400).contains(&vault_min_delay) {
        return Err(HkError::BadParam);
    }
    Ok(())
}

/// `upgrade_maker`: the OTC range is off (otc_max = 0) or a non-empty range above zero.
pub fn check_otc_range(otc_min: u64, otc_max: u64) -> Result<(), HkError> {
    if !(otc_max == 0 || (otc_min > 0 && otc_min <= otc_max)) {
        return Err(HkError::BadParam);
    }
    Ok(())
}

/// Pay-link names: 3..=32 of [a-z0-9-], not starting or ending with '-'.
pub fn check_link_name(n: &[u8]) -> Result<(), HkError> {
    if !(n.len() >= 3 && n.len() <= 32) {
        return Err(HkError::BadParam);
    }
    if !n.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-') {
        return Err(HkError::BadParam);
    }
    if !(n[0] != b'-' && n[n.len() - 1] != b'-') {
        return Err(HkError::BadParam);
    }
    Ok(())
}

/// Vault params: at least one watchtower; a named keeper (whoever triggers a conversion picks the
/// maker and when the watchtowers hear about it, so "anyone" would let an attacker-maker drain the
/// vault through no-show swaps); a non-empty size range within the swap cap; schedule, price floor
/// and timelock within bounds.
pub fn check_vault_params(c: &Config, p: &VaultParams) -> Result<(), HkError> {
    if !p.watchtowers.iter().any(|w| *w != Pubkey::default()) {
        return Err(HkError::NoWatchtower);
    }
    if p.keeper == Pubkey::default() {
        return Err(HkError::BadParam);
    }
    if !(p.min_lamports > 0 && p.min_lamports <= p.max_lamports) {
        return Err(HkError::BadParam);
    }
    if p.max_lamports > c.max_swap {
        return Err(HkError::BadParam);
    }
    if !(p.interval >= 0 && p.interval <= 30 * 86_400) {
        return Err(HkError::BadParam);
    }
    if p.min_rate == 0 {
        return Err(HkError::BadParam);
    }
    if !(p.delay >= c.vault_min_delay && p.delay <= 30 * 86_400) {
        return Err(HkError::BadParam);
    }
    Ok(())
}

/// `vault_propose`: stage new params (and optionally an unpause) behind the CURRENT delay, so a
/// proposal cannot shorten its own wait. Replaces any earlier proposal.
pub fn vault_propose(v: &mut Vault, p: VaultParams, unpause: bool, t: i64) -> Result<(), HkError> {
    v.pending_unpause = unpause;
    v.pending_at = t.checked_add(v.p.delay.max(1)).ok_or(HkError::Overflow)?;
    v.pending = p;
    Ok(())
}

/// `vault_apply`: a pending proposal, once its timelock has passed. The clock is read only after
/// the pending check, as in the original handler.
pub fn vault_apply<E: From<HkError>>(v: &mut Vault, now: impl FnOnce() -> Result<i64, E>) -> Result<(), E> {
    if v.pending_at == 0 {
        return Err(HkError::NothingPending.into());
    }
    if !(now()? >= v.pending_at) {
        return Err(HkError::Timelocked.into());
    }
    v.p = v.pending.clone();
    if v.pending_unpause {
        v.paused = false;
    }
    v.pending_unpause = false;
    v.pending = VaultParams::default();
    v.pending_at = 0;
    Ok(())
}

/// `vault_cancel`: drop a pending proposal and a pending withdrawal.
pub fn vault_cancel(v: &mut Vault) {
    v.pending = VaultParams::default();
    v.pending_at = 0;
    v.pending_unpause = false;
    v.withdraw_at = 0;
    v.withdraw_amount = 0;
}

/// `vault_tighten`: instant, but only in the safe direction: pause, raise the price floor, lower
/// the size cap (not below the minimum), slow the schedule. Anything else (unpausing included)
/// goes through the timelock. An emergency pause also drops a pending unpause.
pub fn vault_tighten(v: &mut Vault, paused: u8, min_rate: u64, max_lamports: u64, interval: i64) -> Result<(), HkError> {
    if paused > 1 {
        return Err(HkError::BadParam);
    }
    if !(paused == 1 || !v.paused) {
        return Err(HkError::Timelocked);
    }
    if min_rate < v.p.min_rate {
        return Err(HkError::Timelocked);
    }
    if !(max_lamports <= v.p.max_lamports && max_lamports >= v.p.min_lamports) {
        return Err(HkError::Timelocked);
    }
    if !(interval >= v.p.interval && interval <= 30 * 86_400) {
        return Err(HkError::Timelocked);
    }
    v.paused = paused == 1;
    if v.paused {
        v.pending_unpause = false;
    }
    v.p.min_rate = min_rate;
    v.p.max_lamports = max_lamports;
    v.p.interval = interval;
    Ok(())
}

/// `vault_lock` terms fixed by the vault, not the keeper: not paused, the named keeper or the
/// owner, due, size in range, price at or above the floor (`xmr_amount / amount >= min_rate`
/// piconero per SOL, exact in 128 bits). Returns the clock, read after the keeper check as in the
/// original handler.
pub fn vault_lock_terms<E: From<HkError>>(
    v: &Vault,
    keeper: &Pubkey,
    now: impl FnOnce() -> Result<i64, E>,
    amount: u64,
    xmr_amount: u64,
) -> Result<i64, E> {
    if v.paused {
        return Err(HkError::Paused.into());
    }
    if !(*keeper == v.p.keeper || *keeper == v.owner) {
        return Err(HkError::Unauthorized.into());
    }
    let t = now()?;
    if t < v.next_at {
        return Err(HkError::NotDue.into());
    }
    if !(amount >= v.p.min_lamports && amount <= v.p.max_lamports) {
        return Err(HkError::AmountOutOfRange.into());
    }
    if !((xmr_amount as u128) * 1_000_000_000u128 >= (v.p.min_rate as u128) * (amount as u128)) {
        return Err(HkError::RateTooLow.into());
    }
    Ok(t)
}

/// Bookkeeping after a conversion: next due time, counters.
pub fn vault_converted(v: &mut Vault, t: i64, amount: u64) -> Result<(), HkError> {
    v.next_at = t.checked_add(v.p.interval).ok_or(HkError::Overflow)?;
    v.conversions = v.conversions.checked_add(1).ok_or(HkError::Overflow)?;
    v.locked_lamports = v.locked_lamports.checked_add(amount).ok_or(HkError::Overflow)?;
    Ok(())
}

/// A vault-funded escrow takes `amount` plus the rent top-up out of the vault, never below the
/// vault's own rent reserve `keep`. Returns the lamports to move.
pub fn vault_funding(amount: u64, top: u64, vault_lamports: u64, keep: u64) -> Result<u64, HkError> {
    let avail = vault_lamports.saturating_sub(keep);
    let total = amount.checked_add(top).ok_or(HkError::Overflow)?;
    if total > avail {
        return Err(HkError::AmountOutOfRange);
    }
    Ok(total)
}

/// `vault_withdraw_request`: start the withdrawal timelock (current delay, at least 1 s).
pub fn vault_withdraw_request<E: From<HkError>>(
    v: &mut Vault,
    amount: u64,
    now: impl FnOnce() -> Result<i64, E>,
) -> Result<(), E> {
    if amount == 0 {
        return Err(HkError::BadParam.into());
    }
    v.withdraw_amount = amount;
    v.withdraw_at = now()?.checked_add(v.p.delay.max(1)).ok_or(HkError::Overflow)?;
    Ok(())
}

/// `vault_withdraw`: a requested withdrawal whose timelock has passed.
pub fn vault_withdraw_due<E: From<HkError>>(v: &Vault, now: impl FnOnce() -> Result<i64, E>) -> Result<(), E> {
    if v.withdraw_at == 0 {
        return Err(HkError::NothingPending.into());
    }
    if !(now()? >= v.withdraw_at) {
        return Err(HkError::Timelocked.into());
    }
    Ok(())
}

/// The withdrawal amount: what was requested, capped at what is free above the rent reserve.
/// Clears the request.
pub fn vault_withdraw_take(v: &mut Vault, vault_lamports: u64, keep: u64) -> u64 {
    let free = vault_lamports.saturating_sub(keep);
    let amt = v.withdraw_amount.min(free);
    v.withdraw_at = 0;
    v.withdraw_amount = 0;
    amt
}

// ---------------------------------------------------------------------------------------------
// HTLC kind (SOL <-> transparent ZEC; handlers in `htlc.rs`)
// ---------------------------------------------------------------------------------------------
//
// One deadline `t1`. Before t1 only the claimer can act: claim with the preimage, or give up
// (abort). From t1 only the refund to the locker. There is no `ready`, no locker or watchtower
// abort, and the refund needs no secret: the other chain's lock already exists when the SOL is
// locked, and a locker abort racing a claim would make that claim fail ON CHAIN with the preimage
// in its data, handing the locker both sides.

use crate::{DIR_SOL_TO_ZEC, DIR_SOL_TO_ZEC_PT, DIR_ZEC_TO_SOL, DIR_ZEC_TO_SOL_PT};
use crate::htlc::Htlc;

pub fn is_htlc_dir(direction: u8) -> bool {
    direction == DIR_SOL_TO_ZEC || direction == DIR_ZEC_TO_SOL || is_point_dir(direction)
}
/// The point-locked HTLC directions (ZEC v2): `hashlock` holds an ed25519 point.
pub fn is_point_dir(direction: u8) -> bool {
    direction == DIR_SOL_TO_ZEC_PT || direction == DIR_ZEC_TO_SOL_PT
}
/// The user locks SOL and the maker claims it (SOL -> ZEC, either lock kind).
pub fn is_sol_to_zec(direction: u8) -> bool {
    direction == DIR_SOL_TO_ZEC || direction == DIR_SOL_TO_ZEC_PT
}

/// The claim's secret check, by kind. A hash lock takes `htlc_claim` (sha256(x) == hashlock), a
/// point lock takes `htlc_pt_claim` (canonical t, t*G == T); the wrong instruction for the kind is
/// refused before any check, so neither secret can ever be checked against the other kind of lock.
pub fn htlc_check_secret<S, M>(direction: u8, point_ix: bool, secret: &[u8; 32], lock: &[u8; 32], sha256: S, mul_g: M) -> Result<(), HkError>
where
    S: FnOnce(&[u8; 32]) -> [u8; 32],
    M: FnOnce(&[u8; 32]) -> Option<[u8; 32]>,
{
    if is_point_dir(direction) != point_ix {
        return Err(HkError::BadParam);
    }
    if point_ix {
        check_reveal_with(secret, lock, mul_g)
    } else {
        check_preimage_with(secret, lock, sha256)
    }
}

/// `htlc_lock` checks: pause, maker status, an HTLC direction the maker takes, who may be locker
/// and claimer (SOL->ZEC: the user locks, the maker claims; ZEC->SOL: the maker locks), amount
/// range, per-swap and open-TVL caps, a non-zero ZEC amount and hashlock, and the deadline within
/// the config's t0 + window bounds. Returns the new open TVL.
pub fn htlc_lock_terms(
    c: &Config,
    m: &Maker,
    locker: &Pubkey,
    claimer: &Pubkey,
    direction: u8,
    amount: u64,
    zec_amount: u64,
    hashlock: &[u8; 32],
    t1_secs: i64,
) -> Result<u64, HkError> {
    if c.paused {
        return Err(HkError::Paused);
    }
    if !m.active {
        return Err(HkError::MakerInactive);
    }
    if !is_htlc_dir(direction) {
        return Err(HkError::BadParam);
    }
    if m.directions & direction == 0 {
        return Err(HkError::DirectionUnsupported);
    }
    let maker_role = if is_sol_to_zec(direction) { claimer } else { locker };
    if *maker_role != m.authority {
        return Err(HkError::BadParam);
    }
    if !(*claimer != *locker && *claimer != Pubkey::default()) {
        return Err(HkError::BadParam);
    }
    if !(amount >= m.min && amount <= m.max) {
        return Err(HkError::AmountOutOfRange);
    }
    if amount > c.max_swap {
        return Err(HkError::CapExceeded);
    }
    let tvl = c.open_tvl.checked_add(amount).ok_or(HkError::Overflow)?;
    if tvl > c.max_open_tvl {
        return Err(HkError::CapExceeded);
    }
    if zec_amount == 0 || *hashlock == [0u8; 32] {
        return Err(HkError::BadParam);
    }
    let lo = c.min_t0.checked_add(c.min_window).ok_or(HkError::Overflow)?;
    let hi = c.max_t0.checked_add(c.max_window).ok_or(HkError::Overflow)?;
    if !(t1_secs >= lo && t1_secs <= hi) {
        return Err(HkError::BadParam);
    }
    Ok(tvl)
}

/// `sha256(secret) == hashlock`, with `sha256` passed in (the program passes the syscall; Kani an
/// arbitrary result). The ZEC script checks `OP_SIZE 32` and `OP_SHA256` on the same 32 bytes.
pub fn check_preimage_with<F>(secret: &[u8; 32], hashlock: &[u8; 32], sha256: F) -> Result<(), HkError>
where
    F: FnOnce(&[u8; 32]) -> [u8; 32],
{
    if sha256(secret) != *hashlock {
        return Err(HkError::WrongSecret);
    }
    Ok(())
}

/// `htlc_claim` window: Locked and strictly before t1 (open from the lock: no t0, no `ready`).
pub fn htlc_claim_window(state: u8, t: i64, t1: i64) -> Result<(), HkError> {
    if !(t < t1) {
        return Err(HkError::TooLate);
    }
    if state != ST_LOCKED {
        return Err(HkError::BadState);
    }
    Ok(())
}

/// `htlc_abort`: only the claimer (giving up its own claim), while Locked, before t1. The locker
/// and watchtowers have no abort: the counterparty has already locked on the other chain.
pub fn htlc_abort_check(h: &Htlc, who: &Pubkey, t: i64) -> Result<AbortKind, HkError> {
    if *who != h.claimer {
        return Err(HkError::Unauthorized);
    }
    if h.state != ST_LOCKED {
        return Err(HkError::BadState);
    }
    if !(t < h.t1) {
        return Err(HkError::TooLate);
    }
    // SOL->ZEC: the claimer is the maker (it declines); ZEC->SOL: the user cancels.
    if is_sol_to_zec(h.direction) {
        Ok(AbortKind::Declined)
    } else {
        Ok(AbortKind::Cancelled)
    }
}

/// `htlc_refund` window: Aborted (by the claimer, any time), or Locked at/after t1.
pub fn htlc_refund_window(state: u8, t: i64, t1: i64) -> Result<(), HkError> {
    match state {
        ST_ABORTED => Ok(()),
        ST_LOCKED => {
            if t >= t1 {
                Ok(())
            } else {
                Err(HkError::TooEarly)
            }
        }
        _ => Err(HkError::BadState),
    }
}

/// `htlc_close`: only a settled (Claimed/Refunded) HTLC escrow.
pub fn htlc_close_allowed(state: u8) -> Result<(), HkError> {
    if !(state == ST_CLAIMED || state == ST_REFUNDED) {
        return Err(HkError::BadState);
    }
    Ok(())
}

/// `release` for an HTLC escrow: same counters, same idempotence.
pub fn htlc_release(h: &mut Htlc, m: &mut Maker, c: &mut Config) -> Result<(), HkError> {
    if h.released {
        return Ok(());
    }
    m.open_swaps = m.open_swaps.checked_sub(1).ok_or(HkError::Overflow)?;
    m.open_lamports = m.open_lamports.checked_sub(h.amount).ok_or(HkError::Overflow)?;
    c.open_tvl = c.open_tvl.checked_sub(h.amount).ok_or(HkError::Overflow)?;
    h.released = true;
    Ok(())
}

#[cfg(test)]
mod late_finish_tests {
    use super::*;
    use crate::F_PROOF;
    const T0: i64 = 1_000_000;
    const T1: i64 = T0 + 2 * 3600;
    fn late(state: u8, flags: u8, t: i64) -> Result<(), HkError> {
        ready_window_late::<HkError>(state, T0, T1, flags, || Ok(t))
    }
    #[test]
    fn ready_after_t0_until_t1_minus_margin() {
        assert!(late(ST_LOCKED, 0, T0 - 1).is_ok());
        assert!(late(ST_LOCKED, F_PROOF, T0 + 60).is_ok(), "a late ready after t0 (the point of late finish)");
        assert!(late(ST_LOCKED, F_PROOF, T1 - crate::LATE_READY_MARGIN - 1).is_ok());
        assert_eq!(late(ST_LOCKED, F_PROOF, T1 - crate::LATE_READY_MARGIN), Err(HkError::TooLate));
        assert_eq!(late(ST_LOCKED, 0, T1), Err(HkError::TooLate));
        assert_eq!(late(ST_READY, 0, T0 - 1), Err(HkError::BadState));
        assert_eq!(late(ST_LOCKED, F_PAY, T0 - 1), Err(HkError::Unauthorized));
    }
    #[test]
    fn never_stricter_than_t0_when_the_window_is_short() {
        let t1 = T0 + 10;
        assert!(ready_window_late::<HkError>(ST_LOCKED, T0, t1, 0, || Ok(T0 - 1)).is_ok());
        assert_eq!(ready_window_late::<HkError>(ST_LOCKED, T0, t1, 0, || Ok(T0)), Err(HkError::TooLate));
    }
}
