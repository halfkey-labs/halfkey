//! Pure rules of the final program round: v2 escrows (integrator share, finisher tip, direct
//! payout), deposit orders and open offers. The handlers (`escrow2.rs`, `deposit.rs`,
//! `direct.rs`, `offer.rs`, and the v2 branches in `lib.rs`) call these in order and keep the
//! account plumbing, CPIs and curve syscalls. Kani: `proofs_final.rs`; proptest: `fuzz_final.rs`.
//!
//! Legacy escrows are untouched: every function that sits on a v1 path (`abort_check_v2`,
//! `refund_secret_v2`, `proof_window_floor`) is the v1 rule for every input a v1 escrow can have
//! (no `F_DIRECT` bit; `lock`/`lock2` refuse it), which `proofs_final::fr_v1_paths_unchanged`
//! checks.

use crate::logic::{self, AbortKind};
use crate::offer::Offer;
use crate::{
    Escrow, HkError, DIR_SOL_TO_XMR, DIR_XMR_TO_SOL, F_DIRECT, F_OTC, F_PAY, F_PROOF, MAX_INTEGRATOR_BPS, MAX_TIP,
    MIN_PROOF_WINDOW, ST_CLAIMED, ST_LOCKED, ST_REFUNDED,
};
use solana_pubkey::Pubkey;

/// Filler deposit of an offer: 1% of the amount, at least 0.01 SOL.
pub const FILL_DEPOSIT_BPS: u16 = 100;
pub const MIN_FILL_DEPOSIT: u64 = 10_000_000;
/// Longest proof window an offer may give a filler, and the longest offer life.
pub const MAX_FILL_WINDOW: i64 = 7 * 86_400;
pub const MAX_OFFER_LIFE: i64 = 30 * 86_400;

pub const OF_OPEN: u8 = 1;
pub const OF_RESERVED: u8 = 2;
/// Terminal (the handlers close the account right after; kept for the model).
pub const OF_DONE: u8 = 3;
pub const OF_CANCELLED: u8 = 4;

// ---------------------------------------------------------------------------------------------
// Settlement
// ---------------------------------------------------------------------------------------------

/// Settlement split with an integrator share: (to_claimer, protocol_fee, integrator_fee), each
/// fee `floor(amount * bps / 10_000)`.
pub fn split3(amount: u64, fee_bps: u16, integrator_bps: u16) -> Result<(u64, u64, u64), HkError> {
    let fee = logic::bps_of(amount, fee_bps);
    let ifee = logic::bps_of(amount, integrator_bps);
    let to = amount.checked_sub(fee).and_then(|x| x.checked_sub(ifee)).ok_or(HkError::Overflow)?;
    Ok((to, fee, ifee))
}

/// Whether an escrow's refund cannot hand the maker its XMR back (it reveals nothing), so a
/// committee outage until t1 would strand the maker: pay links, cashout vaults, direct payout.
pub fn needs_window_floor(flags: u8) -> bool {
    flags & (F_PAY | F_DIRECT) != 0
}

/// Reviewer #2: those escrows get a claim window of at least MIN_PROOF_WINDOW.
pub fn proof_window_floor(flags: u8, window_secs: i64) -> Result<(), HkError> {
    if needs_window_floor(flags) && window_secs < MIN_PROOF_WINDOW {
        return Err(HkError::WindowTooShort);
    }
    Ok(())
}

/// Integrator share and tip bounds. `integrator == default` means none (then the share is 0).
/// The tip is at most MAX_TIP and a tenth of the amount.
pub fn check_shares(integrator: &Pubkey, integrator_bps: u16, tip: u64, amount: u64) -> Result<(), HkError> {
    if integrator_bps > MAX_INTEGRATOR_BPS {
        return Err(HkError::FeeTooHigh);
    }
    if *integrator == Pubkey::default() && integrator_bps != 0 {
        return Err(HkError::BadParam);
    }
    if tip > MAX_TIP || tip > amount / 10 {
        return Err(HkError::FeeTooHigh);
    }
    Ok(())
}

/// The terms a v2 lock adds on top of `logic::check_lock_terms` (which gets the legacy flag bits
/// only). Flags: `F_PROOF` (XMR->SOL only), `F_DIRECT` (SOL->XMR only, no watchtowers: only the
/// maker may abort, and its refund reveals nothing, so the window has the floor) and `F_OTC`
/// (SOL->XMR: an OTC tranche, with the maker's OTC range, the OTC cap and OTC reputation; also
/// for deposit orders). Pay and vault escrows stay v1. Returns the legacy flags for
/// `check_lock_terms`.
pub fn check_v2_terms(
    direction: u8,
    flags: u8,
    integrator: &Pubkey,
    integrator_bps: u16,
    tip: u64,
    amount: u64,
    window_secs: i64,
    wt: &[Pubkey; 2],
) -> Result<u8, HkError> {
    if flags & !(F_PROOF | F_DIRECT | F_OTC) != 0 {
        return Err(HkError::BadParam);
    }
    if flags & F_PROOF != 0 && direction != DIR_XMR_TO_SOL {
        return Err(HkError::BadParam);
    }
    if flags & F_OTC != 0 && direction != DIR_SOL_TO_XMR {
        return Err(HkError::BadParam);
    }
    if flags & F_DIRECT != 0 {
        if direction != DIR_SOL_TO_XMR {
            return Err(HkError::BadParam);
        }
        if wt.iter().any(|w| *w != Pubkey::default()) {
            return Err(HkError::BadParam);
        }
    }
    check_shares(integrator, integrator_bps, tip, amount)?;
    proof_window_floor(flags, window_secs)?;
    Ok(flags & (F_PROOF | F_OTC))
}

/// `ready` by the side that receives the XMR when no refund could give the maker its XMR back
/// (the link owner of a pay escrow, the locker of a direct-payout escrow): Locked, before t1.
pub fn late_ready_window<E: From<HkError>>(state: u8, t1: i64, now: impl FnOnce() -> Result<i64, E>) -> Result<(), E> {
    if state != ST_LOCKED {
        return Err(HkError::BadState.into());
    }
    if !(now()? < t1) {
        return Err(HkError::TooLate.into());
    }
    Ok(())
}

/// `abort`: a direct-payout escrow can only be aborted by its claimer (the maker giving up): any
/// other abort after the maker paid the user's own address would strand the maker's XMR. Every
/// other escrow: `logic::abort_check` unchanged.
pub fn abort_check_v2(e: &Escrow, who: &Pubkey, t: i64) -> Result<AbortKind, HkError> {
    if e.flags & F_DIRECT != 0 && *who != e.claimer {
        return Err(HkError::Unauthorized);
    }
    logic::abort_check(e, who, t)
}

/// Refund secret: a direct-payout refund reveals nothing (its refund point is the user's own
/// address key), so it must pass zeroes; every other escrow: `logic::refund_secret_check`.
pub fn refund_secret_v2<F>(flags: u8, secret: &[u8; 32], point: &[u8; 32], mul_g: F) -> Result<(), HkError>
where
    F: FnOnce(&[u8; 32]) -> Option<[u8; 32]>,
{
    if flags & F_DIRECT != 0 {
        if *secret != [0u8; 32] {
            return Err(HkError::BadParam);
        }
        return Ok(());
    }
    logic::refund_secret_check(flags, secret, point, mul_g)
}

/// `close` of a v2 escrow: settled; a direct-payout one by anyone (nothing to keep readable),
/// an order escrow only from the order's deadline (so the order cannot be filled twice); any
/// other v2 escrow by its locker (the claimer's revealed half stays in its history either way).
pub fn close_v2_allowed<E: From<HkError>>(
    state: u8,
    flags: u8,
    who_is_locker: bool,
    order_deadline: i64,
    now: impl FnOnce() -> Result<i64, E>,
) -> Result<(), E> {
    if !(state == ST_CLAIMED || state == ST_REFUNDED) {
        return Err(HkError::BadState.into());
    }
    if flags & F_DIRECT != 0 {
        if order_deadline != 0 && now()? < order_deadline {
            return Err(HkError::TooEarly.into());
        }
        return Ok(());
    }
    if !who_is_locker {
        return Err(HkError::Unauthorized.into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Deposit orders
// ---------------------------------------------------------------------------------------------

/// Lamports a fill moves from the order address into the escrow: what the escrow needs (amount
/// + tip + its rent top-up), plus the whole leftover when it is below the rent-exempt minimum of
/// an empty account (a system account can only be left with 0 or at least that much; such dust
/// goes back to the refund address with the escrow's rent at close).
pub fn fill_take(balance: u64, amount: u64, tip: u64, rent_top: u64, rent_min0: u64) -> Result<u64, HkError> {
    let need = amount.checked_add(tip).and_then(|x| x.checked_add(rent_top)).ok_or(HkError::Overflow)?;
    if balance < need {
        return Err(HkError::Underpaid);
    }
    let left = balance - need;
    if left > 0 && left < rent_min0 {
        Ok(balance)
    } else {
        Ok(need)
    }
}

/// Longest an order may run: a fill needs `deadline - now <= MAX_ORDER_LIFE`, and an order whose
/// deadline is further out than that can never fill, so it is refundable at once.
pub const MAX_ORDER_LIFE: i64 = 7 * 86_400;

/// `order_refund`: from the deadline (nothing can fill any more), at once when the order was
/// filled (what is left is an over- or late payment), at once when R itself signs (it may take
/// its deposit back whenever no fill landed; a fill racing it is harmless, the SOL only ever
/// reaches R or the escrow), or when the deadline is beyond MAX_ORDER_LIFE (unfillable).
pub fn order_refund_allowed(now: i64, deadline: i64, filled: bool, r_signed: bool) -> Result<(), HkError> {
    let unfillable = deadline.checked_sub(now).map_or(true, |left| left > MAX_ORDER_LIFE);
    if now >= deadline || filled || r_signed || unfillable {
        Ok(())
    } else {
        Err(HkError::TooEarly)
    }
}

/// Split of an order refund: (to the refund address, to the caller). The caller earns the tip
/// only for refunding an order that was never filled (a filled order's tip lives in its escrow),
/// and only when the rest still leaves the refund address rent-exempt.
pub fn order_refund_split(balance: u64, tip: u64, filled: bool, rent_min0: u64) -> (u64, u64) {
    match tip.checked_add(rent_min0) {
        Some(x) if !filled && tip > 0 && balance >= x => (balance - tip, tip),
        _ => (balance, 0),
    }
}

// ---------------------------------------------------------------------------------------------
// Open offers
// ---------------------------------------------------------------------------------------------

pub fn filler_deposit(amount: u64) -> u64 {
    logic::bps_of(amount, FILL_DEPOSIT_BPS).max(MIN_FILL_DEPOSIT)
}

/// `offer_open` terms beyond the config caps: a non-zero XMR amount, the shares, a proof window
/// in [MIN_PROOF_WINDOW, MAX_FILL_WINDOW] and a life in (0, MAX_OFFER_LIFE].
pub fn offer_terms(amount: u64, xmr_amount: u64, integrator: &Pubkey, integrator_bps: u16, tip: u64, fill_window: i64, life: i64) -> Result<(), HkError> {
    if amount == 0 || xmr_amount == 0 {
        return Err(HkError::BadParam);
    }
    check_shares(integrator, integrator_bps, tip, amount)?;
    if fill_window < MIN_PROOF_WINDOW {
        return Err(HkError::WindowTooShort);
    }
    if fill_window > MAX_FILL_WINDOW || !(life > 0 && life <= MAX_OFFER_LIFE) {
        return Err(HkError::BadParam);
    }
    Ok(())
}

/// A reservation whose proof window passed: its deposit goes to the bidder and the offer is
/// open again. Returns the forfeited lamports (0 if there was no lapsed reservation).
pub fn lapse(o: &mut Offer, now: i64) -> Result<u64, HkError> {
    if o.state == OF_RESERVED && now >= o.deadline {
        let d = o.deposit;
        o.state = OF_OPEN;
        o.filler = Pubkey::default();
        o.deposit = 0;
        o.forfeits = o.forfeits.checked_add(1).ok_or(HkError::Overflow)?;
        return Ok(d);
    }
    Ok(0)
}

/// `offer_take`: a lapsed reservation is forfeited first; then the offer must be open, unexpired
/// and the filler not the bidder. The filler reserves it for `fill_window` with its deposit.
/// Returns (forfeited to the bidder, deposit the filler pays in).
pub fn offer_take(o: &mut Offer, filler: &Pubkey, now: i64) -> Result<(u64, u64), HkError> {
    if *filler == o.bidder || *filler == Pubkey::default() {
        return Err(HkError::BadParam);
    }
    let forfeit = lapse(o, now)?;
    match o.state {
        OF_OPEN => {}
        OF_RESERVED => return Err(HkError::Reserved),
        _ => return Err(HkError::BadState),
    }
    if now >= o.expires_at {
        return Err(HkError::Expired);
    }
    let dep = filler_deposit(o.amount);
    o.state = OF_RESERVED;
    o.filler = *filler;
    o.deposit = dep;
    o.reserved_at = now;
    o.deadline = now.checked_add(o.fill_window).ok_or(HkError::Overflow)?;
    o.fill_seq = o.fill_seq.checked_add(1).ok_or(HkError::Overflow)?;
    Ok((forfeit, dep))
}

/// `offer_settle` release: the current reservation, inside its proof window. The caller then
/// checks the payment proof for exactly this fill (`fill_seq` is in the payment id).
pub fn offer_release_check(o: &Offer, now: i64) -> Result<(), HkError> {
    if o.state != OF_RESERVED {
        return Err(HkError::BadState);
    }
    if !(now < o.deadline) {
        return Err(HkError::TooLate);
    }
    Ok(())
}

/// `offer_settle` cancel: a lapsed reservation is forfeited first; a live one blocks the cancel.
/// An open offer is cancelled by its bidder at any time, by anyone once expired. Returns the
/// forfeited deposit (to the bidder, with the amount).
pub fn offer_cancel(o: &mut Offer, who_is_bidder: bool, now: i64) -> Result<u64, HkError> {
    let forfeit = lapse(o, now)?;
    match o.state {
        OF_OPEN => {}
        OF_RESERVED => return Err(HkError::Reserved),
        _ => return Err(HkError::BadState),
    }
    if !(who_is_bidder || now >= o.expires_at) {
        return Err(HkError::Unauthorized);
    }
    o.state = OF_CANCELLED;
    Ok(forfeit)
}

/// `offer_settle` forfeit: anyone, once a reservation's proof window has passed.
pub fn offer_forfeit(o: &mut Offer, now: i64) -> Result<u64, HkError> {
    if o.state != OF_RESERVED {
        return Err(HkError::BadState);
    }
    if now < o.deadline {
        return Err(HkError::TooEarly);
    }
    lapse(o, now)
}
