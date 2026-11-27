//! Kani proof harnesses for the HALFKEY escrow.
//! Run: `cd program && cargo kani --features no-entrypoint -Z stubbing`.
//! See docs/FORMAL-VERIFICATION.md for what each harness proves and what it assumes.
//!
//! Groups:
//!  * `eq_*`   the extracted `logic` functions equal a verbatim copy of the pre-refactor inline
//!             handler code (`orig`), for all inputs (the refactor did not change behaviour);
//!  * `p*_*`   properties of single functions, for all inputs unless a bound is stated;
//!  * `sm_*`   the escrow lifecycle model (`model.rs`, built on the same `logic` functions the
//!             handlers call, with lamport balances): open-counter induction, and an inductive
//!             invariant (`model::inv`) that lock establishes and every instruction preserves,
//!             so the per-step properties hold in every reachable state.

use crate::logic::{self, AbortKind};
use crate::*;

// ---------------------------------------------------------------------------------------------
// Nondeterministic constructors
// ---------------------------------------------------------------------------------------------

fn any_key() -> Pubkey {
    Pubkey::new_from_array(kani::any())
}

fn any_config() -> Config {
    Config {
        paused: kani::any(),
        bump: kani::any(),
        vault_bump: kani::any(),
        admin: any_key(),
        fee_recipient: any_key(),
        halfkey_mint: any_key(),
        fee_bps: kani::any(),
        holder_fee_bps: kani::any(),
        holder_min: kani::any(),
        min_bond: kani::any(),
        max_swap: kani::any(),
        max_open_tvl: kani::any(),
        open_tvl: kani::any(),
        min_t0: kani::any(),
        max_t0: kani::any(),
        min_window: kani::any(),
        max_window: kani::any(),
        unbond_secs: kani::any(),
        total_swaps: kani::any(),
        total_volume: kani::any(),
        total_fees: kani::any(),
        otc_max_swap: kani::any(),
        vault_min_delay: kani::any(),
        offer_tvl: kani::any(),
    }
}

fn any_maker() -> Maker {
    Maker {
        active: kani::any(),
        directions: kani::any(),
        bump: kani::any(),
        authority: any_key(),
        bond: kani::any(),
        min: kani::any(),
        max: kani::any(),
        open_swaps: kani::any(),
        open_lamports: kani::any(),
        completed: kani::any(),
        aborted: kani::any(),
        expired: kani::any(),
        volume: kani::any(),
        created_at: kani::any(),
        withdraw_after: kani::any(),
        spread_bps: kani::any(),
        endpoint: Vec::new(),
        cancelled: kani::any(),
        declined: kani::any(),
        staked: kani::any(),
        stake_unlock_at: kani::any(),
        v2: kani::any(),
        ext: MakerExt {
            otc_fills: kani::any(),
            otc_volume: kani::any(),
            otc_failed: kani::any(),
            otc_declined: kani::any(),
            pay_fills: kani::any(),
            pay_volume: kani::any(),
            pay_failed: kani::any(),
            pay_declined: kani::any(),
            otc_min: kani::any(),
            otc_max: kani::any(),
        },
    }
}

fn any_escrow() -> Escrow {
    Escrow {
        state: kani::any(),
        direction: kani::any(),
        bump: kani::any(),
        released: kani::any(),
        swap_id: kani::any(),
        locker: any_key(),
        claimer: any_key(),
        maker: any_key(),
        amount: kani::any(),
        xmr_amount: kani::any(),
        fee_bps: kani::any(),
        claim_point: kani::any(),
        refund_point: kani::any(),
        view_pub: kani::any(),
        quote_hash: kani::any(),
        watchtowers: [any_key(), any_key()],
        created_at: kani::any(),
        t0: kani::any(),
        t1: kani::any(),
        settled_at: kani::any(),
        secret: kani::any(),
        flags: kani::any(),
        link: any_key(),
        // v1 escrows only: the v2 extension has its own model (model2.rs, proofs_final.rs).
        v2: false,
        ext: EscrowExt::default(),
    }
}

fn any_vp() -> VaultParams {
    VaultParams {
        keeper: any_key(),
        watchtowers: [any_key(), any_key()],
        link: any_key(),
        min_lamports: kani::any(),
        max_lamports: kani::any(),
        interval: kani::any(),
        min_rate: kani::any(),
        delay: kani::any(),
    }
}

fn any_vault() -> Vault {
    Vault {
        bump: kani::any(),
        paused: kani::any(),
        pending_unpause: kani::any(),
        owner: any_key(),
        p: any_vp(),
        next_at: kani::any(),
        created_at: kani::any(),
        pending_at: kani::any(),
        pending: any_vp(),
        withdraw_at: kani::any(),
        withdraw_amount: kani::any(),
        conversions: kani::any(),
        locked_lamports: kani::any(),
        refunds: kani::any(),
        refunded_lamports: kani::any(),
    }
}

fn same_vault(a: &Vault, b: &Vault) -> bool {
    a.paused == b.paused
        && a.pending_unpause == b.pending_unpause
        && a.p == b.p
        && a.next_at == b.next_at
        && a.pending_at == b.pending_at
        && a.pending == b.pending
        && a.withdraw_at == b.withdraw_at
        && a.withdraw_amount == b.withdraw_amount
        && a.conversions == b.conversions
        && a.locked_lamports == b.locked_lamports
}

fn same_ext(a: &MakerExt, b: &MakerExt) -> bool {
    a.otc_fills == b.otc_fills
        && a.otc_volume == b.otc_volume
        && a.otc_failed == b.otc_failed
        && a.otc_declined == b.otc_declined
        && a.pay_fills == b.pay_fills
        && a.pay_volume == b.pay_volume
        && a.pay_failed == b.pay_failed
        && a.pay_declined == b.pay_declined
        && a.otc_min == b.otc_min
        && a.otc_max == b.otc_max
}

fn pe<T>(r: Result<T, HkError>) -> Result<T, ProgramError> {
    r.map_err(Into::into)
}

// ---------------------------------------------------------------------------------------------
// Verbatim copies of the pre-refactor inline code (git d00f39f, program/src/lib.rs), lifted into
// functions of their inputs. `req!` returns ProgramError, as in the original.
// ---------------------------------------------------------------------------------------------

mod orig {
    use crate::*;

    pub fn scalar_is_canonical(s: &[u8; 32]) -> bool {
        for i in (0..32).rev() {
            if s[i] != L[i] {
                return s[i] < L[i];
            }
        }
        false
    }

    pub fn check_reveal(secret: &[u8; 32], point: &[u8; 32], mul: Option<[u8; 32]>) -> ProgramResult {
        req!(scalar_is_canonical(secret), HkError::NonCanonicalScalar);
        let got = mul.ok_or(HkError::BadPoint)?;
        req!(got == *point, HkError::WrongSecret);
        Ok(())
    }

    pub fn pay(from: u64, to: u64, lamports: u64) -> Result<(u64, u64), ProgramError> {
        let f = from.checked_sub(lamports).ok_or(HkError::Overflow)?;
        let t = to.checked_add(lamports).ok_or(HkError::Overflow)?;
        Ok((f, t))
    }

    fn add(a: u64, b: u64) -> Result<u64, ProgramError> {
        a.checked_add(b).ok_or_else(|| HkError::Overflow.into())
    }
    fn sub(a: u64, b: u64) -> Result<u64, ProgramError> {
        a.checked_sub(b).ok_or_else(|| HkError::Overflow.into())
    }

    pub fn lock_terms(
        c: &Config,
        m: &Maker,
        locker: &Pubkey,
        claimer: Pubkey,
        direction: u8,
        amount: u64,
        xmr_amount: u64,
        t0_secs: i64,
        window_secs: i64,
    ) -> Result<u64, ProgramError> {
        req!(!c.paused, HkError::Paused);
        req!(m.active, HkError::MakerInactive);
        req!(m.directions & direction != 0, HkError::DirectionUnsupported);
        match direction {
            DIR_SOL_TO_XMR => req!(claimer == m.authority, HkError::BadParam),
            DIR_XMR_TO_SOL => req!(*locker == m.authority, HkError::BadParam),
            _ => return Err(HkError::BadParam.into()),
        }
        req!(claimer != *locker && claimer != Pubkey::default(), HkError::BadParam);
        req!(amount >= m.min && amount <= m.max, HkError::AmountOutOfRange);
        req!(amount <= c.max_swap, HkError::CapExceeded);
        let tvl = add(c.open_tvl, amount)?;
        req!(tvl <= c.max_open_tvl, HkError::CapExceeded);
        req!(xmr_amount > 0, HkError::BadParam);
        req!(t0_secs >= c.min_t0 && t0_secs <= c.max_t0, HkError::BadParam);
        req!(window_secs >= c.min_window && window_secs <= c.max_window, HkError::BadParam);
        Ok(tvl)
    }

    pub fn watchtowers(wt: &[Pubkey; 2], claimer: Pubkey) -> ProgramResult {
        for w in wt.iter() {
            req!(*w != claimer, HkError::BadParam);
        }
        Ok(())
    }

    pub fn fee_bps(c: &Config, m: &Maker) -> u16 {
        if c.halfkey_mint != Pubkey::default() && m.staked >= c.holder_min && m.stake_unlock_at == 0 {
            c.holder_fee_bps
        } else {
            c.fee_bps
        }
    }

    pub fn deadlines(t: i64, t0_secs: i64, window_secs: i64) -> Result<(i64, i64), ProgramError> {
        let t0 = t.checked_add(t0_secs).ok_or(HkError::Overflow)?;
        let t1 = t0.checked_add(window_secs).ok_or(HkError::Overflow)?;
        Ok((t0, t1))
    }

    pub fn open_counters(m: &mut Maker, c: &mut Config, amount: u64, tvl: u64) -> ProgramResult {
        m.open_swaps = m.open_swaps.checked_add(1).ok_or(HkError::Overflow)?;
        m.open_lamports = add(m.open_lamports, amount)?;
        c.open_tvl = tvl;
        Ok(())
    }

    pub fn release(e: &mut Escrow, m: &mut Maker, c: &mut Config) -> ProgramResult {
        if e.released {
            return Ok(());
        }
        m.open_swaps = m.open_swaps.checked_sub(1).ok_or(HkError::Overflow)?;
        m.open_lamports = sub(m.open_lamports, e.amount)?;
        c.open_tvl = sub(c.open_tvl, e.amount)?;
        e.released = true;
        Ok(())
    }

    /// `now()` is passed as a value; `clock_read` reports whether the original read it.
    pub fn ready(e: &Escrow, now: i64, clock_read: &mut bool) -> ProgramResult {
        req!(e.state == ST_LOCKED, HkError::BadState);
        *clock_read = true;
        req!(now < e.t0, HkError::TooLate);
        Ok(())
    }

    /// Returns the stat counter bumped: 0 declined, 1 cancelled, 2 aborted.
    pub fn abort(e: &Escrow, who: &Pubkey, t: i64) -> Result<u8, ProgramError> {
        let maker_side = if e.direction == DIR_SOL_TO_XMR { e.claimer } else { e.locker };
        if *who == e.claimer {
            req!(e.state == ST_LOCKED || e.state == ST_READY, HkError::BadState);
            req!(t < e.t1, HkError::TooLate);
            if *who == maker_side {
                Ok(0)
            } else {
                Ok(1)
            }
        } else {
            let is_wt = e.watchtowers.iter().any(|w| *w != Pubkey::default() && w == who);
            req!(*who == e.locker || is_wt, HkError::Unauthorized);
            req!(e.state == ST_LOCKED, HkError::BadState);
            req!(t < e.t0, HkError::TooLate);
            if *who == e.locker {
                if *who == maker_side {
                    Ok(0)
                } else {
                    Ok(1)
                }
            } else {
                Ok(2)
            }
        }
    }

    pub fn claim_window(e: &Escrow, t: i64) -> ProgramResult {
        req!(t < e.t1, HkError::TooLate);
        match e.state {
            ST_READY => {}
            ST_LOCKED => req!(t >= e.t0, HkError::TooEarly),
            _ => return Err(HkError::BadState.into()),
        }
        Ok(())
    }

    pub fn split_fee(amount: u64, fee_bps: u16) -> Result<(u64, u64), ProgramError> {
        let fee = ((amount as u128) * (fee_bps as u128) / 10_000) as u64;
        let to_claimer = sub(amount, fee)?;
        Ok((to_claimer, fee))
    }

    pub fn expire(e: &Escrow, now: i64, clock_read: &mut bool) -> ProgramResult {
        req!(e.state == ST_LOCKED || e.state == ST_READY, HkError::BadState);
        req!(!e.released, HkError::BadState);
        *clock_read = true;
        req!(now >= e.t1, HkError::TooEarly);
        Ok(())
    }

    pub fn refund_window(e: &Escrow, t: i64) -> ProgramResult {
        match e.state {
            ST_ABORTED => {}
            ST_LOCKED | ST_READY => req!(t >= e.t1, HkError::TooEarly),
            _ => return Err(HkError::BadState.into()),
        }
        Ok(())
    }

    pub fn close(e: &Escrow) -> ProgramResult {
        req!(e.state == ST_CLAIMED || e.state == ST_REFUNDED, HkError::BadState);
        Ok(())
    }

    pub fn ed25519(d: &[u8], signer_key: &Pubkey, msg: &[u8]) -> ProgramResult {
        req!(d.len() >= 16 && d[0] == 1, HkError::NoConsent);
        let u = |i: usize| u16::from_le_bytes([d[i], d[i + 1]]);
        let (sig_off, sig_ix, pk_off, pk_ix, msg_off, msg_len, msg_ix) =
            (u(2) as usize, u(4), u(6) as usize, u(8), u(10) as usize, u(12) as usize, u(14));
        req!(sig_ix == u16::MAX && pk_ix == u16::MAX && msg_ix == u16::MAX, HkError::NoConsent);
        req!(sig_off.checked_add(64).is_some_and(|e| e <= d.len()), HkError::NoConsent);
        req!(pk_off.checked_add(32).is_some_and(|e| e <= d.len()), HkError::NoConsent);
        req!(msg_off.checked_add(msg_len).is_some_and(|e| e <= d.len()), HkError::NoConsent);
        req!(d[pk_off..pk_off + 32] == *signer_key.as_ref(), HkError::NoConsent);
        req!(&d[msg_off..msg_off + msg_len] == msg, HkError::NoConsent);
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Verbatim copies of the platform branch's inline code (git 3f2d99e, program/src/lib.rs), lifted
// into functions of their inputs: the reference for the platform rules moved into `logic`.
// ---------------------------------------------------------------------------------------------

mod orig_platform {
    use crate::*;
    /// The platform branch's flag set (before v1.5 added F_PROOF).
    const F_ALL: u8 = F_PAY | F_OTC | F_VAULT;

    fn add(a: u64, b: u64) -> Result<u64, ProgramError> {
        a.checked_add(b).ok_or_else(|| HkError::Overflow.into())
    }
    fn cap_for(c: &Config, flags: u8) -> u64 {
        if flags & F_OTC != 0 && c.otc_max_swap > 0 { c.otc_max_swap } else { c.max_swap }
    }

    /// open_escrow, from `req!(!c.paused ...)` to the window check.
    pub fn lock_terms(
        c: &Config,
        m: &Maker,
        locker_key: &Pubkey,
        claimer: Pubkey,
        direction: u8,
        amount: u64,
        xmr_amount: u64,
        t0_secs: i64,
        window_secs: i64,
        flags: u8,
    ) -> Result<u64, ProgramError> {
        req!(!c.paused, HkError::Paused);
        req!(m.active, HkError::MakerInactive);
        req!(flags & !F_ALL == 0, HkError::BadParam);
        req!(m.directions & direction != 0, HkError::DirectionUnsupported);
        match direction {
            DIR_SOL_TO_XMR => req!(claimer == m.authority, HkError::BadParam),
            DIR_XMR_TO_SOL => req!(*locker_key == m.authority, HkError::BadParam),
            _ => return Err(HkError::BadParam.into()),
        }
        req!(claimer != *locker_key && claimer != Pubkey::default(), HkError::BadParam);
        if flags != 0 {
            req!(m.v2, HkError::NotUpgraded);
        }
        let (lo, hi) = if flags & F_OTC != 0 && m.ext.otc_max > 0 { (m.ext.otc_min, m.ext.otc_max) } else { (m.min, m.max) };
        req!(amount >= lo && amount <= hi, HkError::AmountOutOfRange);
        req!(amount <= cap_for(c, flags), HkError::CapExceeded);
        let tvl = add(c.open_tvl, amount)?;
        req!(tvl <= c.max_open_tvl, HkError::CapExceeded);
        req!(xmr_amount > 0, HkError::BadParam);
        req!(t0_secs >= c.min_t0 && t0_secs <= c.max_t0, HkError::BadParam);
        req!(window_secs >= c.min_window && window_secs <= c.max_window, HkError::BadParam);
        Ok(tvl)
    }

    /// open_escrow's pay branch minus the link account work: Ok(is_pay).
    pub fn pay_shape(flags: u8, direction: u8) -> Result<bool, ProgramError> {
        if flags & F_PAY != 0 {
            req!(direction == DIR_SOL_TO_XMR, HkError::BadParam);
            Ok(true)
        } else {
            req!(flags & F_VAULT == 0, HkError::BadParam);
            Ok(false)
        }
    }

    pub fn watchtowers(wt: &[Pubkey; 2], claimer: Pubkey, locker_key: &Pubkey, flags: u8) -> ProgramResult {
        for w in wt.iter() {
            req!(*w != claimer, HkError::BadParam);
        }
        if flags & F_PAY != 0 {
            req!(wt.iter().any(|w| *w != Pubkey::default()), HkError::NoWatchtower);
            for w in wt.iter() {
                req!(w != locker_key, HkError::BadParam);
            }
        }
        Ok(())
    }

    pub fn ready(e: &Escrow, now: i64, clock_read: &mut bool) -> ProgramResult {
        req!(e.flags & F_PAY == 0, HkError::Unauthorized);
        req!(e.state == ST_LOCKED, HkError::BadState);
        *clock_read = true;
        req!(now < e.t0, HkError::TooLate);
        Ok(())
    }

    /// (counter bumped: 0 declined, 1 cancelled, 2 aborted; ext outcome: 0 none, 1 declined,
    /// 2 failed).
    pub fn abort(e: &Escrow, who: &Pubkey, t: i64) -> Result<(u8, u8), ProgramError> {
        let maker_side = if e.direction == DIR_SOL_TO_XMR { e.claimer } else { e.locker };
        if *who == e.claimer {
            req!(e.state == ST_LOCKED || e.state == ST_READY, HkError::BadState);
            req!(t < e.t1, HkError::TooLate);
            if *who == maker_side {
                Ok((0, 1))
            } else {
                Ok((1, 0))
            }
        } else {
            let is_wt = e.watchtowers.iter().any(|w| *w != Pubkey::default() && w == who);
            let locker_may = *who == e.locker && e.flags & F_PAY == 0;
            req!(locker_may || is_wt, HkError::Unauthorized);
            req!(e.state == ST_LOCKED, HkError::BadState);
            req!(t < e.t0, HkError::TooLate);
            if locker_may {
                if *who == maker_side {
                    Ok((0, 0))
                } else {
                    Ok((1, 0))
                }
            } else {
                Ok((2, 2))
            }
        }
    }

    /// `ext_count` with Outcome encoded 0 Fill, 1 Failed, 2 Declined.
    pub fn ext_count(e: &Escrow, m: &mut Maker, o: u8) -> ProgramResult {
        if e.flags == 0 || !m.v2 {
            return Ok(());
        }
        if e.direction == DIR_XMR_TO_SOL && o != 0 {
            return Ok(());
        }
        let x = &mut m.ext;
        let bump = |fills: &mut u64, vol: &mut u64, failed: &mut u64, declined: &mut u64| -> ProgramResult {
            match o {
                0 => {
                    *fills = add(*fills, 1)?;
                    *vol = add(*vol, e.amount)?;
                }
                1 => *failed = add(*failed, 1)?,
                _ => *declined = add(*declined, 1)?,
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

    /// refund: the secret part (check_reveal with an abstract syscall result).
    pub fn refund_secret(e: &Escrow, secret: &[u8; 32], mul: Option<[u8; 32]>) -> ProgramResult {
        if e.flags & F_PAY != 0 {
            req!(*secret == [0u8; 32], HkError::BadParam);
        } else {
            super::orig::check_reveal(secret, &e.refund_point, mul)?;
        }
        Ok(())
    }

    pub fn close(e: &Escrow) -> ProgramResult {
        req!(e.flags & F_PAY == 0, HkError::BadState);
        req!(e.state == ST_CLAIMED || e.state == ST_REFUNDED, HkError::BadState);
        Ok(())
    }

    /// close_pay after the account checks; `owner` is the link owner.
    pub fn close_pay(e: &Escrow, who: &Pubkey, owner: &Pubkey, now: i64, clock_read: &mut bool) -> ProgramResult {
        let locker_side = *who == e.locker || e.flags & F_VAULT != 0;
        match e.state {
            ST_REFUNDED => req!(locker_side, HkError::Unauthorized),
            ST_CLAIMED => {
                *clock_read = true;
                let late = now >= e.settled_at.checked_add(PAY_CLOSE_GRACE).ok_or(HkError::Overflow)?;
                req!(*who == *owner || (locker_side && late), HkError::Unauthorized);
            }
            _ => return Err(HkError::BadState.into()),
        }
        Ok(())
    }

    pub fn config_ext(c: &Config, otc_max_swap: u64, vault_min_delay: i64) -> ProgramResult {
        req!(otc_max_swap == 0 || (otc_max_swap >= c.max_swap && otc_max_swap <= c.max_open_tvl), HkError::BadParam);
        req!((0..=30 * 86_400).contains(&vault_min_delay), HkError::BadParam);
        Ok(())
    }

    pub fn otc_range(otc_min: u64, otc_max: u64) -> ProgramResult {
        req!(otc_max == 0 || (otc_min > 0 && otc_min <= otc_max), HkError::BadParam);
        Ok(())
    }

    pub fn link_name(n: &[u8]) -> ProgramResult {
        req!(n.len() >= 3 && n.len() <= 32, HkError::BadParam);
        req!(n.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-'), HkError::BadParam);
        req!(n[0] != b'-' && n[n.len() - 1] != b'-', HkError::BadParam);
        Ok(())
    }

    pub fn vault_params(c: &Config, p: &VaultParams) -> ProgramResult {
        req!(p.watchtowers.iter().any(|w| *w != Pubkey::default()), HkError::NoWatchtower);
        req!(p.keeper != Pubkey::default(), HkError::BadParam);
        req!(p.min_lamports > 0 && p.min_lamports <= p.max_lamports, HkError::BadParam);
        req!(p.max_lamports <= c.max_swap, HkError::BadParam);
        req!(p.interval >= 0 && p.interval <= 30 * 86_400, HkError::BadParam);
        req!(p.min_rate > 0, HkError::BadParam);
        req!(p.delay >= c.vault_min_delay && p.delay <= 30 * 86_400, HkError::BadParam);
        Ok(())
    }

    pub fn vault_propose(v: &mut Vault, p: VaultParams, unpause: bool, now: i64) -> ProgramResult {
        v.pending_unpause = unpause;
        v.pending_at = now.checked_add(v.p.delay.max(1)).ok_or(HkError::Overflow)?;
        v.pending = p;
        Ok(())
    }

    pub fn vault_apply(v: &mut Vault, now: i64, clock_read: &mut bool) -> ProgramResult {
        req!(v.pending_at != 0, HkError::NothingPending);
        *clock_read = true;
        req!(now >= v.pending_at, HkError::Timelocked);
        v.p = v.pending.clone();
        if v.pending_unpause {
            v.paused = false;
        }
        v.pending_unpause = false;
        v.pending = VaultParams::default();
        v.pending_at = 0;
        Ok(())
    }

    pub fn vault_cancel(v: &mut Vault) {
        v.pending = VaultParams::default();
        v.pending_at = 0;
        v.pending_unpause = false;
        v.withdraw_at = 0;
        v.withdraw_amount = 0;
    }

    pub fn vault_tighten(v: &mut Vault, paused: u8, min_rate: u64, max_lamports: u64, interval: i64) -> ProgramResult {
        req!(paused <= 1, HkError::BadParam);
        req!(paused == 1 || !v.paused, HkError::Timelocked);
        req!(min_rate >= v.p.min_rate, HkError::Timelocked);
        req!(max_lamports <= v.p.max_lamports && max_lamports >= v.p.min_lamports, HkError::Timelocked);
        req!(interval >= v.p.interval && interval <= 30 * 86_400, HkError::Timelocked);
        v.paused = paused == 1;
        if v.paused {
            v.pending_unpause = false;
        }
        v.p.min_rate = min_rate;
        v.p.max_lamports = max_lamports;
        v.p.interval = interval;
        Ok(())
    }

    /// vault_lock, from `req!(!v.paused ...)` to the rate check; returns the clock.
    pub fn vault_lock_terms(v: &Vault, keeper: &Pubkey, now: i64, clock_read: &mut bool, amount: u64, xmr_amount: u64) -> Result<i64, ProgramError> {
        req!(!v.paused, HkError::Paused);
        req!(*keeper == v.p.keeper || *keeper == v.owner, HkError::Unauthorized);
        *clock_read = true;
        let t = now;
        req!(t >= v.next_at, HkError::NotDue);
        req!(amount >= v.p.min_lamports && amount <= v.p.max_lamports, HkError::AmountOutOfRange);
        req!((xmr_amount as u128) * 1_000_000_000u128 >= (v.p.min_rate as u128) * (amount as u128), HkError::RateTooLow);
        Ok(t)
    }

    pub fn vault_converted(v: &mut Vault, t: i64, amount: u64) -> ProgramResult {
        v.next_at = t.checked_add(v.p.interval).ok_or(HkError::Overflow)?;
        v.conversions = add(v.conversions, 1)?;
        v.locked_lamports = add(v.locked_lamports, amount)?;
        Ok(())
    }

    /// open_escrow's vault funding check (`keep` = vault rent reserve); returns the lamports moved.
    pub fn vault_funding(amount: u64, top: u64, vault_lamports: u64, keep: u64) -> Result<u64, ProgramError> {
        let avail = vault_lamports.saturating_sub(keep);
        req!(add(amount, top)? <= avail, HkError::AmountOutOfRange);
        add(amount, top)
    }

    pub fn vault_withdraw_request(v: &mut Vault, amount: u64, now: i64, clock_read: &mut bool) -> ProgramResult {
        req!(amount > 0, HkError::BadParam);
        v.withdraw_amount = amount;
        *clock_read = true;
        v.withdraw_at = now.checked_add(v.p.delay.max(1)).ok_or(HkError::Overflow)?;
        Ok(())
    }

    /// vault_withdraw after the account checks; returns the amount paid.
    pub fn vault_withdraw(v: &mut Vault, now: i64, clock_read: &mut bool, vault_lamports: u64, keep: u64) -> Result<u64, ProgramError> {
        req!(v.withdraw_at != 0, HkError::NothingPending);
        *clock_read = true;
        req!(now >= v.withdraw_at, HkError::Timelocked);
        let free = vault_lamports.saturating_sub(keep);
        let amt = v.withdraw_amount.min(free);
        v.withdraw_at = 0;
        v.withdraw_amount = 0;
        Ok(amt)
    }
}

// ---------------------------------------------------------------------------------------------
// Refactor equivalence (all inputs)
// ---------------------------------------------------------------------------------------------

#[kani::proof]
#[kani::unwind(33)]
fn eq_scalar_is_canonical() {
    let s: [u8; 32] = kani::any();
    assert_eq!(logic::scalar_is_canonical(&s), orig::scalar_is_canonical(&s));
}

#[kani::proof]
#[kani::unwind(33)]
fn eq_check_reveal() {
    let s: [u8; 32] = kani::any();
    let p: [u8; 32] = kani::any();
    let mul: Option<[u8; 32]> = kani::any();
    let new = pe(logic::check_reveal_with(&s, &p, |_| mul));
    assert_eq!(new, orig::check_reveal(&s, &p, mul));
}

#[kani::proof]
fn eq_pay() {
    let (a, b, x) = (kani::any(), kani::any(), kani::any());
    assert_eq!(pe(logic::pay_amounts(a, b, x)), orig::pay(a, b, x));
}

#[kani::proof]
fn eq_lock_terms() {
    let c = any_config();
    let m = any_maker();
    let locker = any_key();
    let claimer = any_key();
    let (direction, amount, xmr, t0s, ws) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    // Unflagged locks: exactly the phase-1 check.
    let new = pe(logic::check_lock_terms(&c, &m, &locker, &claimer, direction, amount, xmr, t0s, ws, 0));
    assert_eq!(new, orig::lock_terms(&c, &m, &locker, claimer, direction, amount, xmr, t0s, ws));
}

#[kani::proof]
fn eq_lock_terms_platform() {
    let c = any_config();
    let m = any_maker();
    let locker = any_key();
    let claimer = any_key();
    let (direction, amount, xmr, t0s, ws) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    // v1.5 added one accepted flag bit (F_PROOF, eq_lock_terms_proof); every other flag value
    // behaves exactly as on the platform branch.
    let flags: u8 = kani::any_where(|f| f & (F_PROOF | F_READY_ONLY) == 0);
    let new = pe(logic::check_lock_terms(&c, &m, &locker, &claimer, direction, amount, xmr, t0s, ws, flags));
    assert_eq!(new, orig_platform::lock_terms(&c, &m, &locker, claimer, direction, amount, xmr, t0s, ws, flags));
    let (f, d) = (kani::any(), kani::any());
    assert_eq!(pe(logic::pay_shape(f, d)), orig_platform::pay_shape(f, d));
}

#[kani::proof]
#[kani::unwind(33)]
fn eq_watchtowers() {
    let wt = [any_key(), any_key()];
    let claimer = any_key();
    let locker = any_key();
    assert_eq!(pe(logic::check_watchtowers(&wt, &claimer, &locker, 0)), orig::watchtowers(&wt, claimer));
    let flags: u8 = kani::any();
    assert_eq!(pe(logic::check_watchtowers(&wt, &claimer, &locker, flags)), orig_platform::watchtowers(&wt, claimer, &locker, flags));
}

#[kani::proof]
fn eq_fee_bps() {
    let c = any_config();
    let m = any_maker();
    assert_eq!(logic::effective_fee_bps(&c, &m), orig::fee_bps(&c, &m));
}

#[kani::proof]
fn eq_deadlines() {
    let (t, a, b) = (kani::any(), kani::any(), kani::any());
    assert_eq!(pe(logic::deadlines(t, a, b)), orig::deadlines(t, a, b));
}

#[kani::proof]
fn eq_open_counters_and_release() {
    let (mut m1, mut c1) = (any_maker(), any_config());
    let (mut m2, mut c2) = (m1.clone(), c1.clone());
    let (amount, tvl) = (kani::any(), kani::any());
    assert_eq!(pe(logic::open_counters(&mut m1, &mut c1, amount, tvl)), orig::open_counters(&mut m2, &mut c2, amount, tvl));
    assert!(m1.open_swaps == m2.open_swaps && m1.open_lamports == m2.open_lamports && c1.open_tvl == c2.open_tvl);

    let mut e1 = any_escrow();
    let mut e2 = e1.clone();
    assert_eq!(pe(logic::release(&mut e1, &mut m1, &mut c1)), orig::release(&mut e2, &mut m2, &mut c2));
    assert!(e1.released == e2.released);
    assert!(m1.open_swaps == m2.open_swaps && m1.open_lamports == m2.open_lamports && c1.open_tvl == c2.open_tvl);
}

#[kani::proof]
fn eq_windows() {
    let e = any_escrow();
    let t: i64 = kani::any();
    let mut read_o = false;
    let mut read_n = false;
    let n = logic::ready_window::<ProgramError>(e.state, e.t0, 0, || {
        read_n = true;
        Ok(t)
    });
    assert_eq!(n, orig::ready(&e, t, &mut read_o));
    assert_eq!(read_n, read_o, "clock read in the same cases");
    let (mut read_o, mut read_n) = (false, false);
    let n = logic::ready_window::<ProgramError>(e.state, e.t0, e.flags, || {
        read_n = true;
        Ok(t)
    });
    assert_eq!(n, orig_platform::ready(&e, t, &mut read_o));
    assert_eq!(read_n, read_o, "clock read in the same cases");

    let (mut read_o, mut read_n) = (false, false);
    let n = logic::expire_window::<ProgramError>(e.state, e.released, e.t1, || {
        read_n = true;
        Ok(t)
    });
    assert_eq!(n, orig::expire(&e, t, &mut read_o));
    assert_eq!(read_n, read_o, "clock read in the same cases");

    assert_eq!(pe(logic::claim_window(e.state, t, e.t0, e.t1)), orig::claim_window(&e, t));
    assert_eq!(pe(logic::refund_window(e.state, t, e.t1)), orig::refund_window(&e, t));
    assert_eq!(pe(logic::close_allowed(e.state, 0)), orig::close(&e));
    assert_eq!(pe(logic::close_allowed(e.state, e.flags)), orig_platform::close(&e));
}

#[kani::proof]
#[kani::unwind(33)]
fn eq_abort() {
    let mut e = any_escrow();
    e.flags &= !F_PAY; // phase-1 rules for every escrow that is not a pay escrow
    let who = any_key();
    let t: i64 = kani::any();
    let new = pe(logic::abort_check(&e, &who, t)).map(|k| match k {
        AbortKind::Declined => 0u8,
        AbortKind::Cancelled => 1,
        AbortKind::Watchtower => 2,
    });
    assert_eq!(new, orig::abort(&e, &who, t));
}

#[kani::proof]
#[kani::unwind(33)]
fn eq_abort_platform() {
    let e = any_escrow();
    let who = any_key();
    let t: i64 = kani::any();
    let new = pe(logic::abort_check(&e, &who, t)).map(|k| {
        let ext = match logic::abort_ext_outcome(k, who == e.claimer) {
            None => 0u8,
            Some(logic::Outcome::Declined) => 1,
            Some(logic::Outcome::Failed) => 2,
            Some(logic::Outcome::Fill) => 9,
        };
        let kind = match k {
            AbortKind::Declined => 0u8,
            AbortKind::Cancelled => 1,
            AbortKind::Watchtower => 2,
        };
        (kind, ext)
    });
    assert_eq!(new, orig_platform::abort(&e, &who, t));
}

#[kani::proof]
fn eq_ext_count() {
    let e = any_escrow();
    let m = any_maker();
    let o: u8 = kani::any_where(|o| *o <= 2);
    let out = [logic::Outcome::Fill, logic::Outcome::Failed, logic::Outcome::Declined][o as usize];
    let (mut m1, mut m2) = (m.clone(), m);
    assert_eq!(pe(logic::ext_count(&e, &mut m1, out)), orig_platform::ext_count(&e, &mut m2, o));
    assert!(same_ext(&m1.ext, &m2.ext));
}

#[kani::proof]
#[kani::unwind(33)]
fn eq_refund_secret_and_close_pay() {
    let e = any_escrow();
    let secret: [u8; 32] = kani::any();
    let mul: Option<[u8; 32]> = kani::any();
    let n = pe(logic::refund_secret_check(e.flags, &secret, &e.refund_point, |_| mul));
    assert_eq!(n, orig_platform::refund_secret(&e, &secret, mul));

    let (who, owner) = (any_key(), any_key());
    let now: i64 = kani::any();
    let (mut read_o, mut read_n) = (false, false);
    let n = logic::close_pay_allowed::<ProgramError>(e.state, e.flags, who == e.locker, who == owner, e.settled_at, || {
        read_n = true;
        Ok(now)
    });
    assert_eq!(n, orig_platform::close_pay(&e, &who, &owner, now, &mut read_o));
    assert_eq!(read_n, read_o, "clock read in the same cases");
}

#[kani::proof]
#[kani::unwind(33)]
fn eq_platform_params() {
    let c = any_config();
    let (x, d) = (kani::any(), kani::any());
    assert_eq!(pe(logic::check_config_ext(&c, x, d)), orig_platform::config_ext(&c, x, d));
    let (lo, hi) = (kani::any(), kani::any());
    assert_eq!(pe(logic::check_otc_range(lo, hi)), orig_platform::otc_range(lo, hi));
    let p = any_vp();
    assert_eq!(pe(logic::check_vault_params(&c, &p)), orig_platform::vault_params(&c, &p));
    let buf: [u8; 32] = kani::any();
    let len: usize = kani::any_where(|l| *l <= 32);
    kani::assume(len >= 1); // the handler reads a u8 length; an empty name fails the length check first
    assert_eq!(pe(logic::check_link_name(&buf[..len])), orig_platform::link_name(&buf[..len]));
}

#[kani::proof]
fn eq_vault_timelock() {
    let v = any_vault();
    let p = any_vp();
    let (unpause, t): (bool, i64) = (kani::any(), kani::any());
    let (mut v1, mut v2) = (v.clone(), v.clone());
    assert_eq!(pe(logic::vault_propose(&mut v1, p.clone(), unpause, t)), orig_platform::vault_propose(&mut v2, p, unpause, t));
    assert!(same_vault(&v1, &v2));

    let (mut v1, mut v2) = (v.clone(), v.clone());
    let (mut read_o, mut read_n) = (false, false);
    let n = logic::vault_apply::<ProgramError>(&mut v1, || {
        read_n = true;
        Ok(t)
    });
    assert_eq!(n, orig_platform::vault_apply(&mut v2, t, &mut read_o));
    assert!(read_n == read_o && same_vault(&v1, &v2));

    let (mut v1, mut v2) = (v.clone(), v.clone());
    logic::vault_cancel(&mut v1);
    orig_platform::vault_cancel(&mut v2);
    assert!(same_vault(&v1, &v2));

    let (paused, rate, max, iv) = (kani::any(), kani::any(), kani::any(), kani::any());
    let (mut v1, mut v2) = (v.clone(), v);
    assert_eq!(pe(logic::vault_tighten(&mut v1, paused, rate, max, iv)), orig_platform::vault_tighten(&mut v2, paused, rate, max, iv));
    assert!(same_vault(&v1, &v2));
}

#[kani::proof]
fn eq_vault_money() {
    let v = any_vault();
    let keeper = any_key();
    let (t, amount, xmr): (i64, u64, u64) = (kani::any(), kani::any(), kani::any());
    let (mut read_o, mut read_n) = (false, false);
    let n = logic::vault_lock_terms::<ProgramError>(&v, &keeper, || {
        read_n = true;
        Ok(t)
    }, amount, xmr);
    assert_eq!(n, orig_platform::vault_lock_terms(&v, &keeper, t, &mut read_o, amount, xmr));
    assert_eq!(read_n, read_o);

    let (mut v1, mut v2) = (v.clone(), v.clone());
    assert_eq!(pe(logic::vault_converted(&mut v1, t, amount)), orig_platform::vault_converted(&mut v2, t, amount));
    assert!(same_vault(&v1, &v2));

    let (top, lamports, keep): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
    assert_eq!(pe(logic::vault_funding(amount, top, lamports, keep)), orig_platform::vault_funding(amount, top, lamports, keep));

    let (mut v1, mut v2) = (v.clone(), v.clone());
    let (mut read_o, mut read_n) = (false, false);
    let n = logic::vault_withdraw_request::<ProgramError>(&mut v1, amount, || {
        read_n = true;
        Ok(t)
    });
    assert_eq!(n, orig_platform::vault_withdraw_request(&mut v2, amount, t, &mut read_o));
    assert!(read_n == read_o && same_vault(&v1, &v2));

    let (mut v1, mut v2) = (v.clone(), v);
    let (mut read_o, mut read_n) = (false, false);
    let n = logic::vault_withdraw_due::<ProgramError>(&v1, || {
        read_n = true;
        Ok(t)
    })
    .map(|_| logic::vault_withdraw_take(&mut v1, lamports, keep));
    assert_eq!(n, orig_platform::vault_withdraw(&mut v2, t, &mut read_o, lamports, keep));
    assert!(read_n == read_o && same_vault(&v1, &v2));
}

/// `bps_of` with its 128-bit divider replaced by the definition of unsigned integer division:
/// the unique q with q*10_000 <= amount*bps < q*10_000 + 10_000, truncated to u64 like the code.
/// Sound because Rust's `/` on unsigned integers is exactly floor division (language semantics,
/// trusted like the rest of the compiler); SAT does not finish proofs through a 128-bit divider
/// circuit, so harnesses that reach the fee use this stub (run with `-Z stubbing`).
fn spec_bps_of(amount: u64, bps: u16) -> u64 {
    let prod = amount as u128 * bps as u128; // < 2^80
    let q: u128 = kani::any();
    let qm = q.checked_mul(10_000);
    kani::assume(matches!(qm, Some(x) if x <= prod && prod < x + 10_000));
    q as u64
}

// split_fee: the fee expression moved verbatim into `bps_of`; the rest is `checked_sub` with the
// same Overflow error. Not a Kani harness: with the default SAT solver, comparing two 128-bit
// dividers (or two stubbed quotients) does not finish; Kani's Bitwuzla backend finished but also
// reported a false counterexample on a true property (amount 8192, bps 64), so it is not used.
// Covered by fuzz::split_fee_edges_match_original and fuzz::split_fee_matches_original (20k cases).

/// Bounded: instruction data up to 160 bytes (a single-signature, 32-byte-message precompile
/// instruction as the client builds it is 144 bytes).
#[kani::proof]
#[kani::unwind(161)]
fn eq_ed25519() {
    const N: usize = 160;
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any_where(|l| *l <= N);
    let d = &buf[..len];
    let key = any_key();
    let msg: [u8; 32] = kani::any();
    assert_eq!(pe(logic::ed25519_ix_binds(d, &key.to_bytes(), &msg)), orig::ed25519(d, &key, &msg));
}

// ---------------------------------------------------------------------------------------------
// P4: accounting
// ---------------------------------------------------------------------------------------------

/// For every u16 fee (even ones the program can never store): whenever the split succeeds it
/// conserves the amount exactly; it never panics.
#[kani::proof]
#[kani::stub(logic::bps_of, spec_bps_of)]
fn p4_split_fee_conserves_any_bps() {
    let amount: u64 = kani::any();
    let bps: u16 = kani::any();
    if let Ok((to_claimer, fee)) = logic::split_fee(amount, bps) {
        assert!(to_claimer as u128 + fee as u128 == amount as u128);
    }
}

/// `pay` moves exactly `x` lamports: the pair's total is unchanged, no overflow, no wrap.
#[kani::proof]
fn p4_pay_conserves() {
    let (a, b, x): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
    match logic::pay_amounts(a, b, x) {
        Ok((f, t)) => {
            assert!(f as u128 + t as u128 == a as u128 + b as u128);
            assert!(f == a - x && t == b + x);
        }
        Err(e) => assert!(e == HkError::Overflow && (x > a || b.checked_add(x).is_none())),
    }
}

/// Config params accepted by init/update bound the escrow fee to <= 1% and keep deadlines far
/// from overflow; so every stored escrow has fee_bps <= MAX_FEE_BPS.
#[kani::proof]
#[kani::unwind(33)]
fn p4_config_bounds_fee_and_windows() {
    let buf: [u8; 140] = kani::any();
    let mut r = Rd::new(&buf);
    if let Ok(p) = read_config_params(&mut r) {
        let mut c = Config::default();
        apply_params(&mut c, p);
        assert!(c.fee_bps <= MAX_FEE_BPS && c.holder_fee_bps <= c.fee_bps);
        assert!(c.min_t0 >= 1 && c.min_t0 <= c.max_t0 && c.max_t0 <= 30 * 86_400);
        assert!(c.min_window >= 1 && c.min_window <= c.max_window && c.max_window <= 30 * 86_400);
        let m = any_maker();
        let c2 = Config { halfkey_mint: any_key(), holder_min: kani::any(), ..c.clone() };
        assert!(logic::effective_fee_bps(&c2, &m) <= MAX_FEE_BPS);
        // Any clock up to year ~292e9 minus 60 days: deadlines never overflow.
        let t: i64 = kani::any_where(|t| *t >= 0 && *t <= i64::MAX - 60 * 86_400);
        let t0s: i64 = kani::any_where(|x| *x >= c.min_t0 && *x <= c.max_t0);
        let ws: i64 = kani::any_where(|x| *x >= c.min_window && *x <= c.max_window);
        let (t0, t1) = logic::deadlines(t, t0s, ws).unwrap();
        assert!(t < t0 && t0 < t1);
    }
}

// ---------------------------------------------------------------------------------------------
// P5: consent binding
// ---------------------------------------------------------------------------------------------

/// The consent message is a fixed-length (317 byte) encoding, so equal messages mean equal terms
/// (injective). With sha256 collision resistance and ed25519 unforgeability (assumed), a maker
/// signature over sha256(message) binds every listed field.
#[kani::proof]
#[kani::unwind(400)]
fn p5_consent_message_injective() {
    let pid = any_key();
    let (e1, e2) = (any_key(), any_key());
    let (l1, l2) = (any_key(), any_key());
    let (c1, c2) = (any_key(), any_key());
    let (d1, d2): (u8, u8) = (kani::any(), kani::any());
    let (a1, a2): (u64, u64) = (kani::any(), kani::any());
    let (x1, x2): (u64, u64) = (kani::any(), kani::any());
    let (cp1, cp2): ([u8; 32], [u8; 32]) = (kani::any(), kani::any());
    let (rp1, rp2): ([u8; 32], [u8; 32]) = (kani::any(), kani::any());
    let (v1, v2): ([u8; 32], [u8; 32]) = (kani::any(), kani::any());
    let (q1, q2): ([u8; 32], [u8; 32]) = (kani::any(), kani::any());
    let (t1, t2): (i64, i64) = (kani::any(), kani::any());
    let (w1, w2): (i64, i64) = (kani::any(), kani::any());
    let (x1e, x2e): (i64, i64) = (kani::any(), kani::any());
    let (f1, f2): (u16, u16) = (kani::any(), kani::any());
    let m1 = consent_message(&pid, &e1, &l1, &c1, d1, a1, x1, &cp1, &rp1, &v1, &q1, t1, w1, x1e, f1);
    let m2 = consent_message(&pid, &e2, &l2, &c2, d2, a2, x2, &cp2, &rp2, &v2, &q2, t2, w2, x2e, f2);
    assert!(m1.len() == 317 && m2.len() == 317);
    if m1 == m2 {
        assert!(e1 == e2 && l1 == l2 && c1 == c2 && d1 == d2 && a1 == a2 && x1 == x2);
        assert!(cp1 == cp2 && rp1 == rp2 && v1 == v2 && q1 == q2);
        assert!(t1 == t2 && w1 == w2 && x1e == x2e && f1 == f2);
    }
}

/// Bounded (data <= 160 bytes): if `ed25519_ix_binds` accepts the precompile instruction data,
/// then the precompile, reading the same data by its documented layout
/// ([u8 n=1][u8 pad][u16 sig_off][u16 sig_ix][u16 pk_off][u16 pk_ix][u16 msg_off][u16 msg_len]
/// [u16 msg_ix], u16::MAX = this instruction), verifies exactly one signature whose public key
/// is `signer` and whose message is exactly `msg`, all inside this instruction.
#[kani::proof]
#[kani::unwind(161)]
fn p5_ed25519_binds_signer_and_message() {
    const N: usize = 160;
    let buf: [u8; N] = kani::any();
    let len: usize = kani::any_where(|l| *l <= N);
    let d = &buf[..len];
    let signer: [u8; 32] = kani::any();
    let msg: [u8; 32] = kani::any();
    if logic::ed25519_ix_binds(d, &signer, &msg).is_ok() {
        // Precompile's view of the same bytes.
        assert!(d.len() >= 16);
        let num_signatures = d[0];
        assert!(num_signatures == 1);
        let rd = |i: usize| u16::from_le_bytes([d[i], d[i + 1]]);
        assert!(rd(4) == u16::MAX && rd(8) == u16::MAX && rd(14) == u16::MAX);
        let (sig_off, pk_off, msg_off, msg_len) = (rd(2) as usize, rd(6) as usize, rd(10) as usize, rd(12) as usize);
        assert!(sig_off + 64 <= d.len() && pk_off + 32 <= d.len() && msg_off + msg_len <= d.len());
        assert!(d[pk_off..pk_off + 32] == signer);
        assert!(msg_len == 32 && d[msg_off..msg_off + msg_len] == msg);
    }
}

/// Every lock that passes the terms check is either SOL->XMR with the maker as claimer (and the
/// handler then requires the maker's ed25519 consent) or XMR->SOL with the maker as the locker
/// (whose transaction signature is the consent). No third direction exists.
#[kani::proof]
fn p5_lock_needs_maker() {
    let c = any_config();
    let m = any_maker();
    let locker = any_key();
    let claimer = any_key();
    let (direction, amount, xmr, t0s, ws) = (kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    let flags: u8 = kani::any();
    if logic::check_lock_terms(&c, &m, &locker, &claimer, direction, amount, xmr, t0s, ws, flags).is_ok() {
        assert!(
            (direction == DIR_SOL_TO_XMR && claimer == m.authority)
                || (direction == DIR_XMR_TO_SOL && locker == m.authority)
        );
        assert!(claimer != locker && claimer != Pubkey::default());
    }
}

/// Watchtowers are not part of the v1 maker's consent. That is safe because a watchtower's abort
/// power is a subset of the locker's own: whenever a watchtower may abort, the locker may too
/// (watchtower != claimer is enforced at lock). Pay escrows are the exception (the payer cannot
/// abort, only watchtowers): there the watchtowers are part of the maker's v2 consent
/// (p5_consent_message_v2_injective).
#[kani::proof]
#[kani::unwind(33)]
fn p5_watchtower_power_within_locker() {
    let mut e = any_escrow();
    e.flags &= !F_PAY;
    let w = any_key();
    let t: i64 = kani::any();
    kani::assume(w != e.claimer && e.locker != e.claimer);
    if logic::abort_check(&e, &w, t).is_ok() {
        assert!(logic::abort_check(&e, &e.locker, t).is_ok());
    }
}

// ---------------------------------------------------------------------------------------------
// P6: pause
// ---------------------------------------------------------------------------------------------

#[kani::proof]
fn p6_pause_blocks_locks() {
    let mut c = any_config();
    c.paused = true;
    let m = any_maker();
    let (locker, claimer) = (any_key(), any_key());
    let r = logic::check_lock_terms(&c, &m, &locker, &claimer, kani::any(), kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    assert!(r == Err(HkError::Paused));
}

/// Exits never depend on the pause flag. The exit decision functions (ready_window, abort_check,
/// claim_window, refund_window, expire_window, close_allowed, check_reveal_with, split_fee,
/// pay_amounts) take no Config at all, so they cannot read it (enforced by their signatures);
/// `release` is the only exit-path function that touches the config, and it gives the same result
/// and the same effects with the flag on or off, for all inputs. The handlers read `paused` only in
/// lock / register_maker / update_maker (fuzz::paused_read_sites_unchanged).
#[kani::proof]
fn p6_release_ignores_pause() {
    let e = any_escrow();
    let m = any_maker();
    let c = any_config();
    let (mut e1, mut m1, mut c1) = (e.clone(), m.clone(), c.clone());
    let (mut e2, mut m2, mut c2) = (e, m, c);
    c1.paused = false;
    c2.paused = true;
    let r1 = logic::release(&mut e1, &mut m1, &mut c1);
    let r2 = logic::release(&mut e2, &mut m2, &mut c2);
    assert!(r1 == r2);
    assert!(e1.released == e2.released && m1.open_swaps == m2.open_swaps && m1.open_lamports == m2.open_lamports);
    assert!(c1.open_tvl == c2.open_tvl && c1.paused == false && c2.paused == true);
}

// ---------------------------------------------------------------------------------------------
// P7: scalar canonicity (all 2^256 inputs)
// ---------------------------------------------------------------------------------------------

fn limbs(s: &[u8; 32]) -> (u128, u128) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    lo.copy_from_slice(&s[..16]);
    hi.copy_from_slice(&s[16..]);
    (u128::from_le_bytes(lo), u128::from_le_bytes(hi))
}

/// scalar_is_canonical(s) <=> s < L as a 256-bit little-endian integer.
#[kani::proof]
#[kani::unwind(33)]
fn p7_canonical_iff_less_than_l() {
    let s: [u8; 32] = kani::any();
    let (lo, hi) = limbs(&s);
    let (llo, lhi) = limbs(&L);
    let lt = hi < lhi || (hi == lhi && lo < llo);
    assert_eq!(logic::scalar_is_canonical(&s), lt);
}

/// Every alias s + k*L (k >= 1, no 256-bit overflow) of any scalar is rejected, so each residue
/// class mod L has exactly one accepted encoding. (2^256 / L < 16, so k <= 15 covers every alias.)
#[kani::proof]
#[kani::unwind(33)]
fn p7_aliases_rejected() {
    let s: [u8; 32] = kani::any();
    let k: u64 = kani::any_where(|k| *k >= 1 && *k <= 15);
    // a = s + k*L over 256 bits, four u64 limbs with u128 intermediates; skip if it overflows.
    let limb = |b: &[u8; 32], i: usize| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap());
    let mut a = [0u8; 32];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let v = limb(&s, i) as u128 + (limb(&L, i) as u128) * (k as u128) + carry;
        a[8 * i..8 * i + 8].copy_from_slice(&(v as u64).to_le_bytes());
        carry = v >> 64;
    }
    kani::assume(carry == 0);
    assert!(!logic::scalar_is_canonical(&a));
}

/// The reveal check accepts only a canonical scalar whose image under the syscall equals the
/// committed point, and never consults the syscall for a non-canonical one.
#[kani::proof]
#[kani::unwind(33)]
fn p7_check_reveal_sound() {
    let s: [u8; 32] = kani::any();
    let p: [u8; 32] = kani::any();
    let img: Option<[u8; 32]> = kani::any();
    let mut called = false;
    let r = logic::check_reveal_with(&s, &p, |_| {
        called = true;
        img
    });
    if r.is_ok() {
        assert!(logic::scalar_is_canonical(&s) && img == Some(p));
    }
    if !logic::scalar_is_canonical(&s) {
        assert!(r == Err(HkError::NonCanonicalScalar) && !called);
    }
}

// ---------------------------------------------------------------------------------------------
// Counter liveness: release never underflows, so counters can never block an exit
// ---------------------------------------------------------------------------------------------
//
// Invariant I: maker.open_swaps / open_lamports and config.open_tvl equal the contribution of all
// unreleased escrows (each counts 1 / amount / amount), plus, for open_tvl, other makers' escrows.
// Only `open_counters` (lock) and `release` write these fields (by inspection: no other
// assignment exists in lib.rs/logic.rs), a new maker / config starts at zero, an escrow's amount
// never changes, and `withdraw_maker` needs zero counters. The two harnesses below are the
// inductive steps, for one escrow `e` against arbitrary "everything else" (b_*), so I holds for
// any number of escrows in any order, and therefore `release` never fails on an unreleased escrow.

/// Step for `release` (abort / claim / expire / refund): from I, release succeeds and leaves
/// exactly the others' contribution; a second release is a no-op.
#[kani::proof]
fn sm_release_inductive() {
    let mut e = any_escrow();
    let (b_n, b_l, b_t): (u32, u64, u64) = (kani::any(), kani::any(), kani::any());
    let (own_n, own_l) = if e.released { (0u32, 0u64) } else { (1u32, e.amount) };
    let mut m = any_maker();
    let mut c = any_config();
    let (Some(n), Some(l), Some(t)) = (b_n.checked_add(own_n), b_l.checked_add(own_l), b_t.checked_add(own_l)) else {
        return; // I is only claimed for states that exist (counters are u64/u32 values)
    };
    m.open_swaps = n;
    m.open_lamports = l;
    c.open_tvl = t;
    assert!(logic::release(&mut e, &mut m, &mut c).is_ok());
    assert!(e.released && m.open_swaps == b_n && m.open_lamports == b_l && c.open_tvl == b_t);
    assert!(logic::release(&mut e, &mut m, &mut c).is_ok());
    assert!(m.open_swaps == b_n && m.open_lamports == b_l && c.open_tvl == b_t);
}

/// Step for `lock`: from I for the others, a successful lock (terms check, then open_counters)
/// adds exactly the new escrow's contribution.
#[kani::proof]
fn sm_lock_inductive() {
    let mut c = any_config();
    let mut m = any_maker();
    let (b_n, b_l, b_t) = (m.open_swaps, m.open_lamports, c.open_tvl);
    let (locker, claimer) = (any_key(), any_key());
    let amount: u64 = kani::any();
    let Ok(tvl) = logic::check_lock_terms(&c, &m, &locker, &claimer, kani::any(), amount, kani::any(), kani::any(), kani::any(), kani::any()) else { return };
    if logic::open_counters(&mut m, &mut c, amount, tvl).is_ok() {
        assert!(m.open_swaps as u64 == b_n as u64 + 1);
        assert!(m.open_lamports as u128 == b_l as u128 + amount as u128);
        assert!(c.open_tvl as u128 == b_t as u128 + amount as u128);
        assert!(c.open_tvl <= c.max_open_tvl); // the cap holds after every lock
    }
}

// ---------------------------------------------------------------------------------------------
// Escrow lifecycle model (src/model.rs): P1, P2, P3, P4, P6 for every reachable state
// ---------------------------------------------------------------------------------------------

use crate::model::{self, Op, World};

fn any_op() -> Op {
    let i: usize = kani::any_where(|x| *x < model::OPS.len());
    model::OPS[i]
}

fn any_actor() -> Pubkey {
    let id: u8 = kani::any_where(|i| *i >= model::LOCKER && *i <= model::RANDO);
    model::key(id)
}

/// Mode of inv_step: STATE = P1 authorization, P2, P3, counters and the invariant itself;
/// MONEY = P1 amounts, P4. Split so each SAT instance only contains what it asserts.
const STATE: u8 = 0;
const MONEY: u8 = 1;

// ---------------------------------------------------------------------------------------------
// Lifecycle: inductive invariant (model::inv)
// ---------------------------------------------------------------------------------------------

fn any_actor_or_default() -> Pubkey {
    if kani::any() { Pubkey::default() } else { any_actor() }
}

/// An arbitrary world: any escrow state, amounts, times, history, balances, counters.
fn any_world() -> World {
    let e = Escrow {
        locker: model::key(model::LOCKER),
        claimer: model::key(model::CLAIMER),
        watchtowers: [any_actor_or_default(), any_actor_or_default()],
        ..any_escrow()
    };
    World {
        e,
        m: any_maker(),
        c: any_config(),
        closed: kani::any(),
        rent: kani::any(),
        escrow: kani::any(),
        locker: kani::any(),
        claimer: kani::any(),
        vault: kani::any(),
        claims: kani::any(),
        refunds: kani::any(),
        ready_at: kani::any(),
        abort: if kani::any() { Some((any_actor(), kani::any(), kani::any())) } else { None },
        proof_arg: if kani::any() { Some((if kani::any() { model::key(model::ESCROW) } else { any_key() }, kani::any(), kani::any())) } else { None },
    }
}

/// Base case: every escrow `lock` creates satisfies the invariant (config invariant from
/// p4_config_bounds_fee_and_windows assumed).
#[kani::proof]
#[kani::unwind(34)]
fn sm_inv_base() {
    let c = any_config();
    kani::assume(c.fee_bps <= MAX_FEE_BPS && c.holder_fee_bps <= c.fee_bps);
    kani::assume(c.min_t0 >= 1 && c.max_t0 <= 30 * 86_400 && c.min_window >= 1 && c.max_window <= 30 * 86_400);
    let mut m = any_maker();
    let direction: u8 = kani::any();
    m.authority = model::key(if direction == DIR_SOL_TO_XMR { model::CLAIMER } else { model::LOCKER });
    let lock_in = model::LockIn {
        c,
        m,
        direction,
        amount: kani::any(),
        xmr_amount: kani::any(),
        t0_secs: kani::any(),
        window_secs: kani::any(),
        watchtowers: [any_actor_or_default(), any_actor_or_default()],
        claim_point: kani::any(),
        refund_point: kani::any(),
        t_lock: kani::any_where(|t| *t >= 0 && *t <= i64::MAX - 60 * 86_400),
        rent: kani::any(),
        balances: (kani::any(), kani::any(), kani::any()),
        flags: kani::any(),
    };
    let r = model::lock(lock_in);
    kani::cover!(r.is_ok(), "a lock succeeds");
    kani::cover!(matches!(&r, Ok(w) if w.e.flags & F_PAY != 0), "a pay lock succeeds");
    if let Ok(w) = r {
        assert!(model::inv(&w, w.e.created_at));
    }
}

/// Inductive step: from ANY world satisfying the invariant, any instruction (any op, signer,
/// destination, secret, syscall result, pause flag, later time) that succeeds keeps the
/// invariant and satisfies the per-step properties. With sm_inv_base, the properties hold in
/// every reachable state after any number of instructions.
fn inv_step<const MODE: u8>() {
    let w = any_world();
    let t_prev: i64 = kani::any();
    kani::assume(model::inv(&w, t_prev));
    let t: i64 = kani::any_where(|t| *t >= t_prev); // A3: the clock never goes backwards
    let op = any_op();
    let (signer, dest) = (any_actor(), any_actor());
    let secret: [u8; 32] = kani::any();
    let img: Option<[u8; 32]> = kani::any();
    let reveal = |s: &[u8; 32], p: &[u8; 32]| logic::check_reveal_with(s, p, |_| img);
    let mut next = w.clone();
    next.c.paused = kani::any();
    let ok = model::step(&mut next, op, signer, dest, t, secret, reveal).is_ok();
    // Non-vacuity: every instruction can succeed from some invariant state (and while paused).
    kani::cover!(ok && op == Op::Ready, "ready reachable");
    kani::cover!(ok && op == Op::Abort, "abort reachable");
    kani::cover!(ok && op == Op::Claim && w.e.state == ST_READY, "claim after ready reachable");
    kani::cover!(ok && op == Op::Claim && w.e.state == ST_LOCKED, "claim at t0 reachable");
    kani::cover!(ok && op == Op::Refund && w.e.state == ST_ABORTED, "refund after abort reachable");
    kani::cover!(ok && op == Op::Refund && w.e.state != ST_ABORTED, "refund after t1 reachable");
    kani::cover!(ok && op == Op::Expire, "expire reachable");
    kani::cover!(ok && op == Op::Close, "close reachable");
    kani::cover!(ok && next.c.paused && op == Op::Refund, "refund while paused reachable");
    let pay = w.e.flags & F_PAY != 0;
    kani::cover!(ok && pay && op == Op::Abort && signer != w.e.claimer, "pay: watchtower abort reachable");
    kani::cover!(ok && pay && op == Op::Refund, "pay: refund reachable");
    kani::cover!(ok && pay && op == Op::Claim, "pay: claim reachable");
    kani::cover!(ok && pay && op == Op::Close && w.e.state == ST_CLAIMED, "pay: close of a claimed escrow reachable");
    let proof_mode = w.e.flags & F_PROOF != 0;
    kani::cover!(ok && proof_mode && op == Op::Claim && w.e.state == ST_LOCKED, "proof mode: claim at t0 with a proof reachable");
    kani::cover!(ok && proof_mode && op == Op::Claim && w.e.state == ST_READY, "proof mode: claim after ready reachable");
    if ok {
        if MODE == MONEY {
            model::check_money(&w, &next, op, w.total());
        } else {
            model::check_state(&w, &next, op, signer, dest, t, &secret, reveal);
            assert!(model::inv(&next, t), "invariant broken");
        }
    }
}

#[kani::proof]
#[kani::unwind(34)]
#[kani::stub(logic::bps_of, spec_bps_of)]
fn sm_inv_step_state() {
    inv_step::<STATE>();
}

#[kani::proof]
#[kani::unwind(34)]
#[kani::stub(logic::bps_of, spec_bps_of)]
fn sm_inv_step_money() {
    inv_step::<MONEY>();
}

// ---------------------------------------------------------------------------------------------
// P8: platform (pay links, OTC tranches, cashout vaults), single-function properties
// ---------------------------------------------------------------------------------------------

/// The v2 consent message (flagged locks) is a fixed-length (414 byte) encoding of the v1 terms
/// plus flags, the pay link and both watchtowers, under its own prefix: equal messages mean equal
/// terms, and no v2 message equals a v1 message. So a maker's v2 signature binds the watchtowers
/// that alone may abort a pay escrow.
#[kani::proof]
#[kani::unwind(420)]
fn p5_consent_message_v2_injective() {
    let pid = any_key();
    let (e1, e2) = (any_key(), any_key());
    let (l1, l2) = (any_key(), any_key());
    let (c1, c2) = (any_key(), any_key());
    let (d1, d2): (u8, u8) = (kani::any(), kani::any());
    let (a1, a2): (u64, u64) = (kani::any(), kani::any());
    let (x1, x2): (u64, u64) = (kani::any(), kani::any());
    let (cp1, cp2): ([u8; 32], [u8; 32]) = (kani::any(), kani::any());
    let (rp1, rp2): ([u8; 32], [u8; 32]) = (kani::any(), kani::any());
    let (v1, v2): ([u8; 32], [u8; 32]) = (kani::any(), kani::any());
    let (q1, q2): ([u8; 32], [u8; 32]) = (kani::any(), kani::any());
    let (t1, t2): (i64, i64) = (kani::any(), kani::any());
    let (w1, w2): (i64, i64) = (kani::any(), kani::any());
    let (x1e, x2e): (i64, i64) = (kani::any(), kani::any());
    let (f1, f2): (u16, u16) = (kani::any(), kani::any());
    let (g1, g2): (u8, u8) = (kani::any(), kani::any());
    let (k1, k2) = (any_key(), any_key());
    let (wt1, wt2) = ([any_key(), any_key()], [any_key(), any_key()]);
    let m1 = consent_message_v2(&pid, &e1, &l1, &c1, d1, a1, x1, &cp1, &rp1, &v1, &q1, t1, w1, x1e, f1, g1, &k1, &wt1);
    let m2 = consent_message_v2(&pid, &e2, &l2, &c2, d2, a2, x2, &cp2, &rp2, &v2, &q2, t2, w2, x2e, f2, g2, &k2, &wt2);
    assert!(m1.len() == 414 && m2.len() == 414);
    assert!(m1[..CONSENT_PREFIX_V2.len()] == *CONSENT_PREFIX_V2 && CONSENT_PREFIX_V2 != CONSENT_PREFIX);
    if m1 == m2 {
        assert!(e1 == e2 && l1 == l2 && c1 == c2 && d1 == d2 && a1 == a2 && x1 == x2);
        assert!(cp1 == cp2 && rp1 == rp2 && v1 == v2 && q1 == q2);
        assert!(t1 == t2 && w1 == w2 && x1e == x2e && f1 == f2);
        assert!(g1 == g2 && k1 == k2 && wt1 == wt2);
    }
}

/// A pay escrow's payer (the locker, never the claimer) has no power over it: it cannot mark it
/// ready, cannot abort it, and its refund reveals nothing (only the all-zero secret is accepted
/// and the curve is never consulted). Assumes what every pay lock establishes (p8_lock_shape:
/// the locker is not a watchtower; escrow watchtowers never change after lock).
#[kani::proof]
#[kani::unwind(33)]
fn p8_pay_payer_powerless() {
    let mut e = any_escrow();
    e.flags |= F_PAY;
    kani::assume(e.locker != e.claimer && !e.watchtowers.contains(&e.locker));
    let t: i64 = kani::any();
    assert!(logic::ready_window::<HkError>(e.state, e.t0, e.flags, || Ok(t)) == Err(HkError::Unauthorized));
    assert!(logic::abort_check(&e, &e.locker, t).is_err());
    let secret: [u8; 32] = kani::any();
    let mut called = false;
    let r = logic::refund_secret_check(e.flags, &secret, &e.refund_point, |_| {
        called = true;
        None
    });
    assert!(!called);
    assert!(r.is_ok() == (secret == [0u8; 32]));
}

/// Every lock that passes the lock checks respects the platform shape: known flags only; a flagged
/// escrow's maker has the extension; the amount is inside the maker's range for its kind and under
/// the per-escrow cap for its kind (the OTC cap only for OTC tranches); the open-TVL cap holds;
/// a pay escrow is SOL->XMR with at least one watchtower, none of them the payer or the claimer;
/// the vault flag never appears without the pay flag.
#[kani::proof]
#[kani::unwind(33)]
fn p8_lock_shape() {
    let c = any_config();
    let m = any_maker();
    let (locker, claimer) = (any_key(), any_key());
    let wt = [any_key(), any_key()];
    let (direction, amount, xmr, t0s, ws, flags): (u8, u64, u64, i64, i64, u8) =
        (kani::any(), kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    let Ok(tvl) = logic::check_lock_terms(&c, &m, &locker, &claimer, direction, amount, xmr, t0s, ws, flags) else { return };
    let Ok(pay) = logic::pay_shape(flags, direction) else { return };
    let Ok(()) = logic::check_watchtowers(&wt, &claimer, &locker, flags) else { return };
    assert!(flags & !F_ALL == 0);
    assert!(flags == 0 || m.v2);
    assert!(tvl <= c.max_open_tvl && tvl as u128 == c.open_tvl as u128 + amount as u128);
    if flags & F_OTC != 0 && c.otc_max_swap > 0 {
        assert!(amount <= c.otc_max_swap);
    } else {
        assert!(amount <= c.max_swap);
    }
    if flags & F_OTC != 0 && m.ext.otc_max > 0 {
        assert!(amount >= m.ext.otc_min && amount <= m.ext.otc_max);
    } else {
        assert!(amount >= m.min && amount <= m.max);
    }
    assert!(pay == (flags & F_PAY != 0));
    assert!(flags & F_VAULT == 0 || pay);
    assert!(!wt.contains(&claimer));
    if pay {
        assert!(direction == DIR_SOL_TO_XMR);
        assert!(wt.iter().any(|w| *w != Pubkey::default()) && !wt.contains(&locker));
    }
}

/// A claimed pay escrow still holds the maker's revealed half the recipient needs: only the link
/// owner closes it early; the payer side (anyone, for a vault) only after PAY_CLOSE_GRACE. A
/// refunded one closes only from the payer side. Nothing else closes.
#[kani::proof]
fn p8_close_pay_grace() {
    let (state, flags, is_locker, is_owner, settled_at, now): (u8, u8, bool, bool, i64, i64) =
        (kani::any(), kani::any(), kani::any(), kani::any(), kani::any(), kani::any());
    if logic::close_pay_allowed::<HkError>(state, flags, is_locker, is_owner, settled_at, || Ok(now)).is_ok() {
        let locker_side = is_locker || flags & F_VAULT != 0;
        assert!(state == ST_CLAIMED || state == ST_REFUNDED);
        if state == ST_REFUNDED {
            assert!(locker_side);
        } else if !is_owner {
            assert!(locker_side && now as i128 >= settled_at as i128 + PAY_CLOSE_GRACE as i128);
        }
    }
}

/// `vault_tighten` only ever tightens: it can pause but never unpause, never re-arms a pending
/// unpause, only raises the price floor, only lowers the size cap (not below the minimum), only
/// slows the schedule, and touches nothing else (keeper, watchtowers, link, delay, proposals,
/// withdrawals).
#[kani::proof]
fn p8_vault_tighten_only_tightens() {
    let v = any_vault();
    let mut n = v.clone();
    let (paused, rate, max, iv) = (kani::any(), kani::any(), kani::any(), kani::any());
    if logic::vault_tighten(&mut n, paused, rate, max, iv).is_ok() {
        assert!(!v.paused || n.paused, "unpaused without the timelock");
        assert!(!n.pending_unpause || v.pending_unpause);
        assert!(n.p.min_rate >= v.p.min_rate && n.p.max_lamports <= v.p.max_lamports && n.p.interval >= v.p.interval);
        assert!(n.p.max_lamports >= n.p.min_lamports);
        assert!(n.p.keeper == v.p.keeper && n.p.watchtowers == v.p.watchtowers && n.p.link == v.p.link);
        assert!(n.p.min_lamports == v.p.min_lamports && n.p.delay == v.p.delay);
        assert!(n.pending == v.pending && n.pending_at == v.pending_at);
        assert!(n.withdraw_at == v.withdraw_at && n.withdraw_amount == v.withdraw_amount && n.owner == v.owner);
    }
}

/// Loosening a vault (new params, unpausing) needs the timelock: a proposal applies only at or
/// after `pending_at`, which is at least the CURRENT delay (min 1 s) after the proposal; apply is
/// the only way `pending` reaches the live params.
#[kani::proof]
fn p8_vault_timelock() {
    let v = any_vault();
    let p = any_vp();
    let (unpause, t): (bool, i64) = (kani::any(), kani::any());
    let mut n = v.clone();
    if logic::vault_propose(&mut n, p.clone(), unpause, t).is_ok() {
        assert!(n.pending_at as i128 >= t as i128 + 1 && n.pending_at as i128 >= t as i128 + v.p.delay as i128);
        assert!(n.p == v.p && n.paused == v.paused, "a proposal changed live params");
        assert!(n.pending == p && n.pending_unpause == unpause);
    }
    let t2: i64 = kani::any();
    let mut a = v.clone();
    if logic::vault_apply::<HkError>(&mut a, || Ok(t2)).is_ok() {
        assert!(v.pending_at != 0 && t2 >= v.pending_at);
        assert!(a.p == v.pending && a.pending_at == 0 && !a.pending_unpause);
        assert!(a.paused == (v.paused && !v.pending_unpause));
    }
}

/// A conversion happens only when the vault allows it: not paused, by the named keeper or the
/// owner, when due, sized within the owner's range, at or above the owner's price floor
/// (xmr_amount * 1e9 >= min_rate * amount, exact). The funding never dips into the vault's rent
/// reserve and moves exactly amount + rent top-up; a withdrawal never exceeds what was requested
/// nor what is free above the reserve.
#[kani::proof]
fn p8_vault_money_bounds() {
    let v = any_vault();
    let keeper = any_key();
    let (t, amount, xmr): (i64, u64, u64) = (kani::any(), kani::any(), kani::any());
    if let Ok(t_read) = logic::vault_lock_terms::<HkError>(&v, &keeper, || Ok(t), amount, xmr) {
        assert!(t_read == t && !v.paused && (keeper == v.p.keeper || keeper == v.owner) && t >= v.next_at);
        assert!(amount >= v.p.min_lamports && amount <= v.p.max_lamports);
        assert!(xmr as u128 * 1_000_000_000 >= v.p.min_rate as u128 * amount as u128);
    }
    let (top, lamports, keep): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
    if let Ok(total) = logic::vault_funding(amount, top, lamports, keep) {
        assert!(total as u128 == amount as u128 + top as u128);
        // (A conversion always moves > 0: amount >= min_lamports > 0, check_vault_params.)
        assert!(total == 0 || (lamports > keep && lamports - total >= keep));
    }
    let mut w = v.clone();
    let amt = logic::vault_withdraw_take(&mut w, lamports, keep);
    assert!(amt <= v.withdraw_amount && amt <= lamports.saturating_sub(keep));
    assert!(w.withdraw_at == 0 && w.withdraw_amount == 0);
}

/// OTC / pay reputation only ever touches the maker extension, never the phase-1 counters, the
/// bond or the open counters; it is a no-op for unflagged escrows and pre-extension makers; and
/// on XMR->SOL only fills count.
#[kani::proof]
fn p8_ext_count_scoped() {
    let e = any_escrow();
    let m = any_maker();
    let o: u8 = kani::any_where(|o| *o <= 2);
    let out = [logic::Outcome::Fill, logic::Outcome::Failed, logic::Outcome::Declined][o as usize];
    let mut n = m.clone();
    if logic::ext_count(&e, &mut n, out).is_ok() {
        assert!(n.open_swaps == m.open_swaps && n.open_lamports == m.open_lamports && n.bond == m.bond);
        assert!(n.completed == m.completed && n.aborted == m.aborted && n.expired == m.expired);
        assert!(n.declined == m.declined && n.cancelled == m.cancelled && n.volume == m.volume);
        assert!(n.v2 == m.v2 && n.ext.otc_min == m.ext.otc_min && n.ext.otc_max == m.ext.otc_max);
        if e.flags == 0 || !m.v2 || (e.direction == DIR_XMR_TO_SOL && out != logic::Outcome::Fill) {
            assert!(same_ext(&n.ext, &m.ext));
        }
    }
}
