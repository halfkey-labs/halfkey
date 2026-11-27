//! $HALFKEY staking: SOL rewards from the protocol fees, for anyone who stakes (maker bonds included).
//!
//! Money flow once the burn auction is on (burn.rs):
//!   claim fee -> fee vault --split--> 50% stake pool (rewards)  /  50% burn pot (auction)
//! `split` runs permissionlessly (`split_fees`) and inside every stake, unstake and claim. With
//! nobody staked, 100% goes to the burn pot. Odd lamports (rounding dust) go to the burn pot.
//!
//! Rewards: a reward-per-token accumulator `acc` (scaled by 2^64). Crediting `x` lamports adds
//! floor(x * 2^64 / total_staked); a staker's reward is staked * (acc - acc_at) / 2^64 (floor),
//! settled into `owed` before any change to its stake. Rounding is always down, so the sum of
//! what stakers can claim never exceeds what was credited (Kani: proofs_v15 P11).
//!
//! Flash-stake protection: every stake/unstake/claim settles the fee split FIRST, so fees that
//! reached the vault before a stake are credited to the stake that existed then (a new stake
//! earns only from fees that arrive after it); leaving takes the config's unbond delay, during
//! which the unbonding tokens earn nothing. A stake-crank-unstake round trip therefore earns only
//! the fees that arrived while the tokens were staked, and then sits idle for the whole delay.
//!
//! SOL sent straight to the pool address (a plain transfer, e.g. pump.fun fee sharing pointed at
//! it) is picked up by the next split as `pool_extra` = pool lamports - rent - (credited - claimed)
//! and credited to stakers; with nobody staked it waits in the pool. `deposit_stakers` does the
//! same in one instruction from a signer.
//!
//! Custody: the tokens sit in the same vault as the maker bond (the associated token account of
//! ["stake", owner]) and leave after the same `config.unbond_secs`. A maker's account mirrors
//! its stake (`staked`, `stake_unlock_at`), so the holder fee discount keeps working.

use crate::burn::{fee_vault_check, BurnState, BURN_LEN};
use crate::*;

pub const POOL_SEED: &[u8] = b"stake_pool";
pub const STAKER_SEED: &[u8] = b"staker";
pub const DISC_POOL: u8 = 0x5B;
pub const DISC_STAKER: u8 = 0x5C;
pub const POOL_LEN: usize = 96;
pub const STAKER_LEN: usize = 104;
/// Accumulator scale: acc is reward lamports per staked base unit, times 2^SHIFT.
pub const SHIFT: u32 = 64;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Pool {
    pub bump: u8,
    /// The $HALFKEY mint this pool stakes, pinned at creation from `config.halfkey_mint`. Staking,
    /// unstaking and the holder-discount vault all derive from this, NOT from the (mutable) config,
    /// so changing `config.halfkey_mint` later cannot strand stakers or inject a different mint.
    pub mint: Pubkey,
    pub total_staked: u64,
    pub acc: u128,
    /// Lamports credited to stakers, ever.
    pub distributed: u64,
    /// Lamports paid out to stakers, ever.
    pub claimed: u64,
}

impl Pool {
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!(d.len() == POOL_LEN && d[0] == DISC_POOL, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let bump = r.u8()?;
        r.skip(5)?;
        let mint = r.key()?;
        let total_staked = r.u64()?;
        let lo = r.u64()? as u128;
        let hi = r.u64()? as u128;
        Ok(Self { bump, mint, total_staked, acc: lo | (hi << 64), distributed: r.u64()?, claimed: r.u64()? })
    }
    pub fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_POOL);
        w.u8(1);
        w.u8(self.bump);
        w.pad(5);
        w.put(self.mint.as_ref());
        w.u64(self.total_staked);
        w.u64(self.acc as u64);
        w.u64((self.acc >> 64) as u64);
        w.u64(self.distributed);
        w.u64(self.claimed);
        w.pad(16);
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Staker {
    pub bump: u8,
    pub owner: Pubkey,
    /// Earning stake.
    pub staked: u64,
    /// `acc` when `owed` was last settled.
    pub acc_at: u128,
    /// Settled, unclaimed rewards (lamports).
    pub owed: u64,
    /// Requested out; earns nothing; leaves at `unlock_at`.
    pub unbonding: u64,
    pub unlock_at: i64,
}

impl Staker {
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!(d.len() == STAKER_LEN && d[0] == DISC_STAKER, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(2)?;
        let bump = r.u8()?;
        r.skip(5)?;
        let owner = r.key()?;
        let staked = r.u64()?;
        let lo = r.u64()? as u128;
        let hi = r.u64()? as u128;
        Ok(Self { bump, owner, staked, acc_at: lo | (hi << 64), owed: r.u64()?, unbonding: r.u64()?, unlock_at: r.i64()? })
    }
    pub fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_STAKER);
        w.u8(1);
        w.u8(self.bump);
        w.pad(5);
        w.put(self.owner.as_ref());
        w.u64(self.staked);
        w.u64(self.acc_at as u64);
        w.u64((self.acc_at >> 64) as u64);
        w.u64(self.owed);
        w.u64(self.unbonding);
        w.i64(self.unlock_at);
        w.pad(16);
    }
}

// ---------------------------------------------------------------------------------------------
// Pure rules (Kani: proofs_v15.rs P11). Generic over the accumulator scale so the harnesses can
// run the same code at a small scale; the program uses SHIFT = 64.
// ---------------------------------------------------------------------------------------------

/// The fee split: (to stakers, to burn). Exact: the two always add up to `unsplit`. Stakers get
/// floor(unsplit / 2), the burn pot gets the rest (the odd lamport); nobody staked -> all to burn.
pub fn split(unsplit: u64, total_staked: u64) -> (u64, u64) {
    if total_staked == 0 {
        (0, unsplit)
    } else {
        let s = unsplit / 2;
        (s, unsplit - s)
    }
}

/// Credit `amount` lamports to everyone staked now.
pub fn credit_s<const S: u32>(p: &mut Pool, amount: u64) -> Result<(), HkError> {
    if amount == 0 {
        return Ok(());
    }
    if p.total_staked == 0 {
        return Err(HkError::BadState);
    }
    let inc = ((amount as u128) << S) / p.total_staked as u128;
    p.acc = p.acc.checked_add(inc).ok_or(HkError::Overflow)?;
    p.distributed = p.distributed.checked_add(amount).ok_or(HkError::Overflow)?;
    Ok(())
}

/// Rewards earned since the last settle: floor(staked * (acc - acc_at) / 2^S).
pub fn pending_s<const S: u32>(acc: u128, st: &Staker) -> Result<u64, HkError> {
    let d = acc.checked_sub(st.acc_at).ok_or(HkError::Overflow)?;
    let v = (st.staked as u128).checked_mul(d).ok_or(HkError::Overflow)? >> S;
    u64::try_from(v).map_err(|_| HkError::Overflow)
}

/// Move earned rewards into `owed` (no lamports move; nothing is created or lost).
pub fn settle_s<const S: u32>(p: &Pool, st: &mut Staker) -> Result<(), HkError> {
    let x = pending_s::<S>(p.acc, st)?;
    st.owed = st.owed.checked_add(x).ok_or(HkError::Overflow)?;
    st.acc_at = p.acc;
    Ok(())
}

/// Add `amount` to a stake (after settling). Refused while an unstake is pending (finish it first).
pub fn stake_s<const S: u32>(p: &mut Pool, st: &mut Staker, amount: u64) -> Result<(), HkError> {
    if st.unbonding != 0 {
        return Err(HkError::BadState);
    }
    settle_s::<S>(p, st)?;
    st.staked = st.staked.checked_add(amount).ok_or(HkError::Overflow)?;
    p.total_staked = p.total_staked.checked_add(amount).ok_or(HkError::Overflow)?;
    Ok(())
}

/// `pool_stake`'s last step. Adding nothing (amount 0 = enroll only, or a transfer-fee mint that
/// delivered nothing) changes nothing, so enrolling a pre-v1.5 bond whose unstake is pending
/// works (the record is created with that unstake pending). A real deposit while unbonding is
/// refused by `stake_s`.
pub fn add_stake_s<const S: u32>(p: &mut Pool, st: &mut Staker, got: u64) -> Result<(), HkError> {
    if got == 0 {
        return Ok(());
    }
    stake_s::<S>(p, st, got)
}

/// The part of a pre-v1.5 maker bond the pool takes over: what the bond says, capped by what the
/// pool-mint stake vault holds.
pub fn enrolled_legacy(bond: u64, held: u64) -> u64 {
    bond.min(held)
}

/// Start unbonding `amount` (0 = all): it stops earning now and can leave at `unlock_at`.
pub fn unstake_s<const S: u32>(p: &mut Pool, st: &mut Staker, amount: u64, unlock_at: i64) -> Result<u64, HkError> {
    if st.unbonding != 0 {
        return Err(HkError::BadState);
    }
    let a = if amount == 0 { st.staked } else { amount };
    if a == 0 || a > st.staked {
        return Err(HkError::BadState);
    }
    settle_s::<S>(p, st)?;
    st.staked -= a;
    p.total_staked = p.total_staked.checked_sub(a).ok_or(HkError::Overflow)?;
    st.unbonding = a;
    st.unlock_at = unlock_at;
    Ok(a)
}

/// Settle and take everything owed. Returns the lamports to pay this staker.
pub fn claim_s<const S: u32>(p: &mut Pool, st: &mut Staker) -> Result<u64, HkError> {
    settle_s::<S>(p, st)?;
    let x = st.owed;
    st.owed = 0;
    p.claimed = p.claimed.checked_add(x).ok_or(HkError::Overflow)?;
    Ok(x)
}

/// SOL in the pool beyond its rent and what stakers are still owed: plain transfers (pump.fun
/// fee sharing, `deposit_stakers`) waiting to be credited.
pub fn pool_extra(pool_lamports: u64, keep: u64, p: &Pool) -> u64 {
    pool_lamports.saturating_sub(keep).saturating_sub(p.distributed.saturating_sub(p.claimed))
}

/// What the burn pot gets and what the stakers get from the fee vault's unsplit balance.
pub fn fee_unsplit(vault_lamports: u64, keep: u64, pot: u64) -> u64 {
    vault_lamports.saturating_sub(keep).saturating_sub(pot)
}

pub fn credit(p: &mut Pool, amount: u64) -> Result<(), HkError> {
    credit_s::<SHIFT>(p, amount)
}
pub fn pending(acc: u128, st: &Staker) -> Result<u64, HkError> {
    pending_s::<SHIFT>(acc, st)
}

// ---------------------------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------------------------

pub fn pool_pda(pid: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[POOL_SEED], pid)
}

pub(crate) fn load_pool(a: &AccountInfo, pid: &Pubkey) -> Result<Pool, ProgramError> {
    owned(a, pid)?;
    let p = Pool::load(&a.try_borrow_data()?)?;
    let k = Pubkey::create_program_address(&[POOL_SEED, &[p.bump]], pid).map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(p)
}

fn load_staker(a: &AccountInfo, owner: &Pubkey, pid: &Pubkey) -> Result<Staker, ProgramError> {
    owned(a, pid)?;
    let s = Staker::load(&a.try_borrow_data()?)?;
    req!(s.owner == *owner, HkError::Unauthorized);
    let k = Pubkey::create_program_address(&[STAKER_SEED, owner.as_ref(), &[s.bump]], pid).map_err(|_| HkError::BadPda)?;
    req!(k == *a.key, HkError::BadPda);
    Ok(s)
}

/// Create the pool on first use (no parameters: anyone may pay its rent).
fn pool_or_create<'a>(
    pid: &Pubkey,
    c: &Config,
    payer: &AccountInfo<'a>,
    pool: &AccountInfo<'a>,
    system: &AccountInfo<'a>,
    fee_vault: &AccountInfo<'a>,
) -> Result<Pool, ProgramError> {
    let (pk, pb) = pool_pda(pid);
    req!(pk == *pool.key, HkError::BadPda);
    if pool.data_len() == 0 {
        req!(c.halfkey_mint != Pubkey::default(), HkError::BadAccount); // no staking before the mint is set
        // Staking and the burn use one token: once the auction is on, the pool pins its mint.
        fee_vault_check(fee_vault, c, pid)?;
        if fee_vault.data_len() == BURN_LEN {
            req!(BurnState::load(&fee_vault.try_borrow_data()?)?.mint == c.halfkey_mint, HkError::BadAccount);
        }
        create_pda(payer, pool, system, pid, POOL_LEN, &[POOL_SEED, &[pb]])?;
        let p = Pool { bump: pb, mint: c.halfkey_mint, ..Default::default() };
        p.store(&mut pool.try_borrow_mut_data()?);
        return Ok(p);
    }
    load_pool(pool, pid)
}

/// The fee split and the pool's loose SOL, credited to the current stakers. Runs before any stake
/// change. Before the burn auction is on (plain fee vault) only the pool's loose SOL is credited.
fn sync(pid: &Pubkey, c: &Config, vault: &AccountInfo, pool: &AccountInfo, p: &mut Pool) -> ProgramResult {
    let vk = Pubkey::create_program_address(&[FEE_VAULT_SEED, &[c.vault_bump]], pid).map_err(|_| HkError::BadPda)?;
    req!(vk == *vault.key, HkError::BadPda);
    owned(vault, pid)?;
    let rent = Rent::get()?;
    if vault.data_len() == BURN_LEN {
        let mut b = BurnState::load(&vault.try_borrow_data()?)?;
        let unsplit = fee_unsplit(vault.lamports(), rent.minimum_balance(BURN_LEN), b.pot);
        let (to_stakers, to_burn) = split(unsplit, p.total_staked);
        let mut to_burn = to_burn;
        // No stakers: loose SOL already in the pool (e.g. pump.fun fee sharing sent before anyone
        // staked) would otherwise wait for a lone first staker to scoop it, so send it to the burn.
        if p.total_staked == 0 {
            let idle = pool_extra(pool.lamports(), rent.minimum_balance(POOL_LEN), p);
            if idle > 0 {
                pay(pool, vault, idle)?;
                to_burn = to_burn.checked_add(idle).ok_or(HkError::Overflow)?;
            }
        }
        b.pot = b.pot.checked_add(to_burn).ok_or(HkError::Overflow)?;
        if to_stakers > 0 {
            pay(vault, pool, to_stakers)?;
            credit(p, to_stakers)?;
        }
        b.store(&mut vault.try_borrow_mut_data()?);
    }
    let extra = pool_extra(pool.lamports(), rent.minimum_balance(POOL_LEN), p);
    if extra > 0 && p.total_staked > 0 {
        credit(p, extra)?;
    }
    Ok(())
}

/// Keep a maker's bond fields equal to its stake, so the holder fee discount follows it. The
/// maker PDA of `owner` must be passed (so a maker cannot skip the update); if it does not exist,
/// the owner is not a maker and nothing is written.
fn mirror_maker(pid: &Pubkey, owner: &Pubkey, maker: &AccountInfo, st: &Staker) -> ProgramResult {
    let (mk, _) = Pubkey::find_program_address(&[MAKER_SEED, owner.as_ref()], pid);
    req!(mk == *maker.key, HkError::BadPda);
    if maker.owner != pid || maker.data_len() == 0 {
        return Ok(());
    }
    writable(maker)?;
    let mut m = load_maker(maker, pid)?;
    m.staked = st.staked;
    m.stake_unlock_at = if st.unbonding > 0 { st.unlock_at } else { 0 };
    m.store(&mut maker.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [owner (signer, w), config, mint, source token acct (w), vault (w), stake owner PDA,
///            token program, associated token program, system, pool (w), staker (w),
///            fee_vault (w), maker PDA of owner (w; need not exist)]. Data: amount u64 (0 = just
///            enroll a pre-v1.5 maker bond).
pub(crate) fn pool_stake(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let config = next_account_info(it)?;
    let mint = next_account_info(it)?;
    let source = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let stake_owner = next_account_info(it)?;
    let token_program = next_account_info(it)?;
    let ata_program = next_account_info(it)?;
    let system = next_account_info(it)?;
    let pool = next_account_info(it)?;
    let staker = next_account_info(it)?;
    let fee_vault = next_account_info(it)?;
    let maker = next_account_info(it)?;
    signer(owner)?;
    writable(owner)?;
    writable(pool)?;
    writable(staker)?;
    writable(fee_vault)?;
    let amount = r.u64()?;
    r.done()?;
    let c = load_config(config, pid)?;
    req!(*ata_program.key == ATA_PROGRAM && *system.key == SYSTEM_PROGRAM, HkError::BadAccount);
    let mut p = pool_or_create(pid, &c, owner, pool, system, fee_vault)?;
    // The vault and the required mint come from the pool's pinned mint, never the mutable config.
    let sa = stake_accounts(pid, &p.mint, owner.key, mint, vault, stake_owner, token_program)?;
    sync(pid, &c, fee_vault, pool, &mut p)?;

    let mut st = if staker.data_len() == 0 {
        let (sk, sb) = Pubkey::find_program_address(&[STAKER_SEED, owner.key.as_ref()], pid);
        req!(sk == *staker.key, HkError::BadPda);
        create_pda(owner, staker, system, pid, STAKER_LEN, &[STAKER_SEED, owner.key.as_ref(), &[sb]])?;
        let mut st = Staker { bump: sb, owner: *owner.key, acc_at: p.acc, ..Default::default() };
        // A pre-v1.5 maker bond already sits in this vault: count it from now on.
        let (mk, _) = Pubkey::find_program_address(&[MAKER_SEED, owner.key.as_ref()], pid);
        req!(mk == *maker.key, HkError::BadPda);
        if *maker.owner == *pid && maker.data_len() > 0 {
            let m = load_maker(maker, pid)?;
            // Count only what really sits in the pool-mint vault (a bond made in another mint, if the
            // config mint was changed, is not this pool's stake and could never be paid out by it).
            let held = if vault.data_len() == 0 || vault.owner != token_program.key { 0 } else { token_amount(vault)? };
            let legacy = enrolled_legacy(m.staked, held);
            if legacy > 0 {
                if m.stake_unlock_at == 0 {
                    stake_s::<SHIFT>(&mut p, &mut st, legacy)?;
                } else {
                    // A pending pre-v1.5 unstake carries over as a pending pool unstake (same unlock).
                    st.unbonding = legacy;
                    st.unlock_at = m.stake_unlock_at;
                }
            }
        }
        st
    } else {
        load_staker(staker, owner.key, pid)?
    };

    let mut got = 0;
    if amount > 0 {
        let create = solana_instruction::Instruction {
            program_id: ATA_PROGRAM,
            accounts: vec![
                solana_instruction::AccountMeta::new(*owner.key, true),
                solana_instruction::AccountMeta::new(*vault.key, false),
                solana_instruction::AccountMeta::new_readonly(*stake_owner.key, false),
                solana_instruction::AccountMeta::new_readonly(*mint.key, false),
                solana_instruction::AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
                solana_instruction::AccountMeta::new_readonly(*token_program.key, false),
            ],
            data: vec![1],
        };
        invoke_signed(&create, &[owner.clone(), vault.clone(), stake_owner.clone(), mint.clone(), system.clone(), token_program.clone(), ata_program.clone()], &[])?;
        // Count what actually arrived (transfer-fee mints deliver less than `amount`).
        let before = token_amount(vault)?;
        transfer_checked(&sa, source, vault, owner, amount, &[])?;
        got = token_amount(vault)?.checked_sub(before).ok_or(HkError::Overflow)?;
    }
    add_stake_s::<SHIFT>(&mut p, &mut st, got)?;
    p.store(&mut pool.try_borrow_mut_data()?);
    st.store(&mut staker.try_borrow_mut_data()?);
    mirror_maker(pid, owner.key, maker, &st)
}

/// Accounts: [owner (signer), config, pool (w), staker (w), fee_vault (w), maker PDA of owner (w)].
/// Data: amount u64 (0 = all). The amount stops earning now and can leave after the unbond delay.
pub(crate) fn pool_unstake_request(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let config = next_account_info(it)?;
    let pool = next_account_info(it)?;
    let staker = next_account_info(it)?;
    let fee_vault = next_account_info(it)?;
    let maker = next_account_info(it)?;
    signer(owner)?;
    writable(pool)?;
    writable(staker)?;
    writable(fee_vault)?;
    let amount = r.u64()?;
    r.done()?;
    let c = load_config(config, pid)?;
    let mut st = load_staker(staker, owner.key, pid)?;
    let mut p = load_pool(pool, pid)?;
    sync(pid, &c, fee_vault, pool, &mut p)?;
    let unlock = now()?.checked_add(c.unbond_secs.max(1)).ok_or(HkError::Overflow)?;
    unstake_s::<SHIFT>(&mut p, &mut st, amount, unlock)?;
    p.store(&mut pool.try_borrow_mut_data()?);
    st.store(&mut staker.try_borrow_mut_data()?);
    mirror_maker(pid, owner.key, maker, &st)
}

/// Accounts: [owner (signer), config, mint, dest token acct (w), vault (w), stake owner PDA,
///            token program, staker (w), maker PDA of owner (w), pool]. Pays the unbonded tokens back.
pub(crate) fn pool_unstake(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let config = next_account_info(it)?;
    let mint = next_account_info(it)?;
    let dest = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let stake_owner = next_account_info(it)?;
    let token_program = next_account_info(it)?;
    let staker = next_account_info(it)?;
    let maker = next_account_info(it)?;
    let pool = next_account_info(it)?;
    signer(owner)?;
    writable(staker)?;
    r.done()?;
    let _ = config; // config no longer drives the mint; kept in the account list for compatibility
    let p = load_pool(pool, pid)?;
    let mut st = load_staker(staker, owner.key, pid)?;
    req!(st.unbonding > 0 && now()? >= st.unlock_at, HkError::BondLocked);
    // The vault derives from the pool's pinned mint, so a changed config cannot strand the tokens.
    let sa = stake_accounts(pid, &p.mint, owner.key, mint, vault, stake_owner, token_program)?;
    let seeds: &[&[u8]] = &[STAKE_SEED, owner.key.as_ref(), &[sa.owner_bump]];
    transfer_checked(&sa, vault, dest, stake_owner, st.unbonding, seeds)?;
    st.unbonding = 0;
    st.unlock_at = 0;
    st.store(&mut staker.try_borrow_mut_data()?);
    mirror_maker(pid, owner.key, maker, &st)
}

/// Accounts: [owner (signer, w), config, pool (w), staker (w), fee_vault (w)].
/// Pays all rewards owed to the owner's wallet (one ix, so a wallet can follow it with a swap).
pub(crate) fn pool_claim(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let owner = next_account_info(it)?;
    let config = next_account_info(it)?;
    let pool = next_account_info(it)?;
    let staker = next_account_info(it)?;
    let fee_vault = next_account_info(it)?;
    signer(owner)?;
    writable(owner)?;
    writable(pool)?;
    writable(staker)?;
    writable(fee_vault)?;
    r.done()?;
    let c = load_config(config, pid)?;
    let mut st = load_staker(staker, owner.key, pid)?;
    let mut p = load_pool(pool, pid)?;
    sync(pid, &c, fee_vault, pool, &mut p)?;
    let x = claim_s::<SHIFT>(&mut p, &mut st)?;
    pay(pool, owner, x)?;
    p.store(&mut pool.try_borrow_mut_data()?);
    st.store(&mut staker.try_borrow_mut_data()?);
    msg!("halfkey: staking rewards claimed {}", x);
    Ok(())
}

/// Accounts: [anyone (signer, w), config, fee_vault (w), pool (w), system]. The permissionless crank: 50% of
/// the unsplit fees to stakers, 50% to the burn pot, plus loose SOL in the pool to stakers.
pub(crate) fn split_fees(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let who = next_account_info(it)?;
    let config = next_account_info(it)?;
    let fee_vault = next_account_info(it)?;
    let pool = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(who)?;
    writable(who)?;
    writable(fee_vault)?;
    writable(pool)?;
    r.done()?;
    let c = load_config(config, pid)?;
    req!(fee_vault.data_len() == BURN_LEN, HkError::BadState); // the auction must be on
    let mut p = pool_or_create(pid, &c, who, pool, system, fee_vault)?;
    sync(pid, &c, fee_vault, pool, &mut p)?;
    p.store(&mut pool.try_borrow_mut_data()?);
    Ok(())
}

/// Accounts: [payer (signer, w), config, fee_vault (w), pool (w), system]. Data: lamports u64.
/// Outside SOL for the stakers (100% to them, none to the burn), credited at once.
pub(crate) fn deposit_stakers(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let payer = next_account_info(it)?;
    let config = next_account_info(it)?;
    let fee_vault = next_account_info(it)?;
    let pool = next_account_info(it)?;
    let system = next_account_info(it)?;
    signer(payer)?;
    writable(pool)?;
    writable(fee_vault)?;
    let lamports = r.u64()?;
    r.done()?;
    req!(lamports > 0, HkError::BadParam);
    let c = load_config(config, pid)?;
    let mut p = pool_or_create(pid, &c, payer, pool, system, fee_vault)?;
    req!(p.total_staked > 0, HkError::NothingPending); // nobody to pay yet
    // Split what the vault holds first, so this deposit cannot shift earlier fees around.
    sync(pid, &c, fee_vault, pool, &mut p)?;
    transfer_in(payer, pool, system, lamports)?;
    credit(&mut p, lamports)?;
    p.store(&mut pool.try_borrow_mut_data()?);
    msg!("halfkey: {} lamports to stakers", lamports);
    Ok(())
}
