//! Permissionless $HALFKEY buyback-and-burn of the protocol fees.
//!
//! The 0.5% protocol fee collects in the fee vault PDA. `burn_init` (the config admin, once,
//! one-way) turns that vault into a descending-price auction: the vault account grows to hold
//! the auction state, and from then on `sweep_fees` refuses, so the fees can leave the vault
//! only through `burn_take`.
//!
//! The fees are first split (rewards.rs `split_fees`, also run by every stake action): 50% to
//! $HALFKEY stakers, 50% to the burn pot (100% when nobody is staked). The auction sells only the
//! burn pot.
//!
//! `burn_take` (anyone, no key): the caller burns $HALFKEY from its own token account and
//! receives a lot of the fee vault's SOL at the current auction price, in one instruction.
//!  * The price (base units of $HALFKEY per SOL) starts at twice the last clearing price and
//!    halves every `HALF_LIFE_SECS` (linear in between), never below the floor. A buyer takes
//!    the lot as soon as the price is below what $HALFKEY costs on the market, so the protocol
//!    buys back at about the market price without an oracle, a DEX route, or anyone running a
//!    bot: whoever cranks is paid by the auction itself. A take raises the restart price only in
//!    proportion to the lot it took, so dust takes cannot pump it out of range.
//!  * Bounded: one take moves at most `max_lot` lamports and never touches the vault's rent
//!    reserve. Idempotent: each take restarts the auction at twice its price, so a replayed or
//!    duplicated take is priced out by its own `max_burn`.
//!  * No destination to choose: the SOL goes to the signer that burned, the tokens are burned
//!    (the mint's supply must drop by exactly the burn), and the mint is fixed at init.

use crate::*;

pub const DISC_BURN: u8 = 0xB0;
/// The fee vault's size once the auction is on.
pub const BURN_LEN: usize = 112;
/// Price halving time.
pub const HALF_LIFE_SECS: i64 = 3_600;
/// A lot is priced per SOL.
pub const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BurnState {
    pub mint: Pubkey,
    /// $HALFKEY base units per SOL at `start_at`.
    pub start_price: u64,
    pub floor_price: u64,
    pub max_lot: u64,
    pub start_at: i64,
    pub takes: u64,
    pub total_burned: u64,
    pub total_lamports: u64,
    pub last_price: u64,
    /// Lamports of the fee vault assigned to the burn (the burn half of each split, rewards.rs);
    /// the auction sells only these.
    pub pot: u64,
}

impl BurnState {
    pub fn load(d: &[u8]) -> Result<Self, ProgramError> {
        req!(d.len() == BURN_LEN && d[0] == DISC_BURN, HkError::BadAccount);
        let mut r = Rd::new(d);
        r.skip(8)?;
        Ok(Self {
            mint: r.key()?,
            start_price: r.u64()?,
            floor_price: r.u64()?,
            max_lot: r.u64()?,
            start_at: r.i64()?,
            takes: r.u64()?,
            total_burned: r.u64()?,
            total_lamports: r.u64()?,
            last_price: r.u64()?,
            pot: r.u64()?,
        })
    }
    pub fn store(&self, d: &mut [u8]) {
        let mut w = Wr::new(d);
        w.u8(DISC_BURN);
        w.u8(1);
        w.pad(6);
        w.put(self.mint.as_ref());
        w.u64(self.start_price);
        w.u64(self.floor_price);
        w.u64(self.max_lot);
        w.i64(self.start_at);
        w.u64(self.takes);
        w.u64(self.total_burned);
        w.u64(self.total_lamports);
        w.u64(self.last_price);
        w.u64(self.pot);
    }
}

// ---------------------------------------------------------------------------------------------
// Pure rules (Kani: proofs_v15.rs)
// ---------------------------------------------------------------------------------------------

/// `burn_init` parameters: 1 <= floor <= start, and a positive lot cap.
pub fn check_params(start_price: u64, floor_price: u64, max_lot: u64) -> Result<(), HkError> {
    if !(floor_price >= 1 && floor_price <= start_price && max_lot > 0) {
        return Err(HkError::BadParam);
    }
    Ok(())
}

/// `sweep_fees` is allowed only while the fee vault is a plain (data-less) account.
pub fn sweep_allowed(vault_data_len: usize) -> Result<(), HkError> {
    if vault_data_len != 0 {
        return Err(HkError::BadState);
    }
    Ok(())
}

/// Auction price at `t`: `start >> k` after k half-lives, minus a linear share of the next
/// halving within the current one; never below the floor (nor above the start).
pub fn price_at(start: u64, floor: u64, start_at: i64, t: i64) -> u64 {
    let el = if t > start_at { (t as i128 - start_at as i128) as u128 } else { 0 };
    let k = el / HALF_LIFE_SECS as u128;
    let p = if k >= 64 { 0 } else { start >> k };
    let rem = el % HALF_LIFE_SECS as u128;
    let drop = (p / 2) as u128 * rem / HALF_LIFE_SECS as u128;
    let p = p - drop as u64;
    p.max(floor)
}

/// The result of one take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Take {
    pub lot: u64,
    pub burn: u64,
    pub price: u64,
}

/// `ceil(price * lot / 1e9)`: the $HALFKEY a lot costs at `price`, rounded against the buyer.
pub fn cost(price: u64, lot: u64) -> Result<u64, HkError> {
    let num = (price as u128) * (lot as u128) + (LAMPORTS_PER_SOL as u128 - 1);
    let c = num / LAMPORTS_PER_SOL as u128;
    u64::try_from(c).map_err(|_| HkError::Overflow)
}

/// What a take moves: the burn pot, capped at `max_lot` and never into the rent reserve `keep`;
/// the buyer's bounds are `max_burn` (tokens) and `min_lamports` (SOL).
pub fn take_terms(s: &BurnState, vault_lamports: u64, keep: u64, t: i64, max_burn: u64, min_lamports: u64) -> Result<Take, HkError> {
    let free = vault_lamports.saturating_sub(keep);
    let lot = free.min(s.max_lot).min(s.pot);
    if lot == 0 {
        return Err(HkError::NothingPending);
    }
    if lot < min_lamports {
        return Err(HkError::Slippage);
    }
    let price = price_at(s.start_price, s.floor_price, s.start_at, t);
    let burn = cost(price, lot)?;
    if burn == 0 || burn > max_burn {
        return Err(HkError::Slippage);
    }
    Ok(Take { lot, burn, price })
}

/// After a take: raise the restart price in proportion to how much of a full lot was taken
/// (`price * (1 + lot/max_lot)`), so a dust take barely moves it and cannot pump the price out of
/// range; a full-lot take doubles it. Never below the floor.
pub fn after_take(s: &mut BurnState, k: &Take, t: i64) -> Result<(), HkError> {
    let bump = (k.price as u128) * (k.lot as u128) / (s.max_lot.max(1) as u128);
    s.start_price = u64::try_from(k.price as u128 + bump).unwrap_or(u64::MAX).max(s.floor_price);
    s.start_at = t;
    s.last_price = k.price;
    s.takes = s.takes.checked_add(1).ok_or(HkError::Overflow)?;
    s.total_burned = s.total_burned.checked_add(k.burn).ok_or(HkError::Overflow)?;
    s.total_lamports = s.total_lamports.checked_add(k.lot).ok_or(HkError::Overflow)?;
    s.pot = s.pot.checked_sub(k.lot).ok_or(HkError::Overflow)?;
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------------------------

pub(crate) fn fee_vault_check(vault: &AccountInfo, c: &Config, pid: &Pubkey) -> ProgramResult {
    let vk = Pubkey::create_program_address(&[FEE_VAULT_SEED, &[c.vault_bump]], pid).map_err(|_| HkError::BadPda)?;
    req!(vk == *vault.key, HkError::BadPda);
    owned(vault, pid)
}

fn mint_supply(mint: &AccountInfo) -> Result<u64, ProgramError> {
    let d = mint.try_borrow_data()?;
    req!(d.len() >= 82, HkError::BadAccount);
    Ok(u64::from_le_bytes(d[36..44].try_into().unwrap()))
}

/// Accounts: [admin (signer, w), config, fee_vault (w), mint, system, stake pool PDA (need not exist)].
/// Data: start_price u64, floor_price u64, max_lot u64.
/// One-way: grows the fee vault to hold the auction (the admin pays the extra rent) and fixes
/// the mint to config's $HALFKEY mint, which must be the stake pool's mint if the pool exists.
/// Fees already in the vault (earned before the auction, when they were the fee recipient's to
/// sweep) go to the burn pot: never to the stakers of the moment, who did not stake while they
/// accrued. There is no instruction that turns it off.
pub(crate) fn burn_init(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let admin = next_account_info(it)?;
    let config = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let mint = next_account_info(it)?;
    let system = next_account_info(it)?;
    let pool = next_account_info(it)?;
    signer(admin)?;
    writable(admin)?;
    writable(vault)?;
    let start_price = r.u64()?;
    let floor_price = r.u64()?;
    let max_lot = r.u64()?;
    r.done()?;
    let c = load_config(config, pid)?;
    req!(c.admin == *admin.key, HkError::Unauthorized);
    fee_vault_check(vault, &c, pid)?;
    req!(vault.data_len() == 0, HkError::AlreadyInitialized);
    req!(c.halfkey_mint != Pubkey::default() && *mint.key == c.halfkey_mint, HkError::BadAccount);
    req!(*mint.owner == TOKEN_PROGRAM || *mint.owner == TOKEN_2022_PROGRAM, HkError::BadAccount);
    mint_supply(mint)?;
    // Staking and the burn use one token.
    req!(*pool.key == crate::rewards::pool_pda(pid).0, HkError::BadPda);
    if pool.data_len() > 0 {
        req!(crate::rewards::load_pool(pool, pid)?.mint == *mint.key, HkError::BadAccount);
    }
    check_params(start_price, floor_price, max_lot)?;
    let rent = Rent::get()?;
    let top = rent.minimum_balance(BURN_LEN).saturating_sub(rent.minimum_balance(0));
    transfer_in(admin, vault, system, top)?;
    vault.resize(BURN_LEN)?;
    let pot = vault.lamports().saturating_sub(rent.minimum_balance(BURN_LEN));
    let s = BurnState { mint: *mint.key, start_price, floor_price, max_lot, start_at: now()?, pot, ..Default::default() };
    s.store(&mut vault.try_borrow_mut_data()?);
    msg!("halfkey: burn auction on (start {}, floor {}, lot {})", start_price, floor_price, max_lot);
    Ok(())
}

/// Accounts: [buyer (signer, w), config, fee_vault (w), mint (w), buyer token account (w),
///            token program]. Data: max_burn u64, min_lamports u64.
/// Burns `cost(price, lot)` $HALFKEY from the buyer's token account (the buyer signs the burn)
/// and pays the lot to the buyer.
pub(crate) fn burn_take(pid: &Pubkey, accounts: &[AccountInfo], r: &mut Rd) -> ProgramResult {
    let it = &mut accounts.iter();
    let buyer = next_account_info(it)?;
    let config = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let mint = next_account_info(it)?;
    let source = next_account_info(it)?;
    let token_program = next_account_info(it)?;
    signer(buyer)?;
    writable(buyer)?;
    writable(vault)?;
    writable(mint)?;
    writable(source)?;
    let max_burn = r.u64()?;
    let min_lamports = r.u64()?;
    r.done()?;
    let c = load_config(config, pid)?;
    fee_vault_check(vault, &c, pid)?;
    let mut s = BurnState::load(&vault.try_borrow_data()?)?;
    req!(*mint.key == s.mint, HkError::BadAccount);
    req!(*token_program.key == TOKEN_PROGRAM || *token_program.key == TOKEN_2022_PROGRAM, HkError::BadAccount);
    req!(mint.owner == token_program.key, HkError::BadAccount);
    let decimals = {
        let d = mint.try_borrow_data()?;
        req!(d.len() >= 82, HkError::BadAccount);
        d[44]
    };
    let t = now()?;
    let keep = Rent::get()?.minimum_balance(BURN_LEN);
    let k = take_terms(&s, vault.lamports(), keep, t, max_burn, min_lamports)?;

    // BurnChecked from the buyer's account, signed by the buyer (its signature carries into the
    // CPI). The supply must drop by exactly the burn.
    let before = mint_supply(mint)?;
    let mut data = Vec::with_capacity(10);
    data.push(15u8); // BurnChecked
    data.extend_from_slice(&k.burn.to_le_bytes());
    data.push(decimals);
    let ix = solana_instruction::Instruction {
        program_id: *token_program.key,
        accounts: vec![
            solana_instruction::AccountMeta::new(*source.key, false),
            solana_instruction::AccountMeta::new(*mint.key, false),
            solana_instruction::AccountMeta::new_readonly(*buyer.key, true),
        ],
        data,
    };
    invoke_signed(&ix, &[source.clone(), mint.clone(), buyer.clone(), token_program.clone()], &[])?;
    let after = mint_supply(mint)?;
    req!(before.checked_sub(after) == Some(k.burn), HkError::BadState);

    pay(vault, buyer, k.lot)?;
    after_take(&mut s, &k, t)?;
    s.store(&mut vault.try_borrow_mut_data()?);
    msg!("halfkey: buyback {} lamports, burned {} at {} per SOL", k.lot, k.burn, k.price);
    Ok(())
}
