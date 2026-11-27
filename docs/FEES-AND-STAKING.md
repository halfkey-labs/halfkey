# Protocol fees: $HALFKEY stakers and the burn

The 0.5% protocol fee (0.25% for a bonded maker) lands in the fee vault PDA at every claim, of
every kind: XMR swaps, OTC tranches, pay links, vault conversions and SOL<->ZEC HTLC claims
(tag 48). The split below works on the vault's balance, so every kind's fee is split the same way. Once
the config admin turns the burn auction on (`burn_init`, one-way), the fees can leave the vault
only two ways, both permissionless and keyless:

```
claim fee -> fee vault --split_fees--> 50% stake pool (SOL rewards for $HALFKEY stakers)
                                    \-> 50% burn pot  (sold by the auction for $HALFKEY that is burned)
```

`sweep_fees` (to a configured wallet) refuses from then on. Nobody needs to run a bot: the split
runs inside every stake, unstake and claim and anyone can call `split_fees`; the auction is filled
by whoever finds it profitable.

## The split (`split_fees`, tag 40)

- Unsplit fees = fee vault lamports - its rent - the burn pot.
- Stakers get `floor(unsplit / 2)`, the burn pot gets the rest: the odd lamport (rounding dust)
  goes to the burn. Exact: the two parts always add up (Kani `p11_split_exact`).
- Nobody staked: 100% to the burn pot.

## Staking (tags 36-39, 41)

| Tag | Instruction | Notes |
|---|---|---|
| 36 | `pool_stake(amount)` | anyone; tokens go to the same vault as the maker bond (the associated token account of `["stake", owner]`); the pool and the staker record are created on first use (the pool pins config's $HALFKEY mint then, and every later stake/unstake uses that pinned mint); amount 0 enrolls a pre-v1.5 maker bond (an unstake pending on it carries over as a pending pool unstake; the bond counts only what the pool-mint vault holds) |
| 37 | `pool_unstake_request(amount, 0 = all)` | stops earning at once; leaves after `config.unbond_secs` |
| 38 | `pool_unstake` | pays the unbonded tokens back after the delay |
| 39 | `pool_claim` | pays all rewards owed, in SOL, to the owner's wallet. One instruction with no return value, so a client can put it first in a transaction and lock the same SOL into a SOL->XMR swap right after ("claim as XMR") |
| 41 | `deposit_stakers(lamports)` | outside SOL, 100% to stakers (none to the burn); refused while nobody is staked |
| 40 | `split_fees` | anyone; creates the pool if needed (the caller pays its rent) |

**A maker bond is a stake.** The maker account mirrors its stake (`staked`, `stake_unlock_at`),
so the holder fee discount works exactly as before: on while the stake >= `holder_min` and no
unstake is pending. The old maker-only instructions 14-16 are retired (they could have moved
tokens out of the shared vault without the pool's bookkeeping).

**Rewards:** a reward-per-token accumulator (`acc`, scaled by 2^64). Crediting `x` lamports adds
`floor(x * 2^64 / total_staked)`; a staker earns `staked * (acc - acc_at) / 2^64` (floor), settled
into `owed` before any change to its stake. Rounding is always down, so what stakers can claim
never exceeds what was credited (Kani `p11_claims_never_exceed_credits`); the leftover is < 1
lamport per staker per credit and stays in the pool.

**Flash-stake protection (the simplest safe option):** every stake, unstake and claim runs the
fee split first, so fees that reached the vault before a stake are credited to the stake that
existed then; a new stake only earns from fees that arrive after it. Leaving takes the unbond
delay, during which the tokens earn nothing. A stake-crank-unstake round trip therefore earns only
the fees that arrived while it was staked and then sits idle for the whole delay. **Floor:**
the program refuses `unbond_secs` below 3 days (final round; the e2e build allows 10 s and e2e uses 12 s). With a
short delay a stake made just before a large claim + `split_fees` takes a pro-rata share and leaves
a moment later, and the holder fee discount can be taken the same way (stake, lock at 0.25%,
unstake). The hard on-chain floor (3 days) was added in the final round (FINAL-ROUND.md).

**Fees before the auction:** whatever sits in the fee vault when `burn_init` runs becomes the first
burn pot (the fee recipient could sweep it until then); it is never split to the stakers of that
moment. **One token:** `burn_init` refuses a mint other than the stake pool's, and a pool created
after the auction refuses a config mint other than the burn's.

## SOL sent straight to the pool (pump.fun creator fees)

The pool PDA `["stake_pool"]` (`sdk/v15.ts pdaV15.pool`) accepts plain SOL transfers. The next
split (any stake, unstake, claim or `split_fees`) credits `pool lamports - rent - (credited -
claimed)` to the stakers, so loose SOL can never be counted twice and can never dip into what
stakers are already owed (Kani `p11_pool_extra_never_touches_owed`). With nobody staked, the next
split sends it to the burn pot instead (so a lone first staker cannot scoop it).

**pump.fun:** set the coin's fee-sharing recipient to the pool address. This works if pump.fun
pays the share as a plain lamport transfer to the recipient address (as it does to the cashout
vault addresses, which are program accounts too). If pump.fun's fee sharing requires the recipient
to sign a "claim creator fees" transaction, a PDA cannot sign it directly: that would need a small
permissionless instruction that CPIs pump.fun's claim with the pool PDA as signer (pump.fun program
id and accounts fixed in the program). Not built; check pump.fun's current fee-sharing flow before
launch. Alternatively a wallet that receives the fees can call `deposit_stakers` (100% to stakers).

## The burn auction (tags 34-35)

- `burn_init(start_price, floor_price, max_lot)` (config admin, once): the fee vault grows to hold
  the auction state (the admin pays the extra rent), the mint is fixed to config's $HALFKEY mint.
- `burn_take(max_burn, min_lamports)` (anyone): burn `ceil(price * lot / 1e9)` $HALFKEY from your
  own token account (you sign the burn) and receive the lot: `min(burn pot, max_lot)`, never the
  vault's rent. After a take the price restarts at `price * (1 + lot / max_lot)` (twice the price
  for a full lot, barely higher for dust, so dust takes cannot pump it out of range) and halves
  every hour, never below the floor. The supply must drop by exactly the burn.
- No oracle, no DEX route, no destination to choose; a replayed take is priced out (the auction
  restarts at twice the price). Kani `p9_*`.

## Cost (compute units, local validator)

| `split_fees` 7,052 | `pool_stake` 41,886 (incl. creating the token vault) | `pool_claim` 9,686 | `deposit_stakers` 12,738 | `burn_init` 8,406 | `burn_take` 9,197 |
|---|---|---|---|---|---|
