# HALFKEY v1.5: on-chain Monero payment proofs

> **Launch state: off (ready-only).** Mainnet launches with no attester set (the Monero header
> committee): every claim needs a `ready`. XMR->SOL is covered by the refund towers
> (`sdk/refundtowers.ts`). v1.5 is switch-on-able with the program built from this branch (it ships in the first deploy), with no further program change: see "Switching it on".

## Per swap: stay to confirm or walk away (`F_READY_ONLY`, flag 32)

Every SOL->XMR swap the page starts records the user's choice in the escrow at lock time, bound into
the maker's v2 consent, and nobody can change it afterwards:

- **Stay to confirm** (`lock2` with `F_READY_ONLY`): the program refuses `prove_lock` and every claim
  without the user's `ready`, even with a valid proof record (`zkproof::proof_allowed`,
  `zkproof::claim_gate`; tests `fuzz_v15::ready_only_cannot_be_overridden_by_a_committee_proof`,
  `e2e/zk.test.ts` "ready-only is immutable per swap"). Fully trustless; a committee cannot affect it.
- **Walk away** (flags 0): the maker may also be paid on a payment proof checked by the program,
  against a block header signed by 2 of 3 attesters. The user can close the tab after the lock.

The choice is offered only when the site config has `features.paymentProofs: true` and lists the
attesters, and the maker advertises `claimModes` with `payment-proof` (`claimMode: "payment-proof"`
plus attesters in its config). Otherwise nothing is asked and every swap is stay-to-confirm.
`F_READY_ONLY` is legal only on plain SOL->XMR `lock2` escrows (not pay, vault, OTC-by-`lock3`, or
XMR->SOL) and needs an upgraded (v2) maker account, which `maker/register.ts` always creates.

## Switching it on (owner steps)

1. Three attester keys, each made on the box that runs it, `watchtower/attester.ts` with at least two
   distinct Monero nodes per attester (the local monerod plus an independent one), HTTPS in front.
2. `ops/mainnet/params.json`: `"claimMode": "payment-proof"`, `"attesters": { "threshold": 2, "minConf": 10,
   "signers": [three { url, pubkey }] }`. `node ops/mainnet/set-attesters.ts params.json` prints the plan;
   `--send --admin <admin keypair>` is the owner's signature (creates the committee, epoch 1).
3. Maker config: `"claimMode": "payment-proof"`, `"attesters": [the three URLs]`; restart.
4. Site config: `"attesters": [the three URLs]`, `features.paymentProofs: true`; rebuild/deploy.
5. `node ops/mainnet/preflight.ts params.json` must pass "v1.5 claim mode and header committee"
   (keys, threshold, net and all three live attestations).
6. Monitoring: alert on any attester down (2 of 3 still prove; 1 of 3 cannot), on a maker `proof:` error
   lasting over 30 minutes, and on attesters disagreeing with the reference node.

**Back to ready-only (the fallback flag):** set `claimMode` to `ready-only` in maker and params and
`features.paymentProofs: false` on the site. New swaps are all stay-to-confirm. Open walk-away swaps
keep their terms (proofs still work for them while the committee exists). Rotating the committee
(`set-attesters.ts` with new keys) bumps the epoch, so old headers stop counting for new proofs.

## Trust, in plain words

A walk-away swap trusts that at least 2 of the 3 header signers are honest. If two of them collude
(or one operator controls two keys, e.g. all three on one VPS), they can sign a Monero block that does
not exist, the maker can post a "proof" of a payment that never happened, and take that swap's SOL.
They cannot touch stay-to-confirm swaps, XMR->SOL deposits (those use the refund towers), or anything
outside the per-swap cap (0.5 XMR equivalent) and the open-value cap across all open walk-away swaps.
Signers hold no funds and see no swap; they only vouch "block N has id X with >= 10 confirmations".

**The rule (immutable once the program is frozen):** a SOL->XMR escrow (a swap, an OTC tranche,
a pay-link payment, a cashout-vault conversion; XMR kinds only, the hash-locked SOL<->ZEC kind
settles on its preimage instead) can be claimed by the maker only after the
user's `ready`, or with a Monero payment proof that the Solana program has verified itself. The
old "the maker may claim at `t0` if nobody aborted" path is gone.

It is a **proof, not zero-knowledge**: Monero's own payment proof (TXPROOF_V2, a Schnorr/DLEQ
signature) plus the transaction bytes, checked with Solana's curve25519 and Keccak syscalls. No
SNARK, no trusted setup. The site says "payment proven on chain".

## What the program checks, and what it does not

| Fact | Who establishes it |
|---|---|
| The transaction bytes (prefix + RingCT base) and the prunable hash hash to the txid | **program** (`xmr.rs`) |
| Monero's TXPROOF_V2 proof is valid for this txid, bound to this escrow (message = escrow address in hex): the sender's `OutProofV2` (tx key) or the receiver's `InProofV2` (view key) | **program** |
| An output pays the escrow's shared spend key `B = claim_point + refund_point` with the escrow's view key (`P == Hs(8D‖i)·G + B`, view tag) | **program** |
| The decrypted amount opens that output's Pedersen commitment (`C == y·G + a·H`), and `a >= xmr_amount` | **program** |
| `unlock_time == 0`, tx version 2, RingCT CLSAG/BP+, key inputs only (no coinbase) | **program** |
| The tx is in the block with id X (Merkle path, Monero `tree_hash`, block hashing blob) | **program** |
| A proof record belongs to one escrow instance (seeded by the escrow and its creation time) | **program** |
| Block X is in the canonical Monero chain with >= 10 confirmations | **header committee**: k-of-n attesters (each signs only if two independent monerods agree) |

Monero's proof of work (RandomX) cannot be verified on chain, so the canonical-chain fact rests on
the committee. In one sentence: **a maker can take the SOL without delivering only if k of the n
attesters sign a fake or reorged-away Monero block (or the user signs `ready`).**

## What happens now, per case

- **Maker delivers, user online:** the user's browser checks the lock and signs `ready`; the
  maker claims at once (no proof needed). Unchanged.
- **Maker delivers, user offline:** after 10 confirmations the maker posts the attested header and
  the proof (`attest_header`, `prove_lock`, ~2 transactions, anyone may send them) and claims from
  `t0`. The maker daemon does this by itself (`maker/daemon.ts` + `sdk/prove.ts`).
- **Maker never delivers, user offline, every watchtower down:** nobody can claim. At `t1` the
  escrow is refund-only; the user (any time later, from any device) or anyone for a pay escrow
  refunds the full amount to the locker. Before v1.5 the maker could take the SOL here.
- **Maker delivers but the committee is down (or never attests):** the maker cannot claim without
  the user's `ready`. At `t1` the user refunds; for a swap or OTC tranche the refund reveals the
  user's key half, which hands the maker its XMR back: the maker loses time, not funds. **For a
  pay link or vault conversion it loses the XMR:** the payer can never send `ready` and a pay
  refund reveals nothing, so the XMR stays at the recipient's one-time key. The maker daemon
  therefore sends XMR for a pay escrow only while `t1 - now >= payProofSecs + claimMarginSecs`
  (default 3600 + 900 s) and refuses pay links when its `t0 + window` is shorter than that.
- **Abort before `t0`** (locker or a listed watchtower) still works and still refunds early. It is
  no longer needed for safety.

### Watchtower liveness, per product (after v1.5)

| Product | Needs a live watchtower for safety? |
|---|---|
| SOL->XMR swap | **No.** Proof-gated. A watchtower only speeds up a refund. |
| OTC tranches (SOL->XMR) | **No.** Same gate. A watchtower abort is still the "maker failed" reputation signal. |
| Pay links (payer can never say `ready`) | **No.** The maker can claim only with delivery to the recipient's one-time key proven. Before v1.5 this product relied entirely on watchtowers. |
| Cashout vaults (vault conversions are pay escrows) | **No.** Same as pay links. |
| XMR->SOL | Unchanged: the **maker** (the locker) protects itself by aborting a swap with no deposit before `t0`; that is the maker's own liveness, not the user's. With `F_PROOF` set (our maker sets it on every XMR->SOL lock), the user's claim without the maker's `ready` also needs a proof of the user's deposit, so even an offline maker is safe. |
| SOL<->ZEC (HTLC kind, `docs/ZEC.md`) | **Not proof-gated, by design.** The claim publishes the hashlock preimage that opens the ZEC script, so the claim itself pays the counterparty. `proof_gated` is false for directions 4/8; the HTLC claim (tag 48) never reads a proof record. |

## Instructions (tags 31-33)

| Tag | Instruction | Who | What |
|---|---|---|---|
| 31 | `set_attesters` | config admin | up to 7 keys, threshold k, Monero network, `min_conf >= 10`; every call bumps the epoch (old headers stop counting for new proofs) |
| 32 | `attest_header` | anyone | an Ed25519 precompile instruction right before it with >= k distinct committee signatures over `"halfkey-xmr-header-v1" ‖ net ‖ height ‖ block_id ‖ confirmations`; creates `["xmrhdr", epoch, block_id]` |
| 33 | `prove_lock` | anyone | verifies the proof against the escrow and the attested header; creates `["xmrout", output_key]` with the escrow, amount, txid, block |
| 9 | `claim` (changed) | claimer | a proof-gated escrow in state Locked needs the proof record as a 6th account (`claim_gate`) |

## Cost

| | Compute units (local validator, Agave 4.2) |
|---|---|
| Monero verification inside `prove_lock` (parse, txid, DLEQ, output, amount, Merkle path) | ~20,000 (research prototype measured 19,767-20,285) |
| `prove_lock` total (adds escrow load, `B` addition, PDA search + create) | 33,000-42,000 |
| `attest_header` (2 or 3 signatures; the precompile itself is billed per signature) | 9,500-11,200 |
| `claim` with the proof record | 14,434 (12,406 without) |

Rent: header ~0.0016 SOL (shared by every swap in that block), proof record ~0.0021 SOL (paid by
whoever proves, normally the maker). The proof transaction is ~800-1,100 bytes (fits one tx for
txs with up to ~6 inputs; makers lock from 1-2 inputs).

## Live stagenet run

`e2e/zk-stagenet.ts`: a real payment from the maker's stagenet wallet to a proof-gated escrow's
shared address, the wallet's own `get_tx_proof` (OutProofV2), our SDK's InProofV2 accepted by
`monero-wallet-rpc check_tx_proof`, a bare claim at `t0` rejected, two attesters each
cross-checking two public stagenet nodes, `attest_header`, `prove_lock` with the wallet proof
(the InProof simulated too), and the claim with the proof. The real tx, proof and block are kept as
a host-test fixture (`e2e/fixtures/xmr-stagenet-proof.json`, test
`fuzz_v15::real_stagenet_wallet_proof_verifies`). Receipt: `.run/receipt-zk-stagenet.json`.

## Privacy cost

A posted proof links the escrow to its Monero output and amount, publicly and forever. The
destination is still a one-time key only the user can spend. Users who care should sweep through
an extra hop or export keys and wait; FCMP++ removes ring analysis; a SNARK wrapper that hides
which output paid is the v2 item (ZK-LOCKS.md in the research notes).

## Known limits

- **Committee trust and rotation.** The committee is set by the config admin until the admin is
  retired; then it is frozen. Choose operators who are not makers. A rotation (epoch bump) does not
  revoke proofs already recorded.
- **Tx format.** Monero's FCMP++/Carrot upgrade changes the output derivation (Blake2b, X25519).
  The program must be upgraded or a new version deployed before Monero activates it, or proofs
  stop verifying (fail-closed: claims then need the user's `ready`, refunds are unaffected).
- **Additional tx keys** (subaddress destinations, 3+ outputs) are not supported: the verifier
  uses the first tx public key. HALFKEY's shared address is a standard address, and wallets send
  to it with the main tx key.
- **Proof before `t1` only.** Proofs and claims close at `t1` like every claim.

## Security review (fresh-eyes pass) and what was fixed

A reviewer went over `program/src` against `main`. Fixed in this branch:

- **Proof record is per escrow instance** (`["xmrout", escrow, created_at]`), not per Monero output.
  Two problems this closes: (a) a "twin" escrow that copies a victim's shared key could otherwise
  grab the victim's per-output record and permanently block the honest proof (a pay escrow can
  never be readied, so its XMR would strand) — now the twin writes its own record and the honest
  escrow proves independently; (b) an escrow address freed by `close` could be relocked and claimed
  with the old record — now `claim_gate` requires `rec.escrow_created == escrow.created_at`.
- **The stake pool pins its mint** at creation (`Pool::mint`) and derives the token vault from it,
  not from the mutable `config.halfkey_mint` (the burn already pins its mint in its state). A later
  config change can no longer strand stakers' tokens or let a different mint be staked into the pool.
- **Burn restart price scales with the lot taken**, so dust `burn_take`s cannot pump the price out
  of range and stall the buyback.
- **Idle pool SOL goes to the burn** when nobody is staked (no lone first-staker scoop), and
  `split_fees` creates the pool if needed.

Confirmed fine by the reviewer: the Monero parser/txid/Merkle/DLEQ/amount math (differences only
cause rejections, never false accepts), the Ed25519 precompile checks, account PDA/owner checks,
the burn supply-drop and rent reserve, and the rewards accumulator (no overflow, rounds down,
splits before any stake change).

## Integration review (main..integrate2) and what was fixed

A second fresh-eyes pass over the merged program (v1.5 + the SOL<->ZEC HTLC kind + any-coin):

- **Proof records are bound to the escrow's terms** (`["xmrout", escrow, created_at,
  proof_terms]`, `proof_terms = sha256("halfkey-proof-terms-v1" || claim_point || refund_point ||
  view_pub)`). Before, an escrow closed and re-locked at the same address in the same second
  (possible for a vault with `interval = 0` and a colluding keeper) could be claimed against the
  old instance's payment. The SDK derives the same PDA (`pdaV15.proof(pid, escrow, escrowAccount)`).
- **Legacy bond with a pending unstake** (fixed in rewards.rs): enrolling it into the pool reverted
  (the enroll-only call went through `stake_s`, which refuses while unbonding), and with
  instructions 14-16 retired the tokens and the maker's SOL bond could never leave. Enroll-only is
  now a no-op step, and the bond counts only what the pool-mint vault really holds.
- **Fees earned before `burn_init`** become the first burn pot instead of being split to whoever is
  staked when the auction starts.
- **One token for staking and the burn**: `burn_init` takes the pool account and refuses a mint
  other than the pool's; creating the pool after the auction refuses a config mint other than the
  burn's.

Open, for a decision before mainnet (not changed here):

- **Pay/vault escrows depend on the committee.** DECIDED in the final round (docs/FINAL-ROUND.md
  section 6): both remedies. The link owner may sign `ready` on a pay escrow until `t1`, and pay,
  vault and direct-payout escrows need a claim window of at least 6 h on chain.
- **Pool unbond floor.** DECIDED in the final round: config refuses `unbond_secs` below 3 days.
- **A watchtower can still abort a proven pay escrow before `t0`**, which strands the maker's XMR
  like a committee outage. The program could refuse that abort once a proof record exists.
- **Reused HTLC hashlock:** nothing on chain stops two HTLC escrows sharing a hashlock; the maker
  desk and the SDK must never reuse a secret or a ZEC HTLC outpoint.
- Proof records (176 B) cannot be closed; their rent stays locked. Pause does not stop
  `burn_take`, pool instructions, `prove_lock` or `attest_header` (exits and bookkeeping).

## Left for the final program round (before the mainnet freeze)

- **Proof-tx size / multi-input locks.** A proof is one Solana tx (~510 B + 33 B per Merkle level);
  a Monero tx with ~4+ inputs or additional tx pubkeys does not fit. Pay-mode makers must lock from
  1-2 consolidated inputs (documented), or add a chunked proof-buffer account. Until then an
  oversized lock cannot be proven: the maker cannot claim (no theft) and the SOL refunds at `t1`.
- **IN proofs with a torsioned `R`.** wallet2 clears torsion from `R` before an InProof; the
  on-chain check does not, so it would reject such a proof. HALFKEY's own `R` is always prime-order,
  so our flows are unaffected; document that third-party InProofs must use a prime-order `R`.
- **`ready` after `t0`.** Allowed until `t1` in the final round for the escrows a committee outage
  could strand (a pay escrow's link owner, a direct-payout escrow's locker). A plain 2-of-2 swap
  keeps `ready` before `t0` (its refund hands the maker its XMR back, so nothing strands).
- **Attester rotation / burn tuning.** `set_attesters` takes effect at once (consider pinning the
  epoch at lock or a timelock); `burn_init` params are permanent and one-way (allow lowering the
  floor and changing `max_lot`, destinations fixed).
- **Flash staking around a large claim.** Bundling stake -> claim -> split -> unstake earns a share
  of one split for the cost of `unbond_secs` idle; the final round enforces `unbond_secs >= 3 days`.
- **Retroactive gating.** The rule gates every SOL->XMR escrow; on the immutable launch program
  there are no pre-existing escrows, but if ever upgraded in place, gate only escrows locked after
  the committee is active (store an epoch at lock).
