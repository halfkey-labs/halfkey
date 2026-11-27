# HALFKEY program: formal verification

Scope: the Solana program `program/src/lib.rs` (native Rust escrow for SOL <-> XMR atomic swaps).
Branch `formal` (proposed fix for the one bug found: branch `formal-fix`). Tool:
[Kani](https://github.com/model-checking/kani) 0.68.0, a bit-precise bounded model checker for
Rust (CBMC backend), plus proptest and the existing local-validator suite. Date: 2026-11-04.

**Summary.** The escrow's decision and accounting logic (state machine, time windows, abort rules,
lamport moves, fee split, caps, pause, consent parsing, scalar check) now lives in pure functions
(`program/src/logic.rs`) that the instruction handlers call. Kani proves each of them equal to the
pre-refactor code, and proves P1-P6 and the scalar half of P7 over them for every possible input
(two consent-parsing harnesses are bounded to 160 bytes of instruction data). For the
whole escrow lifecycle it proves an inductive invariant: `lock` establishes it and every
instruction preserves it, so the safety properties hold in every reachable state after any number
of instructions (over a model of the handlers built from the same functions; account plumbing is
not modelled). The curve checks (points, `s*G`) are not proven; they are tested against the same
library code the validator's syscalls run. One real defect was found (BUG-1, low severity:
non-canonical encodings of the identity pass the on-chain point check), with failing tests and a
separate one-check fix.

## Results

| Property | Status | How |
|---|---|---|
| P1 funds leave only by claim (claimer, valid `s`) or refund (locker) | **proven** over the lifecycle model (inductive, all reachable states) + inspection and a tripwire test for the program-wide part | `sm_inv_base`, `sm_inv_step_state`, `sm_inv_step_money`, `p7_check_reveal_sound`; `fuzz::lamport_debit_sites_unchanged` |
| P2 claim and refund mutually exclusive | **proven** (inductive invariant; window functions for all inputs) | `sm_inv_*`, `eq_windows` |
| P3 refund only after abort / t1; claim only in its window | **proven** (per instruction, and as an invariant over the lifecycle) | `eq_windows`, `eq_abort`, `sm_inv_step_state` |
| P4 fee + payout = amount; refund = amount; lamports conserved; no overflow | **proven**: split and `pay` conserve for all inputs, and every instruction conserves the parties' total in every reachable state. **Tested**: the fee's exact value and the 1% bound (edge grid + 20k random cases) | `p4_*`, `sm_inv_step_money`, `fuzz::split_fee_*` |
| Counters can never block an exit (release never underflows) | **proven** (inductive, any number of escrows) | `sm_release_inductive`, `sm_lock_inductive` |
| P5 no lock without the maker's signed consent over the exact terms | **proven** (role check, message injectivity), **bounded-proven** (precompile data <= 160 bytes); sha256/ed25519/precompile **assumed** | `p5_*`, e2e consent tests |
| P6 pause blocks only new locks, never exits | **proven** for lock and for the exit logic (all inputs), plus signatures and a tripwire test for the handlers | `p6_pause_blocks_locks`, `p6_release_ignores_pause`, `fuzz::paused_read_sites_unchanged` |
| P7a scalar check rejects `s + k*L` aliases | **proven** (all 2^256 inputs) | `p7_canonical_iff_less_than_l`, `p7_aliases_rejected`, `p7_check_reveal_sound` |
| P7b point check rejects torsion / identity | **tested, not proven**; exhaustive over all 40 non-canonical encodings, which found **BUG-1** | `fuzz::*point*`, `fuzz::noncanonical_*`, e2e |
| Refactor did not change behaviour | **proven** for every extracted function except the fee expression (moved verbatim; differential-tested); e2e suite passes on both builds | `eq_*`, `fuzz::split_fee_*`, `e2e/program.test.ts` |

## 1. Tool choice

| Tool | Verdict | Why |
|---|---|---|
| **Kani** (model-checking/kani, MIT/Apache) | **chosen** | Checks the real Rust source with no rewrite and no annotations in program code. Bit-precise: every u64/i64/u128 overflow, cast, index and panic is a checked property. Free and local (macOS aarch64 bundle ~350 MB plus a pinned nightly toolchain). Limits: loops are unrolled (the lifecycle is handled by induction instead); no Solana runtime, syscalls or hashes, so the logic has to be pure (hence the refactor); SAT handles bit-level logic well but not wide nonlinear arithmetic (see P4). |
| Certora Solana Prover | not used | GPL-3 since 2025 and verifies the compiled SBF, which would also cover the account glue. The documented workflow (`certoraSolanaProver`) submits jobs to Certora's cloud with a key; running locally means building the prover from source (JDK 19+, Z3, CVC5, LLVM tools, Gradle). Too heavy, and not clearly key-free, for this pass. Worth it for an audit. |
| Verus | not used | Code must be rewritten in Verus' dialect inside `verus!{}` with manual invariants: a parallel model, not the shipped code. |
| Creusot | not used | Deductive (Why3); the opam/Why3/solver install is several GB and the specs are manual. |
| Prusti | not used | Effectively unmaintained, pinned to an old nightly; will not build the Solana 3.x crates. |
| proptest | **used** | Long random runs (up to 40 instructions) of the same lifecycle model with the real curve code; curve checks; differential tests against the original fee code. Dev-dependency only. |
| Trident / honggfuzz | not used | Trident fuzzes whole transactions through the SVM (would cover the account glue) but targets Anchor programs; honggfuzz adds little over proptest for pure logic. A LiteSVM/Trident transaction fuzzer is the natural next step (section 6). |

## 2. Refactor (no behaviour change)

`program/src/logic.rs` holds, as pure functions over plain values and the existing state structs:

| Function | Replaces (in `lib.rs`) |
|---|---|
| `check_lock_terms` | `lock`: pause, maker active and direction, locker/claimer roles, amount range, per-swap cap, open-TVL cap, xmr amount, t0 and window ranges |
| `check_watchtowers`, `effective_fee_bps`, `deadlines`, `open_counters` | the rest of `lock` |
| `ready_window`, `abort_check`, `claim_window`, `refund_window`, `expire_window`, `close_allowed` | the state and time checks of `ready`, `abort`, `claim`, `refund`, `expire`, `close` |
| `split_fee` (+ `bps_of`, the fee expression moved verbatim), `pay_amounts`, `release` | claim fee split, lamport moves, open-counter release |
| `ed25519_ix_binds` | the precompile-data parsing in `require_ed25519` |
| `scalar_is_canonical`, `check_reveal_with` | the scalar check and reveal (`s*G` is passed in; the program passes the syscall) |

The handlers call these in the same order as the inline checks they replaced and return the same
error codes; `ready` and `expire` still read the clock only after their state checks. Account
loading, PDAs, CPIs, rent and the curve syscalls stay in the handlers. Commits: `4b04522`
(refactor), then the proofs and tests on top.

Evidence that behaviour is unchanged:
1. **Kani equivalence** (`eq_*`, 11 harnesses): each extracted function equals, for all inputs, a
   verbatim copy of the pre-refactor code (module `orig` in `proofs.rs`, from commit d00f39f),
   including the error returned and whether the clock is read. `eq_ed25519` is bounded to
   instruction data of up to 160 bytes (a real one is 144).
2. **Fee expression**: moved character for character into `bps_of`; `fuzz::split_fee_*` compares
   `split_fee` with the original code on an edge grid and 20,000 random inputs (SAT cannot compare
   two 128-bit dividers).
3. **Existing suite**: `e2e/program.test.ts` on a local validator: 26/26 pass on the refactored
   build, the same as on the pre-refactor build (section 4).

## 3. Properties in detail

Notation: *proven* = Kani, all inputs; *bounded* = Kani, all inputs up to the stated bound;
*fuzzed* = proptest; *tested* = example tests; *inspection* = argued from the code.

**The lifecycle model** (`program/src/model.rs`) follows each handler's sequence of checks and
effects using the same `logic` functions, and tracks the lamports of the escrow, locker, claimer
and fee vault plus a little history (claims, refunds, when Ready was signed, who aborted when). It
assumes the account checks passed (owners, PDAs, discriminators, signer flags: covered by the e2e
suite). Its invariant `model::inv` says, roughly: the state is one of the five; `claims == 1`
exactly when Claimed and `refunds == 1` exactly when Refunded; the escrow holds rent + amount
exactly while Locked/Ready/Aborted, rent once settled, nothing once closed (closed only when
settled); Ready was signed before `t0`; an abort happened inside its window by an allowed signer;
the counters are released at the first exit, or by expire at/after `t1`.

- `sm_inv_base`: every successful `lock` (arbitrary config and maker, both directions, any amount,
  windows, fee, watchtowers, rent and pre-funding) satisfies the invariant.
- `sm_inv_step_state` / `sm_inv_step_money`: from ANY world satisfying the invariant, any
  instruction (ready, abort, claim, refund, expire, close; signer locker / claimer / watchtower /
  stranger; any refund destination; any secret; any result of the `s*G` syscall; pause on or off;
  any later clock) that succeeds preserves the invariant and satisfies the per-step properties
  below (`model::check_state`, `model::check_money`).
- Together these are an induction: the properties hold in every reachable state, for any number of
  instructions. `kani::cover!` checks in both step harnesses confirm it is not vacuous: each of
  ready, abort, claim after Ready, claim at `t0`, refund after abort, refund after `t1`, expire,
  close, and refund while paused is reachable from an invariant state (9 of 9 covers satisfied),
  and `sm_inv_base` covers a successful lock.

The proptest walks (`fuzz::lifecycle_random_walk` with the real curve code, 40-instruction runs;
`fuzz::lifecycle_unconstrained_walk` over near-arbitrary configs) check the same properties and
the invariant after every step.

**P1. Locked funds leave the escrow only by claim (to the claimer, with a valid `s`) or refund (to the locker).**
- Lifecycle (proven, inductive): the principal leaves only in a claim signed by the recorded claimer whose
  secret passed `check_reveal` (canonical, and the syscall said `s*G == claim_point`), paying exactly
  `amount - fee` to the claimer and `fee` to the vault; or in a refund to the recorded locker, after
  the refund-point reveal, of exactly `amount`. `close` runs only after one of those and returns only
  the rent (and any pre-funding) to the locker. No other instruction moves lamports. In SOL->XMR the
  claimer is the maker (`p5_lock_needs_maker`).
- Program-wide (inspection, with a tripwire): lamports leave program accounts only through `pay`
  (directly or via `close_account`), called from claim, refund and close (escrow), sweep_fees (the
  fee-vault PDA only, to the configured recipient) and withdraw_maker (the maker account; `Maker::load`
  rejects an escrow by size and discriminator). `fuzz::lamport_debit_sites_unchanged` fails if a debit
  site is added or moved.

**P2. Claim and refund are mutually exclusive.**
- Lifecycle (proven, inductive): never both, each at most once (`claims`/`refunds` are tied to the
  terminal states by the invariant).
- Why, from the proven window functions: `claim_window` accepts only Locked/Ready, `refund_window`
  only Aborted/Locked/Ready (`eq_windows` pins both to the original); success writes Claimed or
  Refunded; no instruction leaves those states except `close`, which deletes the account (a later
  lock at the same address is a new swap). At one instant the conditions are disjoint: Locked/Ready
  claim needs `t < t1`, Locked/Ready refund needs `t >= t1`, Aborted is refund-only. This does not
  depend on the clock being monotonic.

**P3. Refund only after abort or timeout; claim only within its window.**
- Proven per instruction (`eq_windows`, `eq_abort` fix the window functions to the original code).
- Lifecycle (proven, inductive): every claim has `t < t1` and (`t >= t0`, or state Ready, which only the locker
  can set and only before `t0`); every refund has state Aborted or `t >= t1`; every abort was by the
  claimer before `t1`, or by the locker or a listed non-default watchtower while Locked and before `t0`.

**P4. Fee + payout + refund equal the locked amount; no lamport created or lost; no overflow.**
- `p4_split_fee_conserves_any_bps` (proven): for every amount and every u16 fee, a successful split has
  `payout + fee == amount`; it never panics.
- `p4_pay_conserves` (proven): `pay` moves exactly `x` and never wraps.
- `p4_config_bounds_fee_and_windows` (proven): any parameters accepted by init/update give fee
  <= 100 bps, `1 <= min_t0 <= max_t0 <= 30 d`, `1 <= min_window <= max_window <= 30 d`, and
  deadlines that cannot overflow for any clock below `i64::MAX - 60 days`.
- `sm_inv_step_money` (proven, inductive): in every reachable state, every instruction leaves the
  four parties' total lamports unchanged; claims and refunds move exactly `amount`.
- **Tested, not proven:** the fee's exact value `floor(amount * bps / 10_000)` and the bounds "never
  fails, at most 1%" for stored fees (<= 100 bps). These are elementary consequences of floor
  division (`floor(a*b/10^4) <= a*100/10^4 = a/100 <= a`), checked on an edge grid (including
  `u64::MAX`), 20,000 random inputs by default (50,000 in the release run), and in every proptest
  lifecycle step. Kani does not finish
  them: proving facts through a 128-bit divider or a symbolic 64x16 multiplier is beyond SAT here.
  In the lifecycle harnesses the divider is replaced by the definition of unsigned division (the
  unique `q` with `q*10^4 <= a*b < q*10^4 + 10^4`), which is exact Rust semantics, not an
  approximation. Kani's Bitwuzla (SMT) backend was also tried: it reported a false counterexample on
  this true property (amount 8192, bps 64; concrete replay shows it holds), so no result from it is
  counted.
- Counters (proven, inductive): if the maker's and global open counters equal the contribution of
  all unreleased escrows, a lock adds exactly the new one's and a release removes exactly its own,
  never failing; a second release is a no-op. Only `open_counters` and `release` write these fields
  (inspection), new accounts start at zero and amounts never change, so `release` can never underflow
  and block an abort, claim, expire or refund, for any number of escrows in any order.

**P5. No lock against a maker without the maker's signed consent over the exact terms.**
- `p5_lock_needs_maker` (proven): every lock that passes the terms check is SOL->XMR with the maker as
  claimer (the handler then requires the precompile consent) or XMR->SOL with the maker as the
  signing locker.
- `p5_consent_message_injective` (proven): the consent message is a fixed 317-byte encoding, so equal
  messages imply equal program id, escrow address, locker, claimer, direction, both amounts, all three
  points, quote hash, t0, window, expiry and fee.
- `p5_ed25519_binds_signer_and_message` (bounded: data <= 160 bytes): whenever the program accepts the
  previous instruction, the precompile, reading the same bytes by its documented layout, checks
  exactly one signature, by the maker's key, over exactly the 32-byte digest, all inside that
  instruction.
- `p5_watchtower_power_within_locker` (proven): watchtowers are not in the consent; safe, because a
  watchtower can abort only when the locker could.
- Assumed: sha256 collision resistance, ed25519 unforgeability, the precompile verifying what its
  layout says, and (inspection) `lock` hashing the same values it stores. The e2e suite covers
  missing consent, wrong signer, changed terms, an instruction in between, expiry and replay on
  another swap id.

**P6. Pause blocks only new locks, never exits.**
- `p6_pause_blocks_locks` (proven): paused => `check_lock_terms` returns `Paused`.
- `p6_release_ignores_pause` (proven): the exit decision functions (`ready_window`, `abort_check`,
  `claim_window`, `refund_window`, `expire_window`, `close_allowed`, `check_reveal_with`,
  `split_fee`, `pay_amounts`) take no config at all, so they cannot read the flag (the compiler
  enforces this); `release`, the only exit-path function that touches the config, gives the same
  result and effects with the flag on and off, for all inputs.
- Tripwire (`fuzz::paused_read_sites_unchanged`): in the handlers the flag is read only by
  `register_maker` and `update_maker` (re-activation), and in `logic` only by `check_lock_terms`.
- The inductive step harnesses run with the flag arbitrary, and a cover shows a refund succeeding
  while paused. The proptest walks compare every step with the flag on and off. e2e: a refund
  succeeds while paused.
- Tried and dropped: a direct two-copy comparison of every instruction from any state
  (`p6_exits_ignore_pause`) was stopped unfinished after 13 minutes (two full copies of a step
  in one SAT instance); the decomposition above covers the same property cheaply.

**P7. The scalar check rejects `s + L` aliases; the point check rejects torsioned and identity points.**
- `p7_canonical_iff_less_than_l` (proven, all 2^256 inputs): `scalar_is_canonical(s) <=> s < L`.
- `p7_aliases_rejected` (proven): `s + k*L` is rejected for every s and every k >= 1 that fits in 256
  bits, so each residue mod L has exactly one accepted encoding.
- `p7_check_reveal_sound` (proven): a reveal passes only if the scalar is canonical and the syscall
  returned exactly the committed point; for a non-canonical scalar the syscall is never called.
- Point check (`point_is_prime_order`): **tested, not proven** (curve arithmetic is out of reach of a
  bit-level model checker). On the host build of `solana-curve25519` 3.1.14, which is the code
  Agave's curve syscalls run: all 8 small-order points rejected; random `s*G` accepted and
  `s*G + T` rejected for each of the 7 non-zero torsion points (proptest); all 40 non-canonical
  32-byte encodings checked exhaustively, which found BUG-1. e2e covers identity, torsioned,
  small-order, off-curve, claim == refund, and BUG-1, on the real validator.

## 4. Run results

Machine: Apple Silicon, 10 cores, shared with other workloads (load average 15-70 during runs, so
times are pessimistic).

**Kani: one run of every harness** (`cargo kani --features no-entrypoint -Z stubbing`):
`Complete - 28 successfully verified harnesses, 0 failures, 28 total.` (439 s wall clock)

| Harness | Property | Result | Time | Covers |
|---|---|---|---|---|
| eq_abort | refactor equivalence | verified | 1.8 s | - |
| eq_check_reveal | refactor equivalence | verified | 1.3 s | - |
| eq_deadlines | refactor equivalence | verified | 0.2 s | - |
| eq_ed25519 | refactor equivalence (data <= 160 B) | verified | 168.5 s | - |
| eq_fee_bps | refactor equivalence | verified | 0.2 s | - |
| eq_lock_terms | refactor equivalence | verified | 1.5 s | - |
| eq_open_counters_and_release | refactor equivalence | verified | 1.4 s | - |
| eq_pay | refactor equivalence | verified | 0.2 s | - |
| eq_scalar_is_canonical | refactor equivalence | verified | 1.0 s | - |
| eq_watchtowers | refactor equivalence | verified | 0.6 s | - |
| eq_windows | refactor equivalence (ready/claim/refund/expire/close) | verified | 0.6 s | - |
| p4_config_bounds_fee_and_windows | P4 config bounds | verified | 2.1 s | - |
| p4_pay_conserves | P4 | verified | 0.2 s | - |
| p4_split_fee_conserves_any_bps | P4 | verified | 0.1 s | - |
| p5_consent_message_injective | P5 | verified | 7.8 s | - |
| p5_ed25519_binds_signer_and_message | P5 (data <= 160 B) | verified | 89.5 s | - |
| p5_lock_needs_maker | P5 | verified | 0.5 s | - |
| p5_watchtower_power_within_locker | P5 | verified | 1.3 s | - |
| p6_pause_blocks_locks | P6 | verified | 0.1 s | - |
| p6_release_ignores_pause | P6 | verified | 0.8 s | - |
| p7_aliases_rejected | P7a | verified | 1.2 s | - |
| p7_canonical_iff_less_than_l | P7a | verified | 0.5 s | - |
| p7_check_reveal_sound | P7a / P1 | verified | 1.3 s | - |
| sm_inv_base | P1-P4 base case | verified | 4.1 s | 1 of 1 covers |
| sm_inv_step_money | P1, P4 inductive step | verified | 112.2 s | 9 of 9 covers |
| sm_inv_step_state | P1, P2, P3 inductive step | verified | 25.5 s | 9 of 9 covers |
| sm_lock_inductive | counters | verified | 0.8 s | - |
| sm_release_inductive | counters | verified | 0.5 s | - |

**Host tests** (`cargo test --features no-entrypoint`): 15 pass, plus the ignored BUG-1 test,
which fails as expected (`-- --ignored`). They cover: the proptest lifecycle walks (40-instruction
runs with the real curve code, and near-arbitrary configs with an arbitrary `s*G` result; both
check every step's properties and the invariant), points and scalars on the real curve code
(small-order, torsion, all 40 non-canonical encodings, aliases), the fee differential tests, and
the debit-site and pause-read tripwires. Release run with `PROPTEST_CASES=50000`: all 15 pass
(31 s). On `formal-fix`: 16 pass (BUG-1 included).

**e2e** (`e2e/program.test.ts`, local `solana-test-validator`, fresh ledger per run):

| Build | Result |
|---|---|
| `formal` (refactor) | 26/26 pass; BUG-1 test (`todo`) reports red as intended |
| baseline d00f39f (pre-refactor) | 26/26 pass; same BUG-1 `todo` result |
| `formal-fix` | 27/27 pass, including BUG-1; `lock` 26,689 CU vs 23,638 (+3,051 for three extra syscalls) |

Under heavy load two earlier `formal` runs each had one failure in a test that allows only 1-2
seconds before a deadline (`expire ... TooEarly`, then `auto-claim ... TooEarly`: the transaction
landed after the deadline). Each passed in the other runs and in the clean run above, and Kani
proves the window functions equal to the original, so these are test-timing flakes (O6).

## 4b. Platform instructions (integrate branch)

The platform branch (OTC tranches, pay links, cashout vaults) was merged on top of this
extraction. Its new rules were moved into `logic.rs` the same way and are covered as follows.

**Equivalence to the platform branch's inline code** (`orig_platform` in `proofs.rs` is a
verbatim copy of `git 3f2d99e`; `check_lock_terms` etc. with `flags == 0` are still proven equal
to the phase-1 code): `eq_lock_terms_platform` (terms incl. flags, maker extension, OTC range and
cap; `pay_shape`), `eq_watchtowers` (pay: >= 1 watchtower, locker not one), `eq_windows`
(ready/close with flags), `eq_abort_platform` (pay-mode locker cannot abort; reputation outcome),
`eq_ext_count`, `eq_refund_secret_and_close_pay`, `eq_platform_params` (set_config_ext,
upgrade_maker range, link names, vault params), `eq_vault_timelock` (propose/apply/cancel/tighten),
`eq_vault_money` (vault_lock terms, conversion bookkeeping, funding, withdraw request/withdraw).

**Properties:** `p5_consent_message_v2_injective` (414-byte v2 consent binds flags, link and both
watchtowers; distinct prefix from v1), `p8_pay_payer_powerless` (no ready, no abort, refund
reveals nothing and never touches the curve), `p8_lock_shape`, `p8_close_pay_grace`,
`p8_vault_tighten_only_tightens`, `p8_vault_timelock`, `p8_vault_money_bounds` (rate floor exact
in 128 bits, rent reserve kept, withdraw <= request and <= free), `p8_ext_count_scoped`
(reputation touches only the extension). The lifecycle model (`model.rs`) now takes flags: pay
escrows are in `sm_inv_base` / `sm_inv_step_*` (no ready, abort only by claimer or watchtower,
zero-secret refund, `close_pay` grace), with covers for each pay exit.

**Not covered by Kani** (tested by `e2e/platform.test.ts` on a local validator instead): the
pay-link key derivation `derive_pay` (sha256 + curve syscalls), the link / vault account loading
and PDA checks, the vault-funded escrow creation (allocate/assign CPIs, then `pay`), the maker
account resize in `upgrade_maker`, and the vault's own lamport balance across conversions (the
model tracks one escrow; vault funding and withdraw are proven per call, not as a ledger).

**Run** (`cargo kani --features no-entrypoint -Z stubbing`, Apple Silicon, shared machine):
`Complete - 43 successfully verified harnesses, 0 failures, 43 total.` (11 min 20 s wall clock;
`sm_inv_step_money` 177 s, `eq_ed25519` 155 s, `p5_ed25519_binds_signer_and_message` 81 s,
`eq_vault_money` 67 s; all covers satisfied, 13/13 per step harness, 2/2 base). Host tests: 17
pass (the unconstrained lifecycle walk now draws flags, OTC caps and v2 makers);
`PROPTEST_CASES=5000 --release`: 17 pass.

## 4c. v1.5: payment proofs, the claim rule, the burn auction, staking

New code: `program/src/xmr.rs` (Monero verifier), `zkproof.rs` (committee, headers, `prove_lock`,
claim gate), `burn.rs`, `rewards.rs`. Harnesses in `program/src/proofs_v15.rs`; the lifecycle model
(`model.rs`) gained the claim gate, so `sm_inv_base` / `sm_inv_step_*` now cover it.

| Property | Status | How |
|---|---|---|
| **P10 claim rule:** every SOL->XMR claim (and a proof-mode XMR->SOL claim) without the locker's Ready happens only with a proof record of THIS escrow instance (same address and lock time) for >= its XMR amount; otherwise `NotProven` | **proven** (all inputs) + in every reachable state of the lifecycle model | `p10_claim_gate_binds_escrow_and_amount`, `sm_inv_step_state` (P10 assertion in `model::check_state`) |
| The statement a proof is checked against comes only from the escrow (spend key = claim + refund point, view key, minimum, message) | **proven** | `p10_statement_from_escrow` |
| For ANY curve/hash behaviour, the output check accepts only if the curve confirmed `s*G + B == P` for the escrow's B and `y*G + a*H == C` for the returned amount a, and a >= the minimum | **proven** (curve and keccak replaced by an arbitrary recording stub) | `p10_output_check_binds_key_and_amount` |
| prove_lock only on an open proof-gated escrow before t1; the header must be current-epoch, same network, deep enough, and the very block the proof folded to | **proven** | `p10_prove_window_and_header` |
| Committee rules (1 <= k <= n, distinct non-zero keys, known net, >= 10 conf) | **tested** (did not finish in Kani within 600 s; opt-in harness) | `fuzz_v15::attestation_rules`, e2e `set_attesters`; `p10_attester_set_rules` behind `--cfg kani_slow` |
| The attestation parser counts only distinct listed keys signing exactly the header message, all inline | **bounded-proven once** (instruction data <= 52 bytes, 2,250 s), excluded from the routine run; **tested** | `p10_attestation_counts_only_listed_signers` (`--cfg kani_slow`), `fuzz_v15::attestation_rules`, `fuzz_v15::attestation_parser_never_panics`, e2e `attest_header` |
| The proof flag changes lock acceptance only by needing the maker extension | **proven** | `eq_lock_terms_proof` |
| **P9 burn:** for ANY price curve and cost rounding a take moves 0 < lot <= min(max_lot, pot), never the rent reserve, within the buyer's bounds; the take (burn from the signer, pay the signer) conserves lamports and pays only the burner; sweep_fees refuses once the auction is on; price within [floor, start] | **proven** | `p9_take_bounded`, `p9_take_pays_only_the_burner`, `p9_sweep_blocked_once_burning`, `p9_price_bounds` |
| The restart price follows `price * (1 + lot/max_lot)`: >= the price and the floor, <= twice the price, exactly twice for a full lot; counters grow by exactly the take | **tested** (128-bit divider by a symbolic `max_lot`; did not finish within 600 s even bounded; opt-in harness) | `fuzz_v15::burn_take_bounds` (512 cases), e2e `burn_take`; `p9_after_take_restarts_higher` behind `--cfg kani_slow` |
| **P11 staking:** one staker's actions never change another's record or the accumulator; stake and unstake move earned rewards into `owed` exactly; the 50/50 split is exact (stakers floor(u/2), the odd lamport to the burn); loose pool SOL never dips into what is owed | **proven** (accumulator scale 2^8 with 12-24-bit values, same generic code; the program runs 2^64; split and pool-extra for all inputs) | `p11_one_staker_cannot_touch_another`, `p11_stake_unstake_conserve_rewards`, `p11_split_exact`, `p11_pool_extra_never_touches_owed` |
| **P11, total claimed <= total credited** (inductive invariant I* over stake / unstake / claim by two stakers) | **bounded-proven once** (427 s alone), opt-in because it exceeds the 600 s budget under load; **tested** at full 2^64 scale | `p11_claims_never_exceed_credits` (`--cfg kani_slow`), `fuzz_v15::rewards_random_walk` (asserts claimed + owed + pending <= credited after every step, 2,000 runs), e2e staking (pool solvency) |
| **P11, credit step:** crediting x keeps I* (`total * floor(x*2^S/total) <= x*2^S`) | **tested, NOT proven by Kani.** The step has a 128-bit divider by a symbolic total; CBMC did not finish it in ~10 hours even at scale 2^4 with 5-10-bit values, so the harness was dropped | `fuzz_v15::credit_keeps_claims_within_credits` (proptest, real 2^64 scale), `fuzz_v15::rewards_random_walk` (2,000 runs over 4 stakers), staking e2e tests (`e2e/zk.test.ts`: pro-rata claims, deposits, solvency of the pool) |

**Tested, not proven** (`program/src/fuzz_v15.rs`, host build of the same curve/keccak code the
syscalls run): the verifier on 4 synthetic-but-real-format vectors (a real stagenet tx re-keyed to
the escrow) and on the **live stagenet wallet proof** (a real wallet tx + `get_tx_proof` OutProofV2
+ real block); every rejection case (amount, other escrow, other key, kind, non-canonical c, other
output, branch side/level, header, ntx, prunable hash, time lock, forged amount vs commitment); any
single-bit flip anywhere in the tx bytes (512 random cases); the parser on random bytes and
truncations; `sc_reduce32` and the canonical check against curve25519-dalek (512 random cases);
the burn price monotone and the take bounds (512 cases each); the rewards random walk with real
2^64 arithmetic over 4 stakers (2,000 runs, up to 60 operations); layouts; and a tripwire listing
every lamport debit site in the v1.5 modules (`burn_take:pay`, `sync:pay` x2, `pool_claim:pay`).

**Not covered by Kani** (tested on a local validator, `e2e/zk.test.ts`): account plumbing for the
new instructions (PDAs, owners, the Ed25519 precompile instruction lookup, the fee-vault resize,
token CPIs and the supply-drop check), and Monero chain canonicality (the committee's job).

## 4d. v1.5 run (Kani 0.68, Apple Silicon, shared machine)

Every harness now runs with a per-harness limit: `cargo kani --features no-entrypoint -Z stubbing
-Z unstable-options --harness-timeout 600` (and an outer wall-clock guard). A first, unlimited run
left one harness in CBMC for about 10 hours: the staking credit step (`p11_credit_...`, a 128-bit
divider by a symbolic total). It was dropped from Kani and is covered by proptest and e2e instead
(table above).

- Phase-1 + platform harnesses: **43/43 verified** on the v1.5 source (2,988 s of solver time in
  total; the run's raw log was not kept).
- v1.5 routine harnesses: **13/13 verified** (slowest `p10_output_check_binds_key_and_amount`
  32 s alone, all others under 11 s).
- Opt-in slow harnesses (`RUSTFLAGS="--cfg kani_slow"`): `p11_claims_never_exceed_credits`
  (verified once, 427 s alone; timed out at 600 s in a batch), `p10_attestation_counts_only_listed_signers`
  (verified once, 2,250 s), `p10_attester_set_rules` and `p9_after_take_restarts_higher` (did not
  finish within 600 s). Dropped entirely: the staking credit step (did not finish in ~10 h). All of
  these properties are tested (proptest at full scale + e2e), as listed above.
- Routine total on the `zk` branch: **56 harnesses (43 + 13), all verified, none over 600 s.**
- Host tests (`cargo test --features no-entrypoint`): 37 pass, including the live stagenet wallet proof.


## 4e. Merged run (`integrate2`: v1.5 + the HTLC kind + any-coin, after the integration review)

`cargo kani --features no-entrypoint -Z stubbing -Z unstable-options --harness-timeout 600 -j 3`,
under an outer wall-clock guard that kills the whole cargo-kani process tree (not only CBMC):
**`Complete - 66 successfully verified harnesses, 0 failures, 66 total.`** (43 phase-1/platform +
13 v1.5 + 10 HTLC; about 18 min wall clock, 3,152 s of solver time over 3 jobs on a shared machine
with the validator suite running; slowest harness 545 s, none hit the 600 s limit). The four
`kani_slow` harnesses were not re-run. One spec change: `p10_claim_gate_binds_escrow_and_amount`
now states the gate per XMR direction (SOL->XMR always, XMR->SOL with `F_PROOF`, never the HTLC
directions 4/8) and asserts it equals `zkproof::proof_gated`; the old spec expected a gate for
directions other than 1/2 when `F_PROOF` was set, which no XMR escrow can have
(`htlc_kinds_disjoint`). Host tests: 48 (`PROPTEST_CASES=5000 --release`: 48), including
`htlc_fuzz::kinds_stay_apart_under_v15`, `fuzz_v15::legacy_pending_unstake_enrolls` and
`fuzz_v15::proof_record_bound_to_terms`.

## 5. Findings

### BUG-1 (low): non-canonical encodings of the identity pass the on-chain point check

`point_is_prime_order` rejects the identity by comparing the input with the canonical bytes
`01 00 .. 00`, then checks `(L-1)*P + P == O`. The curve syscalls decode non-canonical encodings
(dalek reduces `y` mod p and accepts a set sign bit on `x = 0`) and return canonical results, so
three byte strings that encode the identity pass every step:

```
01 00 00 .. 00 80   (x = -0, y = 1)
ee ff ff .. ff 7f   (y = p + 1)
ee ff ff .. ff ff   (y = p + 1, sign bit set)
```

Found by the exhaustive pass over all 40 non-canonical encodings (`fuzz::noncanonical_encodings_audit`;
no non-identity point gets through). Reproduced on the local validator: `lock` accepts each of the
three as claim, refund or view point (9 of 9 cases).

- **Failing tests**: `fuzz::bug1_noncanonical_encodings_rejected` (`#[ignore]` on `formal`; run with
  `cargo test --features no-entrypoint -- --ignored`) and the e2e test `lock: rejects non-canonical
  encodings of the identity (BUG-1)` (node `todo` on `formal`: it runs and reports red without failing
  the suite).
- **Impact: no theft.** `s*G` from the syscall is always canonical, so no secret ever matches such a
  point (`fuzz::noncanonical_point_never_revealable`): a claim against it can never succeed (the
  locker refunds after t1), and a refund against it can never succeed (that escrow's SOL is stuck for
  good). Only the party whose key it is can put it there (its own key in the handshake; in SOL->XMR
  the maker also signs the consent over both points), so it is self-harm, or griefing of a
  counterparty whose client relies on the on-chain check instead of validating keys. The reference
  clients do validate: `sdk/keys.ts::isGoodPoint` rejects non-canonical encodings, the taker checks
  the maker's key and the maker daemon compares escrow bytes. It does contradict the README's
  "rejects torsion/identity points on chain".
- **Proposed fix** (branch `formal-fix`, one commit on top of `formal`, not merged): also require the
  canonical re-encoding, `add_edwards(P, O) == P` byte for byte. One extra syscall per point. With it
  the ignored test and the e2e test pass and nothing else changes. A zero-syscall variant exists
  (compare `(L-1)*P` with `P` with its sign bit flipped, after rejecting `(L-1)*P == O`) but is
  harder to review.

### Observations (not bugs)

- **O1. Out-of-date comment.** `scalar_is_canonical` says the syscall reduces scalars mod L. In
  `solana-curve25519` 3.1.14, `multiply_edwards` uses `Scalar::from_canonical_bytes` and returns an
  error for non-canonical scalars. Harmless: the program's own check, proven here, runs first; the
  syscall is a second layer.
- **O2. Consent is single-use per live escrow, not globally.** The consent binds the escrow address,
  and `close` frees that address. Until the consent expires (90 s in the reference daemon), a locker
  who settled and closed could lock the same address again with the same signed consent. The
  reference daemon journals the escrow as done and would not deliver XMR twice; third-party makers
  must not either.
- **O3. Claim statistics are checked arithmetic.** `claim` adds to `maker.volume`,
  `config.total_volume` and `total_fees` with overflow checks, so claims would fail (not wrap) once
  cumulative volume passed u64::MAX lamports (about 18.4 billion SOL). Unreachable in practice; refunds
  do not touch these counters.
- **O4. Dust claims into a fresh wallet.** Nothing requires `amount - fee` to reach the rent-exempt
  minimum (about 0.00089 SOL). A claim paying less than that into an empty wallet passes the program
  and then fails the runtime's rent check, and that failed transaction still puts the secret on
  chain. Makers' `min` (0.05 SOL in the README) keeps real swaps far above it and clients simulate
  first. If tiny swaps are ever allowed, put a floor on `min` in `check_maker_params`.
- **O5. Watchtowers are not in the consent.** Safe: a watchtower's abort power is proven to be a
  subset of the locker's (`p5_watchtower_power_within_locker`).
- **O6. e2e timing.** A few tests allow only 1-2 seconds before a deadline and fail when the machine
  is heavily loaded. Not a program issue; longer windows in those tests would remove the flake.

## 6. Trusted assumptions and what is not covered

- **A1 Solana runtime**: transactions are atomic and serialized on writable accounts; only the owning
  program can debit or write its accounts; signer flags are correct; `Clock`/`Rent` are correct; PDAs
  cannot be forged (sha256).
- **A2 Syscalls and precompiles**: the curve25519 syscalls compute what `solana-curve25519` 3.1.14
  computes on the host (decompression, `s*P` for canonical `s`, canonical output); the ed25519
  precompile verifies the signature its data layout describes; the instructions sysvar is accurate.
- **A3 Clock**: `unix_timestamp` never decreases (Agave clamps the stake-weighted estimate to the
  parent bank's timestamp). The inductive step assumes it (the next instruction's clock is at least
  the last one's); the per-instruction window rules and P2's disjointness argument do not.
- **A4 Cryptography**: sha256 collision resistance, ed25519 unforgeability, discrete-log hardness.
- **A5 Toolchain**: rustc and the SBF toolchain compile the verified Rust faithfully; Kani verifies the
  host build (64-bit, same integer semantics as SBF). Rust's unsigned `/` is floor division (used by
  the division stub).
- **Not modelled**: account plumbing (owner, PDA, discriminator, writable checks), `create_pda`, CPIs,
  the maker registry and the $HALFKEY stake/unstake token flows. Covered by the e2e suite and
  inspection, not by Kani. A LiteSVM or Trident harness that fuzzes whole transactions would close
  this gap.
- **Model fidelity**: the lifecycle proofs are about `model.rs`, which calls the same `logic`
  functions as the handlers but re-states each handler's sequence (a dozen lines per instruction,
  reviewed against `lib.rs`). A divergence between the model's sequence and a handler would not be
  caught by Kani; the e2e suite exercises the real handlers.
- **Bounds**: the only bounded results are the precompile-data harnesses (instruction data <= 160
  bytes; real consents are 144). Everything else holds for all inputs.
- **Out of scope**: the Monero side, SDK, maker daemon, watchtower and key derivation. The program has
  not been audited.

## 7. Re-running

```sh
# Kani (one-time: ~350 MB bundle + a nightly toolchain under ~/.rustup)
cargo install --locked kani-verifier --version 0.68.0 && cargo kani setup

cd program
# every harness (stubbing is needed by the lifecycle and fee harnesses)
cargo kani --features no-entrypoint -Z stubbing
# one harness
cargo kani --features no-entrypoint -Z stubbing --exact --harness proofs::sm_inv_step_state

# host tests: unit, curve, proptest lifecycle walk, fee differential, tripwire
cargo test --features no-entrypoint
PROPTEST_CASES=5000 cargo test --release --features no-entrypoint
cargo test --features no-entrypoint -- --ignored      # BUG-1 test (fails on `formal`)

# local-validator suite, from the repo root
npm run build:program
sh e2e/validator.sh &         # RPC_PORT / FAUCET_PORT / GOSSIP_PORT / LEDGER to run beside another
RPC_URL=http://127.0.0.1:8899 npm run test:program
```

Files: `program/src/logic.rs` (extracted logic), `program/src/proofs.rs` (Kani harnesses, `cfg(kani)`),
`program/src/model.rs` (lifecycle model, `cfg(kani|test)`), `program/src/fuzz.rs` (tests, `cfg(test)`).
None of the verification code is compiled into the deployed program.

## HTLC kind (SOL <-> ZEC), added on branch `zec`

`program/src/htlc_proofs.rs`, 10 harnesses over the HTLC section of `logic.rs` and the lifecycle
model `htlc_model.rs` (same structure as `model.rs`: the handlers' sequence of `logic` calls, four
parties' lamports, ghost history). sha256 is an arbitrary function result; the fee divider uses
the same `spec_bps_of` stub.

| Property | Harness |
|---|---|
| H1 no claim without the preimage (claimer-signed, Locked, before t1; claimer + fee vault get exactly the amount) | `htlc_claim_needs_preimage`, `htlc_inv_step_state`, `htlc_inv_step_money` |
| H2 refund only to the locker, only from t1 or after the claimer's own abort; abort is claimer-only | `htlc_refund_only_after_timeout_or_claimer_abort`, `htlc_inv_step_*` |
| H3 no double spend: claim/refund windows disjoint, `claims + refunds <= 1`, settled states terminal, lamports conserved | `htlc_claim_refund_exclusive`, `htlc_inv_step_*` |
| Inductive invariant established by every lock | `htlc_inv_base` |
| Counters: a lock adds exactly its share within the caps; release never underflows and is idempotent | `htlc_lock_inductive`, `htlc_release_inductive` |
| The XMR lock check rejects directions 4/8; the HTLC lock check accepts only them, with the maker in the right role | `htlc_kinds_disjoint` |
| HTLC consent: fixed 250-byte injective encoding, never equal to an XMR consent | `htlc_consent_message_injective` |

Run (`cargo kani --features no-entrypoint -Z stubbing`, Apple Silicon, shared machine):
`Complete - 53 successfully verified harnesses, 0 failures, 53 total.` (12 min 14 s wall clock;
the 10 HTLC harnesses alone: 3 min 20 s). All cover properties satisfied.
