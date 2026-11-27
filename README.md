# HALFKEY

Atomic swaps between Solana and Monero: no pool, no wrapped token, no custodian. Capped beta.

You hold half of the key. The maker holds the other half. Either both sides of a swap complete, or both sides are refunded.

This repository contains the HALFKEY Solana program, the TypeScript SDK that clients use to talk to it, the maker daemon, and the watchtower and refund-tower services.

| Route | How it settles | Status |
|---|---|---|
| SOL ↔ XMR | Split-key atomic swap (below) | Capped beta |
| Solana token → XMR | Routed through Jupiter into the same SOL lock, in one signature | In the program and SDK |
| SOL ↔ ZEC | Hash-time-locked contract on both chains | Coming soon |

---

## Verified build

| | |
|---|---|
| Program source | `program/` |
| Executable hash | `904c57ec3e6660bba2b00758c5458d9687c6186a01e15be0fe2330d71c2a47c8` |
| Build image | `solanafoundation/solana-verifiable-build@sha256:6468b89ae21d87b8eb002f894ac3f3442dbd8bcf5ea93414051e96e00d03b5ab` (Solana 4.1.0) |
| Tool | `solana-verify 0.5.2` |

Anyone can rebuild the program from this repository and get the same hash. You need Docker and [solana-verify](https://github.com/Ellipsis-Labs/solana-verifiable-build):

```sh
cargo install solana-verify --version 0.5.2 --locked
git clone https://github.com/halfkey-labs/halfkey && cd halfkey/program
solana-verify build --library-name halfkey \
  --base-image solanafoundation/solana-verifiable-build@sha256:6468b89ae21d87b8eb002f894ac3f3442dbd8bcf5ea93414051e96e00d03b5ab
solana-verify get-executable-hash target/deploy/halfkey.so
# 904c57ec3e6660bba2b00758c5458d9687c6186a01e15be0fe2330d71c2a47c8
```

To check a deployed program against this source, compare its on-chain hash with the one above:

```sh
solana-verify get-program-hash -u https://api.mainnet-beta.solana.com <program id>
```

## How a swap works

### SOL → XMR

1. **Lock.** You lock SOL in a HALFKEY escrow. The coins sit in the program, not with the maker.
2. **Pay.** The maker sends XMR to a Monero address that neither side can spend alone: its spend key is the sum of your key half and the maker's key half.
3. **Verify.** Your client checks the Monero payment with the address's view key: the amount, and that no time lock was added.
4. **Release.** You send `ready`. To claim the SOL, the maker must publish its key half on Solana. That same transaction completes your key, so the XMR is now yours alone.
5. **Refund.** If the maker never pays, the escrow's timelock expires and your SOL returns to you.

### XMR → SOL

1. **Lock.** The maker locks SOL in an escrow bound to this swap.
2. **Deposit.** You send XMR to the joint address shown by your client. The client only shows it once the refund towers (below) have confirmed they hold their pieces.
3. **Claim.** After the maker confirms your deposit, you claim the SOL. Claiming reveals your key half, which lets the maker sweep the XMR.
4. **Refund.** If the maker disappears after your deposit, the refund towers release the maker's key half to you after the deadline, and your client sweeps the XMR back.

## Security model

| Property | How it is enforced |
|---|---|
| No custody | Funds are either in the program's escrow (Solana) or at an address that needs both key halves (Monero). |
| Atomic release | The program only releases SOL to the maker when the key-half reveal checks out on chain (an ed25519 point check against the committed public key). |
| Timeouts | Every escrow carries a deadline. Claims, refunds and expiry can never be paused. |
| Maker disappears (XMR → SOL) | The maker splits its key half into three pieces held by refund towers. Any two rebuild it, and only after the deadline, when two Solana readers agree the escrow was not claimed. |
| Caps | Per-swap and total-open limits live in the program config and are checked on every lock. |
| Fees | Set in the config, capped in the program at 1% (`MAX_FEE_BPS`). |
| Admin powers | The config admin can pause *new* locks and maker registrations, change fees within the cap, change caps and windows, and hand the role over. It cannot touch funds in an escrow, and it cannot block claims or refunds. |
| Payment proofs | Optional per swap and off by default: the program can verify a Monero payment proof on chain against attested block headers. See [docs/PAYMENT-PROOFS.md](docs/PAYMENT-PROOFS.md). |

The escrow decision and accounting logic is model-checked with [Kani](https://model-checking.github.io/kani/). What is covered, and what is not, is in [docs/FORMAL-VERIFICATION.md](docs/FORMAL-VERIFICATION.md).

## $HALFKEY

Every claim pays a protocol fee (0.5%, or 0.25% for a bonded maker) into a fee vault owned by the program. Once the burn auction is switched on, the split is on chain and keyless:

```
claim fee -> fee vault --split_fees--> 50% stake pool (SOL rewards for $HALFKEY stakers)
                                    \-> 50% burn pot  (auctioned for $HALFKEY, which is burned)
```

Stake $HALFKEY to earn SOL from swaps; maker bonds count as stake. Details: [docs/FEES-AND-STAKING.md](docs/FEES-AND-STAKING.md).

## Repository layout

```
program/         Solana program (Rust): escrows, claims, refunds, payment proofs, maker registry, staking
sdk/             TypeScript SDK: key derivation, instruction builders, swap flows, proofs, discovery
maker/           Maker daemon: quotes, locks, Monero wallet handling, inventory (Docker setup included)
watchtower/      Watchtower and refund-tower services
zecwasm/         Zcash client primitives (WebAssembly) used by the SDK's Zcash route
e2e/             Local-validator suites and the fixtures the program and SDK tests read
web/src/client/  env.ts only: the browser client's on-chain reads (checked by the program's id test)
docs/            Protocol and design notes
```

## Build

Requirements: Rust (stable), the Solana toolchain with `cargo build-sbf`, Node.js 22.18 or later. Docker for the verified build.

```sh
npm ci
npm run build:verified       # Docker build: program/target/deploy/halfkey.so (the hash above)
npm run build:program        # local build into target/deploy/ (hash depends on your toolchain)
npm run build:zecwasm        # rebuilds zecwasm/pkg (needs wasm32-unknown-unknown, wasm-bindgen-cli 0.2.100, llvm-tools)
```

## Test

```sh
npm test                     # SDK, maker and watchtower unit tests (offline)
npm run test:program         # program host tests, including the Kani-checked logic in test mode
```

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## License

Business Source License 1.1. See [LICENSE](LICENSE). Production use requires a license from HALFKEY Labs until the Change Date, after which the code is available under the Apache License 2.0.
