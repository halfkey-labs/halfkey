# Stealth Solana addresses (XMR → SOL to a fresh address)

The SOL from an XMR → SOL swap lands at a one-time Solana address. Only the user can find it and spend it, and nothing on chain links it to the user's wallet. Code: `sdk/stealth.ts`. UI: `web/src/client/stealth.ts`. No program change.

## Keys

| | How it is derived |
|---|---|
| Wallet root | `root = SHA-512(wallet signature over KEY_MESSAGE)`, the same root as the swap halves |
| View scalar | `v = H("halfkey/stealth/view/v1" ‖ root ‖ account)`, with `V = v·G`. It can find outputs and can't spend them. |
| Spend scalar | `s = H("halfkey/stealth/spend/v1" ‖ root ‖ account)`, with `S = s·G` |
| Meta address | `hks1` + base58(version ‖ V ‖ S ‖ checksum). Only needed by third-party payers (pay links). |
| One-time address | The payer picks a fresh `r` and computes `R = r·G`, then `P = H_s("halfkey-stealth-v1" ‖ 8·r·V ‖ i)·G + S` |
| Find (view key) | `P == H_s(… ‖ 8·v·R ‖ i)·G + S` |
| Spend | `s_i = H_s(… ‖ 8·v·R ‖ i) + s mod L`, where `s_i·G == P` |

`H` and `H_s` are SHA-512 reduced mod L. Every point is checked: canonical encoding, not the identity, prime order. Cofactor clearing (`8·`) makes the payer and the receiver agree even if a point carried torsion.

## Where R lives

`R` is the escrow's `swap_id`, which is the PDA seed and is stored in the escrow, so a scan needs nothing extra:
- **Scan:** fetch every XMR → SOL escrow with `getProgramAccounts` (memcmp on direction, `dataSlice` of 144 of the 448 bytes). Every user runs the same query, so the RPC learns nothing. Then compare `claimer` with the one-time key recomputed from `swap_id`.
- **After the maker closes the escrow:** the lock instruction in the program's transaction history still carries `swap_id` and `claimer`. `scanLockHistory` parses top-level instructions and CPIs, including v0 loaded addresses. The browser also keeps a local list of its own stealth swaps (public data only).

## Who picks r

In a swap, **the user's browser picks r**, never the maker. The fresh-eyes review found that `swap_id` also seeds the user's Monero half (`deriveHalf(root, swap_id)`), and a completed claim publishes that half. A maker allowed to choose R could replay an old `(R, P)` pair of the same user, which it would recognise from the user's stable meta address. It would then hold both Monero halves of the new swap and could take the XMR.

So:
- `stealthClaimerForSwap` derives R locally.
- It also refuses any derived address or escrow that has an account or any transaction history (`assertFresh`).
- Third-party payers with no swap half involved, such as future pay links, use `deriveOneTime(meta)` on their side.

## Signing with a raw scalar

`s_i` is a scalar, not an RFC 8032 seed. `signRaw` uses standard Ed25519 arithmetic:
- nonce prefix = `SHA-512("halfkey-stealth-nonce-v1" ‖ s_i)[0..32]`
- `k = H(prefix ‖ M)`
- `A = s_i·G` (always recomputed, never taken from the caller)
- `S = k + H(R ‖ A ‖ M)·s_i`

Fed the expanded key from a seed, `signExpanded` reproduces the RFC 8032 test vectors bit for bit. Signatures verify under noble (strict), OpenSSL, and the Agave runtime, for both legacy and v0 transactions. `StealthSigner` plugs into the SDK's existing signer shape.

## Gasless first spend, then sweep anywhere

- **Claim:** the one-time address holds 0 SOL, so a neutral relayer (watchtower) pays the claim fee. The address signs only as the claimer. The maker never relays it.
  - If no relayer can send the claim in time, the user can pay the fee from the connected wallet.
  - That path asks for an explicit confirmation, because it links the two. It exists because a missed claim would cost the SOL.
- **Sweep:** the one-time address is its own fee payer and the only signer. "Sweep all" closes the account at 0.
  - A partial sweep must leave 0 or at least the rent-exempt minimum.
  - A new destination must receive at least the rent-exempt minimum.
  - Swaps too small to stay rent-exempt after the protocol fee are refused up front.

## Tests

- `sdk/stealth.test.ts` (unit):
  - derivation vectors, cross-checked by an independent recomputation (node:crypto SHA-512, the other multiplication order)
  - RFC 8032 vectors
  - OpenSSL verification
  - wrong view, spend, account, index and scalar
  - torsion-tweaked, small-order and non-canonical R
  - meta address format
  - index validation
  - legacy and v0 signing
- `e2e/stealth.test.ts` (local validator):
  - lock to a one-time address, scan, relayed claim (relayer pays, main wallet untouched), sweep that pays its own fee to a new address (account closed)
  - closed escrow recovered from history
  - v0 partial sweep
  - a forged signature, the wrong scalar and a flipped bit are all rejected by the runtime
  - a stranger's key is `Unauthorized`
  - sweep guards
  - a replayed `(R, P)` is refused
- `e2e/static-ui.ts` (headless, static build under `/ipfs/<cid>/`): "Receive at a fresh address" is shown, and "My stealth funds" scans and sweeps a real stealth receive.

## Privacy limits (honest list)

- **Amounts and timing are public.** The escrow amount, and the sweep that follows it, can be correlated.
- **The maker sees the one-time address** and the user's IP, but not the meta key and not `h`.
- **Sweeping to your own wallet links the two.** The UI warns about it. Sweeping several stealth addresses to one destination links them to each other.
- **Your RPC sees `getBalance` and the sweep** for your one-time addresses. Use your own RPC (Network settings).
- **The wallet's key-message signature now also unlocks the stealth funds**, not just per-swap halves. A site that phishes that one signature can sweep every unswept stealth balance. Sweep promptly. A separate stealth key message would split the scopes, at the cost of one more signature. That is an open question.
- **The scan downloads every XMR → SOL escrow**, about 1–4 ms of CPU each. That is fine at thousands. At around 100k escrows it should move to a Web Worker.
