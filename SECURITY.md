# Security policy

HALFKEY moves real funds. We take reports seriously and respond quickly.

## Reporting a vulnerability

Email **halfkey@proton.me** with:

- a description of the issue and its impact,
- the affected component (program instruction, SDK function, maker or tower code, or protocol step) and version or commit,
- steps or a proof of concept that reproduce it on devnet, a local validator or Monero stagenet.

Please do not open a public issue, and do not test against mainnet funds that are not your own. We acknowledge reports within 48 hours and keep you updated until a fix ships. We are happy to credit researchers who want it.

## Scope

- `program/`: escrow, claim, refund, payment-proof, registry and staking logic.
- `sdk/`: key derivation, transaction construction, proof verification.
- `maker/` and `watchtower/`: the maker daemon, watchtower and refund-tower services.
- The swap protocol as described in this repository's documentation.

The hosted web client is operated separately; report issues with it to the same address.
