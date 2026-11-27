#!/bin/sh
# Builds the HALFKEY ZEC privacy module to WASM (wasm32-unknown-unknown, single-threaded).
#   zecwasm/pkg/          browser + Node build (no test helpers)  -> copied to web/public/zec/ by web/build.mjs
#   zecwasm/pkg-testkit/  same + the seed-wallet / trial-decrypt helpers, for e2e/zec-*.ts only
# Needs: rustup target wasm32-unknown-unknown, wasm-bindgen-cli 0.2.100, rustup component llvm-tools
# (llvm-ar: secp256k1-sys is C, and Apple's ar writes archives rust-lld cannot index for wasm).
set -eu
cd "$(dirname "$0")"
LLAR="$(rustc --print sysroot)/lib/rustlib/$(rustc -vV | sed -n 's/host: //p')/bin/llvm-ar"
export AR_wasm32_unknown_unknown="$LLAR" CC_wasm32_unknown_unknown="${CC_WASM:-clang}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$PWD/target}"
# No build-machine paths in the binary: remap home, the cargo registry, rustup, this crate and the target dir
# (the last matching remap wins). Check after: strings pkg/*.wasm | grep -c "$HOME" must print 0.
unset CARGO_ENCODED_RUSTFLAGS
export RUSTFLAGS="--remap-path-prefix=$HOME=/build --remap-path-prefix=$HOME/.cargo/registry/src=/cargo/registry/src --remap-path-prefix=$HOME/.cargo/git/checkouts=/cargo/git --remap-path-prefix=$HOME/.rustup=/rustup --remap-path-prefix=$PWD=/halfkey/zecwasm --remap-path-prefix=$CARGO_TARGET_DIR=/target"
export CFLAGS_wasm32_unknown_unknown="-ffile-prefix-map=$HOME=/build"
W="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/halfkey_zecwasm.wasm"
cargo build --release --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir pkg "$W"
cargo build --release --target wasm32-unknown-unknown --features testkit
wasm-bindgen --target web --out-dir pkg-testkit "$W"
ls -la pkg/*.wasm pkg-testkit/*.wasm
if strings pkg/*.wasm pkg-testkit/*.wasm | grep -q "$HOME"; then echo "build path leaked into the wasm" >&2; exit 1; fi
