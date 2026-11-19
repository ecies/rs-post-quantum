#!/bin/sh
set -e

# the lib and integration tests inside wasm, under node. needs wasm-bindgen-test-runner at the locked wasm-bindgen
# version. doctests stay native: the runner would report them as passed without running them
cargo test --target wasm32-unknown-unknown --lib --tests

# the runner passes a module whose tests lack the `wasm_bindgen_test` attribute without running them, so wasm must
# list the same tests as native. no `-q`: cargo passes it on as `--quiet`, which the runner rejects
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cargo test --lib --tests -- --list | grep ': test$' | sort > "$tmp/native"
cargo test --target wasm32-unknown-unknown --lib --tests -- --list | grep ': test$' | sort > "$tmp/wasm"
if [ ! -s "$tmp/native" ] || ! diff "$tmp/native" "$tmp/wasm" >&2; then
  echo "wasm does not list the same tests as native (< native only, > wasm only)" >&2
  exit 1
fi

# no runner for wasip2 here, so only check that the lib, tests and examples build
cargo test --target wasm32-wasip2 --no-run
