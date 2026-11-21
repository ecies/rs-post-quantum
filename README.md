# ecies-post-quantum

[![License](https://img.shields.io/github/license/ecies/rs-post-quantum.svg)](https://github.com/ecies/rs-post-quantum/blob/main/LICENSE)
[![Crates](https://img.shields.io/crates/v/ecies-post-quantum)](https://crates.io/crates/ecies-post-quantum)
[![Doc](https://docs.rs/ecies-post-quantum/badge.svg)](https://docs.rs/ecies-post-quantum/latest/ecies_post_quantum/)
[![Recent Downloads](https://img.shields.io/crates/dr/ecies-post-quantum)](https://lib.rs/crates/ecies-post-quantum)
[![CI](https://img.shields.io/github/actions/workflow/status/ecies/rs-post-quantum/ci.yml)](https://github.com/ecies/rs-post-quantum/actions)
[![Codecov](https://img.shields.io/codecov/c/github/ecies/rs-post-quantum.svg)](https://codecov.io/gh/ecies/rs-post-quantum)

Post-quantum public-key encryption in Rust — the **ML-KEM (FIPS 203)** counterpart to [`eciesrs`](https://github.com/ecies/rs). It replaces elliptic-curve key agreement with Module-Lattice-Based Key Encapsulation and pairs it with authenticated symmetric encryption (**AES-256-GCM** or **XChaCha20-Poly1305**).

- **Wire-compatible with JavaScript/TypeScript:** payloads encrypted by this crate can be decrypted by [`@ecies/post-quantum`](https://github.com/ecies/js-post-quantum), and vice versa.
- **`no_std` + `alloc` & WASM ready:** runs on native targets, `wasm32-unknown-unknown`, `wasm32-wasip2`, and embedded targets.
- **Pure Rust by default:** `#![forbid(unsafe_code)]`, with an optional OpenSSL AES backend for faster bulk encryption.

## Install

```bash
cargo add ecies-post-quantum
```

Requires **Rust 1.94** or later.

## Quick start

By default, `encrypt` and `decrypt` use **ML-KEM-768** and **AES-256-GCM** with a 16-byte nonce:

```rust
use ecies_post_quantum::config::AsymmetricAlgorithm;
use ecies_post_quantum::utils::generate_keypair;
use ecies_post_quantum::{decrypt, encrypt};

let (sk, pk) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
let msg = "hello world🌍".as_bytes();

let encrypted = encrypt(pk.as_bytes(), msg).unwrap();
assert_eq!(decrypt(sk.as_bytes(), &encrypted).unwrap(), msg);
```

## Configuration

Use `encrypt_with_config` and `decrypt_with_config` to select a different ML-KEM parameter set, symmetric cipher, or AES-GCM nonce length:

```rust
use ecies_post_quantum::config::{AsymmetricAlgorithm, Config, SymmetricAlgorithm};
use ecies_post_quantum::utils::generate_keypair;
use ecies_post_quantum::{decrypt_with_config, encrypt_with_config};

let config = Config {
    asymmetric_algorithm: AsymmetricAlgorithm::MlKem1024,
    symmetric_algorithm: SymmetricAlgorithm::XChaCha20,
    ..Config::default()
};
let (sk, pk) = generate_keypair(config.asymmetric_algorithm).unwrap();

let encrypted = encrypt_with_config(pk.as_bytes(), b"hello", &config).unwrap();
assert_eq!(decrypt_with_config(sk.as_bytes(), &encrypted, &config).unwrap(), b"hello");
```

> **Note:** Both sides must agree on the `Config` out of band — payloads do not carry algorithm metadata.

`Config` mirrors `@ecies/post-quantum`'s `Config` options and defaults:

| Field | Rust values | JS values | Default |
| --- | --- | --- | --- |
| `asymmetric_algorithm` | `MlKem512`, `MlKem768`, `MlKem1024` | `"ml-kem-512"`, `"ml-kem-768"`, `"ml-kem-1024"` | `MlKem768` |
| `symmetric_algorithm` | `Aes256Gcm`, `XChaCha20` | `"aes-256-gcm"`, `"xchacha20"` | `Aes256Gcm` |
| `symmetric_nonce_length` | `NonceLength::Twelve`, `NonceLength::Sixteen` | `12`, `16` | `Sixteen` (AES-256-GCM only) |

`symmetric_nonce_length` is ignored when `symmetric_algorithm` is `XChaCha20`, which always uses a 24-byte nonce.

### Choosing a configuration

- **ML-KEM parameter set:** `MlKem768` is the NIST-recommended default (FIPS 203, Section 8). Use `MlKem1024` if you want a higher security category and can accept larger keys and ciphertexts, or `MlKem512` if smaller payloads matter more.
- **Symmetric cipher:** `Aes256Gcm` is fastest on CPUs with hardware AES instructions. Choose `XChaCha20` on targets without hardware AES acceleration.

### Optional OpenSSL AES backend

AES-256-GCM runs in pure Rust by default. Enable the `aes-openssl` feature to use OpenSSL instead, which significantly speeds up large messages (XChaCha20-Poly1305 always stays pure Rust):

```toml
ecies-post-quantum = { version = "0.1", features = ["aes-openssl"] }
```

This links against the system OpenSSL library (on Windows, CI installs it via vcpkg).

## Storing the secret key

Expanded ML-KEM secret keys are large (1,632 to 3,168 bytes). For persistence, store the **64-byte `Seed`** instead:

```rust
use ecies_post_quantum::config::AsymmetricAlgorithm;
use ecies_post_quantum::utils::{generate_seed, keypair_from_seed};
use ecies_post_quantum::{decrypt, encrypt};

// Store seed.as_bytes() and protect it like any secret key.
let seed = generate_seed().unwrap();
let (_, pk) = keypair_from_seed(AsymmetricAlgorithm::MlKem768, seed.as_bytes());

let encrypted = encrypt(pk.as_bytes(), b"hello").unwrap();
// `decrypt` accepts either a 64-byte seed or an expanded secret key.
assert_eq!(decrypt(seed.as_bytes(), &encrypted).unwrap(), b"hello");
```

Keep these details in mind when working with seeds:

- **Track the parameter set:** a seed does not record which ML-KEM parameter set it belongs to, so derive keys and decrypt with the same `AsymmetricAlgorithm`.
- **Performance:** passing a seed directly to `decrypt` re-expands the secret key on every call. If you decrypt many messages in memory, expand it once with `keypair_from_seed` and reuse the `SecretKey`.
- **JavaScript interop:** `keypair_from_seed` matches `keygen(seed)` in [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum). Unlike Rust's `decrypt`, `@ecies/post-quantum`'s `decrypt` only accepts the expanded secret key, so expand the seed in JS first.

## API overview

### Encrypt and decrypt

- `encrypt(receiver_pk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error>` — encrypts `msg` using the default config (ML-KEM-768 + AES-256-GCM-16).
- `decrypt(receiver_sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error>` — decrypts a payload from `encrypt` using either an expanded secret key or its 64-byte seed.
- `encrypt_with_config(receiver_pk: &[u8], msg: &[u8], config: &Config) -> Result<Vec<u8>, Error>` — encrypts with an explicit `Config`.
- `decrypt_with_config(receiver_sk: &[u8], msg: &[u8], config: &Config) -> Result<Vec<u8>, Error>` — decrypts with the matching `Config`, using either an expanded secret key or its 64-byte seed.

### Key generation and key types

- `utils::generate_keypair(algorithm: AsymmetricAlgorithm) -> Result<(SecretKey, PublicKey), Error>` — generates a key pair from the system RNG.
- `utils::generate_seed() -> Result<Seed, Error>` — generates a 64-byte seed from the system RNG.
- `utils::keypair_from_seed(algorithm: AsymmetricAlgorithm, seed: &[u8; 64]) -> (SecretKey, PublicKey)` — deterministically derives a key pair from a 64-byte seed.
- `PublicKey` and `SecretKey` expose `as_bytes()` and `algorithm()`; `Seed` exposes `as_bytes()`.
- `SecretKey` and `Seed` are zeroized on drop, compared in constant time, redacted in `Debug`, and do not implement `Clone`.

### Errors (`Error`)

| Variant | Cause |
| --- | --- |
| `InvalidPublicKey` | Wrong length for the parameter set, or failed the FIPS 203 modulus check. |
| `InvalidSecretKey` | Neither a 64-byte seed nor a valid-length expanded key, or failed the FIPS 203 hash check. |
| `InvalidMessage` | During decryption: payload is too short, tampered with, or encrypted for a different key or config. During encryption: message exceeds the symmetric cipher's length limit. |
| `RngFailure` | The system random number generator failed. |

## Key and payload formats

Keys follow FIPS 203 directly (encapsulation key and expanded decapsulation key) and use the exact same byte encoding as `@noble/post-quantum`'s `publicKey` and `secretKey`. A seed is the 64-byte concatenation `d || z` from FIPS 203.

| Component (bytes) | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
| --- | --- | --- | --- |
| Public key | 800 | 1,184 | 1,568 |
| Secret key (expanded) | 1,632 | 2,400 | 3,168 |
| Secret key (seed) | 64 | 64 | 64 |
| ML-KEM ciphertext | 768 | 1,088 | 1,568 |

Each encrypted payload has the layout:

```text
ML-KEM ciphertext || nonce (16, 12, or 24 B) || tag (16 B) || encrypted message
```

- **Nonce:** 16 or 12 bytes for AES-256-GCM, 24 bytes for XChaCha20-Poly1305.
- **Tag:** 16-byte AEAD authentication tag.
- **Encrypted message:** same length as the plaintext.

## Cross-language compatibility

CI verifies interoperability in both directions against `@ecies/post-quantum` from npm across every ML-KEM parameter set and symmetric cipher, on both `x86_64` (AVX2) and `aarch64` (NEON):

- JavaScript decrypts payloads encrypted by Rust (both pure Rust and OpenSSL AES builds).
- Rust decrypts payloads encrypted by JavaScript, using both committed vectors and freshly generated payloads on every run.

## WASM and `no_std`

This crate is `#![no_std]` with `alloc`.

Key generation and encryption rely on [`getrandom`](https://docs.rs/getrandom), which intentionally leaves the randomness backend up to the final application on targets without an OS:

- **Browsers and Node.js (`wasm32-unknown-unknown`):** enable `getrandom`'s `wasm_js` feature in your own `Cargo.toml`:

  ```toml
  [target.'cfg(all(target_arch = "wasm32", target_os = "unknown"))'.dependencies]
  getrandom = { version = "0.4", features = ["wasm_js"] }
  ```

- **Embedded and custom runtimes (e.g., `thumbv7em-none-eabihf`):** select one of `getrandom`'s [opt-in backends](https://docs.rs/getrandom/latest/getrandom/#opt-in-backends), such as `custom`. A backend must be configured even for decrypt-only builds — with `unsupported`, decryption succeeds while key generation and encryption return `Error::RngFailure`.
- **Stack size:** key generation, encryption, and decryption each wipe **80 KiB** of stack via `zeroize::zeroize_stack` before returning. Callers — especially on `no_std` targets without stack guard pages, where a stack overflow silently corrupts adjacent memory — should ensure at least **84 KiB** of free stack space before calling into this crate.

CI runs the test suite on `wasm32-unknown-unknown` under Node.js and checks compilation for `wasm32-wasip2`.

## Security

> **Audit status:** This crate has not had an independent security audit, and its underlying ML-KEM implementation (`libcrux`) is currently pre-release (`0.0.x`).

### ML-KEM implementation

ML-KEM is provided by [`libcrux-ml-kem`](https://github.com/cryspen/libcrux) `0.0.12`:

- **Verified parts:** `libcrux` formally verifies (with hax and F\*) its portable and AVX2 implementations of field arithmetic, NTT, and serialization, as well as its generic high-level ML-KEM algorithms.
- **Unverified parts:** its [verification status](https://github.com/cryspen/libcrux/blob/24330863b3d1d4179e4bcea8cef6bf6fa313057e/libcrux-ml-kem/proofs/verification_status.md) still lists unproven components, including the IND-CPA scheme and sampling. Its SHA-3 dependency (`libcrux-sha3`) is marked pre-verification, and its `aarch64` NEON backend is not verified ([RUSTSEC-2025-0133](https://osv.dev/vulnerability/RUSTSEC-2025-0133), now fixed, was in the NEON code).
- **Side channels:** `libcrux` checks secret independence in its portable code via types and inspects generated assembly, which it describes as best-effort — the compiler gives no constant-time guarantee, and compiled machine code is not formally verified against side channels.

### Key checks and implicit rejection

- **Public keys:** `encrypt` runs the FIPS 203 Section 7.2 modulus check before encapsulating.
- **Secret keys:** `decrypt` runs the FIPS 203 Section 7.3 hash check on expanded secret keys. When decrypting from a 64-byte seed, the derived key satisfies this check by construction, so it is skipped.
- **Tampered or mismatched payloads:** a wrong key or modified ciphertext triggers ML-KEM implicit rejection (producing a pseudorandom shared secret), so AEAD verification fails and decryption returns `Error::InvalidMessage`.

### No separate KDF

The 32-byte ML-KEM shared secret is used directly as the AEAD key (without HKDF), matching `@ecies/post-quantum`. ML-KEM already derives this secret with SHA-3, and every encryption generates a fresh key — so each AEAD key encrypts at most one message, which also makes random 12-byte AES-256-GCM nonces safe.

### Secret material

**What is zeroized:**

- `SecretKey` and `Seed` are wiped on drop (`Seed` is heap-allocated so moving it does not copy its bytes).
- Shared secrets, per-encryption randomness, and the expanded-key copy passed into `libcrux` during decryption are wiped after use.
- Key derivation (`generate_keypair`, `keypair_from_seed`), encryption (`encrypt`, `encrypt_with_config`), and decryption (`decrypt`, `decrypt_with_config`, including failed decryptions after decapsulation) run inside an `#[inline(never)]` frame followed by `zeroize::zeroize_stack` (80 KiB). This wipes the stack frames left by `libcrux`, the symmetric ciphers, and this crate in optimized builds (verified in CI on `x86_64`/AVX2, `aarch64`/NEON, `opt-level = "s"`, LTO, and `libcrux`'s portable path).

**Known limitations (out of reach of stack wiping):**

- **Best-effort guarantee:** `zeroize::zeroize_stack` relies on `#[inline(never)]` not being ignored by the compiler and on stack usage staying within 80 KiB. Unoptimized debug builds use much deeper frames and still leave copies below 80 KiB.
- **CPU and vector registers:** registers can still hold key material after a call returns, and a later signal handler or context switch may save them to the stack.
- **WASM locals:** on WebAssembly, the wipe only covers the linear-memory shadow stack; values the engine keeps in WASM locals live on its own stack and are out of reach.
- **Caller copies:** any copies of keys, seeds, or plaintexts that your application creates or persists remain your responsibility to protect.

### Dependencies and audits

Because `libcrux` releases are `0.0.x`, `libcrux-ml-kem` is pinned to an exact version (`=0.0.12`), and upstream fixes are delivered through releases of this crate.

`cargo audit` runs on pushes, pull requests to `main`, and weekly. It fails on any advisory except `RUSTSEC-2026-0173` (`proc-macro-error2` is unmaintained, and is only reached by `libcrux`'s `cfg(hax)` builds).

## Benchmarks

Run the Criterion benchmarks locally for both AES backends:

```sh
cargo bench
cargo bench --features aes-openssl
```

The suite benchmarks key generation for each ML-KEM level, plus encryption and decryption of 32 B, 100 MiB, and 200 MiB messages using the default AES-256-GCM configuration.

Measured on an Apple M4 (24 GiB, macOS 26.7) with Rust 1.100.0 and Homebrew OpenSSL 4.1 (2026-11-21):

**Small messages and key generation** (OpenSSL AES results are within 0.3 µs):

| Pure Rust AES | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
| --- | --- | --- | --- |
| Key generation | 7.6 µs | 13.7 µs | 19.9 µs |
| Encrypt 32 B | 7.7 µs | 12.0 µs | 16.4 µs |
| Decrypt 32 B | 7.4 µs | 12.2 µs | 16.9 µs |

**Large messages** (ML-KEM-768; AES-256-GCM and memory copying dominate, so ML-KEM-512 and ML-KEM-1024 are within 4%):

| Operation | Pure Rust AES | OpenSSL AES |
| --- | --- | --- |
| Encrypt 100 MiB | 19.2 ms | 11.8 ms |
| Decrypt 100 MiB | 19.3 ms | 11.9 ms |
| Encrypt 200 MiB | 38.5 ms | 23.8 ms |
| Decrypt 200 MiB | 38.6 ms | 24.1 ms |

## Changelog

See [CHANGELOG.md](https://github.com/ecies/rs-post-quantum/blob/main/CHANGELOG.md).
