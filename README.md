# ecies-post-quantum

[![License](https://img.shields.io/github/license/ecies/rs-post-quantum.svg)](https://github.com/ecies/rs-post-quantum/blob/main/LICENSE)
[![Crates](https://img.shields.io/crates/v/ecies-post-quantum)](https://crates.io/crates/ecies-post-quantum)
[![Doc](https://docs.rs/ecies-post-quantum/badge.svg)](https://docs.rs/ecies-post-quantum/latest/ecies_post_quantum/)
[![CI](https://img.shields.io/github/actions/workflow/status/ecies/rs-post-quantum/ci.yml)](https://github.com/ecies/rs-post-quantum/actions)
[![Codecov](https://img.shields.io/codecov/c/github/ecies/rs-post-quantum.svg)](https://codecov.io/gh/ecies/rs-post-quantum)

Post-quantum Cryptography Integrated Encryption Scheme in Rust, replacing "ec" in [`eciesrs`](https://github.com/ecies/rs) with ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism, FIPS 203).

This is the Rust version of [`@ecies/post-quantum`](https://github.com/ecies/js-post-quantum), and the two are compatible: a payload encrypted by one can be decrypted by the other.

## Install

```bash
cargo add ecies-post-quantum
```

It needs Rust 1.94 or later.

## Quick start

```rust
use ecies_post_quantum::config::AsymmetricAlgorithm;
use ecies_post_quantum::utils::generate_keypair;
use ecies_post_quantum::{decrypt, encrypt};

let (sk, pk) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
let msg = "hello world🌍".as_bytes();

let encrypted = encrypt(pk.as_bytes(), msg).unwrap();
assert_eq!(decrypt(sk.as_bytes(), &encrypted).unwrap(), msg);
```

## API

- `encrypt(receiver_pk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error>` encrypts to an ML-KEM-768 public key with the default config.
- `decrypt(receiver_sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error>` decrypts it with the secret key, either the expanded key or its 64-byte seed.
- `encrypt_with_config` and `decrypt_with_config` take a `&Config` as their last argument. Both sides must use the same config: the payload doesn't record it.
- `utils::generate_keypair(AsymmetricAlgorithm) -> Result<(SecretKey, PublicKey), Error>` draws a key pair from the system random number generator.
- `utils::generate_seed() -> Result<Seed, Error>` draws a 64-byte seed from it instead: the compact form of a secret key, for any parameter set (see [Storing the secret key](#storing-the-secret-key)).
- `utils::keypair_from_seed(AsymmetricAlgorithm, &[u8; 64]) -> (SecretKey, PublicKey)` derives the key pair of a seed, the same as `keygen(seed)` in [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum).
- `SecretKey` and `PublicKey` give their bytes with `as_bytes()` and their parameter set with `algorithm()`, and `Seed` gives its bytes with `as_bytes()`. `SecretKey` and `Seed` are wiped on drop, compared in constant time, left out of `Debug`, and can't be cloned.

`Error` tells why a call failed:

- `InvalidPublicKey`: the public key has the wrong length for the parameter set, or fails its modulus check.
- `InvalidSecretKey`: the secret key is neither a 64-byte seed nor an expanded key of the right length, or is an expanded key that fails its hash check.
- `InvalidMessage`: the payload is too short, was not encrypted to this key and config, or was tampered with. When encrypting, the message is too long for the symmetric cipher.
- `RngFailure`: the system random number generator failed.

## Configuration

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

The fields and defaults are the same as JS's `Config`:

| Field | Rust | JS | Default |
| --- | --- | --- | --- |
| `asymmetric_algorithm` | `MlKem512`, `MlKem768`, `MlKem1024` | `"ml-kem-512"`, `"ml-kem-768"`, `"ml-kem-1024"` | ML-KEM-768 |
| `symmetric_algorithm` | `Aes256Gcm`, `XChaCha20` | `"aes-256-gcm"`, `"xchacha20"` | AES-256-GCM |
| `symmetric_nonce_length` | `Twelve`, `Sixteen` | `12`, `16` | 16, for AES-256-GCM only |

### Which configuration should I choose?

ML-KEM-768 is the parameter set that NIST recommends as the default (FIPS 203, section 8). Choose ML-KEM-1024 for a higher security category, at the cost of larger keys and payloads.

AES-256-GCM is fast on CPUs with AES instructions. Without them, XChaCha20-Poly1305 is faster.

### OpenSSL AES backend

AES-256-GCM is pure Rust by default. The `aes-openssl` feature runs it on OpenSSL instead, which is faster on large messages. XChaCha20-Poly1305 stays pure Rust. The feature links the system's OpenSSL; on Windows, CI installs it with vcpkg.

```toml
ecies-post-quantum = { version = "0.1", features = ["aes-openssl"] }
```

## Key and payload formats

| Bytes | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
| --- | --- | --- | --- |
| Public key | 800 | 1184 | 1568 |
| Secret key, expanded | 1632 | 2400 | 3168 |
| Secret key, seed | 64 | 64 | 64 |
| ML-KEM ciphertext | 768 | 1088 | 1568 |

The keys are the FIPS 203 encapsulation key and expanded decapsulation key, with the same bytes as `@noble/post-quantum`'s `publicKey` and `secretKey`. The seed is `d || z` from FIPS 203. `decrypt` accepts either form of the secret key and tells them apart by length, while JS's `decrypt` takes only the expanded key.

A payload is:

```text
ML-KEM ciphertext || nonce (16, 12 or 24 bytes) || tag (16 bytes) || encrypted message
```

The nonce is 16 or 12 bytes for AES-256-GCM, and 24 bytes for XChaCha20-Poly1305. The encrypted message is as long as the message.

### Storing the secret key

Store the 64-byte seed rather than the expanded key: it is smaller, and `decrypt` takes it as it is. It doesn't record the parameter set, so derive the keys and decrypt with the same one. Decrypting from the seed derives the expanded key again on every call, so it is slower than decrypting from the expanded key, and in release builds it leaves more copies of the key on the stack (see [Secret material](#secret-material)).

```rust
use ecies_post_quantum::config::AsymmetricAlgorithm;
use ecies_post_quantum::utils::{generate_seed, keypair_from_seed};
use ecies_post_quantum::{decrypt, encrypt};

let seed = generate_seed().unwrap(); // store seed.as_bytes(), and keep it as secret as the key
let (_, pk) = keypair_from_seed(AsymmetricAlgorithm::MlKem768, seed.as_bytes());

let encrypted = encrypt(pk.as_bytes(), b"hello").unwrap();
assert_eq!(decrypt(seed.as_bytes(), &encrypted).unwrap(), b"hello");
```

In JS, `keygen(seed)` of `@noble/post-quantum` derives the same keys from the seed.

## Cross-language compatibility

CI checks both directions against `@ecies/post-quantum` from npm, for every parameter set and cipher, on x86_64 (AVX2) and aarch64 (NEON): JS decrypts the payloads that Rust encrypts, and Rust decrypts payloads that JS encrypts, both committed ones and fresh ones on every run.

## WASM and `no_std`

The crate is `no_std` with `alloc`.

On `wasm32-unknown-unknown`, key generation and encryption take their randomness from [`getrandom`](https://docs.rs/getrandom), which has no default source there. In a browser or Node.js, enable its `wasm_js` feature in your own crate:

```toml
[target.'cfg(all(target_arch = "wasm32", target_os = "unknown"))'.dependencies]
getrandom = { version = "0.4", features = ["wasm_js"] }
```

For other runtimes, and for targets without an operating system such as `thumbv7em-none-eabihf`, pick one of getrandom's [opt-in backends](https://docs.rs/getrandom/latest/getrandom/#opt-in-backends), such as `custom`. Every build needs one, even if it only decrypts: with `unsupported`, decryption works, while key generation and encryption return `Error::RngFailure`.

The test suite runs inside `wasm32-unknown-unknown` under Node.js, and builds for `wasm32-wasip2`.

## Security

### ML-KEM implementation

ML-KEM comes from [`libcrux-ml-kem`](https://github.com/cryspen/libcrux) 0.0.12.
- **What libcrux says is verified:** its portable and AVX2 code for field arithmetic, NTT and serialization, and its generic code for the high-level algorithms, with hax and F\*.
- **What is not, yet:** its [verification status](https://github.com/cryspen/libcrux/blob/24330863b3d1d4179e4bcea8cef6bf6fa313057e/libcrux-ml-kem/proofs/verification_status.md) still lists unproven parts, such as the IND-CPA scheme and sampling. The SHA-3 code it hashes with, `libcrux-sha3`, is marked pre-verification.
- **On aarch64,** it runs its NEON code, which is not verified. [RUSTSEC-2025-0133](https://osv.dev/vulnerability/RUSTSEC-2025-0133), since fixed, was in that code.
- **Side channels:** libcrux checks its portable code for secret independence through its types, and inspects the generated assembly. It calls this best-effort, since the compiler gives no guarantee, and says compiled code is not verified to resist side channels.
- **Maturity:** libcrux calls all its crates pre-release (versions below 0.1).

This crate has not had an independent security audit.

### Key checks

Encryption runs the modulus check of FIPS 203 section 7.2 on the public key, and decryption runs the hash check of section 7.3 on an expanded secret key, before using them. A key derived from a seed passes that check by construction, so decryption from a seed skips it. A wrong key or a tampered ciphertext makes ML-KEM return a pseudorandom shared secret (implicit rejection), so the AEAD tag check fails and decryption returns `InvalidMessage`.

### No key derivation step

The 32-byte ML-KEM shared secret is the AEAD key, as in JS, with no HKDF. ML-KEM already derives it with SHA3, and every message gets a fresh one, so each AEAD key encrypts a single message. That also makes the 12-byte random AES-256-GCM nonce safe.

### Secret material

`SecretKey` and `Seed` are wiped on drop, and so are shared secrets and the randomness the crate draws for encryption. When decrypting with an expanded key, the copy handed to libcrux is wiped too. libcrux takes seeds and randomness by value and doesn't wipe its key types, and the stack frames of libcrux, the ciphers and this crate aren't wiped, so copies of secrets may stay on the stack, the shared secret among them. That includes parts of the secret key, such as z, after any decryption, and copies of the expanded key or of its secret part where the crate derives a key pair from a seed (`generate_keypair`, `keypair_from_seed` and `decrypt` with a seed). Debug builds leave more, sometimes including whole copies of the expanded key after decrypting with it: see [#4](https://github.com/ecies/rs-post-quantum/issues/4). Copies of a seed's bytes that you make, such as a stored one, are yours to protect.

### Dependencies

libcrux releases are 0.0.x, so `libcrux-ml-kem` is pinned exactly, and its fixes reach users through a release of this crate. `cargo audit` runs on pushes and pull requests to `main` and weekly, and fails on any advisory except RUSTSEC-2026-0173: proc-macro-error2 is unmaintained, and only libcrux's `cfg(hax)` builds reach it.

## Benchmark

```sh
cargo bench
cargo bench --features aes-openssl
```

The first command measures key generation at each ML-KEM level, plus encryption and decryption of 32 B, 100 MiB and 200 MiB messages at each level with the default AES-256-GCM. The second runs the same on the OpenSSL backend.

Criterion's estimates on an Apple M4 (24 GiB, macOS 26.7) with Rust 1.100.0 and Homebrew's OpenSSL 4.1, on 2026-11-20:

| Pure Rust AES | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
| --- | --- | --- | --- |
| Key generation | 6.7 µs | 12.5 µs | 18.8 µs |
| Encrypt 32 B | 6.9 µs | 11.3 µs | 15.4 µs |
| Decrypt 32 B | 6.6 µs | 11.5 µs | 16.2 µs |

The OpenSSL build is within 0.6 µs of these.

On large messages, AES-256-GCM and copying the message take nearly all the time, so the ML-KEM level barely matters. With ML-KEM-768 (the other levels are within 4%):

| | Pure Rust AES | OpenSSL AES |
| --- | --- | --- |
| Encrypt 100 MiB | 19.2 ms | 11.8 ms |
| Decrypt 100 MiB | 19.3 ms | 11.9 ms |
| Encrypt 200 MiB | 38.5 ms | 23.8 ms |
| Decrypt 200 MiB | 38.6 ms | 24.1 ms |

## Changelog

See [CHANGELOG.md](https://github.com/ecies/rs-post-quantum/blob/main/CHANGELOG.md).
