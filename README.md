# ecies-post-quantum

Post-quantum Cryptography Integrated Encryption Scheme in Rust, replacing "ec" in [`eciesrs`](https://github.com/ecies/rs) with ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism, FIPS 203).

This is the Rust version of [`@ecies/post-quantum`](https://github.com/ecies/js-post-quantum), and the two are designed to be compatible: a payload encrypted by one can be decrypted by the other.

> [!WARNING]
> Work in progress. The crate is not published yet, and its API may still change.

## Design

- Key encapsulation: ML-KEM-512, ML-KEM-768 (default) or ML-KEM-1024, via [`libcrux-ml-kem`](https://github.com/cryspen/libcrux), whose portable and AVX2 code is formally verified. On aarch64 it runs its NEON code, which is not verified
- Symmetric cipher: AES-256-GCM (default, 16 or 12 bytes nonce) or XChaCha20-Poly1305
- Payload format: `ML-KEM ciphertext || nonce || tag || encrypted data`, where the ML-KEM shared secret is the symmetric key
- `no_std` with `alloc`, and builds on WASM

## WASM and `no_std`

On `wasm32-unknown-unknown`, key generation and encryption take their randomness from [`getrandom`](https://docs.rs/getrandom), which has no default source there. In a browser or Node.js, enable its `wasm_js` feature in your own crate:

```toml
[target.'cfg(all(target_arch = "wasm32", target_os = "unknown"))'.dependencies]
getrandom = { version = "0.4", features = ["wasm_js"] }
```

For other runtimes, and for targets without an operating system such as `thumbv7em-none-eabihf`, pick one of getrandom's [opt-in backends](https://docs.rs/getrandom/latest/getrandom/#opt-in-backends), such as `custom`. Every build needs one, even if it only decrypts: with `unsupported`, decryption works, while key generation and encryption return `Error::RngFailure`.

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).
