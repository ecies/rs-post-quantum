# ecies-post-quantum

Post-quantum Cryptography Integrated Encryption Scheme in Rust, replacing "ec" in [`eciesrs`](https://github.com/ecies/rs) with ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism, FIPS 203).

This is the Rust version of [`@ecies/post-quantum`](https://github.com/ecies/js-post-quantum), and the two are designed to be compatible: a payload encrypted by one can be decrypted by the other.

> [!WARNING]
> Work in progress. The API is not implemented yet and the crate is not published.

## Design

- Key encapsulation: ML-KEM-512, ML-KEM-768 (default) or ML-KEM-1024, via the formally verified [`libcrux-ml-kem`](https://github.com/cryspen/libcrux)
- Symmetric cipher: AES-256-GCM (default, 16 or 12 bytes nonce) or XChaCha20-Poly1305
- Payload format: `ML-KEM ciphertext || nonce || tag || encrypted data`, where the ML-KEM shared secret is the symmetric key
- `no_std` with `alloc`, and builds on WASM

## Changelog

See [CHANGELOG.md](./CHANGELOG.md).
