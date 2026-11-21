# Changelog

## 0.1.1

- Wipe 80 KiB of stack via `zeroize::zeroize_stack` after key derivation (`utils::generate_keypair`, `utils::keypair_from_seed`), encryption (`encrypt`, `encrypt_with_config`), and decryption (`decrypt`, `decrypt_with_config`, including error paths after decapsulation), clearing secret material left in `libcrux`, symmetric cipher, and crate stack frames in optimized builds
- Document the stack-space requirement (~84 KiB in optimized builds, up to about 350 KiB in debug builds, especially for `no_std` targets without guard pages) and what stays out of reach of stack wiping (CPU/vector registers, WASM locals, caller copies)
- Add an unpublished `tests/stack-probe` crate and run it in CI on `x86_64` (AVX2) and `aarch64` (NEON) across release, OpenSSL AES, `opt-level = "s"`, LTO, and portable `libcrux` builds

## 0.1.0

First release, compatible with `@ecies/post-quantum` 0.0.1 and 0.0.2.

- Add `config::SymmetricAlgorithm`, `config::NonceLength` and `consts::XCHACHA20_NONCE_LENGTH`: AES-256-GCM (16 or 12 bytes nonce) or XChaCha20-Poly1305 (24 bytes nonce), with the `nonce || tag || encrypted` layout of `@ecies/post-quantum`
- Add the `aes-openssl` feature to run AES-256-GCM on OpenSSL instead of pure Rust
- Add `encrypt`, `decrypt`, `encrypt_with_config` and `decrypt_with_config`, with the payload of `@ecies/post-quantum`: ML-KEM-512, 768 (default) or 1024, whose shared secret is the symmetric key
- Add `config::Config` and `config::AsymmetricAlgorithm`, with the same defaults as `@ecies/post-quantum`
- Add `SecretKey` (expanded FIPS 203 bytes, wiped on drop, compared in constant time, left out of `Debug`) and `PublicKey`
- Add `utils::generate_keypair`, and `utils::keypair_from_seed`, which derives the same keys as `@noble/post-quantum`'s `keygen(seed)`. `decrypt` also takes the 64-byte seed as the secret key
- Add `Seed` (64 bytes kept on the heap, wiped on drop, compared in constant time, left out of `Debug`) and `utils::generate_seed`, which draws one: the compact secret key to store, whose bytes `utils::keypair_from_seed` and `decrypt` take
- Add `Error`, including `RngFailure` for when the system random number generator fails
- Add `consts::ML_KEM_512_PKE_SIZE`, `ML_KEM_768_PKE_SIZE` and `ML_KEM_1024_PKE_SIZE`, the ML-KEM ciphertext lengths
- Set the MSRV to 1.94: libcrux-platform, pinned by libcrux-ml-kem, needs it on x86
- Mark `Error`, `config::AsymmetricAlgorithm` and `config::SymmetricAlgorithm` `#[non_exhaustive]`, so new variants are not breaking changes
- Run the test suite inside `wasm32-unknown-unknown`, build it for `wasm32-wasip2`, and check payloads against `@ecies/post-quantum` in both directions in CI
