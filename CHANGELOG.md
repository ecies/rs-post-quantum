# Changelog

## Unreleased

- Initial package structure
- Add `symmetric::sym_encrypt` and `symmetric::sym_decrypt`: AES-256-GCM (16 or 12 bytes nonce) or XChaCha20-Poly1305, with the `nonce || tag || encrypted` payload of `@ecies/post-quantum`
- Add the `aes-openssl` feature to run AES-256-GCM on OpenSSL instead of pure Rust
- Add `encrypt`, `decrypt`, `encrypt_with_config` and `decrypt_with_config`, with the payload of `@ecies/post-quantum`: ML-KEM-512, 768 (default) or 1024, whose shared secret is the symmetric key
- Add `config::Config` and `config::AsymmetricAlgorithm`, with the same defaults as `@ecies/post-quantum`
- Add `SecretKey` (expanded FIPS 203 bytes, wiped on drop, compared in constant time, left out of `Debug`) and `PublicKey`
- Add `utils::generate_keypair`, and `utils::keypair_from_seed`, which derives the same keys as `@noble/post-quantum`'s `keygen(seed)`. `decrypt` also takes the 64-byte seed as the secret key
- Add `Error`, including `RngFailure` for when the system random number generator fails
- Add `consts::ML_KEM_512_PKE_SIZE`, `ML_KEM_768_PKE_SIZE` and `ML_KEM_1024_PKE_SIZE`, the ML-KEM ciphertext lengths
- Set the MSRV to 1.94: libcrux-platform, pinned by libcrux-ml-kem, needs it on x86
- Mark `Error`, `config::AsymmetricAlgorithm` and `config::SymmetricAlgorithm` `#[non_exhaustive]`, so new variants are not breaking changes
