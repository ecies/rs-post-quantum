# Changelog

## Unreleased

- Initial package structure
- Add `symmetric::sym_encrypt` and `symmetric::sym_decrypt`: AES-256-GCM (16 or 12 bytes nonce) or XChaCha20-Poly1305, with the `nonce || tag || encrypted` payload of `@ecies/post-quantum`
- Add the `aes-openssl` feature to run AES-256-GCM on OpenSSL instead of pure Rust
