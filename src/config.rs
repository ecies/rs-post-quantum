/// Symmetric cipher algorithm, `symmetricAlgorithm` in JS
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum SymmetricAlgorithm {
    /// AES-256-GCM, `"aes-256-gcm"` in JS
    #[default]
    Aes256Gcm,
    /// XChaCha20-Poly1305, `"xchacha20"` in JS
    XChaCha20,
}

/// AES-256-GCM nonce length, `symmetricNonceLength` in JS. `nonce_length as usize` gives the bytes.
///
/// XChaCha20-Poly1305 ignores it and always uses a 24 bytes nonce.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum NonceLength {
    /// 12 bytes
    Twelve = 12,
    /// 16 bytes
    #[default]
    Sixteen = 16,
}
