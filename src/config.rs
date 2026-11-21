/// Encryption configuration (matches `Config` in `@ecies/post-quantum`). Both sides must use the same config.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct Config {
    /// ML-KEM parameter set.
    pub asymmetric_algorithm: AsymmetricAlgorithm,
    /// Symmetric authenticated cipher.
    pub symmetric_algorithm: SymmetricAlgorithm,
    /// AES-256-GCM nonce length (ignored by XChaCha20-Poly1305).
    pub symmetric_nonce_length: NonceLength,
}

/// ML-KEM parameter set (`asymmetricAlgorithm` in JS).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum AsymmetricAlgorithm {
    /// ML-KEM-512 (`"ml-kem-512"` in JS).
    MlKem512,
    /// ML-KEM-768 (`"ml-kem-768"` in JS), the NIST-recommended default.
    #[default]
    MlKem768,
    /// ML-KEM-1024 (`"ml-kem-1024"` in JS).
    MlKem1024,
}

/// Symmetric cipher algorithm (`symmetricAlgorithm` in JS).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum SymmetricAlgorithm {
    /// AES-256-GCM (`"aes-256-gcm"` in JS).
    #[default]
    Aes256Gcm,
    /// XChaCha20-Poly1305 (`"xchacha20"` in JS).
    XChaCha20,
}

/// AES-256-GCM nonce length (`symmetricNonceLength` in JS). Cast with `as usize` to get the byte length.
///
/// XChaCha20-Poly1305 ignores this setting and always uses a 24-byte nonce.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum NonceLength {
    /// 12-byte nonce.
    Twelve = 12,
    /// 16-byte nonce.
    #[default]
    Sixteen = 16,
}
