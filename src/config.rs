/// Encryption configuration, `Config` in JS. Both sides of a message must use the same one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct Config {
    /// ML-KEM parameter set
    pub asymmetric_algorithm: AsymmetricAlgorithm,
    /// Symmetric cipher
    pub symmetric_algorithm: SymmetricAlgorithm,
    /// AES-256-GCM nonce length, ignored by XChaCha20-Poly1305
    pub symmetric_nonce_length: NonceLength,
}

/// ML-KEM parameter set, `asymmetricAlgorithm` in JS
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum AsymmetricAlgorithm {
    /// ML-KEM-512, `"ml-kem-512"` in JS
    MlKem512,
    /// ML-KEM-768, `"ml-kem-768"` in JS, which NIST recommends as the default
    #[default]
    MlKem768,
    /// ML-KEM-1024, `"ml-kem-1024"` in JS
    MlKem1024,
}

/// Symmetric cipher algorithm, `symmetricAlgorithm` in JS
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[non_exhaustive]
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
