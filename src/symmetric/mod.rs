use chacha20poly1305::XChaCha20Poly1305;

use alloc::vec::Vec;

use crate::config::{NonceLength, SymmetricAlgorithm};
use crate::consts::XCHACHA20_NONCE_LENGTH;
use crate::error::Error;

mod aead;
#[cfg(feature = "aes-openssl")]
mod openssl_aes;

// pure Rust AES-256-GCM, also built with `aes-openssl` in tests to check both backends agree
#[cfg(any(test, not(feature = "aes-openssl")))]
type Aes256Gcm12 = aes_gcm::AesGcm<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U12>;
#[cfg(any(test, not(feature = "aes-openssl")))]
type Aes256Gcm16 = aes_gcm::AesGcm<aes_gcm::aes::Aes256, aes_gcm::aead::consts::U16>;

/// Symmetric encryption with a random nonce, appending `nonce || tag || encrypted` to `output`, which is left as it
/// was on failure.
///
/// Fails with [`Error::RngFailure`] if no nonce can be drawn, and with [`Error::InvalidMessage`] if the cipher fails.
pub(crate) fn sym_encrypt_into(
    output: &mut Vec<u8>,
    algorithm: SymmetricAlgorithm,
    nonce_length: NonceLength,
    key: &[u8],
    plain: &[u8],
) -> Result<(), Error> {
    let nonce_size = match algorithm {
        SymmetricAlgorithm::Aes256Gcm => nonce_length as usize,
        SymmetricAlgorithm::XChaCha20 => XCHACHA20_NONCE_LENGTH,
    };
    let mut nonce = [0u8; XCHACHA20_NONCE_LENGTH];
    let nonce = &mut nonce[..nonce_size];
    getrandom::fill(nonce).map_err(|_| Error::RngFailure)?;
    encrypt_into_with_nonce(output, algorithm, nonce_length, key, nonce, plain).ok_or(Error::InvalidMessage)
}

/// Appends `nonce || tag || encrypted` to `output`, using the given nonce.
///
/// On failure, `output` is left as it was.
fn encrypt_into_with_nonce(
    output: &mut Vec<u8>,
    algorithm: SymmetricAlgorithm,
    nonce_length: NonceLength,
    key: &[u8],
    nonce: &[u8],
    plain: &[u8],
) -> Option<()> {
    match algorithm {
        SymmetricAlgorithm::Aes256Gcm => aes_encrypt_into(output, nonce_length, key, nonce, plain),
        SymmetricAlgorithm::XChaCha20 => aead::encrypt_into::<XChaCha20Poly1305>(output, key, nonce, plain),
    }
}

/// Symmetric decryption of a `nonce || tag || encrypted` payload.
///
/// Returns `None` if the key or payload is malformed, or if authentication fails.
pub(crate) fn sym_decrypt(
    algorithm: SymmetricAlgorithm,
    nonce_length: NonceLength,
    key: &[u8],
    encrypted: &[u8],
) -> Option<Vec<u8>> {
    match algorithm {
        SymmetricAlgorithm::Aes256Gcm => aes_decrypt(nonce_length, key, encrypted),
        SymmetricAlgorithm::XChaCha20 => aead::decrypt::<XChaCha20Poly1305>(key, encrypted),
    }
}

#[cfg(not(feature = "aes-openssl"))]
fn aes_encrypt_into(
    output: &mut Vec<u8>,
    nonce_length: NonceLength,
    key: &[u8],
    nonce: &[u8],
    plain: &[u8],
) -> Option<()> {
    match nonce_length {
        NonceLength::Sixteen => aead::encrypt_into::<Aes256Gcm16>(output, key, nonce, plain),
        NonceLength::Twelve => aead::encrypt_into::<Aes256Gcm12>(output, key, nonce, plain),
    }
}

#[cfg(not(feature = "aes-openssl"))]
fn aes_decrypt(nonce_length: NonceLength, key: &[u8], encrypted: &[u8]) -> Option<Vec<u8>> {
    match nonce_length {
        NonceLength::Sixteen => aead::decrypt::<Aes256Gcm16>(key, encrypted),
        NonceLength::Twelve => aead::decrypt::<Aes256Gcm12>(key, encrypted),
    }
}

#[cfg(feature = "aes-openssl")]
fn aes_encrypt_into(
    output: &mut Vec<u8>,
    nonce_length: NonceLength,
    key: &[u8],
    nonce: &[u8],
    plain: &[u8],
) -> Option<()> {
    if nonce.len() != nonce_length as usize {
        return None;
    }
    openssl_aes::encrypt_into(output, key, nonce, plain)
}

#[cfg(feature = "aes-openssl")]
fn aes_decrypt(nonce_length: NonceLength, key: &[u8], encrypted: &[u8]) -> Option<Vec<u8>> {
    openssl_aes::decrypt(key, nonce_length as usize, encrypted)
}

#[cfg(test)]
mod tests;
