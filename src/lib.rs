#![doc = include_str!("../README.md")]
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

/// Encryption configuration.
pub mod config;
/// Wire-format size constants.
pub mod consts;
/// Key and seed generation helpers.
pub mod utils;

mod error;
mod kem;
mod keys;
mod symmetric;

use alloc::vec::Vec;

use config::Config;
pub use error::Error;
pub use keys::{PublicKey, SecretKey, Seed};

/// Encrypts `msg` to an ML-KEM-768 public key using the default [`Config`].
///
/// Returns `ML-KEM ciphertext || nonce || tag || encrypted`.
pub fn encrypt(receiver_pk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt_with_config(receiver_pk, msg, &Config::default())
}

/// Decrypts a payload from [`encrypt`] using the receiver's ML-KEM-768 secret key (either the expanded key or its
/// 64-byte seed).
pub fn decrypt(receiver_sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    decrypt_with_config(receiver_sk, msg, &Config::default())
}

/// Encrypts `msg` to a public key matching `config.asymmetric_algorithm`.
///
/// Returns `ML-KEM ciphertext || nonce || tag || encrypted`.
pub fn encrypt_with_config(receiver_pk: &[u8], msg: &[u8], config: &Config) -> Result<Vec<u8>, Error> {
    let (mut payload, shared_secret) = kem::encapsulate(config.asymmetric_algorithm, receiver_pk)?;
    symmetric::sym_encrypt_into(
        &mut payload,
        config.symmetric_algorithm,
        config.symmetric_nonce_length,
        &shared_secret[..],
        msg,
    )?;
    Ok(payload)
}

/// Decrypts a payload from [`encrypt_with_config`] using the same `config` and the receiver's secret key (either the
/// expanded key or its 64-byte seed).
pub fn decrypt_with_config(receiver_sk: &[u8], msg: &[u8], config: &Config) -> Result<Vec<u8>, Error> {
    let ciphertext_length = kem::ciphertext_length(config.asymmetric_algorithm);
    if msg.len() < ciphertext_length {
        return Err(Error::InvalidMessage);
    }

    let (ciphertext, encrypted) = msg.split_at(ciphertext_length);
    let shared_secret = kem::decapsulate(config.asymmetric_algorithm, receiver_sk, ciphertext)?;
    symmetric::sym_decrypt(
        config.symmetric_algorithm,
        config.symmetric_nonce_length,
        &shared_secret[..],
        encrypted,
    )
    .ok_or(Error::InvalidMessage)
}
