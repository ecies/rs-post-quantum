use alloc::vec::Vec;
use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::config::AsymmetricAlgorithm;
use crate::error::Error;
use crate::kem::{self, SEED_LENGTH};

/// An ML-KEM secret key, as the expanded FIPS 203 decapsulation key that `@ecies/post-quantum` uses.
///
/// Its bytes are zeroized on drop, compared in constant time, and left out of `Debug`.
pub struct SecretKey {
    algorithm: AsymmetricAlgorithm,
    bytes: Vec<u8>,
}

impl SecretKey {
    /// The ML-KEM parameter set
    pub fn algorithm(&self) -> AsymmetricAlgorithm {
        self.algorithm
    }

    /// The expanded key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        // each parameter set has its own key length, so the bytes alone tell them apart
        bool::from(self.bytes.ct_eq(&other.bytes))
    }
}

impl Eq for SecretKey {}

/// An ML-KEM public key, as the FIPS 203 encapsulation key
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PublicKey {
    algorithm: AsymmetricAlgorithm,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// The ML-KEM parameter set
    pub fn algorithm(&self) -> AsymmetricAlgorithm {
        self.algorithm
    }

    /// The key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Generates a key pair from the system random number generator
pub fn generate_keypair(algorithm: AsymmetricAlgorithm) -> Result<(SecretKey, PublicKey), Error> {
    let mut seed = Zeroizing::new([0u8; SEED_LENGTH]);
    getrandom::fill(seed.as_mut()).map_err(|_| Error::RngFailure)?;
    Ok(keypair_from_seed(algorithm, &seed))
}

/// Derives a key pair from a 64 bytes seed (`d || z` in FIPS 203), the same as `keygen(seed)` in `@noble/post-quantum`.
///
/// The seed is a compact form of the secret key: [`decrypt`](crate::decrypt) accepts it too.
pub fn keypair_from_seed(algorithm: AsymmetricAlgorithm, seed: &[u8; SEED_LENGTH]) -> (SecretKey, PublicKey) {
    let (secret_key, public_key) = kem::keypair_from_seed(algorithm, seed);
    (
        SecretKey {
            algorithm,
            bytes: secret_key,
        },
        PublicKey {
            algorithm,
            bytes: public_key,
        },
    )
}
