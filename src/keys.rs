use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::config::AsymmetricAlgorithm;
use crate::error::Error;
use crate::kem::{self, SEED_LENGTH};

/// An ML-KEM secret key in expanded FIPS 203 decapsulation-key format (matching `@ecies/post-quantum`).
///
/// Its bytes are zeroized on drop, compared in constant time, and redacted from `Debug`.
pub struct SecretKey {
    algorithm: AsymmetricAlgorithm,
    bytes: Vec<u8>,
}

impl SecretKey {
    /// Returns the ML-KEM parameter set of this key.
    pub fn algorithm(&self) -> AsymmetricAlgorithm {
        self.algorithm
    }

    /// Returns the expanded secret key bytes.
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

/// An ML-KEM public key in FIPS 203 encapsulation-key format.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct PublicKey {
    algorithm: AsymmetricAlgorithm,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Returns the ML-KEM parameter set of this key.
    pub fn algorithm(&self) -> AsymmetricAlgorithm {
        self.algorithm
    }

    /// Returns the public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A 64-byte ML-KEM seed (`d || z` in FIPS 203): the compact representation of a secret key for any parameter set.
///
/// Its bytes are heap-allocated so moving a `Seed` does not copy them. They are zeroized on drop, compared in
/// constant time, and redacted from `Debug`.
pub struct Seed(Box<[u8; SEED_LENGTH]>);

impl Seed {
    /// Returns the 64-byte seed, which can be passed to [`keypair_from_seed`] or [`decrypt`](crate::decrypt).
    pub fn as_bytes(&self) -> &[u8; SEED_LENGTH] {
        &self.0
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Seed").finish_non_exhaustive()
    }
}

impl PartialEq for Seed {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0[..].ct_eq(&other.0[..]))
    }
}

impl Eq for Seed {}

/// Generates a key pair from the system random number generator.
pub fn generate_keypair(algorithm: AsymmetricAlgorithm) -> Result<(SecretKey, PublicKey), Error> {
    let seed = generate_seed()?;
    Ok(keypair_from_seed(algorithm, seed.as_bytes()))
}

/// Generates a 64-byte [`Seed`] from the system random number generator.
///
/// Store the seed instead of the much larger expanded key, derive the public key with [`keypair_from_seed`], and pass
/// the seed bytes (or the expanded key) to [`decrypt`](crate::decrypt). A seed does not record its parameter set, so
/// derive keys and decrypt with the same [`AsymmetricAlgorithm`]. `Seed` is zeroized on drop, but any copies you store
/// are your responsibility to protect.
///
/// ```
/// use ecies_post_quantum::config::AsymmetricAlgorithm;
/// use ecies_post_quantum::utils::{generate_seed, keypair_from_seed};
/// use ecies_post_quantum::{decrypt, encrypt};
///
/// let seed = generate_seed().unwrap();
/// let (_, pk) = keypair_from_seed(AsymmetricAlgorithm::MlKem768, seed.as_bytes());
///
/// let encrypted = encrypt(pk.as_bytes(), b"hello").unwrap();
/// assert_eq!(decrypt(seed.as_bytes(), &encrypted).unwrap(), b"hello");
/// ```
pub fn generate_seed() -> Result<Seed, Error> {
    // filled in place on the heap, so no copy is left in this frame
    let mut seed = Seed(Box::new([0u8; SEED_LENGTH]));
    getrandom::fill(&mut seed.0[..]).map_err(|_| Error::RngFailure)?;
    Ok(seed)
}

/// Deterministically derives a key pair from a 64-byte seed (`d || z` in FIPS 203), matching `keygen(seed)` in
/// `@noble/post-quantum`.
///
/// [`decrypt`](crate::decrypt) also accepts the seed directly as the secret key.
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

#[cfg(test)]
mod tests {
    // wasm-bindgen-test runs only its own test attribute
    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    use super::*;

    #[test]
    fn seeds_are_equal_only_with_every_byte_the_same() {
        // `generate_seed` never gives two seeds one byte apart, so they are built here
        let seed = |bytes: [u8; SEED_LENGTH]| Seed(Box::new(bytes));
        assert!(seed([7u8; SEED_LENGTH]) == seed([7u8; SEED_LENGTH]));

        for position in 0..SEED_LENGTH {
            let mut one_byte_changed = [7u8; SEED_LENGTH];
            one_byte_changed[position] = 8;
            assert!(seed([7u8; SEED_LENGTH]) != seed(one_byte_changed), "byte {position}");
        }
    }
}
