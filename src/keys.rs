use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

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

/// A 64 bytes ML-KEM seed (`d || z` in FIPS 203): the compact form of a secret key, for any parameter set.
///
/// Its bytes are kept on the heap, so moving a `Seed` doesn't copy them. They are zeroized on drop, compared in
/// constant time, and left out of `Debug`.
pub struct Seed(Box<[u8; SEED_LENGTH]>);

impl Seed {
    /// The seed bytes, which [`keypair_from_seed`] and [`decrypt`](crate::decrypt) take
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

/// Generates a key pair from the system random number generator
pub fn generate_keypair(algorithm: AsymmetricAlgorithm) -> Result<(SecretKey, PublicKey), Error> {
    let seed = generate_seed()?;
    Ok(keypair_from_seed(algorithm, seed.as_bytes()))
}

/// Draws a [`Seed`] from the system random number generator.
///
/// The seed is the compact form of a secret key: store it instead of the expanded key, derive the public key with
/// [`keypair_from_seed`], and pass its bytes to [`decrypt`](crate::decrypt) as the secret key. It doesn't record the
/// parameter set, so derive the keys and decrypt with the same one. The `Seed` is wiped on drop, but copies of its
/// bytes, such as the stored one, are up to the caller.
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
