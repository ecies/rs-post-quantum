use alloc::vec::Vec;

use zeroize::{Zeroize, Zeroizing};

use crate::config::AsymmetricAlgorithm;
use crate::consts::{ML_KEM_512_PKE_SIZE, ML_KEM_768_PKE_SIZE, ML_KEM_1024_PKE_SIZE};
use crate::error::Error;

/// Key generation seed length: `d || z` in FIPS 203
pub(crate) const SEED_LENGTH: usize = 64;

/// The ML-KEM shared secret, used directly as the symmetric key
pub(crate) type SharedSecret = Zeroizing<[u8; 32]>;

/// ML-KEM ciphertext length for the parameter set
pub(crate) fn ciphertext_length(algorithm: AsymmetricAlgorithm) -> usize {
    match algorithm {
        AsymmetricAlgorithm::MlKem512 => ML_KEM_512_PKE_SIZE,
        AsymmetricAlgorithm::MlKem768 => ML_KEM_768_PKE_SIZE,
        AsymmetricAlgorithm::MlKem1024 => ML_KEM_1024_PKE_SIZE,
    }
}

/// Returns `(expanded secret key, public key)`
pub(crate) fn keypair_from_seed(algorithm: AsymmetricAlgorithm, seed: &[u8; SEED_LENGTH]) -> (Vec<u8>, Vec<u8>) {
    match algorithm {
        AsymmetricAlgorithm::MlKem512 => ml_kem_512::keypair_from_seed(seed),
        AsymmetricAlgorithm::MlKem768 => ml_kem_768::keypair_from_seed(seed),
        AsymmetricAlgorithm::MlKem1024 => ml_kem_1024::keypair_from_seed(seed),
    }
}

/// Checks the public key, then returns `(ciphertext, shared secret)` from fresh randomness
pub(crate) fn encapsulate(algorithm: AsymmetricAlgorithm, public_key: &[u8]) -> Result<(Vec<u8>, SharedSecret), Error> {
    match algorithm {
        AsymmetricAlgorithm::MlKem512 => ml_kem_512::encapsulate(public_key),
        AsymmetricAlgorithm::MlKem768 => ml_kem_768::encapsulate(public_key),
        AsymmetricAlgorithm::MlKem1024 => ml_kem_1024::encapsulate(public_key),
    }
}

/// Checks the expanded secret key, then returns the shared secret
pub(crate) fn decapsulate(
    algorithm: AsymmetricAlgorithm,
    secret_key: &[u8],
    ciphertext: &[u8],
) -> Result<SharedSecret, Error> {
    match algorithm {
        AsymmetricAlgorithm::MlKem512 => ml_kem_512::decapsulate(secret_key, ciphertext),
        AsymmetricAlgorithm::MlKem768 => ml_kem_768::decapsulate(secret_key, ciphertext),
        AsymmetricAlgorithm::MlKem1024 => ml_kem_1024::decapsulate(secret_key, ciphertext),
    }
}

macro_rules! parameter_set {
    ($module:ident, $kem:ident, $PublicKey:ident, $PrivateKey:ident, $Ciphertext:ident) => {
        mod $module {
            use libcrux_ml_kem::$kem::{self, $Ciphertext, $PrivateKey, $PublicKey};

            use super::*;

            pub(super) fn keypair_from_seed(seed: &[u8; SEED_LENGTH]) -> (Vec<u8>, Vec<u8>) {
                let (mut secret_key, public_key) = $kem::generate_key_pair(*seed).into_parts();
                let keys = (secret_key.as_slice().to_vec(), public_key.as_slice().to_vec());
                secret_key[0..].zeroize();
                keys
            }

            pub(super) fn encapsulate(public_key: &[u8]) -> Result<(Vec<u8>, SharedSecret), Error> {
                let public_key = $PublicKey::try_from(public_key).map_err(|_| Error::InvalidPublicKey)?;
                // the modulus check of FIPS 203, 7.2
                if !$kem::validate_public_key(&public_key) {
                    return Err(Error::InvalidPublicKey);
                }

                let mut randomness = Zeroizing::new([0u8; 32]);
                getrandom::fill(randomness.as_mut()).map_err(|_| Error::RngFailure)?;
                let (ciphertext, shared_secret) = $kem::encapsulate(&public_key, *randomness);
                Ok((ciphertext.as_slice().to_vec(), Zeroizing::new(shared_secret)))
            }

            pub(super) fn decapsulate(secret_key: &[u8], ciphertext: &[u8]) -> Result<SharedSecret, Error> {
                // before the key is copied, so the copy is wiped on every path after it
                let ciphertext = $Ciphertext::try_from(ciphertext).map_err(|_| Error::InvalidMessage)?;
                let mut secret_key = $PrivateKey::try_from(secret_key).map_err(|_| Error::InvalidSecretKey)?;

                // the hash check of FIPS 203, 7.3
                let shared_secret = $kem::validate_private_key(&secret_key, &ciphertext)
                    .then(|| Zeroizing::new($kem::decapsulate(&secret_key, &ciphertext)));
                secret_key[0..].zeroize();
                shared_secret.ok_or(Error::InvalidSecretKey)
            }
        }
    };
}

parameter_set!(
    ml_kem_512,
    mlkem512,
    MlKem512PublicKey,
    MlKem512PrivateKey,
    MlKem512Ciphertext
);
parameter_set!(
    ml_kem_768,
    mlkem768,
    MlKem768PublicKey,
    MlKem768PrivateKey,
    MlKem768Ciphertext
);
parameter_set!(
    ml_kem_1024,
    mlkem1024,
    MlKem1024PublicKey,
    MlKem1024PrivateKey,
    MlKem1024Ciphertext
);
