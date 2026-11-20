//! Prints a payload per config for `node tests/js/payloads.mjs decrypt`, in the format of `tests/js_payloads.txt`:
//! "hello world" encrypted to the keys of the seed 0, 1, ..., 63.

use ecies_post_quantum::config::{AsymmetricAlgorithm, Config, NonceLength, SymmetricAlgorithm};
use ecies_post_quantum::encrypt_with_config;
use ecies_post_quantum::utils::keypair_from_seed;

const ASYMMETRIC: [(AsymmetricAlgorithm, &str); 3] = [
    (AsymmetricAlgorithm::MlKem512, "ml-kem-512"),
    (AsymmetricAlgorithm::MlKem768, "ml-kem-768"),
    (AsymmetricAlgorithm::MlKem1024, "ml-kem-1024"),
];

const SYMMETRIC: [(SymmetricAlgorithm, NonceLength, &str); 3] = [
    (SymmetricAlgorithm::Aes256Gcm, NonceLength::Sixteen, "aes-256-gcm 16"),
    (SymmetricAlgorithm::Aes256Gcm, NonceLength::Twelve, "aes-256-gcm 12"),
    (SymmetricAlgorithm::XChaCha20, NonceLength::Sixteen, "xchacha20 16"),
];

fn main() {
    let seed = core::array::from_fn(|i| i as u8);
    for (asymmetric_algorithm, asymmetric_name) in ASYMMETRIC {
        let (_, pk) = keypair_from_seed(asymmetric_algorithm, &seed);
        for (symmetric_algorithm, symmetric_nonce_length, symmetric_names) in SYMMETRIC {
            let config = Config {
                asymmetric_algorithm,
                symmetric_algorithm,
                symmetric_nonce_length,
            };
            let payload = encrypt_with_config(pk.as_bytes(), b"hello world", &config).unwrap();
            println!("{asymmetric_name} {symmetric_names} {}", hex::encode(payload));
        }
    }
}
