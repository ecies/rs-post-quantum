use ecies_post_quantum::config::{AsymmetricAlgorithm, Config};
use ecies_post_quantum::utils::keypair_from_seed;
use ecies_post_quantum::{Error, decrypt_with_config, encrypt_with_config};
use sha3::{Digest, Sha3_256};

const MSG: &[u8] = b"hello world";

/// The seed is the bytes 0 to 63. The fingerprints are SHA3-256 of the keys that
/// `@noble/post-quantum` 0.4.1's `keygen(seed)` returns, computed in Node.js.
const NOBLE_KEYS: [(AsymmetricAlgorithm, &str, &str); 3] = [
    (
        AsymmetricAlgorithm::MlKem512,
        "82f101ff648063b376e2bb6c5b7455f655a50c2feadade150efa0e0e6f365aea",
        "0bd3f5df01098ac9c29d687c7f1bd0588a5573feeef8f1e3b4573fa7f6ab57c8",
    ),
    (
        AsymmetricAlgorithm::MlKem768,
        "a24e16d8f8f9383a95b77050f4d9fd2f5733eec1d63ef3c23ebf9918173669a7",
        "1149f17c3c4ac6ab1e3e2d9d8bd0171355ac0fa31bb8855c48ceade874c0864b",
    ),
    (
        AsymmetricAlgorithm::MlKem1024,
        "61349e5c131a7e116a0463861d7d18663c5627c38c7147ddaadfd48acd7a4535",
        "f0db5d938027fcd9bad87847d52c14cf0c4abcf0703b749793f212111ffb303b",
    ),
];

fn seed() -> [u8; 64] {
    core::array::from_fn(|i| i as u8)
}

fn fingerprint(bytes: &[u8]) -> String {
    hex::encode(Sha3_256::digest(bytes))
}

#[test]
fn derives_the_same_keys_as_noble_from_a_seed() {
    for (algorithm, pk_fingerprint, sk_fingerprint) in NOBLE_KEYS {
        let (sk, pk) = keypair_from_seed(algorithm, &seed());
        assert_eq!(pk.algorithm(), algorithm);
        assert_eq!(fingerprint(pk.as_bytes()), pk_fingerprint, "{algorithm:?} public key");
        assert_eq!(fingerprint(sk.as_bytes()), sk_fingerprint, "{algorithm:?} secret key");
    }
}

#[test]
fn decrypts_with_the_seed_as_with_the_expanded_key() {
    for (asymmetric_algorithm, _, _) in NOBLE_KEYS {
        let config = Config {
            asymmetric_algorithm,
            ..Config::default()
        };
        let (sk, pk) = keypair_from_seed(asymmetric_algorithm, &seed());
        let encrypted = encrypt_with_config(pk.as_bytes(), MSG, &config).unwrap();

        let by_seed = decrypt_with_config(&seed(), &encrypted, &config);
        assert_eq!(by_seed.as_deref(), Ok(MSG), "{asymmetric_algorithm:?} seed");
        let by_expanded_key = decrypt_with_config(sk.as_bytes(), &encrypted, &config);
        assert_eq!(
            by_expanded_key.as_deref(),
            Ok(MSG),
            "{asymmetric_algorithm:?} expanded key"
        );
    }
}

#[test]
fn rejects_a_payload_for_another_seed() {
    // a byte of d, which the key pair is derived from. z, the last 32 bytes, only feeds implicit rejection, so a
    // seed that differs only there still decrypts every valid payload
    let mut other_seed = seed();
    other_seed[0] ^= 1;
    for (asymmetric_algorithm, _, _) in NOBLE_KEYS {
        let config = Config {
            asymmetric_algorithm,
            ..Config::default()
        };
        let (_, pk) = keypair_from_seed(asymmetric_algorithm, &seed());
        let encrypted = encrypt_with_config(pk.as_bytes(), MSG, &config).unwrap();

        // any 64 bytes are a valid seed, so a wrong one fails at authentication, like a wrong expanded key
        let result = decrypt_with_config(&other_seed, &encrypted, &config);
        assert_eq!(result, Err(Error::InvalidMessage), "{asymmetric_algorithm:?}");
    }
}
