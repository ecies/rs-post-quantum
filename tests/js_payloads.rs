use ecies_post_quantum::config::{AsymmetricAlgorithm, Config, NonceLength, SymmetricAlgorithm};
use ecies_post_quantum::decrypt_with_config;
use ecies_post_quantum::utils::keypair_from_seed;
// wasm-bindgen-test runs only its own test attribute
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

/// `encrypt(publicKey, "hello world", config)` of `@ecies/post-quantum` 0.0.2, to the keys that `keygen(seed)` derives
/// from the seed 0, 1, ..., 63. One per line: the config in its JS names, then the payload in hex.
///
/// Made by `node tests/js/payloads.mjs encrypt`, after `npm ci` in `tests/js`. CI also runs this test on fresh ones.
const JS_PAYLOADS: &str = include_str!("js_payloads.txt");

const MSG: &[u8] = b"hello world";

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

fn seed() -> [u8; 64] {
    core::array::from_fn(|i| i as u8)
}

fn js_payload(config_names: &str) -> Vec<u8> {
    let prefix = format!("{config_names} ");
    let line = JS_PAYLOADS
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no payload for {config_names}"));
    hex::decode(&line[prefix.len()..]).unwrap()
}

#[test]
fn decrypts_payloads_from_js() {
    for (asymmetric_algorithm, asymmetric_name) in ASYMMETRIC {
        let (sk, _) = keypair_from_seed(asymmetric_algorithm, &seed());
        for (symmetric_algorithm, symmetric_nonce_length, symmetric_names) in SYMMETRIC {
            let config = Config {
                asymmetric_algorithm,
                symmetric_algorithm,
                symmetric_nonce_length,
            };
            let payload = js_payload(&format!("{asymmetric_name} {symmetric_names}"));

            let by_seed = decrypt_with_config(&seed(), &payload, &config);
            assert_eq!(by_seed.as_deref(), Ok(MSG), "{config:?} seed");
            let by_expanded_key = decrypt_with_config(sk.as_bytes(), &payload, &config);
            assert_eq!(by_expanded_key.as_deref(), Ok(MSG), "{config:?} expanded key");
        }
    }
}
