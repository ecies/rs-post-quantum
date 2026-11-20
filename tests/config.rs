use ecies_post_quantum::config::{AsymmetricAlgorithm, Config, NonceLength, SymmetricAlgorithm};
// wasm-bindgen-test runs only its own test attribute
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[test]
fn defaults_match_js() {
    // `@ecies/post-quantum`'s `config.ts`: "ml-kem-768", "aes-256-gcm", 16
    let js_defaults = Config {
        asymmetric_algorithm: AsymmetricAlgorithm::MlKem768,
        symmetric_algorithm: SymmetricAlgorithm::Aes256Gcm,
        symmetric_nonce_length: NonceLength::Sixteen,
    };
    assert_eq!(Config::default(), js_defaults);
}
