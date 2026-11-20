use ecies_post_quantum::config::{AsymmetricAlgorithm, Config, SymmetricAlgorithm};
use ecies_post_quantum::utils::generate_keypair;
use ecies_post_quantum::{Error, decrypt, decrypt_with_config, encrypt, encrypt_with_config};
// wasm-bindgen-test runs only its own test attribute
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

const MSG: &[u8] = b"hello world";

/// ML-KEM-768: k = 3, so the expanded secret key is `dk_pke (1152) || ek (1184) || H(ek) (32) || z (32)`
const DK_PKE_END: usize = 384 * 3;
const EK_END: usize = DK_PKE_END + 1184;

#[test]
fn rejects_a_payload_for_another_key() {
    let (_, pk) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
    let (other_sk, _) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
    let encrypted = encrypt(pk.as_bytes(), MSG).unwrap();

    assert_eq!(decrypt(other_sk.as_bytes(), &encrypted), Err(Error::InvalidMessage));
}

#[test]
fn rejects_truncated_payloads() {
    let (sk, pk) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
    let encrypted = encrypt(pk.as_bytes(), MSG).unwrap();

    // empty, inside the ML-KEM ciphertext, just the ciphertext, inside the nonce and tag, and one byte short
    for length in [0, 1087, 1088, 1088 + 31, encrypted.len() - 1] {
        let result = decrypt(sk.as_bytes(), &encrypted[..length]);
        assert_eq!(result, Err(Error::InvalidMessage), "{length} bytes");
    }
}

#[test]
fn rejects_keys_of_the_wrong_length() {
    let (sk, pk) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
    let encrypted = encrypt(pk.as_bytes(), MSG).unwrap();

    for length in [0, 1183, 1185] {
        let mut pk = pk.as_bytes().to_vec();
        pk.resize(length, 0);
        assert_eq!(encrypt(&pk, MSG), Err(Error::InvalidPublicKey), "{length} bytes");
    }
    // 64 bytes is a seed, so it is left out here
    for length in [0, 63, 65, 2399, 2401] {
        let mut sk = sk.as_bytes().to_vec();
        sk.resize(length, 0);
        assert_eq!(decrypt(&sk, &encrypted), Err(Error::InvalidSecretKey), "{length} bytes");
    }
}

#[test]
fn rejects_a_public_key_that_fails_the_modulus_check() {
    let (_, pk) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
    let mut pk = pk.as_bytes().to_vec();
    // the first 12-bit coefficient becomes 4095, above q = 3329
    pk[0] = 0xff;
    pk[1] |= 0x0f;

    assert_eq!(encrypt(&pk, MSG), Err(Error::InvalidPublicKey));
}

#[test]
fn rejects_a_secret_key_whose_public_part_is_corrupted() {
    let (sk, pk) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
    let encrypted = encrypt(pk.as_bytes(), MSG).unwrap();

    // a byte of ek, and a byte of H(ek): either breaks the hash check
    for position in [DK_PKE_END, EK_END] {
        let mut sk = sk.as_bytes().to_vec();
        sk[position] ^= 1;
        assert_eq!(
            decrypt(&sk, &encrypted),
            Err(Error::InvalidSecretKey),
            "byte {position}"
        );
    }
}

#[test]
fn rejects_a_secret_key_whose_decryption_part_is_corrupted() {
    let (sk, pk) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
    let encrypted = encrypt(pk.as_bytes(), MSG).unwrap();

    // the hash covers only ek, so a zeroed dk_pke passes it, and fails at authentication instead
    let mut sk = sk.as_bytes().to_vec();
    sk[..DK_PKE_END].fill(0);
    assert_eq!(decrypt(&sk, &encrypted), Err(Error::InvalidMessage));
}

#[test]
fn rejects_keys_from_another_parameter_set() {
    let (sk_768, pk_768) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
    let (sk_512, pk_512) = generate_keypair(AsymmetricAlgorithm::MlKem512).unwrap();
    let encrypted = encrypt(pk_768.as_bytes(), MSG).unwrap();

    assert_eq!(encrypt(pk_512.as_bytes(), MSG), Err(Error::InvalidPublicKey));
    assert_eq!(decrypt(sk_512.as_bytes(), &encrypted), Err(Error::InvalidSecretKey));

    let config_512 = Config {
        asymmetric_algorithm: AsymmetricAlgorithm::MlKem512,
        ..Config::default()
    };
    assert_eq!(
        encrypt_with_config(pk_768.as_bytes(), MSG, &config_512),
        Err(Error::InvalidPublicKey)
    );
    assert_eq!(
        decrypt_with_config(sk_768.as_bytes(), &encrypted, &config_512),
        Err(Error::InvalidSecretKey)
    );
}

#[test]
fn describes_each_error() {
    let messages = [
        (Error::InvalidPublicKey, "invalid public key"),
        (Error::InvalidSecretKey, "invalid secret key"),
        (Error::InvalidMessage, "invalid message"),
        (Error::RngFailure, "random number generator failed"),
    ];
    for (error, message) in messages {
        // through `dyn Error`, so callers can use `?` into `Box<dyn Error>`
        let error: Box<dyn std::error::Error> = Box::new(error);
        assert_eq!(error.to_string(), message);
    }
}

#[test]
fn rejects_a_payload_decrypted_with_another_cipher() {
    let (sk, pk) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
    let encrypted = encrypt(pk.as_bytes(), MSG).unwrap();
    let xchacha20 = Config {
        symmetric_algorithm: SymmetricAlgorithm::XChaCha20,
        ..Config::default()
    };

    assert_eq!(
        decrypt_with_config(sk.as_bytes(), &encrypted, &xchacha20),
        Err(Error::InvalidMessage)
    );
}
