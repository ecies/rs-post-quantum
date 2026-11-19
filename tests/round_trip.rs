use ecies_post_quantum::config::{AsymmetricAlgorithm, Config, NonceLength, SymmetricAlgorithm};
use ecies_post_quantum::utils::generate_keypair;
use ecies_post_quantum::{decrypt, decrypt_with_config, encrypt, encrypt_with_config};

const MSG: &[u8] = "hello world🌍".as_bytes();

/// (parameter set, public key, expanded secret key and ciphertext lengths), from FIPS 203 table 3
const LEVELS: [(AsymmetricAlgorithm, usize, usize, usize); 3] = [
    (AsymmetricAlgorithm::MlKem512, 800, 1632, 768),
    (AsymmetricAlgorithm::MlKem768, 1184, 2400, 1088),
    (AsymmetricAlgorithm::MlKem1024, 1568, 3168, 1568),
];

/// (cipher, nonce setting, nonce length in the payload)
const CIPHERS: [(SymmetricAlgorithm, NonceLength, usize); 3] = [
    (SymmetricAlgorithm::Aes256Gcm, NonceLength::Sixteen, 16),
    (SymmetricAlgorithm::Aes256Gcm, NonceLength::Twelve, 12),
    (SymmetricAlgorithm::XChaCha20, NonceLength::Sixteen, 24),
];

#[test]
fn round_trips_with_the_default_config() {
    let (sk, pk) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
    let encrypted = encrypt(pk.as_bytes(), MSG).unwrap();

    // ML-KEM-768 ciphertext, 16 bytes nonce, tag, then the message
    assert_eq!(encrypted.len(), 1088 + 16 + 16 + MSG.len());
    assert_eq!(decrypt(sk.as_bytes(), &encrypted).unwrap(), MSG);
}

#[test]
fn round_trips_with_every_config() {
    let large: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();

    for (asymmetric_algorithm, pk_length, sk_length, ciphertext_length) in LEVELS {
        let (sk, pk) = generate_keypair(asymmetric_algorithm).unwrap();
        assert_eq!((pk.algorithm(), pk.as_bytes().len()), (asymmetric_algorithm, pk_length));
        assert_eq!((sk.algorithm(), sk.as_bytes().len()), (asymmetric_algorithm, sk_length));

        for (symmetric_algorithm, symmetric_nonce_length, nonce_length) in CIPHERS {
            let config = Config {
                asymmetric_algorithm,
                symmetric_algorithm,
                symmetric_nonce_length,
            };
            for msg in [&b""[..], MSG, &large] {
                let encrypted = encrypt_with_config(pk.as_bytes(), msg, &config).unwrap();
                let expected_length = ciphertext_length + nonce_length + 16 + msg.len();
                assert_eq!(encrypted.len(), expected_length, "{config:?}");

                let decrypted = decrypt_with_config(sk.as_bytes(), &encrypted, &config).unwrap();
                assert!(decrypted == msg, "{config:?}, {} bytes", msg.len());
            }
        }
    }
}
