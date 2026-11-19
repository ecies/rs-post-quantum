use alloc::vec::Vec;

use super::{encrypt_into_with_nonce, sym_decrypt, sym_encrypt, sym_encrypt_into};
use crate::config::{NonceLength, SymmetricAlgorithm};
use crate::error::Error;

/// A known vector, copied from eciesrs, which uses the same `nonce || tag || encrypted` layout
struct Known {
    algorithm: SymmetricAlgorithm,
    nonce_length: NonceLength,
    key: &'static str,
    nonce: &'static str,
    tag: &'static str,
    encrypted: &'static str,
    plain: &'static [u8],
}

impl Known {
    fn key(&self) -> Vec<u8> {
        hex::decode(self.key).unwrap()
    }

    fn nonce(&self) -> Vec<u8> {
        hex::decode(self.nonce).unwrap()
    }

    /// `nonce || tag || encrypted`
    fn payload(&self) -> Vec<u8> {
        [self.nonce, self.tag, self.encrypted]
            .map(|part| hex::decode(part).unwrap())
            .concat()
    }
}

const XCHACHA20_KNOWN: Known = Known {
    algorithm: SymmetricAlgorithm::XChaCha20,
    nonce_length: NonceLength::Sixteen,
    key: "27bd6ec46292a3b421cdaf8a3f0ca759cbc67bcbe7c5855aa0d1e0700fd0e828",
    nonce: "fbd5dd10431af533c403d6f4fa629931e5f31872d2f7e7b6",
    tag: "5b5ccc27324af03b7ca92dd067ad6eb5",
    encrypted: "aa0664f3c00a09d098bf",
    plain: b"helloworld",
};

const KNOWN: [Known; 4] = [
    Known {
        algorithm: SymmetricAlgorithm::Aes256Gcm,
        nonce_length: NonceLength::Sixteen,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "f3e1ba810d2c8900b11312b7c725565f",
        tag: "ec3b71e17c11dbe31484da9450edcf6c",
        encrypted: "02d2ffed93b856f148b9",
        plain: b"helloworld",
    },
    Known {
        algorithm: SymmetricAlgorithm::Aes256Gcm,
        nonce_length: NonceLength::Twelve,
        key: "0000000000000000000000000000000000000000000000000000000000000000",
        nonce: "000000000000000000000000",
        tag: "530f8afbc74536b9a963b4f1c4cb738b",
        encrypted: "",
        plain: b"",
    },
    XCHACHA20_KNOWN,
    // the nonce length setting is AES-only, so XChaCha20-Poly1305 gives the same payload with either value
    Known {
        nonce_length: NonceLength::Twelve,
        ..XCHACHA20_KNOWN
    },
];

/// (algorithm, nonce length setting, nonce bytes in the payload)
const CIPHERS: [(SymmetricAlgorithm, NonceLength, usize); 4] = [
    (SymmetricAlgorithm::Aes256Gcm, NonceLength::Sixteen, 16),
    (SymmetricAlgorithm::Aes256Gcm, NonceLength::Twelve, 12),
    (SymmetricAlgorithm::XChaCha20, NonceLength::Sixteen, 24),
    (SymmetricAlgorithm::XChaCha20, NonceLength::Twelve, 24),
];

#[test]
fn round_trips_with_every_cipher() {
    let key = [7u8; 32];
    let big = alloc::vec![1u8; 2 * 1024 * 1024];
    let messages: [&[u8]; 3] = [b"", "hello world🌍".as_bytes(), &big];

    for (algorithm, nonce_length, nonce_bytes) in CIPHERS {
        for msg in messages {
            let encrypted = sym_encrypt(algorithm, nonce_length, &key, msg).unwrap();
            assert_eq!(
                encrypted.len(),
                nonce_bytes + 16 + msg.len(),
                "{algorithm:?} {nonce_length:?}"
            );

            let decrypted = sym_decrypt(algorithm, nonce_length, &key, &encrypted);
            assert_eq!(decrypted.as_deref(), Some(msg), "{algorithm:?} {nonce_length:?}");
        }
    }
}

#[test]
fn draws_every_nonce_byte_at_random() {
    let key = [7u8; 32];
    for (algorithm, nonce_length, nonce_bytes) in CIPHERS {
        let nonces: Vec<Vec<u8>> = (0..64)
            .map(|_| sym_encrypt(algorithm, nonce_length, &key, b"same message").unwrap()[..nonce_bytes].to_vec())
            .collect();

        // a random byte comes out the same 64 times with a chance of 256^-63
        for position in 0..nonce_bytes {
            let varies = nonces.iter().any(|nonce| nonce[position] != nonces[0][position]);
            assert!(varies, "{algorithm:?} {nonce_length:?} byte {position}");
        }
    }
}

#[test]
fn rejects_any_tampered_byte() {
    let key = [7u8; 32];
    for (algorithm, nonce_length, _) in CIPHERS {
        let encrypted = sym_encrypt(algorithm, nonce_length, &key, b"hello world").unwrap();
        assert!(sym_decrypt(algorithm, nonce_length, &key, &encrypted).is_some());

        // every byte of the nonce, the tag and the encrypted data
        for i in 0..encrypted.len() {
            let mut tampered = encrypted.clone();
            tampered[i] ^= 1;
            let decrypted = sym_decrypt(algorithm, nonce_length, &key, &tampered);
            assert_eq!(decrypted, None, "{algorithm:?} {nonce_length:?} byte {i}");
        }
    }
}

#[test]
fn rejects_the_wrong_key() {
    for (algorithm, nonce_length, _) in CIPHERS {
        let encrypted = sym_encrypt(algorithm, nonce_length, &[7u8; 32], b"hello world").unwrap();
        let decrypted = sym_decrypt(algorithm, nonce_length, &[8u8; 32], &encrypted);
        assert_eq!(decrypted, None, "{algorithm:?} {nonce_length:?}");
    }
}

#[test]
fn rejects_payloads_shorter_than_nonce_and_tag() {
    let key = [7u8; 32];
    for (algorithm, nonce_length, nonce_bytes) in CIPHERS {
        for length in 0..nonce_bytes + 16 {
            let decrypted = sym_decrypt(algorithm, nonce_length, &key, &alloc::vec![0u8; length]);
            assert_eq!(decrypted, None, "{algorithm:?} {nonce_length:?} length {length}");
        }
    }
}

#[test]
fn rejects_keys_that_are_not_32_bytes() {
    for (algorithm, nonce_length, _) in CIPHERS {
        let encrypted = sym_encrypt(algorithm, nonce_length, &[7u8; 32], b"hello world").unwrap();
        for key_length in [0, 16, 31, 33, 64] {
            let key = alloc::vec![7u8; key_length];
            let context = (algorithm, nonce_length, key_length);
            assert_eq!(
                sym_encrypt(algorithm, nonce_length, &key, b"hello world"),
                None,
                "{context:?}"
            );
            assert_eq!(
                sym_decrypt(algorithm, nonce_length, &key, &encrypted),
                None,
                "{context:?}"
            );
        }
    }
}

#[test]
fn rejects_payloads_from_another_cipher() {
    let key = [7u8; 32];
    for (algorithm, nonce_length, nonce_bytes) in CIPHERS {
        let encrypted = sym_encrypt(algorithm, nonce_length, &key, b"hello world").unwrap();

        for (other_algorithm, other_nonce_length, other_nonce_bytes) in CIPHERS {
            let decrypted = sym_decrypt(other_algorithm, other_nonce_length, &key, &encrypted);
            // XChaCha20-Poly1305 ignores the nonce length, so both of its settings are the same cipher
            let same_cipher = (algorithm, nonce_bytes) == (other_algorithm, other_nonce_bytes);
            let context = (algorithm, nonce_length, other_algorithm, other_nonce_length);
            assert_eq!(decrypted.is_some(), same_cipher, "{context:?}");
        }
    }
}

#[test]
fn leaves_existing_bytes_untouched_when_encryption_fails() {
    for (algorithm, nonce_length, _) in CIPHERS {
        let mut output = b"ml-kem ciphertext".to_vec();
        let result = sym_encrypt_into(&mut output, algorithm, nonce_length, &[7u8; 31], b"hello world");
        assert_eq!(result, Err(Error::InvalidMessage), "{algorithm:?} {nonce_length:?}");
        assert_eq!(output, b"ml-kem ciphertext", "{algorithm:?} {nonce_length:?}");
    }
}

#[test]
fn rejects_a_nonce_that_does_not_match_the_setting() {
    // (algorithm, nonce length setting, a nonce of the wrong size for it)
    let mismatches = [
        (SymmetricAlgorithm::Aes256Gcm, NonceLength::Sixteen, 12),
        (SymmetricAlgorithm::Aes256Gcm, NonceLength::Twelve, 16),
        (SymmetricAlgorithm::XChaCha20, NonceLength::Sixteen, 16),
        (SymmetricAlgorithm::XChaCha20, NonceLength::Twelve, 12),
    ];
    for (algorithm, nonce_length, nonce_size) in mismatches {
        let mut output = b"ml-kem ciphertext".to_vec();
        let nonce = alloc::vec![9u8; nonce_size];
        let result = encrypt_into_with_nonce(&mut output, algorithm, nonce_length, &[7u8; 32], &nonce, b"hi");
        let context = (algorithm, nonce_length, nonce_size);
        assert_eq!(result, None, "{context:?}");
        assert_eq!(output, b"ml-kem ciphertext", "{context:?}");
    }
}

#[test]
fn decrypts_known_vectors() {
    for known in KNOWN {
        let decrypted = sym_decrypt(known.algorithm, known.nonce_length, &known.key(), &known.payload());
        let context = (known.algorithm, known.nonce_length);
        assert_eq!(decrypted.as_deref(), Some(known.plain), "{context:?}");
    }
}

#[test]
fn encrypts_known_vectors_after_existing_bytes() {
    for known in KNOWN {
        let prefix = b"ml-kem ciphertext";
        let mut output = prefix.to_vec();
        let (algorithm, nonce_length) = (known.algorithm, known.nonce_length);
        encrypt_into_with_nonce(
            &mut output,
            algorithm,
            nonce_length,
            &known.key(),
            &known.nonce(),
            known.plain,
        )
        .unwrap();

        let expected = [prefix.as_slice(), &known.payload()].concat();
        assert_eq!(output, expected, "{algorithm:?} {nonce_length:?}");
    }
}

/// With `aes-openssl`, the public functions above run on OpenSSL. These tests check it against pure Rust AES directly
#[cfg(feature = "aes-openssl")]
mod openssl_backend {
    use super::super::{Aes256Gcm12, Aes256Gcm16, aead, openssl_aes};

    fn rust_encrypt(output: &mut alloc::vec::Vec<u8>, key: &[u8], nonce: &[u8], msg: &[u8]) -> Option<()> {
        match nonce.len() {
            16 => aead::encrypt_into::<Aes256Gcm16>(output, key, nonce, msg),
            _ => aead::encrypt_into::<Aes256Gcm12>(output, key, nonce, msg),
        }
    }

    fn rust_decrypt(key: &[u8], nonce_length: usize, encrypted: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        match nonce_length {
            16 => aead::decrypt::<Aes256Gcm16>(key, encrypted),
            _ => aead::decrypt::<Aes256Gcm12>(key, encrypted),
        }
    }

    #[test]
    fn openssl_and_rust_aes_produce_the_same_payloads() {
        let key = [7u8; 32];
        // not a multiple of the 16 bytes block size
        let big = alloc::vec![3u8; 1024 * 1024 + 5];
        let messages: [&[u8]; 3] = [b"", "hello world🌍".as_bytes(), &big];
        let prefix = b"ml-kem ciphertext";

        for nonce in [[9u8; 16].as_slice(), [9u8; 12].as_slice()] {
            for msg in messages {
                let (mut from_rust, mut from_openssl) = (prefix.to_vec(), prefix.to_vec());
                rust_encrypt(&mut from_rust, &key, nonce, msg).unwrap();
                openssl_aes::encrypt_into(&mut from_openssl, &key, nonce, msg).unwrap();
                assert_eq!(from_openssl, from_rust, "nonce {} msg {}", nonce.len(), msg.len());

                let payload = &from_rust[prefix.len()..];
                let by_openssl = openssl_aes::decrypt(&key, nonce.len(), payload);
                let by_rust = rust_decrypt(&key, nonce.len(), payload);
                assert_eq!(
                    by_openssl.as_deref(),
                    Some(msg),
                    "nonce {} msg {}",
                    nonce.len(),
                    msg.len()
                );
                assert_eq!(by_rust.as_deref(), Some(msg), "nonce {} msg {}", nonce.len(), msg.len());
            }
        }
    }

    #[test]
    fn leaves_existing_bytes_untouched_when_openssl_fails() {
        // OpenSSL refuses an empty nonce, which the public functions never pass on
        let mut output = b"ml-kem ciphertext".to_vec();
        let result = openssl_aes::encrypt_into(&mut output, &[7u8; 32], &[], b"hello world");
        assert_eq!(result, None);
        assert_eq!(output, b"ml-kem ciphertext");
    }

    // 32-bit targets can't hold a slice over `isize::MAX`, which is `i32::MAX` there, so the panic can't happen
    #[cfg(target_pointer_width = "64")]
    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "allocates about 4 GiB, so it runs in release builds only"
    )]
    fn encrypts_and_decrypts_more_than_2_gib() {
        use super::{NonceLength, SymmetricAlgorithm, Vec, sym_decrypt, sym_encrypt};

        // 251 is odd, so the pattern never repeats at a power-of-two distance, and misplaced bytes show
        fn byte_at(i: usize) -> u8 {
            (i % 251) as u8
        }
        // over `i32::MAX`, the most rust-openssl takes in one call, and not a multiple of the 16 bytes block size
        let size = (1 << 31) + 5;
        let key = [7u8; 32];

        let plain: Vec<u8> = (0..size).map(byte_at).collect();
        let encrypted = sym_encrypt(SymmetricAlgorithm::Aes256Gcm, NonceLength::Sixteen, &key, &plain).unwrap();
        drop(plain);
        assert_eq!(encrypted.len(), 16 + 16 + size);

        // one decryption at a time, so at most two copies of the message are in memory
        let by_rust = rust_decrypt(&key, 16, &encrypted).unwrap();
        assert!(by_rust.iter().copied().eq((0..size).map(byte_at)), "pure Rust");
        drop(by_rust);

        let by_openssl = sym_decrypt(SymmetricAlgorithm::Aes256Gcm, NonceLength::Sixteen, &key, &encrypted).unwrap();
        assert!(by_openssl.iter().copied().eq((0..size).map(byte_at)), "OpenSSL");
    }
}
