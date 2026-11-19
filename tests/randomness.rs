use ecies_post_quantum::config::AsymmetricAlgorithm;
use ecies_post_quantum::encrypt;
use ecies_post_quantum::utils::{generate_keypair, generate_seed};
// wasm-bindgen-test runs only its own test attribute
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use wasm_bindgen_test::wasm_bindgen_test as test;

#[test]
fn encapsulates_with_fresh_randomness() {
    let (_, pk) = generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap();
    let first = encrypt(pk.as_bytes(), b"m").unwrap();
    let second = encrypt(pk.as_bytes(), b"m").unwrap();

    // with fixed randomness, anyone with the public key could re-derive the shared secret
    assert_ne!(first[..1088], second[..1088]);
}

#[test]
fn draws_d_and_every_byte_of_z_at_random() {
    let keys: Vec<_> = (0..64)
        .map(|_| generate_keypair(AsymmetricAlgorithm::MlKem768).unwrap().0)
        .collect();
    let bytes: Vec<&[u8]> = keys.iter().map(|key| key.as_bytes()).collect();

    // the seed is d || z. The key up to its last 32 bytes is hashed from d, so d can only be checked as a whole
    assert!(bytes.iter().any(|key| key[..2368] != bytes[0][..2368]));

    // z is copied into those last 32 bytes, where a random byte comes out the same 64 times with a chance of 256^-63
    for position in 2368..2400 {
        let varies = bytes.iter().any(|key| key[position] != bytes[0][position]);
        assert!(varies, "byte {position}");
    }
}

#[test]
fn draws_every_byte_of_a_generated_seed_at_random() {
    let seeds: Vec<[u8; 64]> = (0..64).map(|_| *generate_seed().unwrap().as_bytes()).collect();

    // a random byte comes out the same 64 times with a chance of 256^-63
    for position in 0..64 {
        let varies = seeds.iter().any(|seed| seed[position] != seeds[0][position]);
        assert!(varies, "byte {position}");
    }
}

#[test]
fn draws_d_and_z_of_a_generated_seed_apart() {
    let seed = generate_seed().unwrap();

    // two halves drawn apart come out the same with a chance of 256^-32
    assert_ne!(seed.as_bytes()[..32], seed.as_bytes()[32..]);
}
