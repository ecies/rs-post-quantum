use ecies_post_quantum::config::AsymmetricAlgorithm;
use ecies_post_quantum::encrypt;
use ecies_post_quantum::utils::generate_keypair;

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
