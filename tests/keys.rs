use ecies_post_quantum::config::AsymmetricAlgorithm;
use ecies_post_quantum::utils::{generate_seed, keypair_from_seed};

#[test]
fn secret_key_debug_leaves_out_the_bytes() {
    let (sk, _) = keypair_from_seed(AsymmetricAlgorithm::MlKem768, &[7u8; 64]);
    assert_eq!(format!("{sk:?}"), "SecretKey { algorithm: MlKem768, .. }");
}

#[test]
fn secret_keys_are_equal_only_with_the_same_algorithm_and_bytes() {
    let (sk, _) = keypair_from_seed(AsymmetricAlgorithm::MlKem768, &[7u8; 64]);
    let (same, _) = keypair_from_seed(AsymmetricAlgorithm::MlKem768, &[7u8; 64]);
    let (other_seed, _) = keypair_from_seed(AsymmetricAlgorithm::MlKem768, &[8u8; 64]);
    let (other_algorithm, _) = keypair_from_seed(AsymmetricAlgorithm::MlKem512, &[7u8; 64]);

    // the last seed byte only goes into z, which ends the secret key, so the keys differ in their last byte alone
    let mut last_byte_changed = [7u8; 64];
    last_byte_changed[63] = 8;
    let (other_z, _) = keypair_from_seed(AsymmetricAlgorithm::MlKem768, &last_byte_changed);
    assert_eq!(sk.as_bytes()[..2399], other_z.as_bytes()[..2399]);

    assert!(sk == same);
    assert!(sk != other_seed);
    assert!(sk != other_algorithm);
    assert!(sk != other_z);
}

#[test]
fn seed_debug_leaves_out_the_bytes() {
    let seed = generate_seed().unwrap();
    assert_eq!(format!("{seed:?}"), "Seed { .. }");
}

#[test]
fn seeds_are_equal_only_with_the_same_bytes() {
    let seed = generate_seed().unwrap();
    let other = generate_seed().unwrap();

    // seeds only come from `generate_seed`, so the one pair with the same bytes is a seed and itself
    #[allow(clippy::eq_op)]
    let same = seed == seed;
    assert!(same);
    assert!(seed != other);
}
