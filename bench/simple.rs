use core::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ecies_post_quantum::config::{AsymmetricAlgorithm, Config};
use ecies_post_quantum::utils::generate_keypair;
use ecies_post_quantum::{decrypt_with_config, encrypt_with_config};

const LEVELS: [(AsymmetricAlgorithm, &str); 3] = [
    (AsymmetricAlgorithm::MlKem512, "ml-kem-512"),
    (AsymmetricAlgorithm::MlKem768, "ml-kem-768"),
    (AsymmetricAlgorithm::MlKem1024, "ml-kem-1024"),
];

const SIZES: [(usize, &str); 3] = [(32, "32B"), (100 << 20, "100M"), (200 << 20, "200M")];

fn keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");
    for (algorithm, name) in LEVELS {
        group.bench_function(name, |b| b.iter(|| generate_keypair(algorithm).unwrap()));
    }
    group.finish();
}

fn encrypt_and_decrypt(c: &mut Criterion) {
    for (size, size_name) in SIZES {
        let msg = vec![7u8; size];
        let mut group = c.benchmark_group(size_name);
        if size > 32 {
            group.sample_size(10).measurement_time(Duration::from_secs(10));
        }

        for (asymmetric_algorithm, name) in LEVELS {
            let config = Config {
                asymmetric_algorithm,
                ..Config::default()
            };
            let (sk, pk) = generate_keypair(asymmetric_algorithm).unwrap();
            let encrypted = encrypt_with_config(pk.as_bytes(), &msg, &config).unwrap();

            group.bench_function(BenchmarkId::new("encrypt", name), |b| {
                b.iter(|| encrypt_with_config(pk.as_bytes(), &msg, &config).unwrap())
            });
            group.bench_function(BenchmarkId::new("decrypt", name), |b| {
                b.iter(|| decrypt_with_config(sk.as_bytes(), &encrypted, &config).unwrap())
            });
        }
        group.finish();
    }
}

criterion_group!(benches, keygen, encrypt_and_decrypt);
criterion_main!(benches);
