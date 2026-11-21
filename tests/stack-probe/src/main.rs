use std::cell::RefCell;
use std::hint::black_box;
use std::process::ExitCode;

use ecies_post_quantum::config::{AsymmetricAlgorithm, Config, NonceLength, SymmetricAlgorithm};
use ecies_post_quantum::consts::{ML_KEM_512_PKE_SIZE, ML_KEM_768_PKE_SIZE, ML_KEM_1024_PKE_SIZE};
use ecies_post_quantum::utils::{generate_keypair, generate_seed, keypair_from_seed};
use ecies_post_quantum::{Error, PublicKey, SecretKey, Seed, decrypt_with_config, encrypt_with_config};

type KeyPair = (SecretKey, PublicKey);

const SCAN_SIZE: usize = 512 * 1024;
const PAD_SIZE: usize = 16 * 1024;
const MARKER: u8 = 0xA5;

/// Upper bound on bytes above `zeroize_stack`'s zeroed buffer (the outer public function's
/// frame plus `zeroize_stack`'s own saved-register prologue). Checked against release assembly.
const MAX_OUTER_FRAME_BYTES: usize = 256;

/// Minimum contiguous zero run that proves `zeroize_stack` actually ran.
const MIN_WIPE_RUN_BYTES: usize = 16 * 1024;

/// Maximum dirty bytes allowed immediately below `zeroize_stack`'s zeroed buffer:
/// - on aarch64, `bzero` uses the link register and pushes nothing to the stack (`0`);
/// - on x86_64, `call memset` pushes an 8-byte return address below the buffer (allow up to 64 B).
#[cfg(target_arch = "aarch64")]
const MAX_BELOW_WIPE_DIRTY_BYTES: usize = 0;
#[cfg(not(target_arch = "aarch64"))]
const MAX_BELOW_WIPE_DIRTY_BYTES: usize = 64;

const KNOWN_SEED: [u8; 64] = {
    let mut b = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        b[i] = (i as u8).wrapping_mul(37).wrapping_add(0x13);
        i += 1;
    }
    b
};

const KNOWN_M: [u8; 32] = {
    let mut b = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        b[i] = (i as u8).wrapping_mul(53).wrapping_add(0x41);
        i += 1;
    }
    b
};

const KNOWN_NONCE: [u8; 24] = {
    let mut b = [0u8; 24];
    let mut i = 0;
    while i < 24 {
        b[i] = (i as u8).wrapping_mul(29).wrapping_add(0x71);
        i += 1;
    }
    b
};

thread_local! {
    static RNG_QUEUE: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
}

fn set_rng_outputs(outputs: &[&[u8]]) {
    RNG_QUEUE.with(|q| {
        let mut q = q.borrow_mut();
        q.clear();
        for out in outputs {
            q.push(out.to_vec());
        }
    });
}

#[unsafe(no_mangle)]
fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
    RNG_QUEUE.with(|q| {
        let mut q = q.borrow_mut();
        if q.is_empty() {
            return Err(getrandom::Error::UNEXPECTED);
        }
        let next = q.remove(0);
        if next.len() != len {
            return Err(getrandom::Error::UNEXPECTED);
        }
        // SAFETY: `getrandom` guarantees `dest` is valid for writes of `len` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(next.as_ptr(), dest, len);
        }
        Ok(())
    })
}

#[inline(never)]
fn prepare_stack(marker: u8) -> usize {
    let mut region = [marker; SCAN_SIZE];
    black_box(&mut region);
    region.as_ptr() as usize
}

#[inline(never)]
fn current_sp() -> usize {
    let local: u8 = 0;
    black_box(&local as *const u8 as usize)
}

#[inline(never)]
fn call_under_pad<R, F: FnOnce() -> R>(f: F) -> (usize, R) {
    let mut pad = [0u8; PAD_SIZE];
    black_box(&mut pad);
    let sp_before = current_sp();
    let result = f();
    black_box(&mut pad);
    (sp_before, result)
}

/// Copies `[low_addr .. high_addr]` into the pre-allocated heap buffer `out` without allocating.
#[inline(never)]
fn snapshot_stack(low_addr: usize, high_addr: usize, out: &mut [u8]) {
    let len = high_addr - low_addr;
    assert!(len <= out.len());
    let src = low_addr as *const u8;
    for (i, dst) in out[..len].iter_mut().enumerate() {
        // SAFETY: Reading stack memory below the current frame (separated by `PAD_SIZE`)
        // that was previously committed and initialized by `prepare_stack` in this thread.
        *dst = unsafe { core::ptr::read_volatile(src.add(i)) };
    }
}

struct ScanStats {
    /// Deepest byte below `sp_before` that differs from `MARKER` (peak stack depth of call + wipe).
    dirty_depth: usize,
    /// Distance from `sp_before` down to the top of the wipe's contiguous zero run (`None` if no wipe run found).
    outer_frame_bytes: Option<usize>,
    /// Length of the wipe's contiguous `0x00` run (`0` if no wipe run found).
    wipe_run_bytes: usize,
    /// Deepest non-`MARKER` byte below the wipe's contiguous zero run (0 on aarch64; tiny `call memset`
    /// return-address record on x86_64; large if inner call exceeded `N`).
    below_wipe_dirty_depth: usize,
    /// Matches of known secret byte sequences anywhere in the scanned region (including outer frame).
    secret_hits: Vec<(&'static str, usize)>,
}

struct SecretNeedle<'a> {
    name: &'static str,
    bytes: &'a [u8],
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || needle.len() > haystack.len() {
        return 0;
    }
    haystack.windows(needle.len()).filter(|w| *w == needle).count()
}

/// Decodes `dk_pke` into `k` polynomials of 256 little-endian `i16` coefficients (512 bytes each),
/// matching `ByteDecode_12` in FIPS 203 and `libcrux`'s unpacked representation.
fn decode_s_hat(dk_pke: &[u8]) -> Vec<[u8; 512]> {
    let (chunks, rem) = dk_pke.as_chunks::<384>();
    assert!(rem.is_empty());
    let mut polys = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let mut poly = [0u8; 512];
        for i in 0..128 {
            let b0 = u16::from(chunk[3 * i]);
            let b1 = u16::from(chunk[3 * i + 1]);
            let b2 = u16::from(chunk[3 * i + 2]);
            let c0 = (b0 | ((b1 & 0x0f) << 8)) as i16;
            let c1 = ((b1 >> 4) | (b2 << 4)) as i16;
            poly[4 * i..4 * i + 2].copy_from_slice(&c0.to_le_bytes());
            poly[4 * i + 2..4 * i + 4].copy_from_slice(&c1.to_le_bytes());
        }
        polys.push(poly);
    }
    polys
}

fn dk_pke_len(alg: AsymmetricAlgorithm) -> usize {
    match alg {
        AsymmetricAlgorithm::MlKem512 => 768,
        AsymmetricAlgorithm::MlKem768 => 1152,
        AsymmetricAlgorithm::MlKem1024 => 1536,
        _ => unreachable!(),
    }
}

fn ct_len(alg: AsymmetricAlgorithm) -> usize {
    match alg {
        AsymmetricAlgorithm::MlKem512 => ML_KEM_512_PKE_SIZE,
        AsymmetricAlgorithm::MlKem768 => ML_KEM_768_PKE_SIZE,
        AsymmetricAlgorithm::MlKem1024 => ML_KEM_1024_PKE_SIZE,
        _ => unreachable!(),
    }
}

fn libcrux_encapsulate_known(alg: AsymmetricAlgorithm, pk: &[u8], m: [u8; 32]) -> (Vec<u8>, [u8; 32]) {
    match alg {
        AsymmetricAlgorithm::MlKem512 => {
            let pk = libcrux_ml_kem::mlkem512::MlKem512PublicKey::try_from(pk).unwrap();
            let (ct, ss) = libcrux_ml_kem::mlkem512::encapsulate(&pk, m);
            (ct.as_slice().to_vec(), ss)
        }
        AsymmetricAlgorithm::MlKem768 => {
            let pk = libcrux_ml_kem::mlkem768::MlKem768PublicKey::try_from(pk).unwrap();
            let (ct, ss) = libcrux_ml_kem::mlkem768::encapsulate(&pk, m);
            (ct.as_slice().to_vec(), ss)
        }
        AsymmetricAlgorithm::MlKem1024 => {
            let pk = libcrux_ml_kem::mlkem1024::MlKem1024PublicKey::try_from(pk).unwrap();
            let (ct, ss) = libcrux_ml_kem::mlkem1024::encapsulate(&pk, m);
            (ct.as_slice().to_vec(), ss)
        }
        _ => unreachable!(),
    }
}

fn run_probe<R, F: FnOnce() -> R>(
    snapshot_buf: &mut [u8],
    needles: &[SecretNeedle<'_>],
    dk_pke_32b_chunks: &[&[u8]],
    s_hat_polys: &[[u8; 512]],
    f: F,
) -> (ScanStats, R) {
    let low_addr = prepare_stack(MARKER);
    let (sp_before, result) = call_under_pad(f);
    assert!(
        sp_before > low_addr && sp_before - low_addr <= SCAN_SIZE,
        "unexpected stack direction or layout: low={low_addr:#x}, sp_before={sp_before:#x}"
    );
    let len = sp_before - low_addr;
    snapshot_stack(low_addr, sp_before, snapshot_buf);
    let snap = &snapshot_buf[..len];

    let dirty_depth = snap.iter().position(|&b| b != MARKER).map_or(0, |i| len - i);

    // Locate the highest contiguous `0x00` run of length >= MIN_WIPE_RUN_BYTES below `sp_before`.
    let mut outer_frame_bytes = None;
    let mut wipe_run_bytes = 0usize;
    let mut below_wipe_dirty_depth = dirty_depth;

    let mut pos = len;
    while pos > 0 {
        if snap[pos - 1] == 0x00 {
            let run_end = pos;
            while pos > 0 && snap[pos - 1] == 0x00 {
                pos -= 1;
            }
            let run_start = pos;
            let run_len = run_end - run_start;
            if run_len >= MIN_WIPE_RUN_BYTES {
                outer_frame_bytes = Some(len - run_end);
                wipe_run_bytes = run_len;
                below_wipe_dirty_depth = snap[..run_start]
                    .iter()
                    .position(|&b| b != MARKER)
                    .map_or(0, |i| run_start - i);
                break;
            }
        } else {
            pos -= 1;
        }
    }

    let mut secret_hits = Vec::new();
    for needle in needles {
        let count = count_occurrences(snap, needle.bytes);
        if count > 0 {
            secret_hits.push((needle.name, count));
        }
    }

    if !dk_pke_32b_chunks.is_empty() {
        let matched_chunks = dk_pke_32b_chunks
            .iter()
            .filter(|chunk| count_occurrences(snap, chunk) > 0)
            .count();
        if matched_chunks > 0 {
            secret_hits.push(("dk_pke_32b_chunks", matched_chunks));
        }
    }

    if !s_hat_polys.is_empty() {
        let matched_polys = s_hat_polys
            .iter()
            .filter(|poly| count_occurrences(snap, &poly[..]) > 0)
            .count();
        if matched_polys > 0 {
            secret_hits.push(("s_hat_polys", matched_polys));
        }
    }

    (
        ScanStats {
            dirty_depth,
            outer_frame_bytes,
            wipe_run_bytes,
            below_wipe_dirty_depth,
            secret_hits,
        },
        result,
    )
}

fn alg_name(alg: AsymmetricAlgorithm) -> &'static str {
    match alg {
        AsymmetricAlgorithm::MlKem512 => "mlkem512",
        AsymmetricAlgorithm::MlKem768 => "mlkem768",
        AsymmetricAlgorithm::MlKem1024 => "mlkem1024",
        _ => unreachable!(),
    }
}

fn cipher_configs() -> Vec<(&'static str, SymmetricAlgorithm, NonceLength)> {
    vec![
        ("aes16", SymmetricAlgorithm::Aes256Gcm, NonceLength::Sixteen),
        ("aes12", SymmetricAlgorithm::Aes256Gcm, NonceLength::Twelve),
        ("xchacha", SymmetricAlgorithm::XChaCha20, NonceLength::Sixteen),
    ]
}

fn nonce_len(sym: SymmetricAlgorithm, nonce_length: NonceLength) -> usize {
    match sym {
        SymmetricAlgorithm::Aes256Gcm => nonce_length as usize,
        SymmetricAlgorithm::XChaCha20 => 24,
        _ => unreachable!(),
    }
}

fn run_suite(measure_only: bool, filter: Option<&str>) -> ExitCode {
    let mut snapshot_buf = vec![0u8; SCAN_SIZE];
    let mut failures = 0usize;
    let mut max_dirty_depth = 0usize;
    let mut max_outer_frame = 0usize;
    let mut max_below_wipe = 0usize;
    let mut cases_run = 0usize;

    // The public functions, as pointers whose value the optimizer can't see. Under LTO, a direct call can be inlined
    // into `call_under_pad`, whose frame lies above `sp_before`, and the scan would then miss the public function's
    // own frame.
    let generate_seed = black_box(generate_seed as fn() -> Result<Seed, Error>);
    let keypair_from_seed = black_box(keypair_from_seed as fn(AsymmetricAlgorithm, &[u8; 64]) -> KeyPair);
    let generate_keypair = black_box(generate_keypair as fn(AsymmetricAlgorithm) -> Result<KeyPair, Error>);
    let encrypt_with_config = black_box(encrypt_with_config as fn(&[u8], &[u8], &Config) -> Result<Vec<u8>, Error>);
    let decrypt_with_config = black_box(decrypt_with_config as fn(&[u8], &[u8], &Config) -> Result<Vec<u8>, Error>);

    // Warm up dynamic linker / PLT entries (e.g. bzero/memset) before probing.
    let _ = keypair_from_seed(AsymmetricAlgorithm::MlKem768, &KNOWN_SEED);

    let mut check_case = |name: &str, expect_wiped: bool, stats: &ScanStats| {
        cases_run += 1;
        max_dirty_depth = max_dirty_depth.max(stats.dirty_depth);
        let secret_fail = !stats.secret_hits.is_empty();
        let wipe_fail = if expect_wiped {
            match stats.outer_frame_bytes {
                Some(outer) => {
                    max_outer_frame = max_outer_frame.max(outer);
                    max_below_wipe = max_below_wipe.max(stats.below_wipe_dirty_depth);
                    outer > MAX_OUTER_FRAME_BYTES || stats.below_wipe_dirty_depth > MAX_BELOW_WIPE_DIRTY_BYTES
                }
                None => true,
            }
        } else {
            false
        };
        let failed = secret_fail || wipe_fail;

        if measure_only || failed {
            let status = if failed { "FAIL" } else { "OK  " };
            let outer_str = stats
                .outer_frame_bytes
                .map_or_else(|| "none".to_string(), |n| format!("{n} B"));
            println!(
                "{status} {name:<50} dirty={:>6} B  outer={:>6}  wipe={:>6} B  below={:>6} B  secrets={:?}",
                stats.dirty_depth, outer_str, stats.wipe_run_bytes, stats.below_wipe_dirty_depth, stats.secret_hits
            );
        }
        if failed {
            failures += 1;
        }
    };

    let should_run = |name: &str| filter.is_none_or(|f| name.contains(f));

    // Baseline: nothing (no wipe expected, just checks harness overhead)
    if should_run("baseline") {
        let (stats, ()) = run_probe(&mut snapshot_buf, &[], &[], &[], || {});
        check_case("baseline", false, &stats);
    }

    // generate_seed (fills heap directly via getrandom; no libcrux frames)
    if should_run("generate_seed") {
        let needles = [
            SecretNeedle {
                name: "seed",
                bytes: &KNOWN_SEED,
            },
            SecretNeedle {
                name: "d",
                bytes: &KNOWN_SEED[..32],
            },
            SecretNeedle {
                name: "z",
                bytes: &KNOWN_SEED[32..],
            },
            SecretNeedle {
                name: "seed[8..64]",
                bytes: &KNOWN_SEED[8..],
            },
        ];
        for round in 1..=2 {
            set_rng_outputs(&[&KNOWN_SEED]);
            let (stats, res) = run_probe(&mut snapshot_buf, &needles, &[], &[], generate_seed);
            let seed = res.expect("generate_seed");
            assert_eq!(seed.as_bytes(), &KNOWN_SEED);
            let name = format!("generate_seed/r{round}");
            check_case(&name, false, &stats);
            drop(seed);
        }
    }

    let algs = [
        AsymmetricAlgorithm::MlKem512,
        AsymmetricAlgorithm::MlKem768,
        AsymmetricAlgorithm::MlKem1024,
    ];

    for alg in algs {
        let aname = alg_name(alg);
        let (sk_ref, pk_ref) = keypair_from_seed(alg, &KNOWN_SEED);
        let sk_bytes = sk_ref.as_bytes().to_vec();
        let pk_bytes = pk_ref.as_bytes().to_vec();
        let dk_pke = &sk_bytes[..dk_pke_len(alg)];
        let (chunks, rem) = dk_pke.as_chunks::<32>();
        assert!(rem.is_empty());
        let dk_pke_chunks: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
        let s_hat_polys = decode_s_hat(dk_pke);
        let z_bytes = &KNOWN_SEED[32..];
        let d_bytes = &KNOWN_SEED[..32];

        // 1. keypair_from_seed
        let kfs_base = format!("keypair_from_seed/{aname}");
        if should_run(&kfs_base) {
            let needles = [
                SecretNeedle {
                    name: "sk",
                    bytes: &sk_bytes,
                },
                SecretNeedle {
                    name: "dk_pke",
                    bytes: dk_pke,
                },
                SecretNeedle {
                    name: "seed",
                    bytes: &KNOWN_SEED,
                },
                SecretNeedle {
                    name: "d",
                    bytes: d_bytes,
                },
                SecretNeedle {
                    name: "z",
                    bytes: z_bytes,
                },
                SecretNeedle {
                    name: "seed[8..64]",
                    bytes: &KNOWN_SEED[8..],
                },
            ];
            for round in 1..=2 {
                let (stats, (sk, pk)) = run_probe(&mut snapshot_buf, &needles, &dk_pke_chunks, &s_hat_polys, || {
                    keypair_from_seed(alg, &KNOWN_SEED)
                });
                assert_eq!(sk.as_bytes(), sk_bytes.as_slice());
                assert_eq!(pk.as_bytes(), pk_bytes.as_slice());
                let name = format!("{kfs_base}/r{round}");
                check_case(&name, true, &stats);
                drop((sk, pk));
            }
        }

        // 2. generate_keypair
        let gkp_base = format!("generate_keypair/{aname}");
        if should_run(&gkp_base) {
            let needles = [
                SecretNeedle {
                    name: "sk",
                    bytes: &sk_bytes,
                },
                SecretNeedle {
                    name: "dk_pke",
                    bytes: dk_pke,
                },
                SecretNeedle {
                    name: "seed",
                    bytes: &KNOWN_SEED,
                },
                SecretNeedle {
                    name: "d",
                    bytes: d_bytes,
                },
                SecretNeedle {
                    name: "z",
                    bytes: z_bytes,
                },
                SecretNeedle {
                    name: "seed[8..64]",
                    bytes: &KNOWN_SEED[8..],
                },
            ];
            for round in 1..=2 {
                set_rng_outputs(&[&KNOWN_SEED]);
                let (stats, res) = run_probe(&mut snapshot_buf, &needles, &dk_pke_chunks, &s_hat_polys, || {
                    generate_keypair(alg)
                });
                let (sk, pk) = res.expect("generate_keypair");
                assert_eq!(sk.as_bytes(), sk_bytes.as_slice());
                assert_eq!(pk.as_bytes(), pk_bytes.as_slice());
                let name = format!("{gkp_base}/r{round}");
                check_case(&name, true, &stats);
                drop((sk, pk));
            }
        }

        // Precompute known K for KNOWN_M
        let (_expected_ct, known_k) = libcrux_encapsulate_known(alg, &pk_bytes, KNOWN_M);
        let msg = b"hello post-quantum stack probe message";

        for (cname, sym, nl) in cipher_configs() {
            let cfg = Config {
                asymmetric_algorithm: alg,
                symmetric_algorithm: sym,
                symmetric_nonce_length: nl,
            };
            let nlen = nonce_len(sym, nl);

            // Build a known ciphertext using KNOWN_M and KNOWN_NONCE
            set_rng_outputs(&[&KNOWN_M, &KNOWN_NONCE[..nlen]]);
            let valid_payload = encrypt_with_config(&pk_bytes, msg, &cfg).expect("encrypt setup");

            let mut tampered_tag_payload = valid_payload.clone();
            let last = tampered_tag_payload.len() - 1;
            tampered_tag_payload[last] ^= 0x01;

            let truncated_after_ct = valid_payload[..ct_len(alg)].to_vec();

            let mut bad_hash_sk = sk_bytes.clone();
            // Flip a byte in H(ek) (immediately before the trailing 32-byte z)
            let h_pos = bad_hash_sk.len() - 33;
            bad_hash_sk[h_pos] ^= 0x01;

            // 3. encrypt_with_config
            let enc_base = format!("encrypt/{aname}/{cname}");
            if should_run(&enc_base) {
                let needles = [
                    SecretNeedle {
                        name: "K",
                        bytes: &known_k,
                    },
                    SecretNeedle {
                        name: "m",
                        bytes: &KNOWN_M,
                    },
                ];
                for round in 1..=2 {
                    set_rng_outputs(&[&KNOWN_M, &KNOWN_NONCE[..nlen]]);
                    let (stats, res) = run_probe(&mut snapshot_buf, &needles, &[], &[], || {
                        encrypt_with_config(&pk_bytes, msg, &cfg)
                    });
                    let ct = res.expect("encrypt_with_config");
                    assert_eq!(ct, valid_payload);
                    let name = format!("{enc_base}/r{round}");
                    check_case(&name, true, &stats);
                    drop(ct);
                }
            }

            // 4. decrypt_with_config (expanded key & seed) x (ok, tampered_tag, truncated_after_ct)
            let dec_needles = [
                SecretNeedle {
                    name: "sk",
                    bytes: &sk_bytes,
                },
                SecretNeedle {
                    name: "dk_pke",
                    bytes: dk_pke,
                },
                SecretNeedle {
                    name: "seed",
                    bytes: &KNOWN_SEED,
                },
                SecretNeedle {
                    name: "d",
                    bytes: d_bytes,
                },
                SecretNeedle {
                    name: "z",
                    bytes: z_bytes,
                },
                SecretNeedle {
                    name: "seed[8..64]",
                    bytes: &KNOWN_SEED[8..],
                },
                SecretNeedle {
                    name: "K",
                    bytes: &known_k,
                },
                SecretNeedle {
                    name: "m'",
                    bytes: &KNOWN_M,
                },
            ];

            for (key_label, key_slice) in [("expanded", sk_bytes.as_slice()), ("seed", KNOWN_SEED.as_slice())] {
                // 4a. ok
                let case_base = format!("decrypt/{aname}/{cname}/{key_label}/ok");
                if should_run(&case_base) {
                    for round in 1..=2 {
                        let (stats, res) =
                            run_probe(&mut snapshot_buf, &dec_needles, &dk_pke_chunks, &s_hat_polys, || {
                                decrypt_with_config(key_slice, &valid_payload, &cfg)
                            });
                        assert_eq!(res.expect("decrypt ok"), msg);
                        let name = format!("{case_base}/r{round}");
                        check_case(&name, true, &stats);
                    }
                }

                // 4b. tampered tag
                let case_base = format!("decrypt/{aname}/{cname}/{key_label}/tampered_tag");
                if should_run(&case_base) {
                    for round in 1..=2 {
                        let (stats, res) =
                            run_probe(&mut snapshot_buf, &dec_needles, &dk_pke_chunks, &s_hat_polys, || {
                                decrypt_with_config(key_slice, &tampered_tag_payload, &cfg)
                            });
                        assert_eq!(res.unwrap_err(), Error::InvalidMessage);
                        let name = format!("{case_base}/r{round}");
                        check_case(&name, true, &stats);
                    }
                }

                // 4c. nothing after ML-KEM ciphertext
                let case_base = format!("decrypt/{aname}/{cname}/{key_label}/truncated");
                if should_run(&case_base) {
                    for round in 1..=2 {
                        let (stats, res) =
                            run_probe(&mut snapshot_buf, &dec_needles, &dk_pke_chunks, &s_hat_polys, || {
                                decrypt_with_config(key_slice, &truncated_after_ct, &cfg)
                            });
                        assert_eq!(res.unwrap_err(), Error::InvalidMessage);
                        let name = format!("{case_base}/r{round}");
                        check_case(&name, true, &stats);
                    }
                }
            }

            // 4d. failed FIPS 203 hash check (expanded key only, once per alg/cipher)
            let case_base = format!("decrypt/{aname}/{cname}/expanded/bad_hash");
            if should_run(&case_base) {
                let bad_needles = [
                    SecretNeedle {
                        name: "bad_sk",
                        bytes: &bad_hash_sk,
                    },
                    SecretNeedle {
                        name: "dk_pke",
                        bytes: dk_pke,
                    },
                    SecretNeedle {
                        name: "z",
                        bytes: z_bytes,
                    },
                ];
                for round in 1..=2 {
                    let (stats, res) = run_probe(&mut snapshot_buf, &bad_needles, &dk_pke_chunks, &s_hat_polys, || {
                        decrypt_with_config(&bad_hash_sk, &valid_payload, &cfg)
                    });
                    assert_eq!(res.unwrap_err(), Error::InvalidSecretKey);
                    let name = format!("{case_base}/r{round}");
                    check_case(&name, true, &stats);
                }
            }
        }
    }

    println!(
        "\nSummary: cases={cases_run}, failures={failures}, max_dirty_depth={max_dirty_depth} B, max_outer_frame={max_outer_frame} B, max_below_wipe={max_below_wipe} B"
    );
    if !measure_only && failures > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn main() -> ExitCode {
    let mut measure_only = false;
    let mut filter: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--measure" => measure_only = true,
            "--filter" => filter = args.next(),
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::FAILURE;
            }
        }
    }

    // Run on a thread with an 8 MiB stack so 512 KiB scan frames have ample room on every OS.
    let handle = std::thread::Builder::new()
        .name("stack-probe".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || run_suite(measure_only, filter.as_deref()))
        .expect("spawn stack-probe thread");
    handle.join().expect("stack-probe thread panicked")
}
