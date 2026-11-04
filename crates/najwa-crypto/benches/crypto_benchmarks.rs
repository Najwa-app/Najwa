//! Criterion benchmarks for the najwa-crypto primitives (S01 §3).

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

use najwa_crypto::aead;
use najwa_crypto::kdf::{argon2id, hkdf_expand, hkdf_sha256, Argon2Params};
use najwa_crypto::keys::ed25519::Ed25519KeyPair;
use najwa_crypto::keys::x25519::X25519KeyPair;

fn bench_aead(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let nonce = [0u8; 24];
    let plaintext = vec![0u8; 1024]; // 1 KiB message
    let ad = b"associated-data";

    c.bench_function("aead_encrypt_1kb", |b| {
        b.iter(|| {
            let _ = aead::encrypt(
                black_box(&key),
                black_box(&nonce),
                black_box(&plaintext),
                black_box(&ad[..]),
            );
        })
    });

    let ciphertext = aead::encrypt(&key, &nonce, &plaintext, &ad[..]).unwrap();
    c.bench_function("aead_decrypt_1kb", |b| {
        b.iter(|| {
            let _ = aead::decrypt(
                black_box(&key),
                black_box(&nonce),
                black_box(&ciphertext),
                black_box(&ad[..]),
            );
        })
    });
}

fn bench_hkdf(c: &mut Criterion) {
    let ikm = [0xAAu8; 32];
    let salt = [0xBBu8; 32];
    let info = b"benchmark-info";

    c.bench_function("hkdf_sha256_32b", |b| {
        b.iter(|| {
            let _ = hkdf_sha256(
                black_box(&ikm),
                black_box(&salt),
                black_box(info),
                black_box(32),
            );
        })
    });

    let prk = [0xCCu8; 32];
    c.bench_function("hkdf_expand_32b", |b| {
        b.iter(|| {
            let _ = hkdf_expand(black_box(&prk), black_box(info), black_box(32));
        })
    });
}

fn bench_argon2(c: &mut Criterion) {
    let password = b"benchmark-password-123!";
    let salt = [0xDDu8; 32];
    let params = Argon2Params::ABSOLUTE_MIN;

    c.bench_function("argon2id_absolute_min", |b| {
        b.iter(|| {
            let _ = argon2id(black_box(password), black_box(&salt), black_box(&params));
        })
    });
}

fn bench_ed25519(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let kp = Ed25519KeyPair::generate(&mut rng);
    let message = b"benchmark message to sign";

    c.bench_function("ed25519_sign", |b| {
        b.iter(|| {
            let _ = kp.sign(black_box(message));
        })
    });

    let sig = kp.sign(message);
    c.bench_function("ed25519_verify", |b| {
        b.iter(|| {
            let _ = kp.public().verify(black_box(message), black_box(&sig));
        })
    });
}

fn bench_x25519(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    c.bench_function("x25519_keygen", |b| {
        b.iter(|| {
            let _ = X25519KeyPair::generate(black_box(&mut rng));
        })
    });

    let kp_a = X25519KeyPair::generate(&mut rng);
    let kp_b = X25519KeyPair::generate(&mut rng);
    c.bench_function("x25519_dh", |b| {
        b.iter(|| {
            let _ = kp_a.diffie_hellman(black_box(kp_b.public()));
        })
    });
}

criterion_group!(
    benches,
    bench_aead,
    bench_hkdf,
    bench_argon2,
    bench_ed25519,
    bench_x25519,
);
criterion_main!(benches);
