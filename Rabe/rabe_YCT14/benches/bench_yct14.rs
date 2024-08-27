use rabe_YCT14::my_setupyct14;
use rabe_YCT14::setup_keygen_yct14;
use rabe_YCT14::setup_encrypt_yct14;
use rabe_YCT14::setup_keygen_encrypt_decrypt_yct14;


use criterion::{
    criterion_group,
    criterion_main,
    Criterion
};

fn my_setupyct14_benchmark(c: &mut Criterion) {
    c.bench_function("setup function", |b| b.iter(||my_setupyct14()));
}

fn setup_keygen_yct14_benchmark(c: &mut Criterion) {
    c.bench_function("keygen + setup function", |b| b.iter(||setup_keygen_yct14()));
}

fn setup_encrypt_yct14_benchmark(c: &mut Criterion) {
    c.bench_function("setup + encrypt function", |b| b.iter(||setup_encrypt_yct14()));
}

fn setup_keygen_encrypt_decrypt_yct14_benchmark(c: &mut Criterion) {
    c.bench_function("setup + keygen + encrypt + decrypt function", |b| b.iter(||setup_keygen_encrypt_decrypt_yct14()));
}


criterion_group!(benches, my_setupyct14_benchmark, setup_keygen_yct14_benchmark, setup_encrypt_yct14_benchmark, setup_keygen_encrypt_decrypt_yct14_benchmark);
criterion_main!(benches);