use rabe_BSW07::my_setup_BSW07;
use rabe_BSW07::setup_keygen_BSW07;
use rabe_BSW07::setup_encrypt_BSW07;
use rabe_BSW07::setup_keygen_encrypt_BSW07;


use criterion::{
    criterion_group,
    criterion_main,
    black_box,
    Criterion
};

fn my_setup_BSW07_benchmark(c: &mut Criterion) {
    c.bench_function("setup", |b| b.iter(||my_setup_BSW07()));
}

fn setup_keygen_BSW07_benchmark(c: &mut Criterion) {
    c.bench_function("keygen + setup", |b| b.iter(||setup_keygen_BSW07()));
}

fn setup_encrypt_BSW07_benchmark(c: &mut Criterion) {
    c.bench_function("setup + encrypt", |b| b.iter(||setup_encrypt_BSW07()));
}

fn setup_keygen_encrypt_BSW07_benchmark(c: &mut Criterion) {
    c.bench_function("setup + keygen + encrypt + decrypt", |b| b.iter(||setup_keygen_encrypt_BSW07()));
}


criterion_group!(benches, my_setup_BSW07_benchmark, setup_keygen_BSW07_benchmark, setup_encrypt_BSW07_benchmark, setup_keygen_encrypt_BSW07_benchmark);
criterion_main!(benches);