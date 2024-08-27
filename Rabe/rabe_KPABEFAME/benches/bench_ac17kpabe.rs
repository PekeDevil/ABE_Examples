use rabe_KPABEFAME_sinoverflow::my_setupac17kpabe;
use rabe_KPABEFAME_sinoverflow::setup_keygen;
use rabe_KPABEFAME_sinoverflow::setup_encryptac17kpabe;
use rabe_KPABEFAME_sinoverflow::setup_keygen_encrypt_decryptac17kpabe;


use criterion::{
    criterion_group,
    criterion_main,
    Criterion
};

fn my_setupac17kpabe_benchmark(c: &mut Criterion) {
    c.bench_function("setup function", |b| b.iter(||my_setupac17kpabe()));
}

fn setup_keygen_benchmark(c: &mut Criterion) {
    c.bench_function("keygen + setup function", |b| b.iter(||setup_keygen()));
}

fn setup_encryptac17kpabe_benchmark(c: &mut Criterion) {
    c.bench_function("setup + encrypt function", |b| b.iter(||setup_encryptac17kpabe()));
}

fn setup_keygen_encrypt_decryptac17kpabe_benchmark(c: &mut Criterion) {
    c.bench_function("setup + keygen + encrypt + decrypt function", |b| b.iter(||setup_keygen_encrypt_decryptac17kpabe()));
}


criterion_group!(benches, my_setupac17kpabe_benchmark, setup_keygen_benchmark, setup_encryptac17kpabe_benchmark, setup_keygen_encrypt_decryptac17kpabe_benchmark);
criterion_main!(benches);