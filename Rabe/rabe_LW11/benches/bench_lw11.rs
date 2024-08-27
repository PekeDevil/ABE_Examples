use rabe_LW11::my_setup_lw11;
use rabe_LW11::setup_authssetup_lw11;
use rabe_LW11::setup_authssetup_keygen_lw11;
use rabe_LW11::setup_authsetup_encrypt_lw11;
use rabe_LW11::setup_authsetup_keygen_encrypt_decrypt_lw11;


use criterion::{
    criterion_group,
    criterion_main,
    Criterion
};

fn my_setup_lw11_benchmark(c: &mut Criterion) {
    c.bench_function("setup", |b| b.iter(||my_setup_lw11()));
}

fn setup_authssetup_lw11_benchmark(c: &mut Criterion) {
    c.bench_function("setup + authsetup", |b| b.iter(||setup_authssetup_lw11()));
}

fn setup_authssetup_keygen_lw11_benchmark(c: &mut Criterion) {
    c.bench_function("keygen + authsetup + setup", |b| b.iter(||setup_authssetup_keygen_lw11()));
}

fn setup_authsetup_encrypt_lw11_benchmark(c: &mut Criterion) {
    c.bench_function("setup + authsetup + encrypt", |b| b.iter(||setup_authsetup_encrypt_lw11()));
}

fn setup_authsetup_keygen_encrypt_decrypt_lw11_benchmark(c: &mut Criterion) {
    c.bench_function("setup + keygen + authsetup + encrypt + decrypt", |b| b.iter(||setup_authsetup_keygen_encrypt_decrypt_lw11()));
}


criterion_group!(benches, my_setup_lw11_benchmark, setup_authssetup_lw11_benchmark, setup_authssetup_keygen_lw11_benchmark, setup_authsetup_encrypt_lw11_benchmark, setup_authsetup_keygen_encrypt_decrypt_lw11_benchmark);
criterion_main!(benches);