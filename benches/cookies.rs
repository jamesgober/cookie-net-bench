//! Every row of cookie-net's plan, section 10: cookie-net against the best
//! Rust competitor for the same operation on the same bytes. The functions
//! timed are in `src/lib.rs`; `tests/equivalence.rs` proves each pair does the
//! same work.

use std::hint::black_box;

use cookie_net_bench::{HEADER, SET_COOKIE_LINE, biscotti_side, net, rwf2, store_side};
use criterion::{Criterion, criterion_group, criterion_main};

fn reading(c: &mut Criterion) {
    let p = biscotti_side::processor();
    let mut g = c.benchmark_group("c1_get_first");
    g.bench_function("cookie-net", |b| {
        b.iter(|| net::get(black_box(HEADER), "theme"))
    });
    g.bench_function("cookie", |b| {
        b.iter(|| rwf2::get(black_box(HEADER), "theme"))
    });
    g.bench_function("biscotti", |b| {
        b.iter(|| biscotti_side::get(black_box(HEADER), "theme", &p))
    });
    g.finish();

    let mut g = c.benchmark_group("c2_get_unique");
    g.bench_function("cookie-net", |b| {
        b.iter(|| net::get_unique(black_box(HEADER), "__Host-sid"))
    });
    g.bench_function("cookie-net-locate", |b| {
        b.iter(|| net::locate(black_box(HEADER), "__Host-sid"))
    });
    g.bench_function("cookie", |b| {
        b.iter(|| rwf2::get_unique(black_box(HEADER), "__Host-sid"))
    });
    g.bench_function("biscotti", |b| {
        b.iter(|| biscotti_side::get_unique(black_box(HEADER), "__Host-sid", &p))
    });
    g.finish();

    let mut g = c.benchmark_group("c3_iterate");
    g.bench_function("cookie-net", |b| b.iter(|| net::iterate(black_box(HEADER))));
    g.bench_function("cookie", |b| b.iter(|| rwf2::iterate(black_box(HEADER))));
    g.finish();
}

fn writing(c: &mut Criterion) {
    let p = biscotti_side::processor();
    let mut g = c.benchmark_group("c4_set_cookie_default");
    g.bench_function("cookie-net-slice", |b| {
        let mut buf = [0u8; 256];
        b.iter(|| net::write_default(black_box(&mut buf)))
    });
    g.bench_function("cookie-net-string", |b| b.iter(net::encode_default));
    g.bench_function("cookie", |b| b.iter(rwf2::encode_default));
    g.bench_function("biscotti", |b| b.iter(|| biscotti_side::encode_default(&p)));
    g.finish();

    let mut g = c.benchmark_group("c5_session_cookie");
    g.bench_function("cookie-net-slice", |b| {
        let mut buf = [0u8; 256];
        b.iter(|| net::write_session(black_box(&mut buf)))
    });
    g.bench_function("cookie", |b| b.iter(rwf2::encode_session));
    g.finish();
}

fn crypto(c: &mut Criterion) {
    let signer = net::signer();
    let key = rwf2::key();
    let mut buf = [0u8; 256];
    let n = net::sign(&signer, &mut buf);
    let signed = std::str::from_utf8(&buf[..n]).unwrap().to_string();
    let rwf2_signed = rwf2::sign(&key);
    let rwf2_verify_jar = rwf2::verify_jar(&rwf2_signed);

    let mut g = c.benchmark_group("c6_sign_64");
    g.bench_function("cookie-net", |b| {
        let mut out = [0u8; 256];
        b.iter(|| net::sign(&signer, black_box(&mut out)))
    });
    g.bench_function("cookie-signedjar", |b| b.iter(|| rwf2::sign(&key)));
    g.finish();

    let mut g = c.benchmark_group("c7_verify_64");
    g.bench_function("cookie-net", |b| {
        b.iter(|| net::verify(&signer, black_box(&signed)))
    });
    g.bench_function("cookie-signedjar", |b| {
        b.iter(|| rwf2::verify(black_box(&rwf2_verify_jar), &key))
    });
    g.finish();

    let sealer = net::sealer();
    let (mut scratch, mut out) = (Vec::with_capacity(256), Vec::with_capacity(256));
    net::seal(&sealer, &mut scratch, &mut out);
    let sealed = String::from_utf8(out.clone()).unwrap();
    let rwf2_sealed = rwf2::seal(&key);
    let rwf2_open_jar = rwf2::open_jar(&rwf2_sealed);

    let mut g = c.benchmark_group("c8_seal_64");
    g.bench_function("cookie-net", |b| {
        b.iter(|| net::seal(&sealer, &mut scratch, &mut out))
    });
    g.bench_function("cookie-privatejar", |b| b.iter(|| rwf2::seal(&key)));
    g.finish();

    let mut g = c.benchmark_group("c9_open_64");
    let mut plain = Vec::with_capacity(128);
    g.bench_function("cookie-net", |b| {
        b.iter(|| net::open(&sealer, black_box(&sealed), &mut plain))
    });
    g.bench_function("cookie-privatejar", |b| {
        b.iter(|| rwf2::open(black_box(&rwf2_open_jar), &key))
    });
    g.finish();
}

fn client(c: &mut Criterion) {
    let mut g = c.benchmark_group("c10_parse_set_cookie");
    g.bench_function("cookie-net", |b| {
        b.iter(|| net::parse_line(black_box(SET_COOKIE_LINE)))
    });
    g.bench_function("cookie", |b| {
        b.iter(|| rwf2::parse_line(black_box(SET_COOKIE_LINE)))
    });
    g.finish();

    let mut jar = net::jar();
    let store = store_side::store();
    let url = store_side::url();
    let mut g = c.benchmark_group("c11_jar_header_20");
    g.bench_function("cookie-net", |b| {
        let mut buf = Vec::with_capacity(1024);
        b.iter(|| net::jar_header(&mut jar, &mut buf))
    });
    g.bench_function("cookie_store", |b| {
        let mut buf = String::with_capacity(1024);
        b.iter(|| store_side::header(&store, black_box(&url), &mut buf))
    });
    g.finish();
}

criterion_group!(benches, reading, writing, crypto, client);
criterion_main!(benches);
