//! Ratios for every row that hold steady under load: cookie-net and the best competitor run
//! in alternating short rounds (so drift hits both equally), each round timed
//! with the thread's own CPU time (so time spent descheduled by other
//! processes is not counted), and the median per-call time of each side is
//! reported with their ratio. Linux only (`CLOCK_THREAD_CPUTIME_ID`).
//!
//! Usage: `cargo run --release --bin ratio [rounds]`

#![cfg_attr(not(target_os = "linux"), allow(unused))]

use std::hint::black_box;

use cookie_net_bench::{HEADER, SET_COOKIE_LINE, biscotti_side, net, rwf2, store_side};

#[cfg(target_os = "linux")]
fn thread_cpu_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec; the clock id is a constant
    // the kernel defines.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    u64::try_from(ts.tv_sec).unwrap_or(0) * 1_000_000_000 + u64::try_from(ts.tv_nsec).unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn thread_cpu_ns() -> u64 {
    0
}

/// Per-call nanoseconds of one round of `iters` calls.
fn round(iters: u32, f: &mut dyn FnMut()) -> f64 {
    let t = thread_cpu_ns();
    for _ in 0..iters {
        f();
    }
    (thread_cpu_ns() - t) as f64 / f64::from(iters)
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

/// Alternates `ours` and `theirs` for `rounds` rounds; returns both medians.
fn compare(
    rounds: usize,
    iters: u32,
    ours: &mut dyn FnMut(),
    theirs: &mut dyn FnMut(),
) -> (f64, f64) {
    // warm up both
    round(iters, ours);
    round(iters, theirs);
    let (mut a, mut b) = (Vec::with_capacity(rounds), Vec::with_capacity(rounds));
    for i in 0..rounds {
        if i % 2 == 0 {
            a.push(round(iters, ours));
            b.push(round(iters, theirs));
        } else {
            b.push(round(iters, theirs));
            a.push(round(iters, ours));
        }
    }
    (median(a), median(b))
}

fn report(row: &str, versus: &str, (ours, theirs): (f64, f64)) {
    let faster = (1.0 - ours / theirs) * 100.0;
    let verdict = if faster >= 20.0 { "meets" } else { "SHORT" };
    println!("| {row} | {ours:.1} | {versus} {theirs:.1} | {faster:+.0}% | {verdict} |");
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("ratio needs Linux (CLOCK_THREAD_CPUTIME_ID)");
}

#[cfg(target_os = "linux")]
fn main() {
    let rounds: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(301);
    let p = biscotti_side::processor();
    println!("| Row | cookie-net (ns) | best competitor (ns) | cookie-net faster by | 20% rule |");
    println!("|---|---|---|---|---|");

    report(
        "C1 get",
        "cookie",
        compare(
            rounds,
            2000,
            &mut || {
                black_box(net::get(black_box(HEADER), "theme"));
            },
            &mut || {
                black_box(rwf2::get(black_box(HEADER), "theme"));
            },
        ),
    );
    report(
        "C2 get_unique",
        "cookie",
        compare(
            rounds,
            1000,
            &mut || {
                black_box(net::get_unique(black_box(HEADER), "__Host-sid"));
            },
            &mut || {
                black_box(rwf2::get_unique(black_box(HEADER), "__Host-sid"));
            },
        ),
    );
    report(
        "C2 locate",
        "cookie",
        compare(
            rounds,
            1000,
            &mut || {
                black_box(net::locate(black_box(HEADER), "__Host-sid"));
            },
            &mut || {
                black_box(rwf2::get_unique(black_box(HEADER), "__Host-sid"));
            },
        ),
    );
    report(
        "C2 get_unique",
        "biscotti",
        compare(
            rounds,
            500,
            &mut || {
                black_box(net::get_unique(black_box(HEADER), "__Host-sid"));
            },
            &mut || {
                black_box(biscotti_side::get_unique(
                    black_box(HEADER),
                    "__Host-sid",
                    &p,
                ));
            },
        ),
    );
    report(
        "C3 iterate",
        "cookie",
        compare(
            rounds,
            1000,
            &mut || {
                black_box(net::iterate(black_box(HEADER)));
            },
            &mut || {
                black_box(rwf2::iterate(black_box(HEADER)));
            },
        ),
    );
    let mut buf = [0u8; 256];
    let mut buf2 = [0u8; 256];
    report(
        "C4 set_cookie (slice)",
        "cookie",
        compare(
            rounds,
            4000,
            &mut || {
                black_box(net::write_default(black_box(&mut buf)));
            },
            &mut || {
                black_box(rwf2::encode_default());
            },
        ),
    );
    report(
        "C4 set_cookie (String)",
        "cookie",
        compare(
            rounds,
            4000,
            &mut || {
                black_box(net::encode_default());
            },
            &mut || {
                black_box(rwf2::encode_default());
            },
        ),
    );
    report(
        "C5 session_cookie",
        "cookie",
        compare(
            rounds,
            4000,
            &mut || {
                black_box(net::write_session(black_box(&mut buf2)));
            },
            &mut || {
                black_box(rwf2::encode_session());
            },
        ),
    );

    let signer = net::signer();
    let key = rwf2::key();
    let mut sbuf = [0u8; 256];
    let n = net::sign(&signer, &mut sbuf);
    let signed = std::str::from_utf8(&sbuf[..n]).unwrap().to_string();
    let rwf2_jar = rwf2::verify_jar(&rwf2::sign(&key));
    let mut obuf = [0u8; 256];
    report(
        "C6 sign 64 B",
        "cookie SignedJar",
        compare(
            rounds,
            1000,
            &mut || {
                black_box(net::sign(&signer, black_box(&mut obuf)));
            },
            &mut || {
                black_box(rwf2::sign(&key));
            },
        ),
    );
    report(
        "C7 verify 64 B",
        "cookie SignedJar",
        compare(
            rounds,
            1000,
            &mut || {
                black_box(net::verify(&signer, black_box(&signed)));
            },
            &mut || {
                black_box(rwf2::verify(black_box(&rwf2_jar), &key));
            },
        ),
    );

    let sealer = net::sealer();
    let (mut scratch, mut out) = (Vec::with_capacity(256), Vec::with_capacity(256));
    net::seal(&sealer, &mut scratch, &mut out);
    let sealed = String::from_utf8(out.clone()).unwrap();
    let rwf2_open = rwf2::open_jar(&rwf2::seal(&key));
    report(
        "C8 seal 64 B",
        "cookie PrivateJar",
        compare(
            rounds,
            300,
            &mut || {
                black_box(net::seal(&sealer, &mut scratch, &mut out));
            },
            &mut || {
                black_box(rwf2::seal(&key));
            },
        ),
    );
    let mut plain = Vec::with_capacity(128);
    report(
        "C9 open 64 B",
        "cookie PrivateJar",
        compare(
            rounds,
            300,
            &mut || {
                black_box(net::open(&sealer, black_box(&sealed), &mut plain));
            },
            &mut || {
                black_box(rwf2::open(black_box(&rwf2_open), &key));
            },
        ),
    );

    report(
        "C10 parse_set_cookie",
        "cookie",
        compare(
            rounds,
            1000,
            &mut || {
                black_box(net::parse_line(black_box(SET_COOKIE_LINE)));
            },
            &mut || {
                black_box(rwf2::parse_line(black_box(SET_COOKIE_LINE)));
            },
        ),
    );

    let mut jar = net::jar();
    let store = store_side::store();
    let url = store_side::url();
    let (mut jb, mut sb) = (Vec::with_capacity(1024), String::with_capacity(1024));
    report(
        "C11 jar header, 20 of 100",
        "cookie_store",
        compare(
            rounds,
            300,
            &mut || {
                black_box(net::jar_header(&mut jar, &mut jb));
            },
            &mut || {
                black_box(store_side::header(&store, black_box(&url), &mut sb));
            },
        ),
    );
}
