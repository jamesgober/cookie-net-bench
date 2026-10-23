<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>cookie-net-bench</b>
    <br>
    <sub><sup>COMPETITOR BENCHMARKS FOR COOKIE-NET</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/cookie-net"><img alt="cookie-net on crates.io" src="https://img.shields.io/crates/v/cookie-net?label=cookie-net"></a>
    <a href="https://github.com/jamesgober/cookie-net-bench/actions"><img alt="CI" src="https://github.com/jamesgober/cookie-net-bench/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<p>
    <strong>cookie-net-bench</strong> measures <a href="https://github.com/jamesgober/cookie-net">cookie-net</a> against <a href="https://crates.io/crates/cookie">cookie</a>, <a href="https://crates.io/crates/biscotti">biscotti</a>, and <a href="https://crates.io/crates/cookie_store">cookie_store</a> on identical input bytes. It is a separate, unpublished repository, so cookie-net never depends on those crates, not even as a dev-dependency. cookie-net comes from crates.io; the competitor versions are pinned by the committed <code>Cargo.lock</code>.
</p>
<p>
    <strong>MSRV is 1.85+</strong> (Rust 2024 edition). Not published (<code>publish = false</code>). Benchmarks are never run in CI: CI builds the harness, lints it, and runs the equivalence tests.
</p>

## Workloads

The rows of cookie-net's plan, section 10. Every input is defined once in [`src/lib.rs`](./src/lib.rs), and both sides of every row are functions there.

| Id | Workload | cookie-net | Competitor |
|---|---|---|---|
| C1 | first value of `theme` in a 6-pair, about 300-byte header | `get` | `cookie::Cookie::split_parse` then find; `biscotti::RequestCookies::parse_header` then `get` |
| C2 | the only value of `__Host-sid`, whole header | `get_unique`; `locate` (with shadows and statistics) | `split_parse`, counting matches; biscotti `get_all` |
| C3 | every pair | `parse(..).iter()` | `split_parse` |
| C4 | `theme=dark` with `Secure; HttpOnly; SameSite=Lax; Path=/` | `SetCookie::new` + `write_to` (stack buffer) and `encode` | `Cookie::build(..).to_string()`; biscotti `ResponseCookies::header_values` |
| C5 | the session cookie (43-character token, 12-hour `Max-Age`) | `session_cookie` + `write_to` | `Cookie::build(..)` |
| C6, C7 | sign and verify a 64-byte value | `Signer` (keyed BLAKE3) | `cookie::SignedJar` (HMAC-SHA-256) |
| C8, C9 | seal and open a 64-byte value | `Sealer` (XChaCha20-Poly1305) | `cookie::PrivateJar` (AES-256-GCM) |
| C10 | parse a 120-byte `Set-Cookie` line as a client | `parse_set_cookie` | `cookie::Cookie::parse` |
| C11 | the `Cookie` header for 20 of 100 stored cookies | `Jar::write_cookie_header` | `cookie_store::CookieStore::get_request_values` |

## Fairness rules

- **Same bytes, same work.** [`tests/equivalence.rs`](./tests/equivalence.rs) runs the exact functions the benches time and asserts they agree: the same values, the same attribute sets, round trips for signing and sealing, and the same pairs from both jars.
- **No percent-decoding.** biscotti percent-decodes by default; it is configured not to, so it does the same work as the others.
- **Allocations count.** Each side is timed through its public API, including the allocations it makes.
- **Security is not equal in C6 to C9, and the table says so.** The `cookie` crate signs the value only (a signed value can be moved to another cookie name); cookie-net binds the name, the key id, and an optional expiry. `PrivateJar` uses 96-bit random nonces (about 2^32 messages per key); cookie-net uses 192-bit ones.

## Two kinds of numbers

- **criterion** (`cargo bench`) gives absolute times.
- **`ratio`** (`cargo run --release --bin ratio`, Linux) decides the 20% rule. The two sides alternate in short rounds, each round timed with the thread's own CPU time, and the medians are compared. Shared machines move wall-clock results by up to two times between runs; alternating rounds and thread CPU time keep the ratios repeatable to a few percent.

`scripts/run.sh` runs the equivalence tests and criterion and writes a results file with the machine, toolchain, and crate versions to [`results/`](./results).

## License

Licensed under either of Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE)) or MIT license ([LICENSE-MIT](./LICENSE-MIT)) at your option.

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
