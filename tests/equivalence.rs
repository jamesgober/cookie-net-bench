//! Each pair of functions the benches time does the same work on the same
//! bytes: the same answer, the same output bytes where the formats match.

use cookie_net_bench::{HEADER, SET_COOKIE_LINE, SID, THEME, biscotti_side, net, rwf2, store_side};

#[test]
fn test_c1_c2_c3_reading_agrees() {
    let p = biscotti_side::processor();
    assert_eq!(net::get(HEADER, "theme"), Some(THEME));
    assert_eq!(rwf2::get(HEADER, "theme"), Some(THEME));
    assert_eq!(biscotti_side::get(HEADER, "theme", &p), Some(THEME.len()));
    assert_eq!(net::get_unique(HEADER, "__Host-sid"), Some(SID));
    assert_eq!(net::locate(HEADER, "__Host-sid"), Some(SID));
    assert_eq!(rwf2::get_unique(HEADER, "__Host-sid"), Some(SID));
    assert_eq!(
        biscotti_side::get_unique(HEADER, "__Host-sid", &p),
        Some(SID.len())
    );
    assert_eq!(net::iterate(HEADER), rwf2::iterate(HEADER));
}

#[test]
fn test_c4_c5_writing_gives_the_same_attributes() {
    // the three crates order attributes differently; compare the sets
    let attrs = |s: &str| {
        let mut v: Vec<String> = s.split("; ").map(str::to_ascii_lowercase).collect();
        v.sort();
        v
    };
    let ours = net::encode_default();
    assert_eq!(attrs(&ours), attrs(&rwf2::encode_default()));
    assert_eq!(
        attrs(&ours),
        attrs(&biscotti_side::encode_default(&biscotti_side::processor()))
    );
    let mut buf = [0u8; 256];
    assert_eq!(net::write_default(&mut buf), ours.len());
    let n = net::write_session(&mut buf);
    assert_eq!(
        attrs(std::str::from_utf8(&buf[..n]).unwrap()),
        attrs(&rwf2::encode_session())
    );
}

#[test]
fn test_c6_to_c9_crypto_round_trips() {
    let signer = net::signer();
    let mut buf = [0u8; 256];
    let n = net::sign(&signer, &mut buf);
    let signed = std::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(
        net::verify(&signer, signed),
        Some(cookie_net_bench::VALUE_64)
    );

    let key = rwf2::key();
    let rwf2_signed = rwf2::sign(&key);
    assert_eq!(
        rwf2::verify(&rwf2::verify_jar(&rwf2_signed), &key).as_deref(),
        Some(cookie_net_bench::VALUE_64)
    );

    let sealer = net::sealer();
    let (mut scratch, mut out) = (Vec::new(), Vec::new());
    net::seal(&sealer, &mut scratch, &mut out);
    let sealed = String::from_utf8(out).unwrap();
    let mut plain = Vec::new();
    assert_eq!(net::open(&sealer, &sealed, &mut plain), 64);
    assert_eq!(plain, cookie_net_bench::VALUE_64.as_bytes());

    let rwf2_sealed = rwf2::seal(&key);
    assert_eq!(
        rwf2::open(&rwf2::open_jar(&rwf2_sealed), &key).as_deref(),
        Some(cookie_net_bench::VALUE_64)
    );
}

#[test]
fn test_c10_client_parsing_agrees() {
    assert_eq!(
        net::parse_line(SET_COOKIE_LINE),
        rwf2::parse_line(SET_COOKIE_LINE)
    );
}

#[test]
fn test_c11_jar_headers_hold_the_same_pairs() {
    let mut jar = net::jar();
    let mut buf = Vec::new();
    assert_eq!(net::jar_header(&mut jar, &mut buf), 20);
    let ours = String::from_utf8(buf).unwrap();
    let store = store_side::store();
    let mut theirs = String::new();
    store_side::header(&store, &store_side::url(), &mut theirs);
    let sorted = |s: &str| {
        let mut v: Vec<String> = s.split("; ").map(str::to_string).collect();
        v.sort();
        v
    };
    assert_eq!(sorted(&ours), sorted(&theirs));
}
