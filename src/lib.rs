//! Shared inputs and both sides of every comparison, used by the benches
//! and by `tests/equivalence.rs`, so the benches time exactly what the
//! equivalence tests prove equal.
//!
//! Workloads are the rows of cookie-net's plan, section 10 (C1 to C11).

use std::sync::OnceLock;

/// A typical browser `Cookie` header: 6 pairs, about 300 bytes, `theme` third.
pub const HEADER: &str = "__Host-sid=Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA; _ga=GA1.2.1234567890.1700000000; theme=dark; _gid=GA1.2.987654321.1700000000; consent=analytics%3Dno%2Cads%3Dno%2Cversion%3D3; lang=fr-CA; _fbp=fb.1.1700000000000.1234567890";

/// The value of `theme` in [`HEADER`].
pub const THEME: &str = "dark";
/// The session token in [`HEADER`].
pub const SID: &str = "Zk3J9qL0wX7aP2mT8sV1cR5dY4hN6bE0uK9gF3jQ2oA";

/// A typical `Set-Cookie` line, about 120 bytes.
pub const SET_COOKIE_LINE: &str = "id=a3fWa; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=2592000; Domain=example.com; Path=/; Secure; HttpOnly; SameSite=Lax";

/// A 64-byte value for signing and sealing.
pub const VALUE_64: &str = "lang=fr-CA|tz=America/Toronto|layout=compact|beta=1|v=20261023xx";

/// The fixed instant the benches use (Unix seconds).
pub const NOW: u64 = 1_800_000_000;

/// 32-byte key for cookie-net.
pub const KEY_32: [u8; 32] = *b"an example key, 32 bytes long!!!";

/// 64-byte master for the `cookie` crate's `Key::from`.
pub const KEY_64: [u8; 64] = *b"a 64-byte master key for the cookie crate, used by SignedJar ok!";

/// cookie-net's side.
pub mod net {
    use cookie_net::{
        self as cookie, Jar, Limits, RequestUrl, Sealer, SetCookie, Signer, parse_set_cookie,
    };
    use parse_net::SliceSink;

    /// C1: the first value of `name`.
    pub fn get<'a>(header: &'a str, name: &str) -> Option<&'a str> {
        cookie::get(header, name)
    }

    /// C2: the only value of `name`, scanning the whole header.
    pub fn get_unique<'a>(header: &'a str, name: &str) -> Option<&'a str> {
        cookie::get_unique(header, name).ok().flatten()
    }

    /// C2 (gateway form): the one-pass locator with statistics and shadows.
    pub fn locate<'a>(header: &'a str, name: &str) -> Option<&'a str> {
        match cookie::locate(header, name, &Limits::DEFAULT).lookup {
            cookie::Lookup::One(v) => Some(v),
            _ => None,
        }
    }

    /// C3: every pair, as (name length + value length) summed so nothing is
    /// optimized away.
    pub fn iterate(header: &str) -> usize {
        cookie::parse(header)
            .iter()
            .map(|p| p.name().len() + p.value().len())
            .sum()
    }

    /// C4: `theme=dark` with the defaults, written into a stack buffer.
    pub fn write_default(buf: &mut [u8]) -> usize {
        let c = SetCookie::new("theme", "dark").unwrap();
        let mut out = SliceSink::new(buf);
        c.write_to(&mut out).unwrap();
        out.len()
    }

    /// C4 as a `String`.
    pub fn encode_default() -> String {
        SetCookie::new("theme", "dark").unwrap().encode()
    }

    /// C5: the session cookie, written into a stack buffer.
    pub fn write_session(buf: &mut [u8]) -> usize {
        let c = cookie::session_cookie("__Host-sid", super::SID, 12 * cookie::HOUR).unwrap();
        let mut out = SliceSink::new(buf);
        c.write_to(&mut out).unwrap();
        out.len()
    }

    /// The signer the benches use.
    pub fn signer() -> Signer {
        Signer::new(super::KEY_32).unwrap()
    }

    /// C6: sign a 64-byte value into a stack buffer.
    pub fn sign(s: &Signer, buf: &mut [u8]) -> usize {
        let mut out = SliceSink::new(buf);
        s.sign_into("prefs", super::VALUE_64, None, &[], &mut out)
            .unwrap();
        out.len()
    }

    /// C7: verify a signed value.
    pub fn verify<'a>(s: &Signer, raw: &'a str) -> Option<&'a str> {
        s.verify("prefs", raw, super::NOW).ok()
    }

    /// The sealer the benches use.
    pub fn sealer() -> Sealer {
        Sealer::new(super::KEY_32).unwrap()
    }

    /// C8: seal a 64-byte value, reusing the scratch and output buffers.
    pub fn seal(s: &Sealer, scratch: &mut Vec<u8>, out: &mut Vec<u8>) -> usize {
        out.clear();
        s.seal_into("flash", super::VALUE_64.as_bytes(), None, &[], scratch, out)
            .unwrap();
        out.len()
    }

    /// C9: open a sealed value into a reused buffer.
    pub fn open(s: &Sealer, raw: &str, out: &mut Vec<u8>) -> usize {
        s.open_into("flash", raw, &[], super::NOW, out).unwrap();
        out.len()
    }

    /// C10: parse a `Set-Cookie` line as a client.
    pub fn parse_line(line: &str) -> usize {
        let v = parse_set_cookie(line).unwrap();
        v.name.len() + v.value.len() + usize::from(v.secure)
    }

    /// C11: a jar with 20 cookies for one host (and 80 for others).
    pub fn jar() -> Jar {
        let mut jar = Jar::new().with_limits(cookie_net::JarLimits::DEFAULT.total(3000));
        for (host, names) in super::jar_cookies() {
            let url = RequestUrl::https(host, "/");
            for line in names {
                jar.store(&url, line.as_str(), super::NOW);
            }
        }
        jar
    }

    /// C11: the `Cookie` header for the 20 cookies of the target host.
    pub fn jar_header(jar: &mut Jar, buf: &mut Vec<u8>) -> usize {
        buf.clear();
        let url = RequestUrl::https(super::JAR_HOST, "/account/orders");
        jar.write_cookie_header(
            &url,
            &cookie_net::RequestContext::default(),
            super::NOW,
            buf,
        )
        .unwrap()
    }
}

/// The `cookie` crate's side (0.18).
pub mod rwf2 {
    use cookie::{Cookie, CookieJar, Key, SameSite};

    /// C1: `split_parse` then find; the crate's way to read a `Cookie` header
    /// without building a jar.
    pub fn get<'a>(header: &'a str, name: &str) -> Option<&'a str> {
        Cookie::split_parse(header)
            .flatten()
            .find(|c| c.name() == name)
            .and_then(|c| c.value_raw())
    }

    /// C2: every pair checked, counting matches.
    pub fn get_unique<'a>(header: &'a str, name: &str) -> Option<&'a str> {
        let mut found = None;
        let mut count = 0;
        for c in Cookie::split_parse(header).flatten() {
            if c.name() == name {
                count += 1;
                found = c.value_raw();
            }
        }
        (count == 1).then_some(found).flatten()
    }

    /// C3: every pair.
    pub fn iterate(header: &str) -> usize {
        Cookie::split_parse(header)
            .flatten()
            .map(|c| c.name().len() + c.value().len())
            .sum()
    }

    /// C4: `theme=dark` with the same attributes, to a `String` (the crate
    /// writes through `Display`).
    pub fn encode_default() -> String {
        Cookie::build(("theme", "dark"))
            .path("/")
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Lax)
            .build()
            .to_string()
    }

    /// C5: the session cookie with the same attributes.
    pub fn encode_session() -> String {
        Cookie::build(("__Host-sid", super::SID))
            .path("/")
            .max_age(cookie::time::Duration::seconds(43_200))
            .secure(true)
            .http_only(true)
            .same_site(SameSite::Lax)
            .build()
            .to_string()
    }

    /// The key the benches use.
    pub fn key() -> Key {
        Key::from(&super::KEY_64)
    }

    /// C6: `SignedJar::add`, then read the signed value back out.
    pub fn sign(key: &Key) -> String {
        let mut jar = CookieJar::new();
        jar.signed_mut(key)
            .add(Cookie::new("prefs", super::VALUE_64));
        jar.get("prefs")
            .map(|c| c.value().to_string())
            .unwrap_or_default()
    }

    /// C7: `SignedJar::get` on a jar holding the signed value.
    pub fn verify_jar(signed: &str) -> CookieJar {
        let mut jar = CookieJar::new();
        jar.add_original(Cookie::new("prefs", signed.to_string()));
        jar
    }

    /// C7.
    pub fn verify(jar: &CookieJar, key: &Key) -> Option<String> {
        jar.signed(key).get("prefs").map(|c| c.value().to_string())
    }

    /// C8: `PrivateJar::add` (AES-256-GCM).
    pub fn seal(key: &Key) -> String {
        let mut jar = CookieJar::new();
        jar.private_mut(key)
            .add(Cookie::new("flash", super::VALUE_64));
        jar.get("flash")
            .map(|c| c.value().to_string())
            .unwrap_or_default()
    }

    /// C9: `PrivateJar::get`.
    pub fn open(jar: &CookieJar, key: &Key) -> Option<String> {
        jar.private(key).get("flash").map(|c| c.value().to_string())
    }

    /// A jar holding a sealed value, for C9.
    pub fn open_jar(sealed: &str) -> CookieJar {
        let mut jar = CookieJar::new();
        jar.add_original(Cookie::new("flash", sealed.to_string()));
        jar
    }

    /// C10: `Cookie::parse`.
    pub fn parse_line(line: &str) -> usize {
        let c = Cookie::parse(line).unwrap();
        c.name().len() + c.value().len() + usize::from(c.secure().unwrap_or(false))
    }
}

/// biscotti's side (0.4).
pub mod biscotti_side {
    use biscotti::{
        Processor, ProcessorConfig, RequestCookies, ResponseCookie, ResponseCookies, SameSite,
    };

    /// A processor with no percent-encoding, so it does the same work as the
    /// other two (biscotti percent-decodes by default).
    pub fn processor() -> Processor {
        let mut config = ProcessorConfig::default();
        config.percent_encode = false;
        config.into()
    }

    /// C1: parse the header into its map, then look one name up. Returns
    /// the value's length, so no side pays for a copy the others skip.
    pub fn get(header: &str, name: &str, p: &Processor) -> Option<usize> {
        let cookies = RequestCookies::parse_header(header, p).ok()?;
        cookies.get(name).map(|c| c.value().len())
    }

    /// C2: parse, then every value of the name; exactly one means found.
    pub fn get_unique(header: &str, name: &str, p: &Processor) -> Option<usize> {
        let cookies = RequestCookies::parse_header(header, p).ok()?;
        let all = cookies.get_all(name)?;
        let mut values = all.values();
        let first = values.next()?.len();
        values.next().is_none().then_some(first)
    }

    /// C4: one response cookie with the same attributes, to its header value.
    pub fn encode_default(p: &Processor) -> String {
        let mut cookies = ResponseCookies::new();
        cookies.insert(
            ResponseCookie::new("theme", "dark")
                .set_path("/")
                .set_secure(true)
                .set_http_only(true)
                .set_same_site(SameSite::Lax),
        );
        cookies.header_values(p).next().unwrap_or_default()
    }
}

/// The host whose 20 cookies C11 reads.
pub const JAR_HOST: &str = "shop.example.com";

/// 20 cookies for [`JAR_HOST`] and 80 for other hosts, as `Set-Cookie` lines.
pub fn jar_cookies() -> &'static [(&'static str, Vec<String>)] {
    static COOKIES: OnceLock<Vec<(&'static str, Vec<String>)>> = OnceLock::new();
    COOKIES.get_or_init(|| {
        let mut out = vec![(
            JAR_HOST,
            (0..20)
                .map(|i| {
                    let path = if i % 3 == 0 { "/account" } else { "/" };
                    format!("c{i}=value-{i:04}-abcdefgh; Path={path}; Secure; HttpOnly")
                })
                .collect(),
        )];
        for h in [
            "a.example.org",
            "b.example.org",
            "c.example.net",
            "d.example.net",
        ] {
            out.push((
                h,
                (0..20)
                    .map(|i| format!("o{i}=x{i}; Path=/; Secure"))
                    .collect(),
            ));
        }
        out
    })
}

/// cookie_store's side (0.22).
pub mod store_side {
    use cookie_store::CookieStore;
    use url::Url;

    /// C11: the same 100 cookies in a `CookieStore`.
    pub fn store() -> CookieStore {
        let mut store = CookieStore::default();
        for (host, lines) in super::jar_cookies() {
            let url = Url::parse(&format!("https://{host}/")).unwrap();
            for line in lines {
                let _ = store.parse(line, &url);
            }
        }
        store
    }

    /// The request URL of C11.
    pub fn url() -> Url {
        Url::parse(&format!("https://{}/account/orders", super::JAR_HOST)).unwrap()
    }

    /// C11: the request values joined as a `Cookie` header.
    pub fn header(store: &CookieStore, url: &Url, buf: &mut String) -> usize {
        buf.clear();
        for (i, (n, v)) in store.get_request_values(url).enumerate() {
            if i > 0 {
                buf.push_str("; ");
            }
            buf.push_str(n);
            buf.push('=');
            buf.push_str(v);
        }
        buf.len()
    }
}
