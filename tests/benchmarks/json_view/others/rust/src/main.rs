//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// The Rust counterpart of bench_all.cpp: the same use cases (validate, sum, select, edit, minify, write), files,
// checks (right result; validation level from malformed-input probes) and timing method (every variant interleaved in every round, each
// timed call after an untimed one, best round); see README.md. The input is the file as bytes (&[u8]); simd-json
// parses in place, so its variants copy the input inside the timed call.
//
// Usage: bench_rs <json_test_data dir> [rounds] [document] [use case]
use serde::de::{DeserializeOwned, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use simd_json::prelude::*;
use sonic_rs::{JsonContainerTrait, JsonValueMutTrait, JsonValueTrait};
use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

#[derive(Default, Debug, Clone, Copy)]
struct Stats {
    num: f64,
    str_: usize,
    nodes: usize,
}

// ---- sum: walk a DOM, visit every value, convert every number, touch every string and key

fn walk_simd(v: &simd_json::BorrowedValue, st: &mut Stats) {
    st.nodes += 1;
    if let Some(o) = v.as_object() {
        for (k, x) in o.iter() {
            st.str_ += k.len();
            walk_simd(x, st);
        }
    } else if let Some(a) = v.as_array() {
        for x in a.iter() {
            walk_simd(x, st);
        }
    } else if let Some(s) = v.as_str() {
        st.str_ += s.len();
    } else if v.is_u64() {
        st.num += v.as_u64().unwrap() as f64;
    } else if v.is_i64() {
        st.num += v.as_i64().unwrap() as f64;
    } else if v.is_f64() {
        st.num += v.as_f64().unwrap();
    }
}

fn walk_sonic(v: &sonic_rs::Value, st: &mut Stats) {
    st.nodes += 1;
    if let Some(o) = v.as_object() {
        for (k, x) in o.iter() {
            st.str_ += k.len();
            walk_sonic(x, st);
        }
    } else if let Some(a) = v.as_array() {
        for x in a.iter() {
            walk_sonic(x, st);
        }
    } else if let Some(s) = v.as_str() {
        st.str_ += s.len();
    } else if v.is_number() {
        if let Some(u) = v.as_u64() {
            st.num += u as f64;
        } else if let Some(i) = v.as_i64() {
            st.num += i as f64;
        } else {
            st.num += v.as_f64().unwrap();
        }
    }
}

fn walk_serde(v: &serde_json::Value, st: &mut Stats) {
    st.nodes += 1;
    match v {
        serde_json::Value::Object(o) => {
            for (k, x) in o.iter() {
                st.str_ += k.len();
                walk_serde(x, st);
            }
        }
        serde_json::Value::Array(a) => {
            for x in a.iter() {
                walk_serde(x, st);
            }
        }
        serde_json::Value::String(s) => st.str_ += s.len(),
        serde_json::Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                st.num += u as f64;
            } else if let Some(i) = n.as_i64() {
                st.num += i as f64;
            } else {
                st.num += n.as_f64().unwrap();
            }
        }
        _ => {}
    }
}

// the same visit without a DOM: a serde visitor, driven by any serde deserializer, in document order
struct Sum<'a>(&'a mut Stats);
struct Key<'a>(&'a mut Stats);

impl<'de> DeserializeSeed<'de> for Sum<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Sum<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<(), E> {
        self.0.nodes += 1;
        Ok(())
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<(), E> {
        self.0.nodes += 1;
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<(), E> {
        self.0.nodes += 1;
        self.0.num += v as f64;
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<(), E> {
        self.0.nodes += 1;
        self.0.num += v as f64;
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<(), E> {
        self.0.nodes += 1;
        self.0.num += v;
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<(), E> {
        self.0.nodes += 1;
        self.0.str_ += v.len();
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
        let st = self.0;
        st.nodes += 1;
        while a.next_element_seed(Sum(&mut *st))?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
        let st = self.0;
        st.nodes += 1;
        while a.next_key_seed(Key(&mut *st))?.is_some() {
            a.next_value_seed(Sum(&mut *st))?;
        }
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for Key<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for Key<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a key")
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<(), E> {
        self.0.str_ += v.len();
        Ok(())
    }
}

fn sum_serde(s: &[u8], st: &mut Stats) -> bool {
    let mut de = serde_json::Deserializer::from_slice(s);
    Sum(st).deserialize(&mut de).is_ok() && de.end().is_ok()
}

fn sum_sonic(s: &[u8], st: &mut Stats) -> bool {
    let mut de = sonic_rs::Deserializer::from_slice(s);
    Sum(st).deserialize(&mut de).is_ok() && de.end().is_ok()
}

fn sum_simd(s: &[u8], st: &mut Stats) -> bool {
    let mut b = s.to_vec();
    match simd_json::Deserializer::from_slice(&mut b) {
        Ok(mut de) => Sum(st).deserialize(&mut de).is_ok(),
        Err(_) => false,
    }
}

// ---- select: read a few fields of every record (the fields of bench_view.cpp)

// on a DOM; serde_json's is the reference
macro_rules! pick_value {
    ($fname:ident, $t:ty) => {
        fn $fname(name: &str, r: &$t) -> f64 {
            fn size(v: &$t) -> usize {
                if let Some(a) = v.as_array() {
                    a.len()
                } else {
                    v.as_object().unwrap().len()
                }
            }
            fn status(acc: &mut f64, s: &$t) {
                *acc += s["id"].as_u64().unwrap() as f64;
                *acc += s["user"]["screen_name"].as_str().unwrap().len() as f64;
                *acc += s["retweet_count"].as_i64().unwrap() as f64;
            }
            let mut acc = 0.0;
            match name {
                "twitter" => {
                    for s in r["statuses"].as_array().unwrap().iter() {
                        status(&mut acc, s);
                    }
                }
                "status" => status(&mut acc, r),
                "citm_catalog" => {
                    for p in r["performances"].as_array().unwrap().iter() {
                        acc += (p["id"].as_u64().unwrap() + p["eventId"].as_u64().unwrap() + size(&p["seatCategories"]) as u64) as f64;
                    }
                    acc += size(&r["events"]) as f64;
                }
                "canada" => {
                    let g = &r["features"][0]["geometry"];
                    acc += (r["type"].as_str().unwrap().len() + g["type"].as_str().unwrap().len() + size(&g["coordinates"])) as f64;
                }
                "jeopardy" => {
                    for q in r.as_array().unwrap().iter() {
                        acc += if q["round"].as_str().unwrap() == "Final Jeopardy!" { 1.0 } else { 0.0 };
                        acc += q["category"].as_str().unwrap().len() as f64;
                    }
                }
                _ => {}
            }
            acc
        }
    };
}
pick_value!(pick_serde, serde_json::Value);
pick_value!(pick_sonic, sonic_rs::Value);
pick_value!(pick_simd, simd_json::BorrowedValue<'_>);

// into structs that declare only the fields the selection uses, the same data as nlohmann/json's from_json() structs in
// bench_all.cpp (nsel); unknown keys are skipped; Count counts the elements of an array or the members of an object
// (nlohmann's count_only)
mod sel {
    use serde::de::{Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
    use serde::Deserialize;
    use std::collections::BTreeMap;
    pub struct Count(pub usize);
    impl<'de> Deserialize<'de> for Count {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Count, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Count;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("an array or an object")
                }
                fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Count, A::Error> {
                    let mut n = 0;
                    while a.next_element::<IgnoredAny>()?.is_some() {
                        n += 1;
                    }
                    Ok(Count(n))
                }
                fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Count, A::Error> {
                    let mut n = 0;
                    while a.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                        n += 1;
                    }
                    Ok(Count(n))
                }
            }
            d.deserialize_any(V)
        }
    }
    #[derive(Deserialize)]
    pub struct User {
        pub screen_name: String,
    }
    #[derive(Deserialize)]
    pub struct Status {
        pub id: u64,
        pub user: User,
        pub retweet_count: i64,
    }
    #[derive(Deserialize)]
    pub struct Twitter {
        pub statuses: Vec<Status>,
    }
    #[derive(Deserialize)]
    pub struct Performance {
        pub id: u64,
        #[serde(rename = "eventId")]
        pub event_id: u64,
        #[serde(rename = "seatCategories")]
        pub seat_categories: Count,
    }
    #[derive(Deserialize)]
    pub struct Citm {
        pub events: BTreeMap<String, Count>,
        pub performances: Vec<Performance>,
    }
    #[derive(Deserialize)]
    pub struct Geometry {
        #[serde(rename = "type")]
        pub type_: String,
        pub coordinates: Count,
    }
    #[derive(Deserialize)]
    pub struct Feature {
        pub geometry: Geometry,
    }
    #[derive(Deserialize)]
    pub struct Canada {
        #[serde(rename = "type")]
        pub type_: String,
        pub features: Vec<Feature>,
    }
    #[derive(Deserialize)]
    pub struct Question {
        pub category: String,
        pub round: String,
    }
}

trait De {
    fn de<T: DeserializeOwned>(s: &[u8]) -> Option<T>;
}
struct SerdeJson;
struct SerdeJsonStr; // checks UTF-8 with std::str::from_utf8 first, then reads from the &str
struct SonicRs;
struct SimdJson;
impl De for SerdeJson {
    fn de<T: DeserializeOwned>(s: &[u8]) -> Option<T> {
        serde_json::from_slice(s).ok()
    }
}
impl De for SerdeJsonStr {
    fn de<T: DeserializeOwned>(s: &[u8]) -> Option<T> {
        serde_json::from_str(std::str::from_utf8(s).ok()?).ok()
    }
}
impl De for SonicRs {
    fn de<T: DeserializeOwned>(s: &[u8]) -> Option<T> {
        sonic_rs::from_slice(s).ok()
    }
}
impl De for SimdJson {
    fn de<T: DeserializeOwned>(s: &[u8]) -> Option<T> {
        let mut b = s.to_vec();
        simd_json::serde::from_slice(&mut b).ok()
    }
}

fn pick_structs<D: De>(name: &str, s: &[u8]) -> Option<f64> {
    fn status(acc: &mut f64, x: &sel::Status) {
        *acc += x.id as f64;
        *acc += x.user.screen_name.len() as f64;
        *acc += x.retweet_count as f64;
    }
    let mut acc = 0.0;
    match name {
        "twitter" => {
            let t: sel::Twitter = D::de(s)?;
            for x in &t.statuses {
                status(&mut acc, x);
            }
        }
        "status" => {
            let x: sel::Status = D::de(s)?;
            status(&mut acc, &x);
        }
        "citm_catalog" => {
            let c: sel::Citm = D::de(s)?;
            for p in &c.performances {
                acc += (p.id + p.event_id + p.seat_categories.0 as u64) as f64;
            }
            acc += c.events.len() as f64;
        }
        "canada" => {
            let c: sel::Canada = D::de(s)?;
            let g = &c.features[0].geometry;
            acc += (c.type_.len() + g.type_.len() + g.coordinates.0) as f64;
        }
        "jeopardy" => {
            let q: Vec<sel::Question> = D::de(s)?;
            for x in &q {
                acc += if x.round == "Final Jeopardy!" { 1.0 } else { 0.0 };
                acc += x.category.len() as f64;
            }
        }
        _ => {}
    }
    Some(acc)
}

// ---- edit: the same edits as bench_all.cpp, then write compact JSON

fn edit_serde(name: &str, r: &mut serde_json::Value) {
    fn status(s: &mut serde_json::Value) {
        let o = s.as_object_mut().unwrap();
        let rc = o["retweet_count"].as_i64().unwrap();
        o.insert("retweet_count".to_string(), (rc + 1).into());
        o.remove("entities");
        o.insert("seen".to_string(), true.into());
    }
    match name {
        "twitter" => {
            for s in r["statuses"].as_array_mut().unwrap() {
                status(s);
            }
        }
        "status" => status(r),
        "citm_catalog" => {
            for p in r["performances"].as_array_mut().unwrap() {
                let o = p.as_object_mut().unwrap();
                let start = o["start"].as_i64().unwrap();
                o.insert("start".to_string(), (start + 1).into());
                o.remove("seatMapImage");
                o.insert("seen".to_string(), true.into());
            }
        }
        "canada" => {
            r["features"][0]["properties"]["name"] = "Kanada".into();
            for f in r["features"].as_array_mut().unwrap() {
                f["geometry"]["coordinates"][0].as_array_mut().unwrap().push(serde_json::json!([0.5, 0.25]));
            }
        }
        "jeopardy" => {
            for q in r.as_array_mut().unwrap() {
                let o = q.as_object_mut().unwrap();
                o.insert("value".to_string(), serde_json::Value::Null);
                o.remove("air_date");
                o.insert("seen".to_string(), true.into());
            }
        }
        _ => {}
    }
}

fn edit_sonic(name: &str, r: &mut sonic_rs::Value) {
    fn status(s: &mut sonic_rs::Value) {
        let o = s.as_object_mut().unwrap();
        let rc = o.get(&"retweet_count").unwrap().as_i64().unwrap();
        o.insert("retweet_count", rc + 1);
        o.remove(&"entities");
        o.insert("seen", true);
    }
    match name {
        "twitter" => {
            for s in r.get_mut("statuses").unwrap().as_array_mut().unwrap().iter_mut() {
                status(s);
            }
        }
        "status" => status(r),
        "citm_catalog" => {
            for p in r.get_mut("performances").unwrap().as_array_mut().unwrap().iter_mut() {
                let o = p.as_object_mut().unwrap();
                let start = o.get(&"start").unwrap().as_i64().unwrap();
                o.insert("start", start + 1);
                o.remove(&"seatMapImage");
                o.insert("seen", true);
            }
        }
        "canada" => {
            let fs = r.get_mut("features").unwrap().as_array_mut().unwrap();
            fs[0].get_mut("properties").unwrap().as_object_mut().unwrap().insert("name", "Kanada");
            for f in fs.iter_mut() {
                let ring = f.get_mut("geometry").unwrap().get_mut("coordinates").unwrap().get_mut(0).unwrap();
                ring.as_array_mut().unwrap().push(sonic_rs::json!([0.5, 0.25]));
            }
        }
        "jeopardy" => {
            for q in r.as_array_mut().unwrap().iter_mut() {
                let o = q.as_object_mut().unwrap();
                o.insert("value", sonic_rs::Value::new_null());
                o.remove(&"air_date");
                o.insert("seen", true);
            }
        }
        _ => {}
    }
}

macro_rules! edit_simd {
    ($fname:ident, $t:ty) => {
        fn $fname(name: &str, r: &mut $t) {
            fn status(s: &mut $t) {
                let o = s.as_object_mut().unwrap();
                let rc = o.get("retweet_count").unwrap().as_i64().unwrap();
                o.insert("retweet_count".into(), (rc + 1).into());
                o.remove("entities");
                o.insert("seen".into(), true.into());
            }
            match name {
                "twitter" => {
                    for s in r.as_object_mut().unwrap().get_mut("statuses").unwrap().as_array_mut().unwrap().iter_mut() {
                        status(s);
                    }
                }
                "status" => status(r),
                "citm_catalog" => {
                    for p in r.as_object_mut().unwrap().get_mut("performances").unwrap().as_array_mut().unwrap().iter_mut() {
                        let o = p.as_object_mut().unwrap();
                        let start = o.get("start").unwrap().as_i64().unwrap();
                        o.insert("start".into(), (start + 1).into());
                        o.remove("seatMapImage");
                        o.insert("seen".into(), true.into());
                    }
                }
                "canada" => {
                    let fs = r.as_object_mut().unwrap().get_mut("features").unwrap().as_array_mut().unwrap();
                    fs[0].as_object_mut().unwrap().get_mut("properties").unwrap().as_object_mut().unwrap().insert("name".into(), "Kanada".into());
                    for f in fs.iter_mut() {
                        let g = f.as_object_mut().unwrap().get_mut("geometry").unwrap().as_object_mut().unwrap();
                        let ring = &mut g.get_mut("coordinates").unwrap().as_array_mut().unwrap()[0];
                        ring.as_array_mut().unwrap().push(vec![<$t>::from(0.5), <$t>::from(0.25)].into());
                    }
                }
                "jeopardy" => {
                    for q in r.as_array_mut().unwrap().iter_mut() {
                        let o = q.as_object_mut().unwrap();
                        o.insert("value".into(), <$t>::Static(simd_json::StaticNode::Null));
                        o.remove("air_date");
                        o.insert("seen".into(), true.into());
                    }
                }
                _ => {}
            }
        }
    };
}
edit_simd!(edit_simd_owned, simd_json::OwnedValue);
edit_simd!(edit_simd_borrowed, simd_json::BorrowedValue<'_>);

// ---- driver

struct Res {
    st: Stats,
    acc: f64,
    want: bool,
    out: Vec<u8>,
}

impl Res {
    fn new(want: bool) -> Res {
        Res { st: Stats::default(), acc: 0.0, want, out: Vec::new() }
    }
}

fn emit(r: &mut Res, o: Vec<u8>) -> bool {
    r.acc = o.len() as f64;
    if r.want {
        r.out = o;
    }
    true
}

struct Variant<'a> {
    name: &'static str,
    f: Box<dyn Fn(&[u8], &mut Res) -> bool + 'a>,
    any_order: bool, // sum: visits objects in another order than the document's
}

fn v<'a>(name: &'static str, f: impl Fn(&[u8], &mut Res) -> bool + 'a) -> Variant<'a> {
    Variant { name, f: Box::new(f), any_order: false }
}

fn v_any<'a>(name: &'static str, f: impl Fn(&[u8], &mut Res) -> bool + 'a) -> Variant<'a> {
    Variant { name, f: Box::new(f), any_order: true }
}

fn run(var: &Variant, s: &[u8], r: &mut Res) -> bool {
    catch_unwind(AssertUnwindSafe(|| (var.f)(s, r))).unwrap_or(false)
}

static mut SINK: f64 = 0.0;
fn sink(x: f64) {
    unsafe { std::ptr::write_volatile(std::ptr::addr_of_mut!(SINK), x) }
}

// the input contract of bench_all.cpp: at least 64 bytes of spare capacity
fn padded(s: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(s.len() + 64);
    r.extend_from_slice(s);
    r
}

// the minified inputs (twitter_min, citm_catalog_min): the whitespace outside strings removed, the bytes inside strings
// untouched (the same function as strip_ws in bench_all.cpp)
fn strip_ws(s: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(s.len());
    let mut in_string = false;
    let mut i = 0;
    while i < s.len() {
        let ch = s[i];
        if in_string {
            r.push(ch);
            if ch == b'\\' && i + 1 < s.len() {
                i += 1;
                r.push(s[i]);
            } else if ch == b'"' {
                in_string = false;
            }
        } else if ch != b' ' && ch != b'\n' && ch != b'\r' && ch != b'\t' {
            r.push(ch);
            in_string = ch == b'"';
        }
        i += 1;
    }
    r
}

// malformed inputs derived from a valid document, as in bench_all.cpp (0xFF in a string value, not a key)
// (what, text, is the 0xFF probe)
fn malformed(s: &[u8]) -> Vec<(&'static str, Vec<u8>, bool)> {
    let (mut first_close, mut mid_quote, mut last_quote) = (None, None, None);
    let mut in_string = false;
    let mut stack: Vec<u8> = Vec::new();
    let mut prev = 0u8;
    let mut i = 0;
    while i < s.len() {
        let ch = s[i];
        if in_string {
            if ch == b'\\' {
                i += 1;
            } else if ch == b'"' {
                in_string = false;
            }
        } else if ch == b'"' {
            in_string = true;
            let value = prev == b':' || (stack.last() == Some(&b'[') && (prev == b'[' || prev == b','));
            if value {
                last_quote = Some(i);
                if mid_quote.is_none() && i >= s.len() / 2 {
                    mid_quote = Some(i);
                }
            }
            prev = b'"';
        } else if ch == b'{' || ch == b'[' {
            stack.push(ch);
            prev = ch;
        } else if ch == b'}' || ch == b']' {
            if ch == b'}' && first_close.is_none() {
                first_close = Some(i);
            }
            stack.pop();
            prev = ch;
        } else if ch == b':' || ch == b',' {
            prev = ch;
        }
        i += 1;
    }
    let mut t = s.to_vec();
    while matches!(t.last(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
        t.pop();
    }
    let mut trailing = t.clone();
    trailing.extend_from_slice(b" ]x"); // after the value
    t.pop();
    let mut out = vec![("truncated input", padded(&t), false), ("trailing garbage", padded(&trailing), false)];
    let mut t = s.to_vec();
    if let Some(c) = first_close {
        t.insert(c, b',');
        out.push(("a stray comma before '}'", padded(&t), false));
    } else {
        // a file without objects (--files): the comma goes before the last ']'
        let c = (0..t.len()).rev().find(|&i| t[i] == b']').unwrap();
        t.insert(c, b',');
        out.push(("a stray comma before ']'", padded(&t), false));
    }
    // a file without string values (--files) gets no UTF-8 probe
    if let Some(q) = mid_quote.or(last_quote) {
        let mut t = s.to_vec();
        t.insert(q + 1, 0xFF);
        out.push(("invalid UTF-8 (0xFF in a string)", padded(&t), true));
    }
    out
}

fn same_text(out: &[u8], expected: &serde_json::Value) -> bool {
    serde_json::from_slice::<serde_json::Value>(out).map(|v| v == *expected).unwrap_or(false)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // --files <dir>: every *.json file of the directory instead of the files below, without select and edit;
    // --conformance <dir>: every validate variant on every *.json file of the directory (JSONTestSuite), no timing
    let files = args.len() > 1 && args[1] == "--files";
    let conformance = args.len() > 1 && args[1] == "--conformance";
    let a = if files || conformance { 2 } else { 1 };
    if args.len() <= a {
        eprintln!("usage: {0} <json_test_data dir> [rounds] [document] [use case]\n       {0} --files <dir> [rounds] [document] [use case]\n       {0} --conformance <dir>", args[0]);
        std::process::exit(1);
    }
    let t = format!("{}/", args[a]);
    let rounds: usize = args.get(a + 1).map(|r| r.parse().unwrap()).unwrap_or(30).max(1);
    let only: String = args.get(a + 2).cloned().unwrap_or_default();
    let only_uc: String = if conformance { "validate".to_string() } else { args.get(a + 3).cloned().unwrap_or_default() };
    // (file, text, batch, the document whose select and edit apply)
    let mut docs: Vec<(String, Vec<u8>, usize, String)> = Vec::new();
    if files || conformance {
        let mut paths: Vec<std::path::PathBuf> = std::fs::read_dir(&t).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().map_or(false, |x| x == "json")).collect();
        paths.sort();
        for p in paths {
            // small files are timed in batches of about 500 KB of input, as status is
            let text = padded(&std::fs::read(&p).unwrap());
            let name = if conformance { p.file_name() } else { p.file_stem() }.unwrap().to_string_lossy().to_string();
            let batch = (500000 / text.len().max(1)).max(1);
            docs.push((name.clone(), text, batch, name));
        }
    } else {
        for f in ["nativejson-benchmark/twitter.json", "nativejson-benchmark/citm_catalog.json", "nativejson-benchmark/canada.json", "jeopardy/jeopardy.json"] {
            let name = f.split('/').nth(1).unwrap().trim_end_matches(".json").to_string();
            docs.push((name.clone(), padded(&std::fs::read(format!("{}{}", t, f)).unwrap()), 1, name));
        }
        let tw: serde_json::Value = serde_json::from_slice(&docs[0].1).unwrap();
        docs.push(("status".to_string(), padded(serde_json::to_string(&tw["statuses"][0]).unwrap().as_bytes()), 200, "status".to_string()));
        let (tw_min, citm_min) = (padded(&strip_ws(&docs[0].1)), padded(&strip_ws(&docs[1].1)));
        docs.push(("twitter_min".to_string(), tw_min, 1, "twitter".to_string()));
        docs.push(("citm_catalog_min".to_string(), citm_min, 1, "citm_catalog".to_string()));
    }

    std::panic::set_hook(Box::new(|_| {})); // a panic is a failed call, reported by the checks
    let simd_reused = RefCell::new((simd_json::Buffers::default(), Vec::<u8>::new()));
    let mut excluded_total = 0;
    for (file, s, batch, base) in &docs {
        if !only.is_empty() && *file != only {
            continue;
        }
        let (file, name) = (file.as_str(), base.as_str());
        let s = s.as_slice();
        let bad = if conformance { Vec::new() } else { malformed(s) };
        for uc in ["validate", "sum", "select", "edit", "minify", "write"] {
            if (!only_uc.is_empty() && uc != only_uc) || (files && (uc == "select" || uc == "edit")) {
                continue;
            }
            // write: each library's document, parsed once outside the timer
            let mut wbuf: Vec<u8>;
            let (w_serde, w_sonic, w_simd) = if uc == "write" {
                wbuf = s.to_vec();
                (
                    Some(serde_json::from_slice::<serde_json::Value>(s).unwrap()),
                    Some(sonic_rs::from_slice::<sonic_rs::Value>(s).unwrap()),
                    Some(simd_json::to_borrowed_value(&mut wbuf).unwrap()),
                )
            } else {
                (None, None, None)
            };
            let reuse = &simd_reused;
            let all: Vec<Variant> = match uc {
                "validate" => vec![
                    v("serde_json: IgnoredAny", |s, _| serde_json::from_slice::<IgnoredAny>(s).is_ok()),
                    v("serde_json: from_utf8 + IgnoredAny", |s, _| std::str::from_utf8(s).ok().map_or(false, |t| serde_json::from_str::<IgnoredAny>(t).is_ok())),
                    v("serde_json: Value", |s, _| serde_json::from_slice::<serde_json::Value>(s).is_ok()),
                    v("sonic-rs: IgnoredAny", |s, _| sonic_rs::from_slice::<IgnoredAny>(s).is_ok()),
                    v("sonic-rs: Value", |s, _| sonic_rs::from_slice::<sonic_rs::Value>(s).is_ok()),
                    v("simd-json: tape (copy)", |s, _| { let mut b = s.to_vec(); simd_json::to_tape(&mut b).is_ok() }),
                    v("simd-json: borrowed (copy)", |s, _| { let mut b = s.to_vec(); let ok = simd_json::to_borrowed_value(&mut b).is_ok(); ok }),
                    v("simd-json: tape (reused)", move |s, _| {
                        let mut g = reuse.borrow_mut();
                        let (ref mut bufs, ref mut b) = *g;
                        b.clear();
                        b.extend_from_slice(s);
                        simd_json::to_tape_with_buffers(b, bufs).is_ok()
                    }),
                ],
                "sum" => vec![
                    v("serde_json: visitor", |s, r| sum_serde(s, &mut r.st)),
                    v_any("serde_json: Value", |s, r| serde_json::from_slice::<serde_json::Value>(s).map(|x| walk_serde(&x, &mut r.st)).is_ok()),
                    v("sonic-rs: visitor", |s, r| sum_sonic(s, &mut r.st)),
                    v("sonic-rs: Value", |s, r| sonic_rs::from_slice::<sonic_rs::Value>(s).map(|x| walk_sonic(&x, &mut r.st)).is_ok()),
                    v("simd-json: visitor (copy)", |s, r| sum_simd(s, &mut r.st)),
                    v_any("simd-json: borrowed (copy)", |s, r| { let mut b = s.to_vec(); simd_json::to_borrowed_value(&mut b).map(|x| walk_simd(&x, &mut r.st)).is_ok() }),
                    v_any("simd-json: borrowed (reused)", move |s, r| {
                        let mut g = reuse.borrow_mut();
                        let (ref mut bufs, ref mut b) = *g;
                        b.clear();
                        b.extend_from_slice(s);
                        simd_json::to_borrowed_value_with_buffers(b, bufs).map(|x| walk_simd(&x, &mut r.st)).is_ok()
                    }),
                ],
                "select" => vec![
                    v("serde_json: structs", move |s, r| pick_structs::<SerdeJson>(name, s).map(|a| r.acc = a).is_some()),
                    v("serde_json: from_utf8 + structs", move |s, r| pick_structs::<SerdeJsonStr>(name, s).map(|a| r.acc = a).is_some()),
                    v("serde_json: Value", move |s, r| serde_json::from_slice::<serde_json::Value>(s).map(|x| r.acc = pick_serde(name, &x)).is_ok()),
                    v("sonic-rs: structs", move |s, r| pick_structs::<SonicRs>(name, s).map(|a| r.acc = a).is_some()),
                    v("sonic-rs: Value", move |s, r| sonic_rs::from_slice::<sonic_rs::Value>(s).map(|x| r.acc = pick_sonic(name, &x)).is_ok()),
                    v("simd-json: structs (copy)", move |s, r| pick_structs::<SimdJson>(name, s).map(|a| r.acc = a).is_some()),
                    v("simd-json: borrowed (copy)", move |s, r| { let mut b = s.to_vec(); let ok = simd_json::to_borrowed_value(&mut b).map(|x| r.acc = pick_simd(name, &x)).is_ok(); ok }),
                ],
                "edit" => vec![
                    v("serde_json: Value", move |s, r| match serde_json::from_slice::<serde_json::Value>(s) {
                        Ok(mut x) => { edit_serde(name, &mut x); emit(r, serde_json::to_vec(&x).unwrap()) }
                        Err(_) => false,
                    }),
                    v("sonic-rs: Value", move |s, r| match sonic_rs::from_slice::<sonic_rs::Value>(s) {
                        Ok(mut x) => { edit_sonic(name, &mut x); emit(r, sonic_rs::to_vec(&x).unwrap()) }
                        Err(_) => false,
                    }),
                    v("simd-json: owned (copy)", move |s, r| { let mut b = s.to_vec(); match simd_json::to_owned_value(&mut b) {
                        Ok(mut x) => { edit_simd_owned(name, &mut x); emit(r, simd_json::to_vec(&x).unwrap()) }
                        Err(_) => false,
                    }}),
                    v("simd-json: borrowed (copy)", move |s, r| { let mut b = s.to_vec(); let ok = match simd_json::to_borrowed_value(&mut b) {
                        Ok(mut x) => { edit_simd_borrowed(name, &mut x); emit(r, simd_json::to_vec(&x).unwrap()) }
                        Err(_) => false,
                    }; ok }),
                ],
                "minify" => vec![
                    v("serde_json: Value", |s, r| serde_json::from_slice::<serde_json::Value>(s).map(|x| emit(r, serde_json::to_vec(&x).unwrap())).unwrap_or(false)),
                    v("sonic-rs: Value", |s, r| sonic_rs::from_slice::<sonic_rs::Value>(s).map(|x| emit(r, sonic_rs::to_vec(&x).unwrap())).unwrap_or(false)),
                    v("simd-json: borrowed (copy)", |s, r| { let mut b = s.to_vec(); simd_json::to_borrowed_value(&mut b).map(|x| emit(r, simd_json::to_vec(&x).unwrap())).unwrap_or(false) }),
                ],
                _ => {
                    let (a, b, c) = (w_serde.as_ref().unwrap(), w_sonic.as_ref().unwrap(), w_simd.as_ref().unwrap());
                    vec![
                        v("serde_json: Value", move |_, r| emit(r, serde_json::to_vec(a).unwrap())),
                        v("sonic-rs: Value", move |_, r| emit(r, sonic_rs::to_vec(b).unwrap())),
                        v("simd-json: borrowed", move |_, r| emit(r, simd_json::to_vec(c).unwrap())),
                    ]
                }
            };

            // the reference result: serde_json's visitor (sum, document order), Value (select, edit, minify, write)
            let mut ref_st = Stats::default();
            let mut ref_acc = 0.0;
            let mut ref_json = serde_json::Value::Null;
            match uc {
                "sum" => {
                    sum_serde(s, &mut ref_st);
                    println!("check {:<13} {:<9} reference: nodes {} str {} num {:.16e}", file, uc, ref_st.nodes, ref_st.str_, ref_st.num);
                }
                "select" => {
                    ref_acc = pick_serde(name, &serde_json::from_slice(s).unwrap());
                    println!("check {:<13} {:<9} reference: {:.16e}", file, uc, ref_acc);
                }
                "validate" => {}
                _ => {
                    ref_json = serde_json::from_slice(s).unwrap();
                    if uc == "edit" {
                        edit_serde(name, &mut ref_json);
                    }
                }
            }
            if conformance {
                // CONF_VARIANT=<name>: only this variant (a stack overflow aborts the process, see conformance.sh)
                let only_var = std::env::var("CONF_VARIANT").unwrap_or_default();
                for var in all.iter().filter(|v| only_var.is_empty() || v.name == only_var) {
                    let mut r = Res::new(true);
                    let verdict = match catch_unwind(AssertUnwindSafe(|| (var.f)(s, &mut r))) {
                        Ok(true) => "accepted",
                        Ok(false) => "rejected",
                        Err(_) => "crashed",
                    };
                    println!("conformance: {} | {} | {}", file, var.name, verdict);
                }
                continue;
            }
            let n_all = all.len();
            let mut vs: Vec<Variant> = Vec::new();
            let mut levels: Vec<&str> = Vec::new();
            for var in all {
                let mut r = Res::new(true);
                let mut why = String::new();
                let mut panicked = false;
                if !catch_unwind(AssertUnwindSafe(|| (var.f)(s, &mut r))).unwrap_or_else(|_| {
                    panicked = true;
                    false
                }) {
                    why = if panicked { "crashes on the valid input" } else { "rejects the valid input" }.to_string();
                } else if uc == "sum"
                    && !(r.st.nodes == ref_st.nodes
                        && r.st.str_ == ref_st.str_
                        && if var.any_order { (r.st.num - ref_st.num).abs() <= 1e-9 * ref_st.num.abs() } else { r.st.num == ref_st.num })
                {
                    why = format!("wrong result (nodes {} str {} num {:.16e})", r.st.nodes, r.st.str_, r.st.num);
                } else if uc == "select" && r.acc != ref_acc {
                    why = format!("wrong result ({:.16e})", r.acc);
                } else if (uc == "edit" || uc == "minify" || uc == "write") && !same_text(&r.out, &ref_json) {
                    why = "the output does not read back as the expected document".to_string();
                }
                if why.is_empty() {
                    // the validation level from the malformed-input probes, as in bench_all.cpp
                    let mut level = "n/a";
                    if uc != "write" {
                        let (mut structural, mut utf8) = (false, false);
                        let mut notes: Vec<String> = Vec::new();
                        for (what, b, is_utf8) in &bad {
                            let mut rb = Res::new(true);
                            match catch_unwind(AssertUnwindSafe(|| (var.f)(b, &mut rb))) {
                                Ok(false) => continue,
                                Ok(true) => {
                                    notes.push(format!("accepts {}", what));
                                    if *is_utf8 { utf8 = true } else { structural = true }
                                }
                                Err(_) => {
                                    notes.push(format!("crashes on {}", what));
                                    structural = true;
                                }
                            }
                        }
                        level = if structural { "partial" } else if utf8 { "no UTF-8" } else { "full" };
                        if !notes.is_empty() {
                            println!("level: {} {} | {} | {} | {}", file, uc, var.name, level, notes.join("; "));
                        }
                    }
                    vs.push(var);
                    levels.push(level);
                } else {
                    excluded_total += 1;
                    println!("excluded: {} {} | {} | {}", file, uc, var.name, why);
                }
            }
            println!("check {:<13} {:<9} {} of {} variants give the right result", file, uc, vs.len(), n_all);
            if vs.is_empty() {
                continue;
            }

            let r = if s.len() > 10_000_000 { rounds.min((rounds / 5).max(3)) } else { rounds };
            let mut best = vec![f64::MAX; vs.len()];
            // a new order of the variants in every round (as in bench_all.cpp): a Fisher-Yates shuffle with xorshift64
            let mut order: Vec<usize> = (0..vs.len()).collect();
            let mut rng: u64 = 12345;
            for i in 0..r {
                if i > 0 {
                    for j in (1..order.len()).rev() {
                        rng ^= rng << 13;
                        rng ^= rng >> 7;
                        rng ^= rng << 17;
                        order.swap(j, (rng % (j as u64 + 1)) as usize);
                    }
                }
                for &k in &order {
                    let var = &vs[k];
                    let mut res = Res::new(false);
                    run(var, s, &mut res); // untimed: the previous variant's leftovers are cleaned up here
                    sink(res.st.num + res.acc);
                    let t0 = Instant::now();
                    for _ in 0..*batch {
                        let mut rt = Res::new(false);
                        let ok = run(var, s, &mut rt);
                        sink(if ok { rt.st.num + rt.acc } else { -1.0 });
                    }
                    let ns = t0.elapsed().as_nanos() as f64 / *batch as f64;
                    best[k] = best[k].min(ns);
                }
            }
            print!("{:<13} {:<9}", file, uc);
            for (k, var) in vs.iter().enumerate() {
                print!(" | {} [{}] {:.1}us ({:.2}x)", var.name, levels[k], best[k] / 1e3, best[k] / best[0]);
            }
            println!();
        }
    }
    println!("done: {} variant(s) excluded", excluded_total);
}
