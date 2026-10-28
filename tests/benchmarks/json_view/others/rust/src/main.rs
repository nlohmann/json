//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// Same workloads and method as bench_all.cpp: parse (build + free), traverse (parse, then visit every
// value, convert every number, touch every string and key), parse+dump; every engine interleaved, an
// untimed call before each timed one, best round reported.
// simd-json parses in place, so its timings include copying the input into a mutable buffer.
use simd_json::prelude::*;
use std::time::Instant;

#[derive(Default, Debug, Clone, Copy)]
struct Stats {
    num: f64,
    str_: usize,
    nodes: usize,
}

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
    use sonic_rs::{JsonContainerTrait, JsonValueTrait};
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

fn same(a: &Stats, b: &Stats) -> bool {
    a.nodes == b.nodes && a.str_ == b.str_ && (a.num - b.num).abs() <= 1e-9 * a.num.abs()
}

static mut SINK: f64 = 0.0;
fn sink(x: f64) {
    unsafe { std::ptr::write_volatile(std::ptr::addr_of_mut!(SINK), x) }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let t = format!("{}/", args[1]);
    let rounds: usize = args.get(2).map(|r| r.parse().unwrap()).unwrap_or(30);
    let mut docs: Vec<(String, String, usize)> = Vec::new();
    for f in ["nativejson-benchmark/twitter.json", "nativejson-benchmark/citm_catalog.json", "nativejson-benchmark/canada.json", "jeopardy/jeopardy.json"] {
        let name = f.split('/').nth(1).unwrap().trim_end_matches(".json").to_string();
        docs.push((name, std::fs::read_to_string(format!("{}{}", t, f)).unwrap(), 1));
    }
    let tw: serde_json::Value = serde_json::from_str(&docs[0].1).unwrap();
    docs.push(("status".to_string(), serde_json::to_string(&tw["statuses"][0]).unwrap(), 200));

    for (name, text, _) in &docs {
        let mut r = Stats::default();
        walk_serde(&serde_json::from_str(text).unwrap(), &mut r);
        let mut a = Stats::default();
        let mut buf = text.as_bytes().to_vec();
        walk_simd(&simd_json::to_borrowed_value(&mut buf).unwrap(), &mut a);
        let mut b = Stats::default();
        walk_sonic(&sonic_rs::from_str(text).unwrap(), &mut b);
        // sonic-rs keeps document order: its sum is compared bit for bit by the caller with json_view's
        println!("check {:<13} simd-json:{} sonic-rs:{} serde_json:OK  (nodes {} str {} num {:.17e} sonic-num {:.17e})",
                 name, if same(&r, &a) { "OK" } else { "MISMATCH" }, if same(&r, &b) { "OK" } else { "MISMATCH" }, r.nodes, r.str_, r.num, b.num);
    }

    for (name, s, batch) in &docs {
        type Eng<'a> = (&'static str, Box<dyn Fn() + 'a>);
        let workloads: Vec<(&str, Vec<Eng>)> = vec![
            ("parse", vec![
                ("simd-json", Box::new(|| { let mut b = s.as_bytes().to_vec(); let v = simd_json::to_borrowed_value(&mut b).unwrap(); sink(v.is_object() as u8 as f64); })),
                ("sonic-rs", Box::new(|| { let v: sonic_rs::Value = sonic_rs::from_str(s).unwrap(); sink(sonic_rs::JsonValueTrait::is_object(&v) as u8 as f64); })),
                ("serde_json", Box::new(|| { let v: serde_json::Value = serde_json::from_str(s).unwrap(); sink(v.is_object() as u8 as f64); })),
            ]),
            ("traverse", vec![
                ("simd-json", Box::new(|| { let mut b = s.as_bytes().to_vec(); let v = simd_json::to_borrowed_value(&mut b).unwrap(); let mut st = Stats::default(); walk_simd(&v, &mut st); sink(st.num); })),
                ("sonic-rs", Box::new(|| { let v: sonic_rs::Value = sonic_rs::from_str(s).unwrap(); let mut st = Stats::default(); walk_sonic(&v, &mut st); sink(st.num); })),
                ("serde_json", Box::new(|| { let v: serde_json::Value = serde_json::from_str(s).unwrap(); let mut st = Stats::default(); walk_serde(&v, &mut st); sink(st.num); })),
            ]),
            ("parse+dump", vec![
                ("simd-json", Box::new(|| { let mut b = s.as_bytes().to_vec(); let v = simd_json::to_borrowed_value(&mut b).unwrap(); let o = simd_json::to_string(&v).unwrap(); sink(o.len() as f64); })),
                ("sonic-rs", Box::new(|| { let v: sonic_rs::Value = sonic_rs::from_str(s).unwrap(); let o = sonic_rs::to_string(&v).unwrap(); sink(o.len() as f64); })),
                ("serde_json", Box::new(|| { let v: serde_json::Value = serde_json::from_str(s).unwrap(); let o = serde_json::to_string(&v).unwrap(); sink(o.len() as f64); })),
            ]),
        ];
        for (wl, engines) in &workloads {
            let r = if s.len() > 10_000_000 { std::cmp::max(3, rounds / 5) } else { rounds };
            let mut best = vec![f64::MAX; engines.len()];
            for _ in 0..r {
                for (k, (_, f)) in engines.iter().enumerate() {
                    f();
                    let t0 = Instant::now();
                    for _ in 0..*batch {
                        f();
                    }
                    let ns = t0.elapsed().as_nanos() as f64 / *batch as f64;
                    best[k] = best[k].min(ns);
                }
            }
            print!("{:<13} {:<11}", name, wl);
            for (k, (n, _)) in engines.iter().enumerate() {
                print!("  {} {:.1}us", n, best[k] / 1e3);
            }
            println!();
        }
    }
}
