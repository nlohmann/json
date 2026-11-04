//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// One fixed benchmark, compiled against the json.hpp of every commit that changed it (see README.md).
// It uses only API that 3.12.0 has; the json_document rows exist only where the header has json_view.hpp.
// Usage: history <dir with twitter.json, citm_catalog.json, canada.json and citm_compact.json>
// Prints one line per workload: the name and the median of 9 batches in microseconds per call.
#include <nlohmann/json.hpp>
#if __has_include(<nlohmann/json_view.hpp>) && !defined(HISTORY_NO_VIEW)
    #include <nlohmann/json_view.hpp>
    #define HISTORY_VIEW 1
#endif
#include <algorithm>
#include <chrono>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using nlohmann::json;
static std::string slurp(const std::string& p)
{
    std::ifstream f(p, std::ios::binary);
    std::stringstream s;
    s << f.rdbuf();
    return s.str();
}
static volatile std::size_t sink;

static void bench(const char* name, const std::function<std::size_t()>& f)
{
    using clk = std::chrono::steady_clock;
    sink = f();  // warm up
    std::size_t n = 1;
    for (;;)
    {
        auto t0 = clk::now();
        for (std::size_t i = 0; i < n; ++i)
        {
            sink = f();
        }
        double dt = std::chrono::duration<double>(clk::now() - t0).count();
        if (dt > 0.02)
        {
            break;
        }
        n *= 2;
    }
    std::vector<double> v;
    for (int b = 0; b < 9; ++b)
    {
        auto t0 = clk::now();
        for (std::size_t i = 0; i < n; ++i)
        {
            sink = f();
        }
        v.push_back(std::chrono::duration<double, std::micro>(clk::now() - t0).count() / n);
    }
    std::sort(v.begin(), v.end());
    std::cout << name << ' ' << std::fixed << std::setprecision(3) << v[4] << '\n';
}

int main(int, char** argv)
{
    std::string d = argv[1];
    const std::string tw = slurp(d + "/twitter.json"), ci = slurp(d + "/citm_catalog.json"),
          ca = slurp(d + "/canada.json"), cii = slurp(d + "/citm_compact.json");
    const json jtw = json::parse(tw), jci = json::parse(ci), jca = json::parse(ca);
    const std::vector<std::uint8_t> cbtw = json::to_cbor(jtw);

    bench("parse_twitter", [&] { return json::parse(tw).size(); });
    bench("parse_citm", [&] { return json::parse(ci).size(); });
    bench("parse_canada", [&] { return json::parse(ca).size(); });
    bench("parse_citm_compact", [&] { return json::parse(cii).size(); });
    bench("parse_twitter_ifstream", [&] { std::ifstream f(d + "/twitter.json"); return json::parse(f).size(); });
    bench("accept_twitter", [&] { return static_cast<std::size_t>(json::accept(tw)); });
#ifdef HISTORY_VIEW
    bench("view_parse_twitter", [&] { const auto doc = nlohmann::json_document::parse(tw); return doc.root().size(); });
    bench("view_parse_citm", [&] { const auto doc = nlohmann::json_document::parse(ci); return doc.root().size(); });
    bench("view_parse_canada", [&] { const auto doc = nlohmann::json_document::parse(ca); return doc.root().size(); });
#endif
    bench("dump_twitter", [&] { return jtw.dump().size(); });
    bench("dump_citm", [&] { return jci.dump().size(); });
    bench("dump_canada", [&] { return jca.dump().size(); });
    bench("dump4_citm", [&] { return jci.dump(4).size(); });
    bench("from_cbor_twitter", [&] { return json::from_cbor(cbtw).size(); });
    bench("to_cbor_twitter", [&] { return json::to_cbor(jtw).size(); });
    bench("copy_destroy_citm", [&] { json c = jci; return c.size(); });
    bench("equal_citm", [&] { json c = jci; return static_cast<std::size_t>(c == jci); });
}
