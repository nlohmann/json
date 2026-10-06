//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// Corpus benchmark: the read-only workloads of bench_view.cpp on any list of
// JSON files (for example the benchmark sets of simdjson and yyjson).
//
//   ./bench_corpus [--rounds N] file...
//
// For every file, all engines must accept it and agree on a traversal (value
// count, string bytes, sum of numbers) before anything is timed. Workloads:
// parse (build and free a document), traverse (visit every value, convert
// every number), dump (compact), and for json_view also dump with the source
// number text, compared with yyjson writing numbers read as raw text
// (YYJSON_READ_NUMBER_AS_RAW). Results go to bench_corpus.csv.
#include <nlohmann/json_view.hpp>

#if JSON_VIEW_BENCH_BOOST
    #include <boost/json.hpp>
    #include <boost/json/src.hpp>
#endif
#include <simdjson.h>
#include <yyjson.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

using nlohmann::json;
using nlohmann::json_document;
using nlohmann::json_view;

static volatile double g_sink;

struct stats
{
    double num = 0;
    std::size_t str = 0, nodes = 0;
};

static void walk(json_view v, stats& st)
{
    ++st.nodes;
    switch (v.type())
    {
        case json::value_t::object:
            for (auto it = v.begin(); it != v.end(); ++it)
            {
                st.str += it.key().size();
                walk(*it, st);
            }
            break;
        case json::value_t::array:
            for (const json_view e : v)
            {
                walk(e, st);
            }
            break;
        case json::value_t::string:
            st.str += v.get_string().size();
            break;
        case json::value_t::number_integer:
            st.num += static_cast<double>(v.get<std::int64_t>());
            break;
        case json::value_t::number_unsigned:
            st.num += static_cast<double>(v.get<std::uint64_t>());
            break;
        case json::value_t::number_float:
            st.num += v.get<double>();
            break;
        default:
            break;
    }
}

static void walk(yyjson_val* v, stats& st)
{
    ++st.nodes;
    switch (yyjson_get_type(v))
    {
        case YYJSON_TYPE_OBJ:
        {
            std::size_t idx, max;
            yyjson_val* k, * val;
            yyjson_obj_foreach(v, idx, max, k, val)
            {
                st.str += yyjson_get_len(k);
                walk(val, st);
            }
            break;
        }
        case YYJSON_TYPE_ARR:
        {
            std::size_t idx, max;
            yyjson_val* val;
            yyjson_arr_foreach(v, idx, max, val)
            {
                walk(val, st);
            }
            break;
        }
        case YYJSON_TYPE_STR:
            st.str += yyjson_get_len(v);
            break;
        case YYJSON_TYPE_NUM:
            st.num += yyjson_is_sint(v) ? static_cast<double>(yyjson_get_sint(v)) : yyjson_is_uint(v) ? static_cast<double>(yyjson_get_uint(v)) : yyjson_get_real(v);
            break;
        default:
            break;
    }
}

static void walk(simdjson::dom::element e, stats& st)
{
    ++st.nodes;
    switch (e.type())
    {
        case simdjson::dom::element_type::OBJECT:
            for (auto f : simdjson::dom::object(e))
            {
                st.str += f.key.size();
                walk(f.value, st);
            }
            break;
        case simdjson::dom::element_type::ARRAY:
            for (auto c : simdjson::dom::array(e))
            {
                walk(c, st);
            }
            break;
        case simdjson::dom::element_type::STRING:
            st.str += std::string_view(e).size();
            break;
        case simdjson::dom::element_type::INT64:
            st.num += static_cast<double>(int64_t(e));
            break;
        case simdjson::dom::element_type::UINT64:
            st.num += static_cast<double>(uint64_t(e));
            break;
        case simdjson::dom::element_type::DOUBLE:
            st.num += double(e);
            break;
        default:
            break;
    }
}

#if JSON_VIEW_BENCH_BOOST
static void walk(const boost::json::value& v, stats& st)
{
    ++st.nodes;
    switch (v.kind())
    {
        case boost::json::kind::object:
            for (const auto& kv : v.get_object())
            {
                st.str += kv.key().size();
                walk(kv.value(), st);
            }
            break;
        case boost::json::kind::array:
            for (const auto& c : v.get_array())
            {
                walk(c, st);
            }
            break;
        case boost::json::kind::string:
            st.str += v.get_string().size();
            break;
        case boost::json::kind::int64:
            st.num += static_cast<double>(v.get_int64());
            break;
        case boost::json::kind::uint64:
            st.num += static_cast<double>(v.get_uint64());
            break;
        case boost::json::kind::double_:
            st.num += v.get_double();
            break;
        default:
            break;
    }
}
#endif

static std::string slurp(const std::string& p)
{
    std::ifstream f(p, std::ios::binary);
    if (!f)
    {
        std::fprintf(stderr, "cannot open %s\n", p.c_str());
        std::exit(1);
    }
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static bool same(const stats& a, const stats& b)
{
    return a.nodes == b.nodes && a.str == b.str && (a.num == b.num || std::fabs(a.num - b.num) <= 1e-9 * std::fabs(a.num));
}

int main(int argc, char** argv)
{
    int rounds = 0; // 0: by size
    std::vector<std::string> files;
    for (int i = 1; i < argc; ++i)
    {
        if (std::strcmp(argv[i], "--rounds") == 0 && i + 1 < argc)
        {
            rounds = std::atoi(argv[++i]);
        }
        else
        {
            files.push_back(argv[i]);
        }
    }
    std::FILE* csv = std::fopen("bench_corpus.csv", "w");
    std::fprintf(csv, "file,bytes,workload,engine,ns\n");
    json_document reused;
    simdjson::dom::parser sj;
    for (const auto& path : files)
    {
        const std::string s = slurp(path);
        const std::string name = path.substr(path.rfind('/') + 1);
        const simdjson::padded_string ps(s);

        // all engines must agree before timing
        stats a, b, c, d;
        const json_document doc = json_document::parse(s);
        walk(doc.root(), a);
        yyjson_doc* y = yyjson_read(s.data(), s.size(), 0);
        auto sjr = sj.parse(ps);
#if JSON_VIEW_BENCH_BOOST
        boost::json::parse_options opt;
        opt.numbers = boost::json::number_precision::precise;
        boost::json::monotonic_resource mr0;
        const boost::json::value bv = boost::json::parse(s, &mr0, opt);
#endif
        if (y == nullptr || sjr.error())
        {
            std::printf("%-34s skipped (an engine rejects it)\n", name.c_str());
            yyjson_doc_free(y);
            continue;
        }
        walk(yyjson_doc_get_root(y), b);
        walk(sjr.value_unsafe(), c);
#if JSON_VIEW_BENCH_BOOST
        walk(bv, d);
#else
        d = a;
#endif
        yyjson_doc_free(y);
        const bool ok = same(a, b) && same(a, c) && same(a, d);

        const int r = rounds > 0 ? rounds : static_cast<int>(std::max<std::size_t>(3, std::min<std::size_t>(60, 400000000 / (s.size() + 1))));
        struct engine
        {
            std::string name;
            std::function<void()> fn;
        };
        json_document vd = json_document::parse(s);
        yyjson_doc* yd = yyjson_read(s.data(), s.size(), 0);
        yyjson_doc* yd_raw = yyjson_read(s.data(), s.size(), YYJSON_READ_NUMBER_AS_RAW);
        simdjson::dom::parser sjd;
        const simdjson::dom::element se = sjd.parse(ps).value_unsafe();
        const std::vector<std::pair<std::string, std::vector<engine>>> workloads =
        {
            {
                "parse", {
                    {"json_view", [&] { auto x = json_document::parse(s); g_sink = static_cast<double>(x.node_count()); }},
                    {"json_view (reused)", [&] { reused.read(s); g_sink = static_cast<double>(reused.node_count()); }},
                    {"yyjson", [&] { yyjson_doc* x = yyjson_read(s.data(), s.size(), 0); g_sink = static_cast<double>(yyjson_doc_get_val_count(x)); yyjson_doc_free(x); }},
                    {"simdjson DOM", [&] { auto e = sj.parse(ps).value_unsafe(); g_sink = e.is_object(); }},
                    {"simdjson DOM (fresh)", [&] { simdjson::dom::parser p; auto e = p.parse(ps).value_unsafe(); g_sink = e.is_object(); }},
#if JSON_VIEW_BENCH_BOOST
                    {"Boost.JSON", [&] { boost::json::monotonic_resource mr; auto v = boost::json::parse(s, &mr); g_sink = v.is_object(); }},
#endif
                }
            },
            {
                "traverse", {
                    {"json_view", [&] { auto x = json_document::parse(s); stats st; walk(x.root(), st); g_sink = st.num; }},
                    {"yyjson", [&] { yyjson_doc* x = yyjson_read(s.data(), s.size(), 0); stats st; walk(yyjson_doc_get_root(x), st); g_sink = st.num; yyjson_doc_free(x); }},
                    {"simdjson DOM", [&] { stats st; walk(sj.parse(ps).value_unsafe(), st); g_sink = st.num; }},
#if JSON_VIEW_BENCH_BOOST
                    {"Boost.JSON", [&] { boost::json::monotonic_resource mr; auto v = boost::json::parse(s, &mr); stats st; walk(v, st); g_sink = st.num; }},
#endif
                }
            },
            {
                "dump", {
                    {"json_view", [&] { std::string o = vd.root().dump(); g_sink = static_cast<double>(o.size()); }},
                    {"yyjson", [&] { std::size_t n = 0; char* o = yyjson_write(yd, 0, &n); g_sink = static_cast<double>(n); std::free(o); }},
                    {"simdjson DOM", [&] { std::string o = simdjson::to_string(se); g_sink = static_cast<double>(o.size()); }},
                    {"json_view (source numbers)", [&] { std::string o = vd.root().dump(-1, ' ', false, json_view::number_format::source); g_sink = static_cast<double>(o.size()); }},
                    {"yyjson (raw numbers)", [&] { std::size_t n = 0; char* o = yyjson_write(yd_raw, 0, &n); g_sink = static_cast<double>(n); std::free(o); }},
                }
            },
        };
        std::printf("%-34s %9zu B%s\n", name.c_str(), s.size(), ok ? "" : "  [ENGINES DISAGREE]");
        for (const auto& wl : workloads)
        {
            std::vector<double> best(wl.second.size(), 1e300);
            for (int i = 0; i < r; ++i)
            {
                for (std::size_t k = 0; k < wl.second.size(); ++k)
                {
                    // an untimed call first: whatever the previous engine left to the allocator
                    // (e.g. thousands of freed json nodes) is cleaned up here, not in the timing
                    wl.second[k].fn();
                    const auto t0 = std::chrono::steady_clock::now();
                    wl.second[k].fn();
                    best[k] = std::min(best[k], std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count());
                }
            }
            std::printf("  %-9s", wl.first.c_str());
            for (std::size_t k = 0; k < wl.second.size(); ++k)
            {
                std::printf("  %s %.2f GB/s (%.2fx)", wl.second[k].name.c_str(), static_cast<double>(s.size()) / best[k], best[k] / best[0]);
                std::fprintf(csv, "%s,%zu,%s,%s,%.1f\n", name.c_str(), s.size(), wl.first.c_str(), wl.second[k].name.c_str(), best[k]);
            }
            std::printf("\n");
            std::fflush(stdout);
        }
        yyjson_doc_free(yd);
        yyjson_doc_free(yd_raw);
    }
    std::fclose(csv);
}
