//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// Same-feature-set benchmark: read-only JSON documents with random access.
//
//   json_view      nlohmann/json_view.hpp (fresh document per parse / reused)
//   yyjson         yyjson_read(): immutable document, random access
//   simdjson DOM   dom::parser (reused, as recommended; "fresh": a new parser
//                  per parse): immutable, random access
// references (different feature sets):
//   simdjson OD    On-Demand: forward-only, lazy
//   Boost.JSON     owning, mutable DOM (monotonic resource)
//   json::parse    owning, mutable DOM (nlohmann today)
//
// Workloads: parse (build + free), traverse (visit everything, convert every
// number, touch every string and key), select (a few fields per document),
// dump (compact serialization of the parsed document).
// All engines run interleaved in every round, each timed call after an untimed
// one of the same engine; the best round is reported.
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
#include <fstream>
#include <functional>
#include <map>
#include <sstream>

using nlohmann::json;
using nlohmann::json_document;
using nlohmann::json_view;

static volatile double g_sink;

struct stats
{
    double num = 0;
    std::size_t str = 0, nodes = 0;
};

// ---------------- traversal ----------------

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

static void walk(const json& j, stats& st)
{
    ++st.nodes;
    switch (j.type())
    {
        case json::value_t::object:
            for (const auto& kv : j.get_ref<const json::object_t&>())
            {
                st.str += kv.first.size();
                walk(kv.second, st);
            }
            break;
        case json::value_t::array:
            for (const auto& e : j.get_ref<const json::array_t&>())
            {
                walk(e, st);
            }
            break;
        case json::value_t::string:
            st.str += j.get_ref<const std::string&>().size();
            break;
        case json::value_t::number_integer:
            st.num += static_cast<double>(*j.get_ptr<const json::number_integer_t*>());
            break;
        case json::value_t::number_unsigned:
            st.num += static_cast<double>(*j.get_ptr<const json::number_unsigned_t*>());
            break;
        case json::value_t::number_float:
            st.num += *j.get_ptr<const json::number_float_t*>();
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
            if (yyjson_is_sint(v))
            {
                st.num += static_cast<double>(yyjson_get_sint(v));
            }
            else if (yyjson_is_uint(v))
            {
                st.num += static_cast<double>(yyjson_get_uint(v));
            }
            else
            {
                st.num += yyjson_get_real(v);
            }
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

static void walk_od(simdjson::ondemand::value v, stats& st)
{
    ++st.nodes;
    switch (v.type())
    {
        case simdjson::ondemand::json_type::object:
            for (auto f : v.get_object())
            {
                st.str += std::string_view(f.unescaped_key()).size();
                walk_od(f.value(), st);
            }
            break;
        case simdjson::ondemand::json_type::array:
            for (auto c : v.get_array())
            {
                walk_od(c.value(), st);
            }
            break;
        case simdjson::ondemand::json_type::string:
            st.str += std::string_view(v.get_string()).size();
            break;
        case simdjson::ondemand::json_type::number:
        {
            simdjson::ondemand::number n = v.get_number();
            switch (n.get_number_type())
            {
                case simdjson::ondemand::number_type::signed_integer:
                    st.num += static_cast<double>(n.get_int64());
                    break;
                case simdjson::ondemand::number_type::unsigned_integer:
                    st.num += static_cast<double>(n.get_uint64());
                    break;
                default:
                    st.num += n.get_double();
                    break;
            }
            break;
        }
        case simdjson::ondemand::json_type::boolean:
            (void)bool(v.get_bool());
            break;
        default:
            (void)v.is_null();
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

// ---------------- selective access ----------------
// twitter: per status id, user.screen_name, retweet_count
// citm: per performance id, eventId, #seatCategories; #events
// canada: type, features[0].geometry.type, #coordinates
// jeopardy: per question: round == "Final Jeopardy!", len(category)
// status (one tweet): id, user.screen_name, retweet_count
// rpc: method, params.minuend, id

static double pick(const std::string& name, json_view r)
{
    double acc = 0;
    if (name == "twitter" || name == "status")
    {
        auto one = [&](json_view s)
        {
            acc += static_cast<double>(s["id"].get<std::uint64_t>());
            acc += static_cast<double>(s["user"]["screen_name"].get_string().size());
            acc += static_cast<double>(s["retweet_count"].get<std::int64_t>());
        };
        if (name == "twitter")
        {
            for (const json_view s : r["statuses"])
            {
                one(s);
            }
        }
        else
        {
            one(r);
        }
    }
    else if (name == "citm_catalog")
    {
        for (const json_view p : r["performances"])
        {
            acc += static_cast<double>(p["id"].get<std::uint64_t>() + p["eventId"].get<std::uint64_t>() + p["seatCategories"].size());
        }
        acc += static_cast<double>(r["events"].size());
    }
    else if (name == "canada")
    {
        const json_view g = r["features"][0]["geometry"];
        acc += static_cast<double>(r["type"].get_string().size() + g["type"].get_string().size() + g["coordinates"].size());
    }
    else if (name == "jeopardy")
    {
        for (const json_view q : r)
        {
            acc += q["round"].get_string() == "Final Jeopardy!" ? 1 : 0;
            acc += static_cast<double>(q["category"].get_string().size());
        }
    }
    else if (name == "rpc")
    {
        acc += static_cast<double>(r["method"].get_string().size());
        acc += static_cast<double>(r["params"]["minuend"].get<std::int64_t>() + r["id"].get<std::int64_t>());
    }
    return acc;
}

static double pick(const std::string& name, const json& r)
{
    double acc = 0;
    if (name == "twitter" || name == "status")
    {
        auto one = [&](const json & s)
        {
            acc += static_cast<double>(s["id"].get<std::uint64_t>());
            acc += static_cast<double>(s["user"]["screen_name"].get_ref<const std::string&>().size());
            acc += static_cast<double>(s["retweet_count"].get<std::int64_t>());
        };
        if (name == "twitter")
        {
            for (const auto& s : r["statuses"])
            {
                one(s);
            }
        }
        else
        {
            one(r);
        }
    }
    else if (name == "citm_catalog")
    {
        for (const auto& p : r["performances"])
        {
            acc += static_cast<double>(p["id"].get<std::uint64_t>() + p["eventId"].get<std::uint64_t>() + p["seatCategories"].size());
        }
        acc += static_cast<double>(r["events"].size());
    }
    else if (name == "canada")
    {
        const json& g = r["features"][0]["geometry"];
        acc += static_cast<double>(r["type"].get_ref<const std::string&>().size() + g["type"].get_ref<const std::string&>().size() + g["coordinates"].size());
    }
    else if (name == "jeopardy")
    {
        for (const auto& q : r)
        {
            acc += q["round"].get_ref<const std::string&>() == "Final Jeopardy!" ? 1 : 0;
            acc += static_cast<double>(q["category"].get_ref<const std::string&>().size());
        }
    }
    else if (name == "rpc")
    {
        acc += static_cast<double>(r["method"].get_ref<const std::string&>().size());
        acc += static_cast<double>(r["params"]["minuend"].get<std::int64_t>() + r["id"].get<std::int64_t>());
    }
    return acc;
}

static double pick(const std::string& name, yyjson_val* r)
{
    double acc = 0;
    auto get = [](yyjson_val * o, const char* k)
    {
        return yyjson_obj_get(o, k);
    };
    if (name == "twitter" || name == "status")
    {
        auto one = [&](yyjson_val * s)
        {
            acc += static_cast<double>(yyjson_get_uint(get(s, "id")));
            acc += static_cast<double>(yyjson_get_len(get(get(s, "user"), "screen_name")));
            acc += static_cast<double>(yyjson_get_sint(get(s, "retweet_count")));
        };
        if (name == "twitter")
        {
            std::size_t idx, max;
            yyjson_val* s;
            yyjson_arr_foreach(get(r, "statuses"), idx, max, s)
            {
                one(s);
            }
        }
        else
        {
            one(r);
        }
    }
    else if (name == "citm_catalog")
    {
        std::size_t idx, max;
        yyjson_val* p;
        yyjson_arr_foreach(get(r, "performances"), idx, max, p)
        {
            acc += static_cast<double>(yyjson_get_uint(get(p, "id")) + yyjson_get_uint(get(p, "eventId")) + yyjson_arr_size(get(p, "seatCategories")));
        }
        acc += static_cast<double>(yyjson_obj_size(get(r, "events")));
    }
    else if (name == "canada")
    {
        yyjson_val* g = get(yyjson_arr_get(get(r, "features"), 0), "geometry");
        acc += static_cast<double>(yyjson_get_len(get(r, "type")) + yyjson_get_len(get(g, "type")) + yyjson_arr_size(get(g, "coordinates")));
    }
    else if (name == "jeopardy")
    {
        std::size_t idx, max;
        yyjson_val* q;
        yyjson_arr_foreach(r, idx, max, q)
        {
            acc += yyjson_equals_str(get(q, "round"), "Final Jeopardy!") ? 1 : 0;
            acc += static_cast<double>(yyjson_get_len(get(q, "category")));
        }
    }
    else if (name == "rpc")
    {
        acc += static_cast<double>(yyjson_get_len(get(r, "method")));
        acc += static_cast<double>(yyjson_get_sint(get(get(r, "params"), "minuend")) + yyjson_get_sint(get(r, "id")));
    }
    return acc;
}

static double pick(const std::string& name, simdjson::dom::element r)
{
    double acc = 0;
    if (name == "twitter" || name == "status")
    {
        auto one = [&](simdjson::dom::element s)
        {
            acc += static_cast<double>(uint64_t(s["id"]));
            acc += static_cast<double>(std::string_view(s["user"]["screen_name"]).size());
            acc += static_cast<double>(int64_t(s["retweet_count"]));
        };
        if (name == "twitter")
        {
            for (auto s : simdjson::dom::array(r["statuses"]))
            {
                one(s);
            }
        }
        else
        {
            one(r);
        }
    }
    else if (name == "citm_catalog")
    {
        for (auto p : simdjson::dom::array(r["performances"]))
        {
            acc += static_cast<double>(uint64_t(p["id"]) + uint64_t(p["eventId"]) + simdjson::dom::array(p["seatCategories"]).size());
        }
        acc += static_cast<double>(simdjson::dom::object(r["events"]).size());
    }
    else if (name == "canada")
    {
        auto g = r["features"].at(0)["geometry"];
        acc += static_cast<double>(std::string_view(r["type"]).size() + std::string_view(g["type"]).size() + simdjson::dom::array(g["coordinates"]).size());
    }
    else if (name == "jeopardy")
    {
        for (auto q : simdjson::dom::array(r))
        {
            acc += std::string_view(q["round"]) == "Final Jeopardy!" ? 1 : 0;
            acc += static_cast<double>(std::string_view(q["category"]).size());
        }
    }
    else if (name == "rpc")
    {
        acc += static_cast<double>(std::string_view(r["method"]).size());
        acc += static_cast<double>(int64_t(r["params"]["minuend"]) + int64_t(r["id"]));
    }
    return acc;
}

static double pick_od(const std::string& name, simdjson::ondemand::document& d)
{
    double acc = 0;
    if (name == "twitter" || name == "status")
    {
        auto one = [&](simdjson::ondemand::object s)
        {
            acc += static_cast<double>(uint64_t(s["id"]));
            acc += static_cast<double>(std::string_view(s["user"]["screen_name"]).size());
            acc += static_cast<double>(int64_t(s["retweet_count"]));
        };
        if (name == "twitter")
        {
            for (auto s : d["statuses"])
            {
                one(s.get_object());
            }
        }
        else
        {
            one(d.get_object());
        }
    }
    else if (name == "citm_catalog")
    {
        simdjson::ondemand::object ev = d["events"].get_object();
        acc += static_cast<double>(ev.count_fields());
        for (auto p : d["performances"])
        {
            simdjson::ondemand::object o = p.get_object();
            const auto a = uint64_t(o["eventId"]) + uint64_t(o["id"]);
            simdjson::ondemand::array sc = o["seatCategories"].get_array();
            acc += static_cast<double>(a + sc.count_elements());
        }
    }
    else if (name == "canada")
    {
        acc += static_cast<double>(std::string_view(d["type"]).size());
        auto g = d["features"].at(0)["geometry"];
        acc += static_cast<double>(std::string_view(g["type"]).size());
        simdjson::ondemand::array co = g["coordinates"].get_array();
        acc += static_cast<double>(co.count_elements());
    }
    else if (name == "jeopardy")
    {
        for (auto q : d)
        {
            simdjson::ondemand::object o = q.get_object();
            acc += static_cast<double>(std::string_view(o["category"]).size());
            acc += std::string_view(o["round"]) == "Final Jeopardy!" ? 1 : 0;
        }
    }
    else if (name == "rpc")
    {
        acc += static_cast<double>(std::string_view(d["method"]).size());
        acc += static_cast<double>(int64_t(d["params"]["minuend"]));
        acc += static_cast<double>(int64_t(d["id"]));
    }
    return acc;
}

// ---------------- harness ----------------

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

struct engine
{
    std::string name;
    std::function<void()> fn;
};

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::fprintf(stderr, "usage: %s <json_test_data directory> [rounds] [document]\n", argv[0]);
        return 1;
    }
    const std::string T = std::string(argv[1]) + "/";
    const int rounds = argc > 2 ? std::atoi(argv[2]) : 30;
    const std::string only = argc > 3 ? argv[3] : "";
    struct doc
    {
        std::string name, text;
        int batch;
    };
    std::vector<doc> docs;
    for (const char* f :
            {"nativejson-benchmark/twitter.json", "nativejson-benchmark/citm_catalog.json", "nativejson-benchmark/canada.json", "jeopardy/jeopardy.json"
            })
    {
        std::string n = std::string(f).substr(std::string(f).find('/') + 1);
        docs.push_back({n.substr(0, n.size() - 5), slurp(T + f), 1});
    }
    docs.push_back({"status", json::parse(docs[0].text)["statuses"][0].dump(), 200});
    docs.push_back({"rpc", R"({"jsonrpc": "2.0", "method": "subtract", "params": {"minuend": 42, "subtrahend": 23}, "id": 3})", 5000});

    // correctness cross-check of the workloads
    for (const auto& dc : docs)
    {
        stats a, b, c, dd;
        walk(json::parse(dc.text), a);
        auto d = json_document::parse(dc.text);
        walk(d.root(), b);
        yyjson_doc* y = yyjson_read(dc.text.data(), dc.text.size(), 0);
        walk(yyjson_doc_get_root(y), c);
        simdjson::dom::parser p;
        walk(p.parse(dc.text).value(), dd);
        const bool ok = a.nodes == b.nodes && a.nodes == c.nodes && a.nodes == dd.nodes && a.str == b.str && a.str == c.str && a.str == dd.str
                        && std::fabs(a.num - b.num) <= 1e-9 * std::fabs(a.num) && std::fabs(a.num - c.num) <= 1e-9 * std::fabs(a.num);
        const double pa = pick(dc.name, json::parse(dc.text)), pb = pick(dc.name, d.root()), pc = pick(dc.name, yyjson_doc_get_root(y)), pd = pick(dc.name, p.parse(dc.text).value());
        std::printf("check %-13s traverse %s select %s\n", dc.name.c_str(), ok ? "OK" : "MISMATCH", (pa == pb && pa == pc && pa == pd) ? "OK" : "MISMATCH");
        yyjson_doc_free(y);
    }

    std::FILE* csv = std::fopen("bench_view.csv", "w");
    std::fprintf(csv, "doc,bytes,workload,engine,ns\n");
    json_document reused;
    simdjson::dom::parser sj;
    simdjson::ondemand::parser od;
    for (const auto& dc : docs)
    {
        if (!only.empty() && dc.name != only)
        {
            continue;
        }
        const std::string& s = dc.text;
        const simdjson::padded_string ps(s);
        const std::string name = dc.name;
        std::vector<std::pair<std::string, std::vector<engine>>> workloads;

        workloads.push_back({"parse", {
                {"json_view", [&] { auto d = json_document::parse(s); g_sink = static_cast<double>(d.node_count()); }},
                {"json_view (reused)", [&] { reused.read(s); g_sink = static_cast<double>(reused.node_count()); }},
                {"yyjson", [&] { yyjson_doc* d = yyjson_read(s.data(), s.size(), 0); g_sink = static_cast<double>(yyjson_doc_get_val_count(d)); yyjson_doc_free(d); }},
                {"simdjson DOM", [&] { auto e = sj.parse(ps).value_unsafe(); g_sink = e.is_object(); }},
                {"simdjson DOM (fresh)", [&] { simdjson::dom::parser p; auto e = p.parse(ps).value_unsafe(); g_sink = e.is_object(); }},
#if JSON_VIEW_BENCH_BOOST
                {"Boost.JSON", [&] { boost::json::monotonic_resource mr; auto v = boost::json::parse(s, &mr); g_sink = v.is_object(); }},
#endif
                {"json::parse", [&] { json j = json::parse(s); g_sink = static_cast<double>(j.size()); }},
            }});
        workloads.push_back({"traverse", {
                {"json_view", [&] { auto d = json_document::parse(s); stats st; walk(d.root(), st); g_sink = st.num; }},
                {"json_view (reused)", [&] { reused.read(s); stats st; walk(reused.root(), st); g_sink = st.num; }},
                {"yyjson", [&] { yyjson_doc* d = yyjson_read(s.data(), s.size(), 0); stats st; walk(yyjson_doc_get_root(d), st); g_sink = st.num; yyjson_doc_free(d); }},
                {"simdjson DOM", [&] { stats st; walk(sj.parse(ps).value_unsafe(), st); g_sink = st.num; }},
                {"simdjson OD", [&] { auto d = od.iterate(ps).value_unsafe(); stats st; walk_od(d.get_value().value_unsafe(), st); g_sink = st.num; }},
#if JSON_VIEW_BENCH_BOOST
                {"Boost.JSON", [&] { boost::json::monotonic_resource mr; auto v = boost::json::parse(s, &mr); stats st; walk(v, st); g_sink = st.num; }},
#endif
                {"json::parse", [&] { json j = json::parse(s); stats st; walk(j, st); g_sink = st.num; }},
            }});
        workloads.push_back({"select", {
                {"json_view", [&] { auto d = json_document::parse(s); g_sink = pick(name, d.root()); }},
                {"json_view (reused)", [&] { reused.read(s); g_sink = pick(name, reused.root()); }},
                {"yyjson", [&] { yyjson_doc* d = yyjson_read(s.data(), s.size(), 0); g_sink = pick(name, yyjson_doc_get_root(d)); yyjson_doc_free(d); }},
                {"simdjson DOM", [&] { g_sink = pick(name, sj.parse(ps).value_unsafe()); }},
                {"simdjson OD", [&] { auto d = od.iterate(ps).value_unsafe(); g_sink = pick_od(name, d); }},
                {"json::parse", [&] { json j = json::parse(s); g_sink = pick(name, j); }},
            }});
        {
            // serialization of an already parsed document
            static json_document vd;
            vd.read(s);
            static yyjson_doc* yd = nullptr;
            if (yd)
            {
                yyjson_doc_free(yd);
            }
            yd = yyjson_read(s.data(), s.size(), 0);
            static simdjson::dom::parser sjd;
            static simdjson::dom::element se;
            se = sjd.parse(ps).value_unsafe();
            static json jd;
            jd = json::parse(s);
            workloads.push_back({"dump", {
                    {"json_view", [&] { std::string o = vd.root().dump(); g_sink = static_cast<double>(o.size()); }},
                    {"yyjson", [&] { std::size_t n = 0; char* o = yyjson_write(yd, 0, &n); g_sink = static_cast<double>(n); std::free(o); }},
                    {"simdjson DOM", [&] { std::string o = simdjson::to_string(se); g_sink = static_cast<double>(o.size()); }},
                    {"json::parse", [&] { std::string o = jd.dump(); g_sink = static_cast<double>(o.size()); }},
                }});
        }

        for (auto& wl : workloads)
        {
            std::vector<double> best(wl.second.size(), 1e300);
            const int r = s.size() > 10000000 ? std::max(3, rounds / 5) : rounds;
            for (int i = 0; i < r; ++i)
            {
                for (std::size_t k = 0; k < wl.second.size(); ++k)
                {
                    // an untimed call first: whatever the previous engine left to the allocator
                    // (e.g. thousands of freed json nodes) is cleaned up here, not in the timing
                    wl.second[k].fn();
                    const auto t0 = std::chrono::steady_clock::now();
                    for (int b = 0; b < dc.batch; ++b)
                    {
                        wl.second[k].fn();
                    }
                    const double ns = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count() / dc.batch;
                    best[k] = std::min(best[k], ns);
                }
            }
            const double ref = best[0];
            std::printf("%-13s %-9s", dc.name.c_str(), wl.first.c_str());
            for (std::size_t k = 0; k < wl.second.size(); ++k)
            {
                const double us = best[k] / 1e3;
                std::printf("  %s %s%s (%.2fx)", wl.second[k].name.c_str(), us >= 100 ? "" : "", (us >= 1000 ? std::to_string(static_cast<long>(us)) + "us" : (std::to_string(us).substr(0, 5) + "us")).c_str(), best[k] / ref);
                std::fprintf(csv, "%s,%zu,%s,%s,%.1f\n", dc.name.c_str(), s.size(), wl.first.c_str(), wl.second[k].name.c_str(), best[k]);
            }
            std::printf("\n");
            std::fflush(stdout);
        }
    }
    std::fclose(csv);
}
