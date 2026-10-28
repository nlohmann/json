//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// Parse/traverse/dump of the nativejson-benchmark files and jeopardy with every engine in one binary,
// interleaved, best round reported (same method as tests/benchmarks/json_view/bench_view.cpp).
// Engines: json_document (nlohmann), yyjson, simdjson DOM and On-Demand, RapidJSON, sonic-cpp,
// Glaze (generic_u64 DOM and lazy_json), Boost.JSON, json::parse.
// Usage: bench_all <json_test_data dir> [rounds] [document]
#include <nlohmann/json_view.hpp>

#include <boost/json.hpp>
#include <boost/json/src.hpp>
#if !BENCH_NO_GLAZE
#include <glaze/glaze.hpp>
#include <glaze/json/lazy.hpp>
#endif
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <simdjson.h>
#include <sonic/sonic.h>
#include <yyjson.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
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

// ---- json::parse and json_view
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
            for (const auto& e : j.get_ref<const json::array_t&>()) walk(e, st);
            break;
        case json::value_t::string: st.str += j.get_ref<const std::string&>().size(); break;
        case json::value_t::number_integer: st.num += static_cast<double>(*j.get_ptr<const json::number_integer_t*>()); break;
        case json::value_t::number_unsigned: st.num += static_cast<double>(*j.get_ptr<const json::number_unsigned_t*>()); break;
        case json::value_t::number_float: st.num += *j.get_ptr<const json::number_float_t*>(); break;
        default: break;
    }
}

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
            for (const json_view e : v) walk(e, st);
            break;
        case json::value_t::string: st.str += v.get_string().size(); break;
        case json::value_t::number_integer: st.num += static_cast<double>(v.get<std::int64_t>()); break;
        case json::value_t::number_unsigned: st.num += static_cast<double>(v.get<std::uint64_t>()); break;
        case json::value_t::number_float: st.num += v.get<double>(); break;
        default: break;
    }
}

// ---- yyjson
static void walk(yyjson_val* v, stats& st)
{
    ++st.nodes;
    switch (yyjson_get_type(v))
    {
        case YYJSON_TYPE_OBJ:
        {
            std::size_t idx, max;
            yyjson_val *k, *val;
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
            yyjson_arr_foreach(v, idx, max, val) walk(val, st);
            break;
        }
        case YYJSON_TYPE_STR: st.str += yyjson_get_len(v); break;
        case YYJSON_TYPE_NUM:
            if (yyjson_is_sint(v)) st.num += static_cast<double>(yyjson_get_sint(v));
            else if (yyjson_is_uint(v)) st.num += static_cast<double>(yyjson_get_uint(v));
            else st.num += yyjson_get_real(v);
            break;
        default: break;
    }
}

// ---- simdjson DOM and On-Demand
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
            for (auto c : simdjson::dom::array(e)) walk(c, st);
            break;
        case simdjson::dom::element_type::STRING: st.str += std::string_view(e).size(); break;
        case simdjson::dom::element_type::INT64: st.num += static_cast<double>(int64_t(e)); break;
        case simdjson::dom::element_type::UINT64: st.num += static_cast<double>(uint64_t(e)); break;
        case simdjson::dom::element_type::DOUBLE: st.num += double(e); break;
        default: break;
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
            for (auto c : v.get_array()) walk_od(c.value(), st);
            break;
        case simdjson::ondemand::json_type::string: st.str += std::string_view(v.get_string()).size(); break;
        case simdjson::ondemand::json_type::number:
        {
            simdjson::ondemand::number n = v.get_number();
            switch (n.get_number_type())
            {
                case simdjson::ondemand::number_type::signed_integer: st.num += static_cast<double>(n.get_int64()); break;
                case simdjson::ondemand::number_type::unsigned_integer: st.num += static_cast<double>(n.get_uint64()); break;
                default: st.num += n.get_double(); break;
            }
            break;
        }
        case simdjson::ondemand::json_type::boolean: (void)bool(v.get_bool()); break;
        default: (void)v.is_null(); break;
    }
}

// ---- RapidJSON
static void walk(const rapidjson::Value& v, stats& st)
{
    ++st.nodes;
    switch (v.GetType())
    {
        case rapidjson::kObjectType:
            for (auto m = v.MemberBegin(); m != v.MemberEnd(); ++m)
            {
                st.str += m->name.GetStringLength();
                walk(m->value, st);
            }
            break;
        case rapidjson::kArrayType:
            for (const auto& e : v.GetArray()) walk(e, st);
            break;
        case rapidjson::kStringType: st.str += v.GetStringLength(); break;
        case rapidjson::kNumberType:
            if (v.IsDouble()) st.num += v.GetDouble();
            else if (v.IsInt64()) st.num += static_cast<double>(v.GetInt64());
            else st.num += static_cast<double>(v.GetUint64());
            break;
        default: break;
    }
}

// ---- sonic-cpp
template<class N>
static void walk_sonic(const N& v, stats& st)
{
    ++st.nodes;
    if (v.IsObject())
    {
        for (auto m = v.MemberBegin(); m != v.MemberEnd(); ++m)
        {
            st.str += m->name.GetStringView().size();
            walk_sonic(m->value, st);
        }
    }
    else if (v.IsArray())
    {
        for (auto e = v.Begin(); e != v.End(); ++e) walk_sonic(*e, st);
    }
    else if (v.IsString())
    {
        st.str += v.GetStringView().size();
    }
    else if (v.IsNumber())
    {
        if (v.IsDouble()) st.num += v.GetDouble();
        else if (v.IsUint64()) st.num += static_cast<double>(v.GetUint64());
        else st.num += static_cast<double>(v.GetInt64());
    }
}

#if !BENCH_NO_GLAZE
// ---- Glaze generic_u64 (owning DOM) and lazy_json (on demand, no validation)
static void walk(const glz::generic_u64& j, stats& st)
{
    ++st.nodes;
    std::visit([&](const auto& x)
    {
        using T = std::decay_t<decltype(x)>;
        if constexpr (std::is_same_v<T, glz::generic_u64::object_t>)
        {
            for (const auto& [k, v] : x)
            {
                st.str += k.size();
                walk(v, st);
            }
        }
        else if constexpr (std::is_same_v<T, glz::generic_u64::array_t>)
        {
            for (const auto& e : x) walk(e, st);
        }
        else if constexpr (std::is_same_v<T, std::string>) st.str += x.size();
        else if constexpr (std::is_same_v<T, double> || std::is_same_v<T, std::int64_t> || std::is_same_v<T, std::uint64_t>) st.num += static_cast<double>(x);
    }, j.data);
}

template<class V>
static void walk_lazy(const V& v, stats& st)
{
    ++st.nodes;
    if (v.is_object())
    {
        for (auto item : v)
        {
            st.str += item.key().size();
            walk_lazy(item, st);
        }
    }
    else if (v.is_array())
    {
        for (auto item : v) walk_lazy(item, st);
    }
    else if (v.is_string())
    {
        st.str += v.template get<std::string>().value().size();
    }
    else if (v.is_number())
    {
        const std::string_view raw = v.raw_json();
        if (raw.find_first_of(".eE") != std::string_view::npos) st.num += v.template get<double>().value();
        else if (raw[0] == '-') st.num += static_cast<double>(v.template get<std::int64_t>().value());
        else st.num += static_cast<double>(v.template get<std::uint64_t>().value());
    }
}

#endif

// ---- Boost.JSON
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
            for (const auto& c : v.get_array()) walk(c, st);
            break;
        case boost::json::kind::string: st.str += v.get_string().size(); break;
        case boost::json::kind::int64: st.num += static_cast<double>(v.get_int64()); break;
        case boost::json::kind::uint64: st.num += static_cast<double>(v.get_uint64()); break;
        case boost::json::kind::double_: st.num += v.get_double(); break;
        default: break;
    }
}

// ---- selective access (copied from bench_view.cpp)
template<class V>
static double pick_view(const std::string& name, V r)
{
    double acc = 0;
    if (name == "twitter" || name == "status")
    {
        auto one = [&](V s)
        {
            acc += static_cast<double>(s["id"].template get<std::uint64_t>());
            acc += static_cast<double>(s["user"]["screen_name"].get_string().size());
            acc += static_cast<double>(s["retweet_count"].template get<std::int64_t>());
        };
        if (name == "twitter")
        {
            for (const V s : r["statuses"])
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
        for (const V p : r["performances"])
        {
            acc += static_cast<double>(p["id"].template get<std::uint64_t>() + p["eventId"].template get<std::uint64_t>() + p["seatCategories"].size());
        }
        acc += static_cast<double>(r["events"].size());
    }
    else if (name == "canada")
    {
        const V g = r["features"][0]["geometry"];
        acc += static_cast<double>(r["type"].get_string().size() + g["type"].get_string().size() + g["coordinates"].size());
    }
    else if (name == "jeopardy")
    {
        for (const V q : r)
        {
            acc += q["round"].get_string() == "Final Jeopardy!" ? 1 : 0;
            acc += static_cast<double>(q["category"].get_string().size());
        }
    }
    else if (name == "rpc")
    {
        acc += static_cast<double>(r["method"].get_string().size());
        acc += static_cast<double>(r["params"]["minuend"].template get<std::int64_t>() + r["id"].template get<std::int64_t>());
    }
    return acc;
}

static double pick(const std::string& name, json_view r)
{
    return pick_view<json_view>(name, r);
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

#if !BENCH_NO_GLAZE
// Glaze reading into structs that declare only the fields the selection uses; unknown keys are skipped
namespace sel
{
struct user { std::string screen_name; };
struct status { std::uint64_t id{}; sel::user user; std::int64_t retweet_count{}; };
struct twitter { std::vector<status> statuses; };
struct performance { std::uint64_t id{}; std::uint64_t eventId{}; std::vector<glz::raw_json_view> seatCategories; };
struct citm { std::map<std::string, glz::raw_json_view> events; std::vector<performance> performances; };
struct geometry { std::string type; std::vector<glz::raw_json_view> coordinates; };
struct feature { sel::geometry geometry; };
struct canada { std::string type; std::vector<feature> features; };
struct question { std::string category; std::string round; };
}

constexpr glz::opts sel_opts{.error_on_unknown_keys = false};

static double pick_glaze_structs(const std::string& name, const std::string& s)
{
    double acc = 0;
    if (name == "twitter" || name == "status")
    {
        auto one = [&](const sel::status& x)
        {
            acc += static_cast<double>(x.id);
            acc += static_cast<double>(x.user.screen_name.size());
            acc += static_cast<double>(x.retweet_count);
        };
        if (name == "twitter")
        {
            sel::twitter t;
            if (glz::read<sel_opts>(t, s)) return -1;
            for (const auto& x : t.statuses) one(x);
        }
        else
        {
            sel::status x;
            if (glz::read<sel_opts>(x, s)) return -1;
            one(x);
        }
    }
    else if (name == "citm_catalog")
    {
        sel::citm c;
        if (glz::read<sel_opts>(c, s)) return -1;
        for (const auto& p : c.performances) acc += static_cast<double>(p.id + p.eventId + p.seatCategories.size());
        acc += static_cast<double>(c.events.size());
    }
    else if (name == "canada")
    {
        sel::canada c;
        if (glz::read<sel_opts>(c, s)) return -1;
        acc += static_cast<double>(c.type.size() + c.features[0].geometry.type.size() + c.features[0].geometry.coordinates.size());
    }
    else if (name == "jeopardy")
    {
        std::vector<sel::question> q;
        if (glz::read<sel_opts>(q, s)) return -1;
        for (const auto& x : q)
        {
            acc += x.round == "Final Jeopardy!" ? 1 : 0;
            acc += static_cast<double>(x.category.size());
        }
    }
    return acc;
}

template<class D>
static double pick_glaze_lazy(const std::string& name, const D& d)
{
    double acc = 0;
    auto one = [&](const auto& x)
    {
        acc += static_cast<double>(x["id"].template get<std::uint64_t>().value());
        acc += static_cast<double>(x["user"]["screen_name"].template get<std::string>().value().size());
        acc += static_cast<double>(x["retweet_count"].template get<std::int64_t>().value());
    };
    if (name == "twitter")
    {
        for (auto x : d["statuses"]) one(x);
    }
    else if (name == "status")
    {
        one(d.root());
    }
    else if (name == "citm_catalog")
    {
        for (auto p : d["performances"])
            acc += static_cast<double>(p["id"].template get<std::uint64_t>().value() + p["eventId"].template get<std::uint64_t>().value() + p["seatCategories"].size());
        acc += static_cast<double>(d["events"].size());
    }
    else if (name == "canada")
    {
        auto g = d["features"][0]["geometry"];
        acc += static_cast<double>(d["type"].template get<std::string>().value().size() + g["type"].template get<std::string>().value().size() + g["coordinates"].size());
    }
    else if (name == "jeopardy")
    {
        for (auto q : d.root())
        {
            acc += q["round"].template get<std::string>().value() == "Final Jeopardy!" ? 1 : 0;
            acc += static_cast<double>(q["category"].template get<std::string>().value().size());
        }
    }
    return acc;
}
#endif

static std::string slurp(const std::string& p)
{
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

struct engine
{
    std::string name;
    std::function<void()> fn;
};

static bool same(const stats& a, const stats& b)
{
    return a.nodes == b.nodes && a.str == b.str && std::fabs(a.num - b.num) <= 1e-9 * std::fabs(a.num);
}

constexpr auto rj_flags = rapidjson::kParseFullPrecisionFlag;   // correctly rounded floats, as every other engine

int main(int argc, char** argv)
{
    const std::string T = std::string(argv[1]) + "/";
    const int rounds = argc > 2 ? std::atoi(argv[2]) : 30;
    const std::string only = argc > 3 ? argv[3] : "";   // time only this document (the check covers all)
    struct doc
    {
        std::string name, text;
        int batch;
    };
    std::vector<doc> docs;
    for (const char* f : {"nativejson-benchmark/twitter.json", "nativejson-benchmark/citm_catalog.json", "nativejson-benchmark/canada.json", "jeopardy/jeopardy.json"})
    {
        std::string n = std::string(f).substr(std::string(f).find('/') + 1);
        docs.push_back({n.substr(0, n.size() - 5), slurp(T + f), 1});
    }
    docs.push_back({"status", json::parse(docs[0].text)["statuses"][0].dump(), 200});

    // correctness: every engine must see the same values as json::parse
    bool all_ok = true;
    for (const auto& dc : docs)
    {
        stats ref;
        walk(json::parse(dc.text), ref);
        std::vector<std::pair<std::string, stats>> got(9, {"(not built)", stats{}});
        { auto d = json_document::parse(dc.text); walk(d.root(), got[0].second); got[0].first = "json_view"; }
        { yyjson_doc* d = yyjson_read(dc.text.data(), dc.text.size(), 0); walk(yyjson_doc_get_root(d), got[1].second); yyjson_doc_free(d); got[1].first = "yyjson"; }
        { simdjson::dom::parser p; walk(p.parse(dc.text).value(), got[2].second); got[2].first = "simdjson DOM"; }
        { simdjson::ondemand::parser p; simdjson::padded_string ps(dc.text); auto d = p.iterate(ps).value(); walk_od(d.get_value().value(), got[3].second); got[3].first = "simdjson OD"; }
        { rapidjson::Document d; d.Parse<rj_flags>(dc.text.data(), dc.text.size()); if (d.HasParseError()) std::puts("RapidJSON parse error"); walk(d, got[4].second); got[4].first = "RapidJSON"; }
        { rapidjson::Document d; d.Parse(dc.text.data(), dc.text.size()); stats x; walk(d, x); std::printf("info %-13s RapidJSON default flags: sum %s\n", dc.name.c_str(), x.num == got[0].second.num ? "exact" : "differs from the correctly rounded one"); }
        { sonic_json::Document d; d.Parse(dc.text.data(), dc.text.size()); if (d.HasParseError()) std::puts("sonic parse error"); walk_sonic(d, got[5].second); got[5].first = "sonic-cpp"; }
#if !BENCH_NO_GLAZE
        { glz::generic_u64 j; auto ec = glz::read_json(j, dc.text); if (ec) std::puts("glaze parse error"); walk(j, got[6].second); got[6].first = "Glaze generic"; }
#endif
#if !BENCH_NO_GLAZE
        { auto r = glz::lazy_json(dc.text); walk_lazy(r->root(), got[7].second); got[7].first = "Glaze lazy"; }
#endif
        { auto v = boost::json::parse(dc.text); walk(v, got[8].second); got[8].first = "Boost.JSON"; }
        std::printf("check %-13s", dc.name.c_str());
        for (const auto& g : got)
        {
            if (g.first == "(not built)") continue;
            const bool ok = same(ref, g.second);
            all_ok = all_ok && ok;
            // every engine but json::parse (std::map order) visits the values in document order, so their sums
            // must be bit-identical to json_view's if every number was converted to the same double
            const bool exact = g.second.num == got[0].second.num;
            std::printf(" %s:%s%s", g.first.c_str(), ok ? "OK" : "MISMATCH", exact ? "" : "(inexact)");
            if (!ok) std::printf("(nodes %zu/%zu str %zu/%zu num %.17g/%.17g)", g.second.nodes, ref.nodes, g.second.str, ref.str, g.second.num, ref.num);
        }
        std::printf("\n");
    }
    for (const auto& dc : docs)
    {
        const auto d = json_document::parse(dc.text);
        const double ref = pick(dc.name, d.root());
        yyjson_doc* y = yyjson_read(dc.text.data(), dc.text.size(), 0);
        const double py = pick(dc.name, yyjson_doc_get_root(y));
        yyjson_doc_free(y);
        simdjson::ondemand::parser p;
        simdjson::padded_string ps(dc.text);
        auto od_doc = p.iterate(ps).value();
        const double po = pick_od(dc.name, od_doc);
#if !BENCH_NO_GLAZE
        const double pg = pick_glaze_structs(dc.name, dc.text);
        auto lz = glz::lazy_json(dc.text);
        const double pl = pick_glaze_lazy(dc.name, *lz);
#else
        const double pg = ref, pl = ref;
#endif
        const bool ok = py == ref && po == ref && pg == ref && pl == ref;
        all_ok = all_ok && ok;
        std::printf("check %-13s select %s (json_view %.17g yyjson %.17g OD %.17g Glaze structs %.17g lazy %.17g)\n", dc.name.c_str(), ok ? "OK" : "MISMATCH", ref, py, po, pg, pl);
    }
    if (!all_ok) std::printf("WARNING: some engines disagree, see above\n");

    json_document reused;   // read() reuses its memory, as simdjson DOM reuses its parser
    simdjson::dom::parser sj;
    simdjson::ondemand::parser od;
    for (const auto& dc : docs)
    {
        if (!only.empty() && dc.name != only) continue;
        const std::string& s = dc.text;
        const simdjson::padded_string ps(s);
        std::vector<std::pair<std::string, std::vector<engine>>> workloads;
        workloads.push_back({"parse", {
            {"json_view", [&] { auto d = json_document::parse(s); g_sink = static_cast<double>(d.node_count()); }},
            {"json_view (reused)", [&] { reused.read(s); g_sink = static_cast<double>(reused.node_count()); }},
            {"yyjson", [&] { yyjson_doc* d = yyjson_read(s.data(), s.size(), 0); g_sink = static_cast<double>(yyjson_doc_get_val_count(d)); yyjson_doc_free(d); }},
            {"simdjson DOM", [&] { auto e = sj.parse(ps).value_unsafe(); g_sink = e.is_object(); }},
            {"simdjson DOM (fresh)", [&] { simdjson::dom::parser p; auto e = p.parse(ps).value_unsafe(); g_sink = e.is_object(); }},
            {"RapidJSON", [&] { rapidjson::Document d; d.Parse<rj_flags>(s.data(), s.size()); g_sink = d.IsObject(); }},
            {"RapidJSON (default flags)", [&] { rapidjson::Document d; d.Parse(s.data(), s.size()); g_sink = d.IsObject(); }},
            {"RapidJSON (in situ, with copy)", [&] { std::string c = s; rapidjson::Document d; d.ParseInsitu<rj_flags>(&c[0]); g_sink = d.IsObject(); }},
            {"sonic-cpp", [&] { sonic_json::Document d; d.Parse(s.data(), s.size()); g_sink = d.IsObject(); }},
#if !BENCH_NO_GLAZE
            {"Glaze generic", [&] { glz::generic_u64 j; auto ec = glz::read_json(j, s); g_sink = static_cast<double>(bool(ec)); }},
#endif
            {"Boost.JSON", [&] { boost::json::monotonic_resource mr; auto v = boost::json::parse(s, &mr); g_sink = v.is_object(); }},
            {"json::parse", [&] { json j = json::parse(s); g_sink = static_cast<double>(j.size()); }},
        }});
        workloads.push_back({"traverse", {
            {"json_view", [&] { auto d = json_document::parse(s); stats st; walk(d.root(), st); g_sink = st.num; }},
            {"json_view (reused)", [&] { reused.read(s); stats st; walk(reused.root(), st); g_sink = st.num; }},
            {"yyjson", [&] { yyjson_doc* d = yyjson_read(s.data(), s.size(), 0); stats st; walk(yyjson_doc_get_root(d), st); g_sink = st.num; yyjson_doc_free(d); }},
            {"simdjson DOM", [&] { stats st; walk(sj.parse(ps).value_unsafe(), st); g_sink = st.num; }},
            {"simdjson OD", [&] { auto d = od.iterate(ps).value_unsafe(); stats st; walk_od(d.get_value().value_unsafe(), st); g_sink = st.num; }},
            {"RapidJSON", [&] { rapidjson::Document d; d.Parse<rj_flags>(s.data(), s.size()); stats st; walk(d, st); g_sink = st.num; }},
            {"RapidJSON (default flags)", [&] { rapidjson::Document d; d.Parse(s.data(), s.size()); stats st; walk(d, st); g_sink = st.num; }},
            {"sonic-cpp", [&] { sonic_json::Document d; d.Parse(s.data(), s.size()); stats st; walk_sonic(d, st); g_sink = st.num; }},
#if !BENCH_NO_GLAZE
            {"Glaze generic", [&] { glz::generic_u64 j; auto ec = glz::read_json(j, s); stats st; walk(j, st); g_sink = st.num + static_cast<double>(bool(ec)); }},
#endif
#if !BENCH_NO_GLAZE
            {"Glaze lazy", [&] { auto r = glz::lazy_json(s); stats st; walk_lazy(r->root(), st); g_sink = st.num; }},
#endif
            {"Boost.JSON", [&] { boost::json::monotonic_resource mr; auto v = boost::json::parse(s, &mr); stats st; walk(v, st); g_sink = st.num; }},
            {"json::parse", [&] { json j = json::parse(s); stats st; walk(j, st); g_sink = st.num; }},
        }});
        {
            const std::string name = dc.name;
            workloads.push_back({"select", {
                {"json_view", [&, name] { auto d = json_document::parse(s); g_sink = pick(name, d.root()); }},
                {"json_view (reused)", [&, name] { reused.read(s); g_sink = pick(name, reused.root()); }},
                {"yyjson", [&, name] { yyjson_doc* d = yyjson_read(s.data(), s.size(), 0); g_sink = pick(name, yyjson_doc_get_root(d)); yyjson_doc_free(d); }},
                {"simdjson OD", [&, name] { auto d = od.iterate(ps).value_unsafe(); g_sink = pick_od(name, d); }},
#if !BENCH_NO_GLAZE
                {"Glaze structs", [&, name] { g_sink = pick_glaze_structs(name, s); }},
                {"Glaze lazy", [&, name] { auto r = glz::lazy_json(s); g_sink = pick_glaze_lazy(name, *r); }},
#endif
            }});
        }
        workloads.push_back({"parse+dump", {
            {"json_view", [&] { auto d = json_document::parse(s); std::string o = d.root().dump(); g_sink = static_cast<double>(o.size()); }},
            {"yyjson", [&] { yyjson_doc* d = yyjson_read(s.data(), s.size(), 0); std::size_t n = 0; char* o = yyjson_write(d, 0, &n); g_sink = static_cast<double>(n); std::free(o); yyjson_doc_free(d); }},
            {"simdjson DOM", [&] { std::string o = simdjson::to_string(sj.parse(ps).value_unsafe()); g_sink = static_cast<double>(o.size()); }},
            {"RapidJSON", [&] { rapidjson::Document d; d.Parse<rj_flags>(s.data(), s.size()); rapidjson::StringBuffer sb; rapidjson::Writer<rapidjson::StringBuffer> w(sb); d.Accept(w); g_sink = static_cast<double>(sb.GetSize()); }},
            {"sonic-cpp", [&] { sonic_json::Document d; d.Parse(s.data(), s.size()); sonic_json::WriteBuffer wb; d.Serialize(wb); g_sink = static_cast<double>(wb.Size()); }},
#if !BENCH_NO_GLAZE
            {"Glaze generic", [&] { glz::generic_u64 j; (void)glz::read_json(j, s); std::string o; (void)glz::write_json(j, o); g_sink = static_cast<double>(o.size()); }},
#endif
            {"Boost.JSON", [&] { boost::json::monotonic_resource mr; auto v = boost::json::parse(s, &mr); std::string o = boost::json::serialize(v); g_sink = static_cast<double>(o.size()); }},
            {"json::parse", [&] { json j = json::parse(s); std::string o = j.dump(); g_sink = static_cast<double>(o.size()); }},
        }});
        for (auto& wl : workloads)
        {
            std::vector<double> best(wl.second.size(), 1e300);
            const int r = s.size() > 10000000 ? std::max(3, rounds / 5) : rounds;
            for (int i = 0; i < r; ++i)
            {
                for (std::size_t k = 0; k < wl.second.size(); ++k)
                {
                    wl.second[k].fn();   // untimed: the previous engine's leftovers are cleaned up here
                    const auto t0 = std::chrono::steady_clock::now();
                    for (int b = 0; b < dc.batch; ++b) wl.second[k].fn();
                    best[k] = std::min(best[k], std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count() / dc.batch);
                }
            }
            std::printf("%-13s %-11s", dc.name.c_str(), wl.first.c_str());
            for (std::size_t k = 0; k < wl.second.size(); ++k)
                std::printf("  %s %.1fus (%.2fx)", wl.second[k].name.c_str(), best[k] / 1e3, best[k] / best[0]);
            std::printf("\n");
            std::fflush(stdout);
        }
    }
}
