//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// Read-modify-write benchmark: parse a document, apply the same logical edits
// with each library's own API, and serialize it (compact).
//
//   json_view     json_editable_document: edits in place, unchanged values stay in the index
//   yyjson        yyjson_read + yyjson_doc_mut_copy (the way to edit a parsed document)
//   Boost.JSON    parse into a mutable DOM (monotonic resource, precise numbers), serialize
//   json::parse   nlohmann::json today
// simdjson has no mutable document and is not part of this comparison.
//
// Workloads:
//   patch   a handful of edits at fixed places (scalars, a new member, a new array element)
//   update  edits in every record (twitter: 100 statuses, citm: 243 performances,
//           canada: 480 rings, jeopardy: 216,930 questions): set scalars, erase a
//           member, add a member (canada: replace the first point of every ring)
//
// Build: see README.md (same flags as bench_view.cpp).
#include <nlohmann/json_view.hpp>

#if JSON_VIEW_BENCH_BOOST
    #include <boost/json.hpp>
    #include <boost/json/src.hpp>
#endif
#include <yyjson.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <sstream>

using nlohmann::json;
using nlohmann::json_editable_document;
using nlohmann::json_editable_view;
#if JSON_VIEW_BENCH_BOOST
    namespace bj = boost::json;
#endif

static volatile std::size_t g_sink;

// ---------------- json_view ----------------

static std::string edit_view(const std::string& name, const std::string& s, bool update)
{
    json_editable_document d = json_editable_document::parse(s);
    const json_editable_view r = d.root();
    if (name == "twitter")
    {
        if (update)
        {
            std::int64_t i = 0;
            for (const json_editable_view st : r["statuses"])
            {
                d.set(st, "retweet_count", i++);
                d.set(st, "favorited", true);
                d.set(st, "text", "redacted");
                d.erase(st, "entities");
                d.set(st, "edited", true);
            }
        }
        else
        {
            d.set(r["search_metadata"], "count", 200);
            d.set(r["statuses"][0], "text", "patched");
            d.set(r["statuses"][0]["user"], "followers_count", 1);
            d.set(r["statuses"][99], "favorited", true);
            d.set(r, "patched", true);
        }
    }
    else if (name == "citm_catalog")
    {
        if (update)
        {
            for (const json_editable_view p : r["performances"])
            {
                d.set(p, "name", "performance");
                d.set(p, "start", p["start"].get<std::int64_t>() + 1);
                d.erase(p, "seatMapImage");
                d.set(p, "edited", true);
            }
        }
        else
        {
            d.set(r["events"]["138586341"], "name", "patched");
            d.set(r["performances"][0], "start", 0);
            d.set(r["venueNames"], "PLEYEL_PLEYEL", "Salle");
            d.set(r, "patched", true);
        }
    }
    else if (name == "canada")
    {
        const json_editable_view coords = r["features"][0]["geometry"]["coordinates"];
        if (update)
        {
            for (const json_editable_view ring : coords)
            {
                d.set(ring, 0, json::array({0.5, 0.5}));
            }
        }
        else
        {
            d.set(r["features"][0]["properties"], "name", "patched");
            d.set(r, "type", "FeatureCollection2");
            d.set(coords[0], 0, json::array({0.0, 0.0}));
        }
    }
    else if (name == "jeopardy")
    {
        if (update)
        {
            for (const json_editable_view q : r)
            {
                d.set(q, "value", "$1");
                d.erase(q, "air_date");
            }
        }
        else
        {
            d.set(r[0], "value", "$0");
            d.set(r[100000], "answer", "patched");
            d.set(r[216929], "round", "x");
            d.push_back(r, json::object({{"category", "NEW"}, {"value", "$5"}}));
        }
    }
    else if (name == "status")
    {
        d.set(r, "retweet_count", 1);
        d.set(r["user"], "name", "x");
    }
    else if (name == "rpc")
    {
        d.set(r, "id", 4);
        d.set(r["params"], "subtrahend", 24);
    }
    return r.dump();
}

// ---------------- nlohmann::json ----------------

static std::string edit_json(const std::string& name, const std::string& s, bool update)
{
    json r = json::parse(s);
    if (name == "twitter")
    {
        if (update)
        {
            std::int64_t i = 0;
            for (auto& st : r["statuses"])
            {
                st["retweet_count"] = i++;
                st["favorited"] = true;
                st["text"] = "redacted";
                st.erase("entities");
                st["edited"] = true;
            }
        }
        else
        {
            r["search_metadata"]["count"] = 200;
            r["statuses"][0]["text"] = "patched";
            r["statuses"][0]["user"]["followers_count"] = 1;
            r["statuses"][99]["favorited"] = true;
            r["patched"] = true;
        }
    }
    else if (name == "citm_catalog")
    {
        if (update)
        {
            for (auto& p : r["performances"])
            {
                p["name"] = "performance";
                p["start"] = p["start"].get<std::int64_t>() + 1;
                p.erase("seatMapImage");
                p["edited"] = true;
            }
        }
        else
        {
            r["events"]["138586341"]["name"] = "patched";
            r["performances"][0]["start"] = 0;
            r["venueNames"]["PLEYEL_PLEYEL"] = "Salle";
            r["patched"] = true;
        }
    }
    else if (name == "canada")
    {
        json& coords = r["features"][0]["geometry"]["coordinates"];
        if (update)
        {
            for (auto& ring : coords)
            {
                ring[0] = json::array({0.5, 0.5});
            }
        }
        else
        {
            r["features"][0]["properties"]["name"] = "patched";
            r["type"] = "FeatureCollection2";
            coords[0][0] = json::array({0.0, 0.0});
        }
    }
    else if (name == "jeopardy")
    {
        if (update)
        {
            for (auto& q : r)
            {
                q["value"] = "$1";
                q.erase("air_date");
            }
        }
        else
        {
            r[0]["value"] = "$0";
            r[100000]["answer"] = "patched";
            r[216929]["round"] = "x";
            r.push_back(json::object({{"category", "NEW"}, {"value", "$5"}}));
        }
    }
    else if (name == "status")
    {
        r["retweet_count"] = 1;
        r["user"]["name"] = "x";
    }
    else if (name == "rpc")
    {
        r["id"] = 4;
        r["params"]["subtrahend"] = 24;
    }
    return r.dump();
}

// ---------------- yyjson ----------------

static std::string edit_yyjson(const std::string& name, const std::string& s, bool update)
{
    yyjson_doc* idoc = yyjson_read(s.data(), s.size(), 0);
    yyjson_mut_doc* d = yyjson_doc_mut_copy(idoc, nullptr);
    yyjson_doc_free(idoc);
    yyjson_mut_val* r = yyjson_mut_doc_get_root(d);
    auto get = [](yyjson_mut_val * o, const char* k)
    {
        return yyjson_mut_obj_get(o, k);
    };
    if (name == "twitter")
    {
        yyjson_mut_val* sts = get(r, "statuses");
        if (update)
        {
            std::size_t idx, max;
            yyjson_mut_val* st;
            std::int64_t i = 0;
            yyjson_mut_arr_foreach(sts, idx, max, st)
            {
                yyjson_mut_set_sint(get(st, "retweet_count"), i++);
                yyjson_mut_set_bool(get(st, "favorited"), true);
                yyjson_mut_set_str(get(st, "text"), "redacted");
                yyjson_mut_obj_remove_key(st, "entities");
                yyjson_mut_obj_add_bool(d, st, "edited", true);
            }
        }
        else
        {
            yyjson_mut_set_sint(get(get(r, "search_metadata"), "count"), 200);
            yyjson_mut_val* s0 = yyjson_mut_arr_get(sts, 0);
            yyjson_mut_set_str(get(s0, "text"), "patched");
            yyjson_mut_set_sint(get(get(s0, "user"), "followers_count"), 1);
            yyjson_mut_set_bool(get(yyjson_mut_arr_get(sts, 99), "favorited"), true);
            yyjson_mut_obj_add_bool(d, r, "patched", true);
        }
    }
    else if (name == "citm_catalog")
    {
        if (update)
        {
            std::size_t idx, max;
            yyjson_mut_val* p;
            yyjson_mut_arr_foreach(get(r, "performances"), idx, max, p)
            {
                yyjson_mut_set_str(get(p, "name"), "performance");
                yyjson_mut_val* start = get(p, "start");
                yyjson_mut_set_sint(start, yyjson_mut_get_sint(start) + 1);
                yyjson_mut_obj_remove_key(p, "seatMapImage");
                yyjson_mut_obj_add_bool(d, p, "edited", true);
            }
        }
        else
        {
            yyjson_mut_set_str(get(get(get(r, "events"), "138586341"), "name"), "patched");
            yyjson_mut_set_sint(get(yyjson_mut_arr_get(get(r, "performances"), 0), "start"), 0);
            yyjson_mut_set_str(get(get(r, "venueNames"), "PLEYEL_PLEYEL"), "Salle");
            yyjson_mut_obj_add_bool(d, r, "patched", true);
        }
    }
    else if (name == "canada")
    {
        yyjson_mut_val* f0 = yyjson_mut_arr_get(get(r, "features"), 0);
        yyjson_mut_val* coords = get(get(f0, "geometry"), "coordinates");
        if (update)
        {
            static const double half[2] = {0.5, 0.5};
            std::size_t idx, max;
            yyjson_mut_val* ring;
            yyjson_mut_arr_foreach(coords, idx, max, ring)
            {
                yyjson_mut_arr_replace(ring, 0, yyjson_mut_arr_with_real(d, half, 2));
            }
        }
        else
        {
            static const double zero[2] = {0.0, 0.0};
            yyjson_mut_set_str(get(get(f0, "properties"), "name"), "patched");
            yyjson_mut_set_str(get(r, "type"), "FeatureCollection2");
            yyjson_mut_arr_replace(yyjson_mut_arr_get(coords, 0), 0, yyjson_mut_arr_with_real(d, zero, 2));
        }
    }
    else if (name == "jeopardy")
    {
        if (update)
        {
            std::size_t idx, max;
            yyjson_mut_val* q;
            yyjson_mut_arr_foreach(r, idx, max, q)
            {
                yyjson_mut_set_str(get(q, "value"), "$1");
                yyjson_mut_obj_remove_key(q, "air_date");
            }
        }
        else
        {
            yyjson_mut_set_str(get(yyjson_mut_arr_get(r, 0), "value"), "$0");
            yyjson_mut_set_str(get(yyjson_mut_arr_get(r, 100000), "answer"), "patched");
            yyjson_mut_set_str(get(yyjson_mut_arr_get(r, 216929), "round"), "x");
            yyjson_mut_val* o = yyjson_mut_obj(d);
            yyjson_mut_obj_add_str(d, o, "category", "NEW");
            yyjson_mut_obj_add_str(d, o, "value", "$5");
            yyjson_mut_arr_append(r, o);
        }
    }
    else if (name == "status")
    {
        yyjson_mut_set_sint(get(r, "retweet_count"), 1);
        yyjson_mut_set_str(get(get(r, "user"), "name"), "x");
    }
    else if (name == "rpc")
    {
        yyjson_mut_set_sint(get(r, "id"), 4);
        yyjson_mut_set_sint(get(get(r, "params"), "subtrahend"), 24);
    }
    std::size_t n = 0;
    char* out = yyjson_mut_write(d, 0, &n);
    std::string result(out, n);
    std::free(out);
    yyjson_mut_doc_free(d);
    return result;
}

#if JSON_VIEW_BENCH_BOOST
// ---------------- Boost.JSON ----------------

static std::string edit_boost(const std::string& name, const std::string& s, bool update)
{
    bj::monotonic_resource mr;
    bj::parse_options opt;
    opt.numbers = bj::number_precision::precise; // correctly rounded, like the others
    bj::value v = bj::parse(s, &mr, opt);
    bj::object* const obj = v.if_object(); // nullptr for jeopardy (an array)
    if (name == "twitter")
    {
        bj::array& sts = (*obj)["statuses"].as_array();
        if (update)
        {
            std::int64_t i = 0;
            for (auto& e : sts)
            {
                bj::object& st = e.as_object();
                st["retweet_count"] = i++;
                st["favorited"] = true;
                st["text"] = "redacted";
                st.erase("entities");
                st["edited"] = true;
            }
        }
        else
        {
            (*obj)["search_metadata"].as_object()["count"] = 200;
            bj::object& s0 = sts[0].as_object();
            s0["text"] = "patched";
            s0["user"].as_object()["followers_count"] = 1;
            sts[99].as_object()["favorited"] = true;
            (*obj)["patched"] = true;
        }
    }
    else if (name == "citm_catalog")
    {
        if (update)
        {
            for (auto& e : (*obj)["performances"].as_array())
            {
                bj::object& p = e.as_object();
                p["name"] = "performance";
                p["start"] = p["start"].as_int64() + 1;
                p.erase("seatMapImage");
                p["edited"] = true;
            }
        }
        else
        {
            (*obj)["events"].as_object()["138586341"].as_object()["name"] = "patched";
            (*obj)["performances"].as_array()[0].as_object()["start"] = 0;
            (*obj)["venueNames"].as_object()["PLEYEL_PLEYEL"] = "Salle";
            (*obj)["patched"] = true;
        }
    }
    else if (name == "canada")
    {
        bj::object& f0 = (*obj)["features"].as_array()[0].as_object();
        bj::array& coords = f0["geometry"].as_object()["coordinates"].as_array();
        if (update)
        {
            for (auto& ring : coords)
            {
                ring.as_array()[0] = bj::array({0.5, 0.5});
            }
        }
        else
        {
            f0["properties"].as_object()["name"] = "patched";
            (*obj)["type"] = "FeatureCollection2";
            coords[0].as_array()[0] = bj::array({0.0, 0.0});
        }
    }
    else if (name == "jeopardy")
    {
        bj::array& a = v.as_array();
        if (update)
        {
            for (auto& e : a)
            {
                bj::object& q = e.as_object();
                q["value"] = "$1";
                q.erase("air_date");
            }
        }
        else
        {
            a[0].as_object()["value"] = "$0";
            a[100000].as_object()["answer"] = "patched";
            a[216929].as_object()["round"] = "x";
            a.push_back(bj::object({{"category", "NEW"}, {"value", "$5"}}));
        }
    }
    else if (name == "status")
    {
        (*obj)["retweet_count"] = 1;
        (*obj)["user"].as_object()["name"] = "x";
    }
    else if (name == "rpc")
    {
        (*obj)["id"] = 4;
        (*obj)["params"].as_object()["subtrahend"] = 24;
    }
    return bj::serialize(v);
}
#endif

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

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        std::fprintf(stderr, "usage: %s <json_test_data directory> [rounds] [document]\n", argv[0]);
        return 1;
    }
    const std::string T = std::string(argv[1]) + "/";
    const int rounds = argc > 2 ? std::atoi(argv[2]) : 20;
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

    using fn = std::string (*)(const std::string&, const std::string&, bool);
    const std::vector<std::pair<std::string, fn>> engines =
    {
        {"json_view", edit_view}, {"yyjson", edit_yyjson},
#if JSON_VIEW_BENCH_BOOST
        {"Boost.JSON", edit_boost},
#endif
        {"json::parse", edit_json}
    };

    std::FILE* csv = std::fopen("bench_edit.csv", "w");
    std::fprintf(csv, "doc,bytes,workload,engine,ns\n");
    for (const auto& dc : docs)
    {
        if (!only.empty() && dc.name != only)
        {
            continue;
        }
        for (const bool update :
                {
                    false, true
                })
        {
            if (update && (dc.name == "status" || dc.name == "rpc"))
            {
                continue;
            }
            // all engines must produce the same value
            const json expected = json::parse(edit_json(dc.name, dc.text, update));
            bool ok = true;
            for (const auto& e : engines)
            {
                ok = ok && json::parse(e.second(dc.name, dc.text, update)) == expected;
            }
            std::vector<double> best(engines.size(), 1e300);
            const int r = dc.text.size() > 10000000 ? std::max(3, rounds / 4) : rounds;
            for (int i = 0; i < r; ++i)
            {
                for (std::size_t k = 0; k < engines.size(); ++k)
                {
                    // an untimed call first: whatever the previous engine left to the allocator
                    // (e.g. thousands of freed json nodes) is cleaned up here, not in the timing
                    g_sink = engines[k].second(dc.name, dc.text, update).size();
                    const auto t0 = std::chrono::steady_clock::now();
                    for (int b = 0; b < dc.batch; ++b)
                    {
                        g_sink = engines[k].second(dc.name, dc.text, update).size();
                    }
                    const double ns = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - t0).count() / dc.batch;
                    best[k] = std::min(best[k], ns);
                }
            }
            const char* wl = update ? "update" : "patch";
            std::printf("%-13s %-7s %s", dc.name.c_str(), wl, ok ? "" : "[OUTPUT MISMATCH] ");
            for (std::size_t k = 0; k < engines.size(); ++k)
            {
                const double us = best[k] / 1e3;
                std::printf("  %s %.*fus (%.2fx)", engines[k].first.c_str(), us < 10 ? 3 : (us < 1000 ? 1 : 0), us, best[k] / best[0]);
                std::fprintf(csv, "%s,%zu,%s,%s,%.1f\n", dc.name.c_str(), dc.text.size(), wl, engines[k].first.c_str(), best[k]);
            }
            std::printf("\n");
            std::fflush(stdout);
        }
    }
    std::fclose(csv);
}
