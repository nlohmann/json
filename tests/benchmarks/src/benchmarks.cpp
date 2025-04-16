//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include <benchmark/benchmark.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <numeric>
#include <vector>
#include <test_data.hpp>

using json = nlohmann::json;

//////////////////////////////////////////////////////////////////////////////
// parse JSON from file
//////////////////////////////////////////////////////////////////////////////

static void ParseFile(benchmark::State& state, const char* filename)
{
    while (state.KeepRunning())
    {
        state.PauseTiming();
        auto* f = new std::ifstream(filename);
        auto* j = new json();
        state.ResumeTiming();

        *j = json::parse(*f);

        state.PauseTiming();
        delete f;
        delete j;
        state.ResumeTiming();
    }

    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    state.SetBytesProcessed(state.iterations() * file.tellg());
}
BENCHMARK_CAPTURE(ParseFile, jeopardy,          TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json");
BENCHMARK_CAPTURE(ParseFile, canada,            TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json");
BENCHMARK_CAPTURE(ParseFile, citm_catalog,      TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json");
BENCHMARK_CAPTURE(ParseFile, twitter,           TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json");
BENCHMARK_CAPTURE(ParseFile, floats,            TEST_DATA_DIRECTORY "/regression/floats.json");
BENCHMARK_CAPTURE(ParseFile, signed_ints,       TEST_DATA_DIRECTORY "/regression/signed_ints.json");
BENCHMARK_CAPTURE(ParseFile, unsigned_ints,     TEST_DATA_DIRECTORY "/regression/unsigned_ints.json");
BENCHMARK_CAPTURE(ParseFile, small_signed_ints, TEST_DATA_DIRECTORY "/regression/small_signed_ints.json");

//////////////////////////////////////////////////////////////////////////////
// parse JSON from string
//////////////////////////////////////////////////////////////////////////////

static void ParseString(benchmark::State& state, const char* filename)
{
    std::ifstream f(filename);
    std::string str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

    while (state.KeepRunning())
    {
        state.PauseTiming();
        auto* j = new json();
        state.ResumeTiming();

        *j = json::parse(str);

        state.PauseTiming();
        delete j;
        state.ResumeTiming();
    }

    state.SetBytesProcessed(state.iterations() * str.size());
}
BENCHMARK_CAPTURE(ParseString, jeopardy,          TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json");
BENCHMARK_CAPTURE(ParseString, canada,            TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json");
BENCHMARK_CAPTURE(ParseString, citm_catalog,      TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json");
BENCHMARK_CAPTURE(ParseString, twitter,           TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json");
BENCHMARK_CAPTURE(ParseString, floats,            TEST_DATA_DIRECTORY "/regression/floats.json");
BENCHMARK_CAPTURE(ParseString, signed_ints,       TEST_DATA_DIRECTORY "/regression/signed_ints.json");
BENCHMARK_CAPTURE(ParseString, unsigned_ints,     TEST_DATA_DIRECTORY "/regression/unsigned_ints.json");
BENCHMARK_CAPTURE(ParseString, small_signed_ints, TEST_DATA_DIRECTORY "/regression/small_signed_ints.json");

//////////////////////////////////////////////////////////////////////////////
// serialize JSON
//////////////////////////////////////////////////////////////////////////////

static void Dump(benchmark::State& state, const char* filename, int indent)
{
    std::ifstream f(filename);
    std::string str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    json j = json::parse(str);

    while (state.KeepRunning())
    {
        j.dump(indent);
    }

    state.SetBytesProcessed(state.iterations() * j.dump(indent).size());
}
BENCHMARK_CAPTURE(Dump, jeopardy / -,          TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json",                 -1);
BENCHMARK_CAPTURE(Dump, jeopardy / 4,          TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json",                 4);
BENCHMARK_CAPTURE(Dump, canada / -,            TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json",       -1);
BENCHMARK_CAPTURE(Dump, canada / 4,            TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json",       4);
BENCHMARK_CAPTURE(Dump, citm_catalog / -,      TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json", -1);
BENCHMARK_CAPTURE(Dump, citm_catalog / 4,      TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json", 4);
BENCHMARK_CAPTURE(Dump, twitter / -,           TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json",      -1);
BENCHMARK_CAPTURE(Dump, twitter / 4,           TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json",      4);
BENCHMARK_CAPTURE(Dump, floats / -,            TEST_DATA_DIRECTORY "/regression/floats.json",                 -1);
BENCHMARK_CAPTURE(Dump, floats / 4,            TEST_DATA_DIRECTORY "/regression/floats.json",                 4);
BENCHMARK_CAPTURE(Dump, signed_ints / -,       TEST_DATA_DIRECTORY "/regression/signed_ints.json",            -1);
BENCHMARK_CAPTURE(Dump, signed_ints / 4,       TEST_DATA_DIRECTORY "/regression/signed_ints.json",            4);
BENCHMARK_CAPTURE(Dump, unsigned_ints / -,     TEST_DATA_DIRECTORY "/regression/unsigned_ints.json",          -1);
BENCHMARK_CAPTURE(Dump, unsigned_ints / 4,     TEST_DATA_DIRECTORY "/regression/unsigned_ints.json",          4);
BENCHMARK_CAPTURE(Dump, small_signed_ints / -, TEST_DATA_DIRECTORY "/regression/small_signed_ints.json",      -1);
BENCHMARK_CAPTURE(Dump, small_signed_ints / 4, TEST_DATA_DIRECTORY "/regression/small_signed_ints.json",      4);

//////////////////////////////////////////////////////////////////////////////
// serialize CBOR
//////////////////////////////////////////////////////////////////////////////
static void ToCbor(benchmark::State& state, const char* filename)
{
    std::ifstream f(filename);
    std::string str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    json j = json::parse(str);

    while (state.KeepRunning())
    {
        json::to_cbor(j);
    }

    state.SetBytesProcessed(state.iterations() * json::to_cbor(j).size());
}
BENCHMARK_CAPTURE(ToCbor, jeopardy,          TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json");
BENCHMARK_CAPTURE(ToCbor, canada,            TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json");
BENCHMARK_CAPTURE(ToCbor, citm_catalog,      TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json");
BENCHMARK_CAPTURE(ToCbor, twitter,           TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json");
BENCHMARK_CAPTURE(ToCbor, floats,            TEST_DATA_DIRECTORY "/regression/floats.json");
BENCHMARK_CAPTURE(ToCbor, signed_ints,       TEST_DATA_DIRECTORY "/regression/signed_ints.json");
BENCHMARK_CAPTURE(ToCbor, unsigned_ints,     TEST_DATA_DIRECTORY "/regression/unsigned_ints.json");
BENCHMARK_CAPTURE(ToCbor, small_signed_ints, TEST_DATA_DIRECTORY "/regression/small_signed_ints.json");

//////////////////////////////////////////////////////////////////////////////
// Parse Msgpack
//////////////////////////////////////////////////////////////////////////////

static void FromMsgpack(benchmark::State& state, const char* filename)
{
    std::ifstream f(filename);
    std::string str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    auto bytes = json::to_msgpack(json::parse(str));
    std::ofstream o("test.msgpack");
    o.write((char*)bytes.data(), bytes.size());
    o.flush();
    o.close();
    for (auto _ : state)
    {
        state.PauseTiming();
        auto* j = new json();
        auto file = fopen("test.msgpack", "rb");
        state.ResumeTiming();

        *j = json::from_msgpack(file);

        state.PauseTiming();
        fclose(file);
        delete j;
        state.ResumeTiming();
    }

    state.SetBytesProcessed(state.iterations() * bytes.size());
}

BENCHMARK_CAPTURE(FromMsgpack, jeopardy, TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json");
BENCHMARK_CAPTURE(FromMsgpack, canada, TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json");
BENCHMARK_CAPTURE(FromMsgpack, citm_catalog, TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json");
BENCHMARK_CAPTURE(FromMsgpack, twitter, TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json");
BENCHMARK_CAPTURE(FromMsgpack, floats, TEST_DATA_DIRECTORY "/regression/floats.json");
BENCHMARK_CAPTURE(FromMsgpack, signed_ints, TEST_DATA_DIRECTORY "/regression/signed_ints.json");
BENCHMARK_CAPTURE(FromMsgpack, unsigned_ints, TEST_DATA_DIRECTORY "/regression/unsigned_ints.json");
BENCHMARK_CAPTURE(FromMsgpack, small_signed_ints, TEST_DATA_DIRECTORY "/regression/small_signed_ints.json");

//////////////////////////////////////////////////////////////////////////////
// serialize binary CBOR
//////////////////////////////////////////////////////////////////////////////
static void BinaryToCbor(benchmark::State& state)
{
    std::vector<uint8_t> data(256);
    std::iota(data.begin(), data.end(), 0);

    auto it = data.begin();
    std::vector<uint8_t> in;
    in.reserve(state.range(0));
    for (int i = 0; i < state.range(0); ++i)
    {
        if (it == data.end())
        {
            it = data.begin();
        }

        in.push_back(*it);
        ++it;
    }

    json::binary_t bin{in};
    json j{{"type", "binary"}, {"data", bin}};

    while (state.KeepRunning())
    {
        json::to_cbor(j);
    }

    state.SetBytesProcessed(state.iterations() * json::to_cbor(j).size());
}
BENCHMARK(BinaryToCbor)->RangeMultiplier(2)->Range(8, 8 << 12);

BENCHMARK_MAIN();
