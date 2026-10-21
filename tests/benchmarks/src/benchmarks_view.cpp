//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// Benchmarks of json_document (nlohmann/json_view.hpp). They use the inputs of
// ParseString and ParseIndented in benchmarks.cpp, so that each ViewParse row
// can be read against the json::parse row of the same file.

#include <benchmark/benchmark.h>
#include <nlohmann/json_view.hpp>
#include <fstream>
#include <iterator>
#include <string>
#include <test_data.hpp>

using json = nlohmann::json;
using json_document = nlohmann::json_document;

static std::string read_file(const char* filename)
{
    std::ifstream f(filename, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

#define JSON_VIEW_BENCHMARK_FILES(fn) \
    BENCHMARK_CAPTURE(fn, jeopardy,          TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json"); \
    BENCHMARK_CAPTURE(fn, canada,            TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json"); \
    BENCHMARK_CAPTURE(fn, citm_catalog,      TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json"); \
    BENCHMARK_CAPTURE(fn, twitter,           TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json"); \
    BENCHMARK_CAPTURE(fn, floats,            TEST_DATA_DIRECTORY "/regression/floats.json"); \
    BENCHMARK_CAPTURE(fn, signed_ints,       TEST_DATA_DIRECTORY "/regression/signed_ints.json"); \
    BENCHMARK_CAPTURE(fn, unsigned_ints,     TEST_DATA_DIRECTORY "/regression/unsigned_ints.json"); \
    BENCHMARK_CAPTURE(fn, small_signed_ints, TEST_DATA_DIRECTORY "/regression/small_signed_ints.json")

//////////////////////////////////////////////////////////////////////////////
// parse into a new document (compare with ParseString)
//////////////////////////////////////////////////////////////////////////////

static void ViewParse(benchmark::State& state, const char* filename)
{
    const std::string str = read_file(filename);

    while (state.KeepRunning())
    {
        state.PauseTiming();
        auto* d = new json_document();
        state.ResumeTiming();

        *d = json_document::parse(str);

        state.PauseTiming();
        delete d;
        state.ResumeTiming();
    }

    state.SetBytesProcessed(state.iterations() * str.size());
}
JSON_VIEW_BENCHMARK_FILES(ViewParse);

//////////////////////////////////////////////////////////////////////////////
// parse into a document that is reused (its memory stays allocated)
//////////////////////////////////////////////////////////////////////////////

static void ViewRead(benchmark::State& state, const char* filename)
{
    const std::string str = read_file(filename);
    json_document d;

    while (state.KeepRunning())
    {
        d.read(str);
        benchmark::DoNotOptimize(d);
    }

    state.SetBytesProcessed(state.iterations() * str.size());
}
JSON_VIEW_BENCHMARK_FILES(ViewRead);

//////////////////////////////////////////////////////////////////////////////
// parse pretty-printed JSON (compare with ParseIndented)
//////////////////////////////////////////////////////////////////////////////

static void ViewParseIndented(benchmark::State& state, const char* filename, int indent)
{
    const std::string indented = json::parse(read_file(filename)).dump(indent);
    json_document d;

    while (state.KeepRunning())
    {
        d.read(indented);
        benchmark::DoNotOptimize(d);
    }

    state.SetBytesProcessed(state.iterations() * indented.size());
}
BENCHMARK_CAPTURE(ViewParseIndented, jeopardy / 4,     TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json",                 4);
BENCHMARK_CAPTURE(ViewParseIndented, canada / 4,       TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json",       4);
BENCHMARK_CAPTURE(ViewParseIndented, citm_catalog / 4, TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json", 4);
BENCHMARK_CAPTURE(ViewParseIndented, twitter / 4,      TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json",      4);

//////////////////////////////////////////////////////////////////////////////
// validate only (compare with Accept)
//////////////////////////////////////////////////////////////////////////////

static void ViewAccept(benchmark::State& state, const char* filename)
{
    const std::string str = read_file(filename);

    while (state.KeepRunning())
    {
        benchmark::DoNotOptimize(json_document::accept(str));
    }

    state.SetBytesProcessed(state.iterations() * str.size());
}
JSON_VIEW_BENCHMARK_FILES(ViewAccept);

//////////////////////////////////////////////////////////////////////////////
// convert a parsed document into a json value
//////////////////////////////////////////////////////////////////////////////

static void ViewMaterialize(benchmark::State& state, const char* filename)
{
    const std::string str = read_file(filename);
    const json_document d = json_document::parse(str);

    while (state.KeepRunning())
    {
        state.PauseTiming();
        auto* j = new json();
        state.ResumeTiming();

        *j = d.root().materialize();

        state.PauseTiming();
        delete j;
        state.ResumeTiming();
    }

    state.SetBytesProcessed(state.iterations() * str.size());
}
JSON_VIEW_BENCHMARK_FILES(ViewMaterialize);

//////////////////////////////////////////////////////////////////////////////
// serialize a parsed document (compare with Dump)
//////////////////////////////////////////////////////////////////////////////

static void ViewDump(benchmark::State& state, const char* filename, int indent)
{
    const std::string str = read_file(filename);
    const json_document d = json_document::parse(str);

    while (state.KeepRunning())
    {
        std::string output = d.root().dump(indent);
        benchmark::DoNotOptimize(output);
    }

    state.SetBytesProcessed(state.iterations() * d.root().dump(indent).size());
}
BENCHMARK_CAPTURE(ViewDump, jeopardy / -,          TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json",                 -1);
BENCHMARK_CAPTURE(ViewDump, jeopardy / 4,          TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json",                 4);
BENCHMARK_CAPTURE(ViewDump, canada / -,            TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json",       -1);
BENCHMARK_CAPTURE(ViewDump, canada / 4,            TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json",       4);
BENCHMARK_CAPTURE(ViewDump, citm_catalog / -,      TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json", -1);
BENCHMARK_CAPTURE(ViewDump, citm_catalog / 4,      TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json", 4);
BENCHMARK_CAPTURE(ViewDump, twitter / -,           TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json",      -1);
BENCHMARK_CAPTURE(ViewDump, twitter / 4,           TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json",      4);
BENCHMARK_CAPTURE(ViewDump, floats / -,            TEST_DATA_DIRECTORY "/regression/floats.json",                 -1);
BENCHMARK_CAPTURE(ViewDump, floats / 4,            TEST_DATA_DIRECTORY "/regression/floats.json",                 4);
BENCHMARK_CAPTURE(ViewDump, signed_ints / -,       TEST_DATA_DIRECTORY "/regression/signed_ints.json",            -1);
BENCHMARK_CAPTURE(ViewDump, signed_ints / 4,       TEST_DATA_DIRECTORY "/regression/signed_ints.json",            4);
BENCHMARK_CAPTURE(ViewDump, unsigned_ints / -,     TEST_DATA_DIRECTORY "/regression/unsigned_ints.json",          -1);
BENCHMARK_CAPTURE(ViewDump, unsigned_ints / 4,     TEST_DATA_DIRECTORY "/regression/unsigned_ints.json",          4);
BENCHMARK_CAPTURE(ViewDump, small_signed_ints / -, TEST_DATA_DIRECTORY "/regression/small_signed_ints.json",      -1);
BENCHMARK_CAPTURE(ViewDump, small_signed_ints / 4, TEST_DATA_DIRECTORY "/regression/small_signed_ints.json",      4);
