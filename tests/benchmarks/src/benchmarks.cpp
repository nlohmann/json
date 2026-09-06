//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
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

//////////////////////////////////////////////////////////////////////////////
// parse binary formats
//////////////////////////////////////////////////////////////////////////////

// Only MessagePack had a read benchmark (FromMsgpack above, left untouched so
// its numbers stay comparable across releases). The benchmarks below cover the
// other formats, and read from a contiguous buffer as well as from a FILE*:
// most callers pass a container, and the two adapters compile to different
// code. The test data repository ships JSON only, so the input for each is
// derived at setup time by serializing a parsed test file.

/// binary format to benchmark; the _optimized variants add UBJSON/BJData size
/// and type annotations, which the readers handle in a separate code path
enum class binary_format
{
    cbor,
    msgpack,
    ubjson,
    ubjson_optimized,
    bjdata,
    bjdata_optimized,
    bson
};

static std::vector<std::uint8_t> to_binary(const json& j, const binary_format format)
{
    switch (format)
    {
        case binary_format::cbor:
            return json::to_cbor(j);
        case binary_format::msgpack:
            return json::to_msgpack(j);
        case binary_format::ubjson:
            return json::to_ubjson(j);
        case binary_format::ubjson_optimized:
            return json::to_ubjson(j, true, true);
        case binary_format::bjdata:
            return json::to_bjdata(j);
        case binary_format::bjdata_optimized:
            return json::to_bjdata(j, true, true);
        case binary_format::bson:
        default:
            return json::to_bson(j);
    }
}

static json from_binary(const std::vector<std::uint8_t>& bytes, const binary_format format)
{
    switch (format)
    {
        case binary_format::cbor:
            return json::from_cbor(bytes);
        case binary_format::msgpack:
            return json::from_msgpack(bytes);
        case binary_format::ubjson:
        case binary_format::ubjson_optimized:
            return json::from_ubjson(bytes);
        case binary_format::bjdata:
        case binary_format::bjdata_optimized:
            return json::from_bjdata(bytes);
        case binary_format::bson:
        default:
            return json::from_bson(bytes);
    }
}

static json from_binary(std::FILE* file, const binary_format format)
{
    switch (format)
    {
        case binary_format::cbor:
            return json::from_cbor(file);
        case binary_format::msgpack:
            return json::from_msgpack(file);
        case binary_format::ubjson:
        case binary_format::ubjson_optimized:
            return json::from_ubjson(file);
        case binary_format::bjdata:
        case binary_format::bjdata_optimized:
            return json::from_bjdata(file);
        case binary_format::bson:
        default:
            return json::from_bson(file);
    }
}

/*!
@brief serialize a parsed test file to @a format

Returns an empty vector and marks the benchmark as skipped if the file cannot
be represented in the format, rather than letting the exception escape: BSON
requires an object at the top level, and several test files are arrays.
*/
static std::vector<std::uint8_t> binary_input(benchmark::State& state, const char* filename, const binary_format format)
{
    std::ifstream f(filename);
    std::string const str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    const json j = json::parse(str);

    if (format == binary_format::bson && !j.is_object())
    {
        state.SkipWithError("BSON requires an object at the top level");
        return {};
    }

    return to_binary(j, format);
}

static void FromBinaryBuffer(benchmark::State& state, const char* filename, const binary_format format)
{
    const std::vector<std::uint8_t> bytes = binary_input(state, filename, format);
    if (bytes.empty())
    {
        return;
    }

    for (auto _ : state)
    {
        // the value is destroyed outside the timed section, because destroying
        // a large DOM is not what this benchmark measures
        state.PauseTiming();
        auto* j = new json();
        state.ResumeTiming();

        *j = from_binary(bytes, format);

        state.PauseTiming();
        delete j;
        state.ResumeTiming();
    }

    state.SetBytesProcessed(state.iterations() * bytes.size());
}

BENCHMARK_CAPTURE(FromBinaryBuffer, cbor / jeopardy, TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json", binary_format::cbor);
BENCHMARK_CAPTURE(FromBinaryBuffer, cbor / canada, TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json", binary_format::cbor);
BENCHMARK_CAPTURE(FromBinaryBuffer, cbor / citm_catalog, TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json", binary_format::cbor);
BENCHMARK_CAPTURE(FromBinaryBuffer, cbor / twitter, TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json", binary_format::cbor);
BENCHMARK_CAPTURE(FromBinaryBuffer, cbor / floats, TEST_DATA_DIRECTORY "/regression/floats.json", binary_format::cbor);
BENCHMARK_CAPTURE(FromBinaryBuffer, cbor / signed_ints, TEST_DATA_DIRECTORY "/regression/signed_ints.json", binary_format::cbor);
BENCHMARK_CAPTURE(FromBinaryBuffer, msgpack / jeopardy, TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json", binary_format::msgpack);
BENCHMARK_CAPTURE(FromBinaryBuffer, msgpack / canada, TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json", binary_format::msgpack);
BENCHMARK_CAPTURE(FromBinaryBuffer, msgpack / citm_catalog, TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json", binary_format::msgpack);
BENCHMARK_CAPTURE(FromBinaryBuffer, msgpack / twitter, TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json", binary_format::msgpack);
BENCHMARK_CAPTURE(FromBinaryBuffer, ubjson / jeopardy, TEST_DATA_DIRECTORY "/jeopardy/jeopardy.json", binary_format::ubjson);
BENCHMARK_CAPTURE(FromBinaryBuffer, ubjson / canada, TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json", binary_format::ubjson);
BENCHMARK_CAPTURE(FromBinaryBuffer, ubjson / citm_catalog, TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json", binary_format::ubjson);
BENCHMARK_CAPTURE(FromBinaryBuffer, ubjson / twitter, TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json", binary_format::ubjson);
BENCHMARK_CAPTURE(FromBinaryBuffer, ubjson_optimized / canada, TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json", binary_format::ubjson_optimized);
BENCHMARK_CAPTURE(FromBinaryBuffer, ubjson_optimized / twitter, TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json", binary_format::ubjson_optimized);
BENCHMARK_CAPTURE(FromBinaryBuffer, bjdata / canada, TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json", binary_format::bjdata);
BENCHMARK_CAPTURE(FromBinaryBuffer, bjdata / twitter, TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json", binary_format::bjdata);
BENCHMARK_CAPTURE(FromBinaryBuffer, bjdata_optimized / canada, TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json", binary_format::bjdata_optimized);
BENCHMARK_CAPTURE(FromBinaryBuffer, bjdata_optimized / twitter, TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json", binary_format::bjdata_optimized);
// BSON requires an object at the top level, so the array-rooted test files
// (jeopardy and the regression files) cannot be captured here
BENCHMARK_CAPTURE(FromBinaryBuffer, bson / canada, TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json", binary_format::bson);
BENCHMARK_CAPTURE(FromBinaryBuffer, bson / citm_catalog, TEST_DATA_DIRECTORY "/nativejson-benchmark/citm_catalog.json", binary_format::bson);
BENCHMARK_CAPTURE(FromBinaryBuffer, bson / twitter, TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json", binary_format::bson);

static void FromBinaryFile(benchmark::State& state, const char* filename, const binary_format format)
{
    const std::vector<std::uint8_t> bytes = binary_input(state, filename, format);
    if (bytes.empty())
    {
        return;
    }

    const char* tmp = "benchmark_input.bin";
    std::ofstream o(tmp, std::ios::binary);
    o.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    o.flush();
    o.close();

    for (auto _ : state)
    {
        state.PauseTiming();
        auto* j = new json();
        auto* file = std::fopen(tmp, "rb");
        state.ResumeTiming();

        *j = from_binary(file, format);

        state.PauseTiming();
        std::fclose(file);
        delete j;
        state.ResumeTiming();
    }

    state.SetBytesProcessed(state.iterations() * bytes.size());
}

BENCHMARK_CAPTURE(FromBinaryFile, cbor / canada, TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json", binary_format::cbor);
BENCHMARK_CAPTURE(FromBinaryFile, cbor / twitter, TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json", binary_format::cbor);
BENCHMARK_CAPTURE(FromBinaryFile, ubjson / canada, TEST_DATA_DIRECTORY "/nativejson-benchmark/canada.json", binary_format::ubjson);
BENCHMARK_CAPTURE(FromBinaryFile, ubjson / twitter, TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json", binary_format::ubjson);
BENCHMARK_CAPTURE(FromBinaryFile, bjdata / twitter, TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json", binary_format::bjdata);
BENCHMARK_CAPTURE(FromBinaryFile, bson / twitter, TEST_DATA_DIRECTORY "/nativejson-benchmark/twitter.json", binary_format::bson);

//////////////////////////////////////////////////////////////////////////////
// parse binary formats: value shapes
//////////////////////////////////////////////////////////////////////////////

// The test files above are wide and shallow, but the readers' cost is per
// container, so these cover the shapes that stress the container handling
// itself. Every shape is wrapped in an object so that BSON, which requires an
// object at the top level, measures the same value as the other formats.

/// deeply nested arrays: one container per level, no other work
static json make_nested()
{
    json nested = json::array();
    json* p = &nested;
    for (std::size_t i = 1; i < 1000; ++i)
    {
        p->push_back(json::array());
        p = &p->operator[](0);
    }

    json j = json::object();
    j["data"] = std::move(nested);
    return j;
}

/// many sibling containers: maximum container churn, minimum nesting
static json make_containers()
{
    json data = json::array();
    for (std::size_t i = 0; i < 100000; ++i)
    {
        data.push_back(json::array({1, 2}));
    }

    json j = json::object();
    j["data"] = std::move(data);
    return j;
}

/// one flat array of numbers: the scalar decoding path, which must not move
static json make_scalars()
{
    json data = json::array();
    for (std::size_t i = 0; i < 1000000; ++i)
    {
        data.push_back(i);
    }

    json j = json::object();
    j["data"] = std::move(data);
    return j;
}

static void FromBinaryShape(benchmark::State& state, json (*build)(), const binary_format format)
{
    const std::vector<std::uint8_t> bytes = to_binary(build(), format);

    for (auto _ : state)
    {
        state.PauseTiming();
        auto* j = new json();
        state.ResumeTiming();

        *j = from_binary(bytes, format);

        state.PauseTiming();
        delete j;
        state.ResumeTiming();
    }

    state.SetBytesProcessed(state.iterations() * bytes.size());
}

BENCHMARK_CAPTURE(FromBinaryShape, nested / cbor, make_nested, binary_format::cbor);
BENCHMARK_CAPTURE(FromBinaryShape, nested / msgpack, make_nested, binary_format::msgpack);
BENCHMARK_CAPTURE(FromBinaryShape, nested / ubjson, make_nested, binary_format::ubjson);
BENCHMARK_CAPTURE(FromBinaryShape, nested / bjdata, make_nested, binary_format::bjdata);
BENCHMARK_CAPTURE(FromBinaryShape, nested / bson, make_nested, binary_format::bson);
BENCHMARK_CAPTURE(FromBinaryShape, containers / cbor, make_containers, binary_format::cbor);
BENCHMARK_CAPTURE(FromBinaryShape, containers / msgpack, make_containers, binary_format::msgpack);
BENCHMARK_CAPTURE(FromBinaryShape, containers / ubjson, make_containers, binary_format::ubjson);
BENCHMARK_CAPTURE(FromBinaryShape, containers / ubjson_optimized, make_containers, binary_format::ubjson_optimized);
BENCHMARK_CAPTURE(FromBinaryShape, containers / bjdata, make_containers, binary_format::bjdata);
BENCHMARK_CAPTURE(FromBinaryShape, containers / bson, make_containers, binary_format::bson);
// BSON names every array element, so a large array measures key generation
// rather than scalar decoding and is left out here
BENCHMARK_CAPTURE(FromBinaryShape, scalars / cbor, make_scalars, binary_format::cbor);
BENCHMARK_CAPTURE(FromBinaryShape, scalars / msgpack, make_scalars, binary_format::msgpack);
BENCHMARK_CAPTURE(FromBinaryShape, scalars / ubjson, make_scalars, binary_format::ubjson);
BENCHMARK_CAPTURE(FromBinaryShape, scalars / bjdata, make_scalars, binary_format::bjdata);

/*!
@brief parse an indefinite-length CBOR string

The writer never emits this form, so the input is assembled by hand: 0x7F
opens the string, each chunk is a one-character string, and 0xFF closes it.
*/
static void FromCborChunkedString(benchmark::State& state, const std::size_t chunks)
{
    std::vector<std::uint8_t> bytes;
    bytes.reserve(2 * chunks + 2);
    bytes.push_back(0x7F);
    for (std::size_t i = 0; i < chunks; ++i)
    {
        bytes.push_back(0x61); // string of length 1
        bytes.push_back(0x61); // 'a'
    }
    bytes.push_back(0xFF);

    for (auto _ : state)
    {
        json j = json::from_cbor(bytes);
        benchmark::DoNotOptimize(j);
    }

    state.SetBytesProcessed(state.iterations() * bytes.size());
}

BENCHMARK_CAPTURE(FromCborChunkedString, 10000 chunks, 10000);

BENCHMARK_MAIN();
