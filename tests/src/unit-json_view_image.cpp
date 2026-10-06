//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json_view.hpp>
using nlohmann::json;
using nlohmann::ordered_json;
using nlohmann::json_document;
using nlohmann::json_editable_document;
using nlohmann::ordered_json_document;
using nlohmann::ordered_json_editable_document;
using image_check = json_document::image_check;
using nlohmann::detail::view::node;

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <limits>
#include <random>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <test_data.hpp>

#if !(defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

namespace
{
#if !defined(JSON_NOEXCEPTION)
std::string exception_of(const std::function<void()>& f)
{
    try
    {
        f();
    }
    catch (const json::exception& e)
    {
        return e.what();
    }
    return "";
}

const char* const check_failed = "[json.exception.parse_error.116] parse error: invalid json_document image: the check failed";
#endif

std::string read_file(const std::string& name)
{
    std::ifstream f(std::string(TEST_DATA_DIRECTORY) + name, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// the offsets of the parts of an image
constexpr std::size_t header_size = 64;

std::uint64_t header_field(const std::vector<std::uint8_t>& image, std::size_t offset)
{
    std::uint64_t v = 0;
    std::memcpy(&v, image.data() + offset, sizeof(v));
    return v;
}

void set_header_field(std::vector<std::uint8_t>& image, std::size_t offset, std::uint64_t v)
{
    std::memcpy(image.data() + offset, &v, sizeof(v));
}

std::size_t node_count(const std::vector<std::uint8_t>& image)
{
    const std::uint64_t count = header_field(image, 8);
    return static_cast<std::size_t>(count);
}

std::size_t text_at(const std::vector<std::uint8_t>& image)
{
    return header_size + (node_count(image) * sizeof(node));
}

node node_at(const std::vector<std::uint8_t>& image, std::size_t i)
{
    node n{};
    std::memcpy(&n, image.data() + header_size + (i * sizeof(node)), sizeof(node));
    return n;
}

void set_node(std::vector<std::uint8_t>& image, std::size_t i, const node& n)
{
    std::memcpy(image.data() + header_size + (i * sizeof(node)), &n, sizeof(node));
}

#if !defined(JSON_NOEXCEPTION)
/// the result of loading an image with a check: "" or the exception message
std::string load_result(const std::vector<std::uint8_t>& image, image_check check)
{
    return exception_of([&]
    {
        const json_document d = json_document::load(image, check);
        static_cast<void>(d);
    });
}

/// a copy of the image with node i changed by f
template<typename F>
std::vector<std::uint8_t> corrupted(const std::vector<std::uint8_t>& image, std::size_t i, F f)
{
    std::vector<std::uint8_t> b = image;
    node n = node_at(b, i);
    f(n);
    set_node(b, i, n);
    return b;
}
#endif

/// a document and the documents loaded from its image must be equal
template<typename Document>
void check_round_trip(const Document& d)
{
    const std::vector<std::uint8_t> image = d.save();
    for (const image_check check :
            {
                image_check::full, image_check::bounds, image_check::none
            })
    {
        const json_document l = json_document::load(image, check);
        CHECK(l.root().dump() == d.root().dump());
        CHECK(l.root().dump(2) == d.root().dump(2));
        CHECK(l.root().materialize() == json(d.root().materialize()));
        // an image of a loaded document is the same image
        CHECK(l.save() == image);
    }
    // an editable document can be loaded, too
    const ordered_json_editable_document e = ordered_json_editable_document::load(image);
    CHECK(e.root().dump() == d.root().dump());
}

std::uint32_t rng()
{
    static std::mt19937 generator(5295); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed): reproducible
    // result_type is std::uint_fast32_t, which may be wider than 32 bits
    const std::mt19937::result_type value = generator();
    return static_cast<std::uint32_t>(value);
}
} // namespace

TEST_CASE("json_view images: round trips")
{
    SECTION("small documents")
    {
        for (const char* text :
                {
                    "null", "true", "false", "0", "-0", "42", "-42", "18446744073709551615", "-9223372036854775808",
                    "123456789012345678901234567890", "1.5", "-1.25e-300", "1E308", "0.1000000000000000000000000001",
                    "\"\"", "\"text\"", R"("esc\"aped\n\u00e9\ud83d\ude00")", "\"\xc3\xa9\xe3\x81\x82\"",
                    "[]", "{}", "[[]]", "[{}]", "{\"\":{}}",
                    R"({"a": [1, 2.5, "x\ty", true, null, {"b": []}], "c": {"d": -3, "eA": "f"}})",
                    R"({"k": 1, "k": 2, "l": [], "k": 3})",
                    "  [1 ,  2 ]  "
                })
        {
            CAPTURE(text)
            // false positive: parse() returns a document with a root
            // @infer-ignore NULLPTR_DEREFERENCE
            check_round_trip(json_document::parse(text));
            // false positive: parse() returns a document with a root
            // @infer-ignore NULLPTR_DEREFERENCE
            check_round_trip(ordered_json_document::parse(text));
        }
    }

    SECTION("files")
    {
        for (const char* name :
                {
                    "/json_testsuite/sample.json", "/nativejson-benchmark/canada.json", "/nativejson-benchmark/citm_catalog.json",
                    "/nativejson-benchmark/twitter.json", "/json_tests/pass1.json", "/json_tests/pass2.json", "/json_tests/pass3.json"
                })
        {
            CAPTURE(name)
            const std::string text = read_file(name);
            const json_document d = json_document::parse(text);
            check_round_trip(d);
            // what a loaded document reads is what parse() produces
            CHECK(json_document::load(d.save()).root().materialize() == json::parse(text));
        }
    }

    SECTION("images are deterministic")
    {
        const std::string text = R"({"b": [1, 2, {"c": "\u00e9"}], "a": 1.5})";
        const json_document d = json_document::parse(text);
        CHECK(d.save() == json_document::parse(text).save());
        CHECK(d.save() == json_editable_document::parse(text).save());
        CHECK(d.save() == ordered_json_document::parse(text).save());
        const json_document copy = json_document::parse_copy(text);
        CHECK(copy.save() == d.save());
    }

    SECTION("large objects get their hash index again")
    {
        std::string text = "{";
        for (int i = 0; i < 1000; ++i)
        {
            text += (i != 0 ? ",\"k" : "\"k") + std::to_string(i) + "\":" + std::to_string(i);
        }
        text += R"(,"k7":"a duplicate","inner":{)";
        for (int i = 0; i < 200; ++i)
        {
            text += (i != 0 ? ",\"m" : "\"m") + std::to_string(i) + "\":" + std::to_string(-i);
        }
        text += "}}";
        const json_document d = json_document::parse(text);
        const std::vector<std::uint8_t> image = d.save();
        for (const image_check check :
                {
                    image_check::full, image_check::none
                })
        {
            const json_document l = json_document::load(image, check);
            for (int i = 0; i < 1000; ++i)
            {
                CHECK(l.root()["k" + std::to_string(i)] == d.root()["k" + std::to_string(i)]);
            }
            CHECK(l.root()["k7"].get<int>() == 7); // the first of duplicate keys
            CHECK(l.root()["inner"]["m199"].get<int>() == -199);
            CHECK(!l.root().contains("k1000"));
            // the index is not part of the image
            CHECK(l.save() == image);
        }
        // the nodes of objects in the image do not carry the number of an index
        CHECK(node_at(image, 0).extra == 0);
    }
}

TEST_CASE("json_view images: edited documents")
{
    const std::string text = R"({"name": "x", "n": 1, "f": 2.5, "list": [1, 2, 3], "obj": {"a": "\u00e9", "b": [true]}, "s": "a\"b"})";

    SECTION("every kind of edit")
    {
        ordered_json_editable_document d = ordered_json_editable_document::parse(text);
        d.set(d.root()["name"], "a new \"name\"");      // string in the edit arena
        d.set(d.root()["n"], -17);                     // negative integer
        d.set(d.root(), "p", 5);                       // non-negative number_integer
        d.set(d.root(), "u", 18446744073709551615u);   // unsigned
        d.set(d.root()["f"], 0.1);                     // float token
        d.set(d.root(), "nan", std::numeric_limits<double>::quiet_NaN());
        d.set(d.root(), "inf", -std::numeric_limits<double>::infinity());
        d.push_back(d.root()["list"], "pushed");       // moved array
        d.insert(d.root()["list"], 0, ordered_json::object({{"new", {1, 2}}}));
        d.erase(d.root()["list"], 2);
        d.erase(d.root(), "s");
        d.set(d.root()["obj"], "c", ordered_json::array({1, "two", 3.5, nullptr, false})); // new object member with a new array
        d.set(d.root(), "copy", d.root()["obj"]);     // a copy of a subtree
        d.set(d.root(), "key \xc3\xa9", true);        // a key in the edit arena

        const std::vector<std::uint8_t> image = d.save();
        const ordered_json expected = ordered_json::parse(d.root().dump());
        for (const image_check check :
                {
                    image_check::full, image_check::bounds, image_check::none
                })
        {
            const ordered_json_document l = ordered_json_document::load(image, check);
            CHECK(l.root().dump() == d.root().dump());
            CHECK(l.root().materialize() == expected);
            CHECK(l.root()["nan"].is_null());
            CHECK(l.root()["inf"].is_null());
            CHECK(l.root()["p"].is_number_integer());
            CHECK(l.root()["p"].get<int>() == 5);
            CHECK(l.root()["f"].get<double>() == 0.1);
            CHECK(l.root()["u"].get<std::uint64_t>() == 18446744073709551615u);
        }
        // the node index is in document order again: an image of the loaded
        // document is the same image
        CHECK(ordered_json_document::load(image).save() == image);
        // number tokens of edits follow the source; the text is the source's
        // prefix
        const ordered_json_document l = ordered_json_document::load(image);
        REQUIRE(l.source().size() > text.size());
        CHECK(std::string(l.source().data(), text.size()) == text);
    }

    SECTION("a loaded document can be edited and saved again")
    {
        const std::vector<std::uint8_t> first = json_editable_document::parse(text).save();
        json_editable_document d = json_editable_document::load(first);
        d.set(d.root()["obj"]["a"], "changed");
        d.push_back(d.root()["list"], 4);
        d.set(d.root(), "z", json::array({json::object()}));
        const std::vector<std::uint8_t> second = d.save();
        const json_document l = json_document::load(second);
        CHECK(l.root().dump() == d.root().dump());
        CHECK(l.root()["obj"]["a"] == "changed");
        CHECK(l.root()["list"].size() == 4);
    }

    SECTION("the root replaced")
    {
        json_editable_document d = json_editable_document::parse(text);
        d.set(d.root(), json::array({1, "x"}));
        check_round_trip(d);
        d.set(d.root(), 3.5);
        check_round_trip(d);
        d.set(d.root(), "text");
        check_round_trip(d);
    }
}

TEST_CASE("json_view images: ownership")
{
    const std::string text = R"({"a": "esc\u00e9aped", "b": [1, 2]})";
    const std::vector<std::uint8_t> image = json_document::parse(text).save();

    SECTION("borrowed")
    {
        const json_document d = json_document::load(image);
        CHECK(!d.owns_source());
        CHECK(d.root()["a"] == "esc\xc3\xa9" "aped");
        const json_document p = json_document::load(image.data(), image.size());
        CHECK(!p.owns_source());
        CHECK(p.root() == d.root());
        // the text is the image's
        CHECK(d.source().data() == reinterpret_cast<const char*>(image.data() + text_at(image)));
    }

    SECTION("owned")
    {
        std::vector<std::uint8_t> copy = image;
        const std::uint8_t* const data = copy.data();
        json_document d = json_document::load(std::move(copy));
        CHECK(d.owns_source());
        CHECK(d.source().data() == reinterpret_cast<const char*>(data + text_at(image)));
        CHECK(d.memory_usage() >= image.size());
        CHECK(d.root()["b"][1] == 2);
        // read() replaces the image
        d.read(std::string("[1]"));
        CHECK(d.owns_source());
        CHECK(d.root().dump() == "[1]");
        const std::string borrowed = "[2]";
        d.read(borrowed);
        CHECK(!d.owns_source());
    }

    SECTION("shrink_to_fit keeps the decoded strings of the image")
    {
        json_document d = json_document::parse(R"(["\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9"])");
        d.shrink_to_fit();
        const std::vector<std::uint8_t> img = d.save();
        json_document l = json_document::load(img);
        l.shrink_to_fit();
        CHECK(l.root().dump() == d.root().dump());
        CHECK(l.save() == img);
    }
}

// the remaining tests are about the exceptions of load() and save()
#if !defined(JSON_NOEXCEPTION)
TEST_CASE("json_view images: errors")
{
    SECTION("a literal as the root: dump() after loading")
    {
        for (const char* text :
                {
                    "null", "true", "false"
                })
        {
            std::vector<std::uint8_t> image = json_document::parse(text).save();
            node n = node_at(image, 0);
            n.off = static_cast<std::uint32_t>(image.size());
            set_node(image, 0, n);
            CHECK(load_result(image, image_check::full) == check_failed);
            CHECK(load_result(image, image_check::bounds) == check_failed);
        }
    }

    SECTION("saving a discarded document")
    {
        const json_document empty{};
        CHECK(exception_of([&] { static_cast<void>(empty.save()); }) == "[json.exception.type_error.320] cannot save a discarded json_document");
        const json_document failed = json_document::parse("[1,", false);
        CHECK(exception_of([&] { static_cast<void>(failed.save()); }) == "[json.exception.type_error.320] cannot save a discarded json_document");
    }

    const std::vector<std::uint8_t> image = json_document::parse(R"({"a": [1, "\u00e9"]})").save();
    const std::string prefix = "[json.exception.parse_error.116] parse error: invalid json_document image: ";

    SECTION("header and sizes")
    {
        CHECK(exception_of([]
        {
            const json_document d = json_document::load(nullptr, 0);
            static_cast<void>(d);
        }) == prefix + "too short");
        CHECK(exception_of([&]
        {
            const json_document d = json_document::load(image.data(), 63);
            static_cast<void>(d);
        }) == prefix + "too short");

        std::vector<std::uint8_t> bad = image;
        bad[0] = 'X';
        CHECK(load_result(bad, image_check::full) == prefix + "unknown format");
        bad = image;
        bad[4] = 2; // version
        CHECK(load_result(bad, image_check::full) == prefix + "unknown format");
        for (std::size_t reserved = 32; reserved < 64; reserved += 8)
        {
            bad = image;
            bad[reserved + 3] = 1;
            CHECK(load_result(bad, image_check::none) == prefix + "unknown format");
        }

        const auto sizes = [&](std::size_t offset, std::uint64_t v)
        {
            std::vector<std::uint8_t> b = image;
            set_header_field(b, offset, v);
            return load_result(b, image_check::none);
        };
        CHECK(sizes(8, 0) == prefix + "sizes out of range");                 // no nodes
        CHECK(sizes(8, 1000) == prefix + "sizes out of range");              // more nodes than bytes
        CHECK(sizes(8, 0xFFFFFFF0u) == prefix + "sizes out of range");
        CHECK(sizes(16, 0xFFFFFFF0u) == prefix + "sizes out of range");      // text size
        CHECK(sizes(16, header_field(image, 16) + 1) == prefix + "sizes out of range");
        CHECK(sizes(16, image.size()) == prefix + "sizes out of range");
        CHECK(sizes(24, 0xFFFFFFF0u) == prefix + "sizes out of range");      // decoded string size
        CHECK(sizes(24, header_field(image, 24) - 1) == prefix + "sizes out of range");

        // the NULs after the text and the decoded strings
        bad = image;
        bad[text_at(image) + header_field(image, 16)] = 'x';
        CHECK(load_result(bad, image_check::none) == prefix + "sizes out of range");
        bad = image;
        bad.back() = 'x';
        CHECK(load_result(bad, image_check::none) == prefix + "sizes out of range");
        // nothing after the image
        bad = image;
        bad.push_back(0);
        CHECK(load_result(bad, image_check::none) == prefix + "sizes out of range");
        // nodes, but not even room for the NULs
        bad.assign(image.begin(), image.begin() + static_cast<std::ptrdiff_t>(text_at(image)));
        CHECK(load_result(bad, image_check::none) == prefix + "sizes out of range");
    }
}

TEST_CASE("json_view images: check")
{
    // nodes: 0 {  1 "s" 2 "x\"y" (escaped)  3 "i" 4 -12  5 "u" 6 7  7 "f" 8 1.5e300  9 "b" 10 true  11 "n" 12 null
    //        13 "a" 14 [  15 "t"  16 {}  ]
    const std::string text = R"({"s":"x\"y","i":-12,"u":7,"f":1.5e300,"b":true,"n":null,"a":["t",{}]})";
    const std::vector<std::uint8_t> image = json_document::parse(text).save();
    REQUIRE(load_result(image, image_check::full).empty());
    REQUIRE(node_count(image) == 17);

    // bounds: rejected by both checks; content: only by the full one
    const auto rejected = [&](const std::vector<std::uint8_t>& b, bool bounds)
    {
        CHECK(load_result(b, image_check::full) == check_failed);
        CHECK(load_result(b, image_check::bounds) == (bounds ? check_failed : ""));
    };

    SECTION("kinds")
    {
        const std::array<std::uint8_t, 4> kinds = {{8, 9, 10, 200}}; // binary, discarded, link, unknown
        for (const std::uint8_t kind : kinds)
        {
            rejected(corrupted(image, 12, [&](node & n)
            {
                n.kind = kind;
            }), true);
        }
        // a key that is not a string
        rejected(corrupted(image, 1, [](node & n)
        {
            n.kind = 0;
            n.len = 0;
            n.off = 0;
        }), true);
    }

    SECTION("flags and extra")
    {
        rejected(corrupted(image, 12, [](node & n)
        {
            n.flags = 4;
        }), true);
        rejected(corrupted(image, 12, [](node & n)
        {
            n.extra = 1;
        }), true);
        rejected(corrupted(image, 10, [](node & n)
        {
            n.flags = 5;
        }), true);
        rejected(corrupted(image, 10, [](node & n)
        {
            n.extra = 1;
        }), true);
        rejected(corrupted(image, 1, [](node & n)
        {
            n.flags = 2; // a string in the edit arena
        }), true);
        rejected(corrupted(image, 1, [](node & n)
        {
            n.extra = 3;
        }), true);
        rejected(corrupted(image, 4, [](node & n)
        {
            n.flags = 2;
        }), true);
        rejected(corrupted(image, 4, [](node & n)
        {
            n.extra = static_cast<std::uint16_t>(n.extra | 0x100u); // an integer with fraction digits
        }), true);
        rejected(corrupted(image, 0, [](node & n)
        {
            n.flags = 8; // moved
        }), true);
        rejected(corrupted(image, 0, [](node & n)
        {
            n.extra = 1; // a hash index
        }), true);
    }

    SECTION("bounds")
    {
        const std::size_t text_size = header_field(image, 16);
        const std::size_t arena_size = header_field(image, 24);
        rejected(corrupted(image, 1, [&](node & n)
        {
            n.off = static_cast<std::uint32_t>(text_size + 1);
        }), true);
        rejected(corrupted(image, 1, [&](node & n)
        {
            n.len = static_cast<std::uint32_t>(text_size);
        }), true);
        rejected(corrupted(image, 2, [&](node & n)
        {
            n.len = static_cast<std::uint32_t>(arena_size + 1);
        }), true);
        rejected(corrupted(image, 6, [&](node & n)
        {
            n.off = static_cast<std::uint32_t>(text_size);
        }), true);
        rejected(corrupted(image, 6, [&](node & n)
        {
            n.off = static_cast<std::uint32_t>(text_size + 5);
        }), true);
        rejected(corrupted(image, 6, [](node & n)
        {
            n.extra = 0; // no digits
        }), true);
        rejected(corrupted(image, 8, [&](node & n)
        {
            n.len = static_cast<std::uint32_t>(text_size);
        }), true);
        rejected(corrupted(image, 8, [](node & n)
        {
            n.len = 2; // shorter than the recorded digits
        }), true);
        rejected(corrupted(image, 14, [&](node & n)
        {
            n.off = static_cast<std::uint32_t>(text_size + 1);
        }), true);
        // literals: their offset sizes the output of dump()
        rejected(corrupted(image, 10, [&](node & n)
        {
            n.off = static_cast<std::uint32_t>(text_size + 1);
        }), true);
        rejected(corrupted(image, 12, [&](node & n)
        {
            n.off = 0xFFFFFFFFu;
        }), true);
    }

    SECTION("structure")
    {
        rejected(corrupted(image, 0, [](node & n)
        {
            n.next = 0;
        }), true);
        rejected(corrupted(image, 0, [](node & n)
        {
            n.next = 18; // beyond the image
        }), true);
        rejected(corrupted(image, 14, [](node & n)
        {
            n.next = 4; // beyond the enclosing object
        }), true);
        rejected(corrupted(image, 0, [](node & n)
        {
            n.len = 6; // member count
        }), true);
        rejected(corrupted(image, 14, [](node & n)
        {
            n.len = 3; // element count
        }), true);
        rejected(corrupted(image, 0, [](node & n)
        {
            n.next = 14; // the object ends after the key "a"
            n.len = 7;
        }), true);
        rejected(corrupted(image, 0, [](node & n)
        {
            n.next = 13; // nodes after the root
            n.len = 6;
        }), true);
        rejected(corrupted(image, 0, [](node & n)
        {
            n.kind = 2; // an array: the "keys" are values, and the counts do not match
        }), true);
        const std::vector<std::uint8_t> as_array = corrupted(image, 16, [](node & n)
        {
            n.kind = 2; // {} as []: fine
        });
        CHECK(load_result(as_array, image_check::full).empty());
        CHECK(json_document::load(as_array).root().dump() == R"({"s":"x\"y","i":-12,"u":7,"f":1.5e+300,"b":true,"n":null,"a":["t",[]]})");
    }

    SECTION("strings")
    {
        // a quote in a source string (the full check only)
        std::vector<std::uint8_t> b = image;
        const std::size_t t = text_at(image);
        const node t15 = node_at(image, 15);
        b[t + t15.off] = '"';
        rejected(b, false);
        // a control character
        b[t + t15.off] = '\n';
        rejected(b, false);
        // invalid UTF-8 in a decoded string
        b = image;
        const node s2 = node_at(image, 2);
        b[t + header_field(image, 16) + 1 + s2.off] = 0xFF;
        rejected(b, false);
    }

    SECTION("numbers")
    {
        const std::size_t t = text_at(image);
        const node i4 = node_at(image, 4);
        const node u6 = node_at(image, 6);
        const node f8 = node_at(image, 8);
        const auto at_token = [&](const node & n, std::size_t k, std::uint8_t c)
        {
            std::vector<std::uint8_t> b = image;
            b[t + n.off + k] = c;
            return b;
        };
        rejected(at_token(i4, 1, 'x'), false);      // -x2
        rejected(at_token(i4, 1, '0'), false);      // -02
        rejected(at_token(i4, 0, '1'), false);      // 112 != -12
        rejected(at_token(f8, 1, 'x'), false);      // 1x5e300
        rejected(at_token(f8, 2, 'e'), false);      // 1.ee300
        rejected(at_token(f8, 4, 'x'), false);      // 1.5ex00
        rejected(at_token(f8, 3, '0'), false);      // 1.50300: another layout
        rejected(at_token(f8, 4, '9'), false);      // 1.5e900: overflow
        rejected(at_token(f8, 0, 'x'), false);
        rejected(at_token(u6, 0, '8'), false);      // 8 != 7
        rejected(corrupted(image, 4, [](node & n)
        {
            n.kind = 6; // "-12" as unsigned: a sign
            n.extra = 3;
        }), false);
        // a non-negative number_integer (as edits write it): fine
        const std::vector<std::uint8_t> positive = corrupted(image, 6, [](node & n)
        {
            n.kind = 5;
            n.extra = 0;
        });
        CHECK(load_result(positive, image_check::full).empty());
        CHECK(json_document::load(positive).root()["u"].is_number_integer());
        rejected(corrupted(image, 8, [](node & n)
        {
            n.kind = 6; // a float token as integer
            n.extra = 7;
        }), false);
    }

    SECTION("float tokens of an image checked for bounds only")
    {
        // A float node whose layout records "many" digits is converted from
        // its token alone; a token that is not a JSON number reads as 0.
        const std::vector<std::uint8_t> img = json_document::parse("[1.5e300,2]").save();
        const std::size_t t = text_at(img);
        for (const char* token :
                {
                    "x.5e300", "01.5e30", "1.xe300", "1.5ex00", "1.5e+x0", "1.5e30x", "-.5e300", "1.5E300"
                })
        {
            CAPTURE(token)
            std::vector<std::uint8_t> b = img;
            node n = node_at(b, 1);
            n.extra = 0xFFFFu;
            set_node(b, 1, n);
            std::memcpy(b.data() + t + n.off, token, n.len);
            const json_document d = json_document::load(b, image_check::bounds);
            const auto v = d.root()[0].get<double>();
            CHECK(v == (std::string(token) == "1.5E300" ? 1.5e300 : 0.0));
            CHECK(load_result(b, image_check::full) == (std::string(token) == "1.5E300" ? "" : check_failed));
        }
    }

    SECTION("integer ranges")
    {
        // tokens of many digits, which the parser stores as floats
        const std::string big = R"([123456789012345678901234, 99999999999999999999, 9223372036854775808])";
        const std::vector<std::uint8_t> img = json_document::parse(big).save();
        const auto as_integer = [&](std::size_t i, std::uint8_t kind, std::uint16_t extra)
        {
            std::vector<std::uint8_t> b = img;
            node n = node_at(b, i);
            n.kind = kind;
            n.extra = extra;
            set_node(b, i, n);
            return load_result(b, image_check::full);
        };
        CHECK(as_integer(1, 6, 24) == check_failed); // more than 20 digits
        CHECK(as_integer(2, 6, 20) == check_failed); // more than 2^64 - 1
        CHECK(as_integer(3, 5, 18) == check_failed); // more than 2^63 - 1 as number_integer
    }
}

TEST_CASE("json_view images: damaged images")
{
    // A damaged image must be rejected, or read safely; with the full check,
    // it also serializes to the JSON it reads as.
    const std::vector<std::string> texts =
    {
        R"({"a": [1, -2, 3.25, "x\u00e9y", true, null], "b": {"c": "\"q\"", "d": 1e10}, "e": ""})",
        R"([[[[]]], {"k": {"k": {"k": 12345678901234567890}}}, "\ud83d\ude00", -0.0, 0])",
    };
    for (const std::string& text : texts)
    {
        const std::vector<std::uint8_t> image = json_document::parse(text).save();
        for (int round = 0; round < 3000; ++round)
        {
            std::vector<std::uint8_t> b = image;
            const std::uint32_t flips = 1 + (rng() % 3);
            for (std::uint32_t k = 0; k < flips; ++k)
            {
                // mostly the nodes, where the damage matters most
                const std::size_t at = rng() % 4 != 0 ? header_size + (rng() % (b.size() - header_size)) : rng() % b.size();
                b[at] = static_cast<std::uint8_t>(rng() % 3 == 0 ? rng() : b[at] ^ (1u << (rng() % 8)));
            }
            for (const image_check check :
                    {
                        image_check::full, image_check::bounds
                    })
            {
                json_document d;
                try
                {
                    d = json_document::load(b, check);
                }
                catch (const json::parse_error& e)
                {
                    CHECK(e.id == 116);
                    continue;
                }
                std::string dumped;
                std::string dumped_ascii;
                try
                {
                    dumped = d.root().dump();
                    dumped_ascii = d.root().dump(-1, ' ', true);
                }
                catch (const json::type_error& e)
                {
                    // invalid UTF-8 (the bounds check only)
                    CHECK(check == image_check::bounds);
                    CHECK(e.id == 316);
                    continue;
                }
                const json j = d.root().materialize();
                if (check == image_check::full)
                {
                    CHECK(json::parse(dumped) == j);
                    CHECK(json::parse(dumped_ascii) == j);
                }
            }
        }
    }
}
#endif

#else

TEST_CASE("json_view images: big-endian targets")
{
    const json_document d = json_document::parse("[1]");
    CHECK_THROWS_WITH_AS(d.save(), "[json.exception.type_error.320] json_document images need a little-endian target", json::type_error&);
}

#endif
