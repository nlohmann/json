//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// cmake/test.cmake selects the C++ standard versions with which to build a
// unit test based on the presence of JSON_HAS_CPP_<VERSION> macros.
// When using macros that are only defined for particular versions of the standard
// (e.g., JSON_HAS_FILESYSTEM for C++17 and up), please mention the corresponding
// version macro in a comment close by, like this:
// JSON_HAS_CPP_<VERSION> (do not remove; see note at top of file)

#include "doctest_compatibility.h"

// for some reason including this after the json header leads to linker errors with VS 2017...
#include <locale>

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#include <cstdio>
#include <list>
#include <type_traits>
#include <utility>

#include "test_utils.hpp"

#ifdef JSON_HAS_CPP_17
    #include <any>
    #include <variant>
#endif

#ifdef JSON_HAS_CPP_17
    #if __has_include(<optional>)
        #include <optional>
    #elif __has_include(<experimental/optional>)
        #include <experimental/optional>
    #endif

    /////////////////////////////////////////////////////////////////////
    // for #4804
    /////////////////////////////////////////////////////////////////////
    using json_4804 = nlohmann::basic_json<std::map,        // ObjectType
    std::vector,     // ArrayType
    std::string,     // StringType
    bool,            // BooleanType
    std::int64_t,    // NumberIntegerType
    std::uint64_t,   // NumberUnsignedType
    double,          // NumberFloatType
    std::allocator,  // AllocatorType
    nlohmann::adl_serializer,  // JSONSerializer
    std::vector<std::byte>,    // BinaryType
    void                       // CustomBaseClass
    >;
#endif

#ifdef JSON_HAS_CPP_20
    #if __has_include(<span>)
        #include <span>
    #endif
#endif

/////////////////////////////////////////////////////////////////////
// for #4825 - explicitly instantiating basic_json must compile; this
// forces instantiation of binary_writer::write_bjdata_ndarray, whose
// static_cast<string_t> was ambiguous under explicit instantiation on
// C++17. Merely compiling this translation unit is the regression test.
/////////////////////////////////////////////////////////////////////
template class nlohmann::basic_json<>;

/////////////////////////////////////////////////////////////////////
// for #4440
/////////////////////////////////////////////////////////////////////
#if JSON_HAS_RANGES == 1
    #include <ranges>
#endif

// NLOHMANN_JSON_SERIALIZE_ENUM uses a static std::pair
DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wexit-time-destructors")

/////////////////////////////////////////////////////////////////////
// for #1021
/////////////////////////////////////////////////////////////////////

using float_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int64_t, std::uint64_t, float>;

/////////////////////////////////////////////////////////////////////
// for #1647
/////////////////////////////////////////////////////////////////////
namespace
{
struct NonDefaultFromJsonStruct
{};

inline bool operator==(NonDefaultFromJsonStruct const& /*unused*/, NonDefaultFromJsonStruct const& /*unused*/)
{
    return true;
}

enum class for_1647
{
    one,
    two
};

// NOLINTNEXTLINE(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays): this is a false positive
NLOHMANN_JSON_SERIALIZE_ENUM(for_1647,
{
    {for_1647::one, "one"},
    {for_1647::two, "two"},
})
}  // namespace

/////////////////////////////////////////////////////////////////////
// for #1299
/////////////////////////////////////////////////////////////////////

struct Data
{
    Data() = default;
    Data(std::string a_, std::string b_)
        : a(std::move(a_))
        , b(std::move(b_))
    {}
    std::string a{}; // NOLINT(readability-redundant-member-init)
    std::string b{}; // NOLINT(readability-redundant-member-init)
};

void from_json(const json& j, Data& data); // NOLINT(misc-use-internal-linkage)
void from_json(const json& j, Data& data)
{
    j["a"].get_to(data.a);
    j["b"].get_to(data.b);
}

bool operator==(Data const& lhs, Data const& rhs); // NOLINT(misc-use-internal-linkage)
bool operator==(Data const& lhs, Data const& rhs)
{
    return lhs.a == rhs.a && lhs.b == rhs.b;
}

//bool operator!=(Data const& lhs, Data const& rhs)
//{
//    return !(lhs == rhs);
//}

namespace nlohmann
{
template<>
struct adl_serializer<NonDefaultFromJsonStruct>
{
    static NonDefaultFromJsonStruct from_json(json const& /*unused*/) noexcept
    {
        return {};
    }
};
}  // namespace nlohmann

/////////////////////////////////////////////////////////////////////
// for #1805
/////////////////////////////////////////////////////////////////////

struct NotSerializableData
{
    int mydata;
    float myfloat;
};

/////////////////////////////////////////////////////////////////////
// for #2574
/////////////////////////////////////////////////////////////////////

struct NonDefaultConstructible
{
    explicit NonDefaultConstructible(int a)
        : x(a)
    {}
    int x;
};

namespace nlohmann
{
template<>
struct adl_serializer<NonDefaultConstructible>
{
    static NonDefaultConstructible from_json(json const& j)
    {
        return NonDefaultConstructible(j.get<int>());
    }
};
}  // namespace nlohmann

/////////////////////////////////////////////////////////////////////
// for #2824
/////////////////////////////////////////////////////////////////////

class sax_no_exception : public nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type>
{
  public:
    explicit sax_no_exception(json& j)
        : nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type>(j, false)
    {}

    static bool parse_error(std::size_t /*position*/, const std::string& /*last_token*/, const json::exception& ex)
    {
        error_string = new std::string(ex.what());  // NOLINT(cppcoreguidelines-owning-memory)
        return false;
    }

    static std::string* error_string;
};

std::string* sax_no_exception::error_string = nullptr;

/////////////////////////////////////////////////////////////////////
// for #2982
/////////////////////////////////////////////////////////////////////

template<class T>
class my_allocator : public std::allocator<T>
{
  public:
    using std::allocator<T>::allocator;

    my_allocator() = default;
    template<class U> my_allocator(const my_allocator<U>& /*unused*/) { }

    template <class U>
    struct rebind
    {
        using other = my_allocator<U>;
    };
};

TEST_CASE("regression tests 2")
{
    SECTION("issue #1001 - Fix memory leak during parser callback")
    {
        const auto* geojsonExample = R"(
          { "type": "FeatureCollection",
            "features": [
              { "type": "Feature",
                "geometry": {"type": "Point", "coordinates": [102.0, 0.5]},
                "properties": {"prop0": "value0"}
                },
              { "type": "Feature",
                "geometry": {
                  "type": "LineString",
                  "coordinates": [
                    [102.0, 0.0], [103.0, 1.0], [104.0, 0.0], [105.0, 1.0]
                    ]
                  },
                "properties": {
                  "prop0": "value0",
                  "prop1": 0.0
                  }
                },
              { "type": "Feature",
                 "geometry": {
                   "type": "Polygon",
                   "coordinates": [
                     [ [100.0, 0.0], [101.0, 0.0], [101.0, 1.0],
                       [100.0, 1.0], [100.0, 0.0] ]
                     ]
                 },
                 "properties": {
                   "prop0": "value0",
                   "prop1": {"this": "that"}
                   }
                 }
               ]
             })";

        const json::parser_callback_t cb = [&](int /*level*/, json::parse_event_t event, json & parsed) noexcept
        {
            // skip uninteresting events
            if (event == json::parse_event_t::value && !parsed.is_primitive())
            {
                return false;
            }

            switch (event)
            {
                case json::parse_event_t::key:
                {
                    return true;
                }
                case json::parse_event_t::value:
                {
                    return false;
                }
                case json::parse_event_t::object_start:
                {
                    return true;
                }
                case json::parse_event_t::object_end:
                {
                    return false;
                }
                case json::parse_event_t::array_start:
                {
                    return true;
                }
                case json::parse_event_t::array_end:
                {
                    return false;
                }

                default:
                {
                    return true;
                }
            }
        };

        auto j = json::parse(geojsonExample, cb, true);
        CHECK(j == json());
    }

    SECTION("issue #1021 - to/from_msgpack only works with standard typization")
    {
        float_json j = 1000.0;
        CHECK(float_json::from_cbor(float_json::to_cbor(j)) == j);
        CHECK(float_json::from_msgpack(float_json::to_msgpack(j)) == j);
        CHECK(float_json::from_ubjson(float_json::to_ubjson(j)) == j);
        CHECK(float_json::from_bon8(float_json::to_bon8(j)) == j);

        float_json j2 = {1000.0, 2000.0, 3000.0};
        CHECK(float_json::from_ubjson(float_json::to_ubjson(j2, true, true)) == j2);
    }

    SECTION("issue #1045 - Using STL algorithms with JSON containers with expected results?")
    {
        json diffs = nlohmann::json::array();
        json m1{{"key1", 42}};
        json m2{{"key2", 42}};
        auto p1 = m1.items();
        auto p2 = m2.items();

        using it_type = decltype(p1.begin());

        std::set_difference(
            p1.begin(),
            p1.end(),
            p2.begin(),
            p2.end(),
            std::inserter(diffs, diffs.end()),
            [&](const it_type & e1, const it_type & e2) -> bool
        {
            using comper_pair = std::pair<std::string, decltype(e1.value())>;              // Trying to avoid unneeded copy
            return comper_pair(e1.key(), e1.value()) < comper_pair(e2.key(), e2.value());  // Using pair comper
        });

        CHECK(diffs.size() == 1);  // Note the change here, was 2
    }

#ifdef JSON_HAS_CPP_17
    SECTION("issue #1292 - Serializing std::variant causes stack overflow")
    {
        static_assert(!std::is_constructible<json, std::variant<int, float>>::value, "unexpected value");
    }
#endif

    SECTION("issue #1299 - compile error in from_json converting to container "
            "with std::pair")
    {
        const json j =
        {
            {"1", {{"a", "testa_1"}, {"b", "testb_1"}}},
            {"2", {{"a", "testa_2"}, {"b", "testb_2"}}},
            {"3", {{"a", "testa_3"}, {"b", "testb_3"}}},
        };

        const std::map<std::string, Data> expected
        {
            {"1", {"testa_1", "testb_1"}},
            {"2", {"testa_2", "testb_2"}},
            {"3", {"testa_3", "testb_3"}},
        };
        const auto data = j.get<decltype(expected)>();
        CHECK(expected == data);
    }

    SECTION("issue #1445 - buffer overflow in dumping invalid utf-8 strings")
    {
        SECTION("a bunch of -1, ensure_ascii=true")
        {
            const auto length = 300;

            json dump_test;
            dump_test["1"] = std::string(length, static_cast<std::string::value_type>(-1));

            std::string expected = R"({"1":")";
            for (int i = 0; i < length; ++i)
            {
                expected += "\\ufffd";
            }
            expected += "\"}";

            auto s = dump_test.dump(-1, ' ', true, nlohmann::json::error_handler_t::replace);
            CHECK(s == expected);
        }
        SECTION("a bunch of -2, ensure_ascii=false")
        {
            const auto length = 500;

            json dump_test;
            dump_test["1"] = std::string(length, static_cast<std::string::value_type>(-2));

            std::string expected = R"({"1":")";
            for (int i = 0; i < length; ++i)
            {
                expected += "\xEF\xBF\xBD";
            }
            expected += "\"}";

            auto s = dump_test.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
            CHECK(s == expected);
        }
        SECTION("test case in issue #1445")
        {
            nlohmann::json dump_test;
            const std::array<int, 108> data =
            {
                {109, 108, 103, 125, -122, -53, 115, 18, 3, 0, 102, 19, 1, 15, -110, 13, -3, -1, -81, 32, 2, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -80, 2, 0, 0, 96, -118, 46, -116, 46, 109, -84, -87, 108, 14, 109, -24, -83, 13, -18, -51, -83, -52, -115, 14, 6, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 3, 0, 0, 0, 35, -74, -73, 55, 57, -128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 33, 0, 0, 0, -96, -54, -28, -26}
            };
            std::string s;
            for (const int i : data)
            {
                s += static_cast<char>(i);
            }
            dump_test["1"] = s;
            // dump() is nodiscard; this only checks that dumping does not throw/crash
            utils::ignore_return_value(dump_test.dump(-1, ' ', true, nlohmann::json::error_handler_t::replace));
        }
    }

    SECTION("issue #1447 - Integer Overflow (OSS-Fuzz 12506)")
    {
        const json j = json::parse("[-9223372036854775808]");
        CHECK(j.dump() == "[-9223372036854775808]");
    }

    SECTION("issue #1708 - minimum value of int64_t can be outputted")
    {
        constexpr auto smallest = (std::numeric_limits<int64_t>::min)();
        const json j = smallest;
        CHECK(j.dump() == std::to_string(smallest));
    }

    SECTION("issue #1727 - Contains with non-const lvalue json_pointer picks the wrong overload")
    {
        const json j = {{"root", {{"settings", {{"logging", true}}}}}};

        auto jptr1 = "/root/settings/logging"_json_pointer;
        auto jptr2 = json::json_pointer{"/root/settings/logging"};

        CHECK(j.contains(jptr1));
        CHECK(j.contains(jptr2));
    }

    SECTION("issue #1647 - compile error when deserializing enum if both non-default from_json and non-member operator== exists for other type")
    {
        // does not compile on ICPC when targeting C++20
#if !(defined(__INTEL_COMPILER) && __cplusplus >= 202000)
        {
            const json j;
            const NonDefaultFromJsonStruct x(j);
            NonDefaultFromJsonStruct y;
            CHECK(x == y);
        }
#endif

        auto val = nlohmann::json("one").get<for_1647>();
        CHECK(val == for_1647::one);
        const json j = val;
    }

    SECTION("issue #1715 - json::from_cbor does not respect allow_exceptions = false when input is string literal")
    {
        SECTION("string literal")
        {
            const json cbor = json::from_cbor("B", true, false);
            CHECK(cbor.is_discarded());
        }

        SECTION("string array")
        {
            const std::array<char, 2> input = {{'B', 0x00}};
            const json cbor = json::from_cbor(input, true, false);
            CHECK(cbor.is_discarded());
        }

        SECTION("std::string")
        {
            const json cbor = json::from_cbor(std::string("B"), true, false);
            CHECK(cbor.is_discarded());
        }
    }

    SECTION("issue #1805 - A pair<T1, T2> is json constructible only if T1 and T2 are json constructible")
    {
        static_assert(!std::is_constructible<json, std::pair<std::string, NotSerializableData>>::value, "unexpected result");
        static_assert(!std::is_constructible<json, std::pair<NotSerializableData, std::string>>::value, "unexpected result");
        static_assert(std::is_constructible<json, std::pair<int, std::string>>::value, "unexpected result");
    }
    SECTION("issue #1825 - A tuple<Args..> is json constructible only if all T in Args are json constructible")
    {
        static_assert(!std::is_constructible<json, std::tuple<std::string, NotSerializableData>>::value, "unexpected result");
        static_assert(!std::is_constructible<json, std::tuple<NotSerializableData, std::string>>::value, "unexpected result");
        static_assert(std::is_constructible<json, std::tuple<int, std::string>>::value, "unexpected result");
    }

    SECTION("issue #1983 - JSON patch diff for op=add formation is not as per standard (RFC 6902)")
    {
        const auto source = R"({ "foo": [ "1", "2" ] })"_json;
        const auto target = R"({"foo": [ "1", "2", "3" ]})"_json;
        const auto result = json::diff(source, target);
        CHECK(result.dump() == R"([{"op":"add","path":"/foo/-","value":"3"}])");
    }

    SECTION("issue #2067 - cannot serialize binary data to text JSON")
    {
        const std::array<unsigned char, 23> data = {{0x81, 0xA4, 0x64, 0x61, 0x74, 0x61, 0xC4, 0x0F, 0x33, 0x30, 0x30, 0x32, 0x33, 0x34, 0x30, 0x31, 0x30, 0x37, 0x30, 0x35, 0x30, 0x31, 0x30}};
        const json j = json::from_msgpack(data.data(), data.size());
        // dump() is nodiscard; this only checks that dumping does not throw
        CHECK_NOTHROW(
            utils::ignore_return_value(
                j.dump(4,                             // Indent
                       ' ',                           // Indent char
                       false,                         // Ensure ascii
                       json::error_handler_t::strict  // Error
                      )));
    }

    SECTION("PR #2181 - regression bug with lvalue")
    {
        // see https://github.com/nlohmann/json/pull/2181#issuecomment-653326060
        const json j{{"x", "test"}};
        const std::string defval = "default value";
        auto val = j.value("x", defval); // NOLINT(bugprone-unused-local-non-trivial-variable)
        auto val2 = j.value("y", defval); // NOLINT(bugprone-unused-local-non-trivial-variable)
    }

    SECTION("issue #2293 - eof doesn't cause parsing to stop")
    {
        const std::vector<uint8_t> data =
        {
            0x7B,
            0x6F,
            0x62,
            0x6A,
            0x65,
            0x63,
            0x74,
            0x20,
            0x4F,
            0x42
        };
        const json result = json::from_cbor(data, true, false);
        CHECK(result.is_discarded());
    }

    SECTION("issue #2315 - json.update and vector<pair>does not work with ordered_json")
    {
        nlohmann::ordered_json jsonAnimals = {{"animal", "dog"}};
        const nlohmann::ordered_json jsonCat = {{"animal", "cat"}};
        jsonAnimals.update(jsonCat);
        CHECK(jsonAnimals["animal"] == "cat");

        auto jsonAnimals_parsed = nlohmann::ordered_json::parse(jsonAnimals.dump());
        CHECK(jsonAnimals == jsonAnimals_parsed);

        const std::vector<std::pair<std::string, int64_t>> intData = {std::make_pair("aaaa", 11),
                                                                      std::make_pair("bbb", 222)
                                                                     };
        nlohmann::ordered_json jsonObj;
        for (const auto& data : intData)
        {
            jsonObj[data.first] = data.second;
        }
        CHECK(jsonObj["aaaa"] == 11);
        CHECK(jsonObj["bbb"] == 222);
    }

    SECTION("issue #2330 - ignore_comment=true fails on multiple consecutive lines starting with comments")
    {
        const std::string ss = "//\n//\n{\n}\n";
        const json j = json::parse(ss, nullptr, true, true);
        CHECK(j.dump() == "{}");
    }

#ifdef JSON_HAS_CPP_20
#ifndef _LIBCPP_VERSION // see https://github.com/nlohmann/json/issues/4490
    // classic Intel ICC reports <span> as includable but cannot actually compile
    // std::span/std::as_bytes usage below
#if __has_include(<span>) && !defined(__ICC) && !defined(__INTEL_COMPILER)
    SECTION("issue #2546 - parsing containers of std::byte")
    {
        const char DATA[] = R"("Hello, world!")"; // NOLINT(misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        // exclude the trailing '\0' that string-literal initialization adds to
        // DATA: std::span(DATA) would span the full array extent (including
        // that NUL), which is only silently accepted as end-of-input by default
        // and would fail under JSON_STRICT_NUL_HANDLING
        const auto s = std::as_bytes(std::span(DATA, sizeof(DATA) - 1));
        const json j = json::parse(s);
        CHECK(j.dump() == "\"Hello, world!\"");
    }
#endif
#endif
#endif

    SECTION("issue #2574 - Deserialization to std::array, std::pair, and std::tuple with non-default constructable types fails")
    {
        SECTION("std::array")
        {
            {
                const json j = {7, 4};
                auto arr = j.get<std::array<NonDefaultConstructible, 2>>();
                CHECK(arr[0].x == 7);
                CHECK(arr[1].x == 4);
            }

            {
                const json j = 7;
                CHECK_THROWS_AS((j.get<std::array<NonDefaultConstructible, 1>>()), json::type_error);
            }
        }

        SECTION("std::pair")
        {
            {
                const json j = {3, 8};
                auto p = j.get<std::pair<NonDefaultConstructible, NonDefaultConstructible>>();
                CHECK(p.first.x == 3);
                CHECK(p.second.x == 8);
            }

            {
                const json j = {4, 1};
                auto p = j.get<std::pair<int, NonDefaultConstructible>>();
                CHECK(p.first == 4);
                CHECK(p.second.x == 1);
            }

            {
                const json j = {6, 7};
                auto p = j.get<std::pair<NonDefaultConstructible, int>>();
                CHECK(p.first.x == 6);
                CHECK(p.second == 7);
            }

            {
                const json j = 7;
                CHECK_THROWS_AS((j.get<std::pair<NonDefaultConstructible, int>>()), json::type_error);
            }
        }

        SECTION("std::tuple")
        {
            {
                const json j = {9};
                auto t = j.get<std::tuple<NonDefaultConstructible>>();
                CHECK(std::get<0>(t).x == 9);
            }

            {
                const json j = {9, 8, 7};
                auto t = j.get<std::tuple<NonDefaultConstructible, int, NonDefaultConstructible>>();
                CHECK(std::get<0>(t).x == 9);
                CHECK(std::get<1>(t) == 8);
                CHECK(std::get<2>(t).x == 7);
            }

            {
                const json j = 7;
                CHECK_THROWS_AS((j.get<std::tuple<NonDefaultConstructible>>()), json::type_error);
            }
        }
    }

    SECTION("issue #4530 - Serialization of empty tuple")
    {
        const auto source_tuple = std::tuple<>();
        const nlohmann::json j = source_tuple;

        CHECK(j.get<decltype(source_tuple)>() == source_tuple);
        CHECK("[]" == j.dump());
    }

    SECTION("issue #2865 - ASAN detects memory leaks")
    {
        // the code below is expected to not leak memory
        {
            nlohmann::json o;
            const std::string s = "bar";

            nlohmann::to_json(o["foo"], s);

            nlohmann::json p = o;

            // call to_json with a non-null JSON value
            nlohmann::to_json(p["foo"], s);
        }

        {
            nlohmann::json o;
            const std::string s = "bar";

            nlohmann::to_json(o["foo"], s);

            // call to_json with a non-null JSON value
            nlohmann::to_json(o["foo"], s);
        }
    }

    SECTION("issue #2824 - encoding of json::exception::what()")
    {
        json j;
        sax_no_exception sax(j);

        CHECK(!json::sax_parse("xyz", &sax));
        CHECK(*sax_no_exception::error_string == "[json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - invalid literal; last read: 'x'");
        delete sax_no_exception::error_string;  // NOLINT(cppcoreguidelines-owning-memory)
    }

    SECTION("issue #2825 - Properly constrain the basic_json conversion operator")
    {
        static_assert(std::is_copy_assignable<nlohmann::ordered_json>::value, "ordered_json must be copy assignable");
    }

    SECTION("issue #2958 - Inserting in unordered json using a pointer retains the leading slash")
    {
        const std::string p = "/root";

        json test1;
        test1[json::json_pointer(p)] = json::object();
        CHECK(test1.dump() == "{\"root\":{}}");

        ordered_json test2;
        test2[ordered_json::json_pointer(p)] = json::object();
        CHECK(test2.dump() == "{\"root\":{}}");

        // json::json_pointer and ordered_json::json_pointer are the same type; behave as above
        ordered_json test3;
        test3[json::json_pointer(p)] = json::object();
        CHECK(std::is_same<json::json_pointer::string_t, ordered_json::json_pointer::string_t>::value);
        CHECK(test3.dump() == "{\"root\":{}}");
    }

    SECTION("issue #2982 - to_{binary format} does not provide a mechanism for specifying a custom allocator for the returned type")
    {
        std::vector<std::uint8_t, my_allocator<std::uint8_t>> my_vector;
        const json j = {1, 2, 3, 4};
        json::to_cbor(j, my_vector);
        json k = json::from_cbor(my_vector);
        CHECK(j == k);
    }

}

TEST_CASE("regression test - parser callback must not lose a duplicate key's prior value")
{
    // a callback that rejects only the scalar value 2
    const json::parser_callback_t drop_value_2 = [](int /*depth*/, json::parse_event_t ev, json & v) noexcept
    {
        return !(ev == json::parse_event_t::value && v == 2);
    };

    SECTION("duplicate key, second (scalar) value rejected - prior value is restored")
    {
        const json j = json::parse(R"({"a":1,"a":2})", drop_value_2);
        CHECK(j.dump() == "{\"a\":1}");
    }

    SECTION("duplicate key, second value is an object rejected at object_end - prior value is restored")
    {
        const json j = json::parse(R"({"a":1,"a":{"x":2}})",
                                   [](int depth, json::parse_event_t ev, json& /*parsed*/) noexcept
        {
            return !(ev == json::parse_event_t::object_end && depth == 1);
        });
        CHECK(j.dump() == "{\"a\":1}");
    }

    SECTION("duplicate key, second value is an array rejected at array_end - prior value is restored")
    {
        const json j = json::parse(R"({"a":1,"a":[9,9]})",
                                   [](int depth, json::parse_event_t ev, json& /*parsed*/) noexcept
        {
            return !(ev == json::parse_event_t::array_end && depth == 1);
        });
        CHECK(j.dump() == "{\"a\":1}");
    }

    SECTION("duplicate key, second value accepted (scalar) - last value wins")
    {
        const json j = json::parse(R"({"a":1,"a":2})", [](int, json::parse_event_t, json&) noexcept
        {
            return true;
        });
        CHECK(j.dump() == "{\"a\":2}");
    }

    SECTION("duplicate key, second value accepted (object) - last value wins")
    {
        const json j = json::parse(R"({"a":1,"a":{"x":2}})", [](int, json::parse_event_t, json&) noexcept
        {
            return true;
        });
        CHECK(j.dump() == "{\"a\":{\"x\":2}}");
    }

    SECTION("brand new (non-duplicate) key, value rejected - member is fully absent")
    {
        const json j = json::parse(R"({"a":1,"b":2})", drop_value_2);
        CHECK(j.dump() == "{\"a\":1}");
    }

    SECTION("duplicate key nested two levels deep")
    {
        const json j = json::parse(R"({"outer":{"a":1,"a":2}})", drop_value_2);
        CHECK(j.dump() == "{\"outer\":{\"a\":1}}");
    }

    SECTION("three occurrences of the same key - middle rejected, last accepted")
    {
        const json j = json::parse(R"({"k":1,"k":2,"k":3})", drop_value_2);
        CHECK(j.dump() == "{\"k\":3}");
    }
}

TEST_CASE("regression test - excessive binary container size honors allow_exceptions=false")
{
    // CBOR array with declared length 2^63
    const std::vector<std::uint8_t> cbor = {0x9b, 0x80, 0, 0, 0, 0, 0, 0, 0};
    // CBOR map with declared length 2^63
    const std::vector<std::uint8_t> cbor_m = {0xbb, 0x80, 0, 0, 0, 0, 0, 0, 0};
    // UBJSON array with declared length 2^63-1
    const std::vector<std::uint8_t> ubj = {'[', '#', 'L', 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    // BJData array with declared length 2^63-1 (little endian)
    const std::vector<std::uint8_t> bjd = {'[', '#', 'L', 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f};

    // allow_exceptions=false must report failure instead of throwing/aborting
    CHECK(json::from_cbor(cbor, true, false).is_discarded());
    CHECK(json::from_cbor(cbor_m, true, false).is_discarded());
    CHECK(json::from_ubjson(ubj, true, false).is_discarded());
    CHECK(json::from_bjdata(bjd, true, false).is_discarded());

    // allow_exceptions=true (the default) must still throw exactly as before.
    // The exact message text is not checked here: on platforms where
    // std::size_t is 32-bit, the CBOR reader's own length-narrowing check
    // (get_cbor_container_size(), unrelated to this fix) intercepts a
    // declared length of 2^63 before it ever reaches the check this test
    // targets, with different (but equally valid, and already correct)
    // wording -- see unit-cbor.cpp for coverage of that message.
    json _;
    CHECK_THROWS_AS(_ = json::from_cbor(cbor), json::out_of_range);

    // regression guard: a genuinely truncated CBOR input must remain discarded
    CHECK(json::from_cbor(std::vector<std::uint8_t> {0x9b, 0, 0, 0, 0, 0, 0, 0, 0x02}, true, false).is_discarded());
}

namespace
{
/// builds a value from SAX events, asks the parser to recover from its first
/// 100 errors, and checks that the events are balanced (see #3989)
class RecoveringParser : public nlohmann::detail::json_sax_dom_parser<json>
{
    using base = nlohmann::detail::json_sax_dom_parser<json>;

  public:
    explicit RecoveringParser(json& j)
        : base(j, false)
    {}

    bool null()
    {
        value();
        return base::null();
    }

    bool boolean(bool val)
    {
        value();
        return base::boolean(val);
    }

    bool number_integer(json::number_integer_t val)
    {
        value();
        return base::number_integer(val);
    }

    bool number_unsigned(json::number_unsigned_t val)
    {
        value();
        return base::number_unsigned(val);
    }

    bool number_float(json::number_float_t val, const std::string& s)
    {
        value();
        return base::number_float(val, s);
    }

    bool string(std::string& val)
    {
        value();
        return base::string(val);
    }

    bool binary(json::binary_t& val)
    {
        value();
        return base::binary(val);
    }

    bool start_object(std::size_t elements)
    {
        value();
        stack.push_back('o');
        return base::start_object(elements);
    }

    bool key(std::string& val)
    {
        if (stack.empty() || stack.back() != 'o')
        {
            well_formed = false;
            return false;
        }
        stack.back() = 'v';
        return base::key(val);
    }

    bool end_object()
    {
        if (stack.empty() || stack.back() != 'o')
        {
            well_formed = false;
            return false;
        }
        stack.pop_back();
        return base::end_object();
    }

    bool start_array(std::size_t elements)
    {
        value();
        stack.push_back('a');
        return base::start_array(elements);
    }

    bool end_array()
    {
        if (stack.empty() || stack.back() != 'a')
        {
            well_formed = false;
            return false;
        }
        stack.pop_back();
        return base::end_array();
    }

    bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/, const json::exception& ex)
    {
        messages.emplace_back(ex.what());
        // a limit, so that a reader that does not stop fails the test
        // instead of making it hang
        return ++errors < 100;
    }

    /// whether the events were balanced and every key was followed by a value
    bool balanced() const
    {
        return well_formed && stack.empty();
    }

    std::size_t errors = 0;
    std::vector<std::string> messages {}; // NOLINT(readability-redundant-member-init)
    std::vector<char> stack {}; // NOLINT(readability-redundant-member-init)
    bool well_formed = true;

  private:
    void value()
    {
        if (!stack.empty())
        {
            if (stack.back() == 'v')
            {
                stack.back() = 'o';
            }
            else if (stack.back() == 'o')
            {
                well_formed = false;
            }
        }
    }

};

struct BinaryParseResult
{
    json value;
    std::size_t errors;
    std::vector<std::string> messages;
    bool ok;
    bool balanced;
};

BinaryParseResult parse_binary_recovering(const std::vector<std::uint8_t>& input, const json::input_format_t format)
{
    json j;
    RecoveringParser sax(j);
    const bool ok = json::sax_parse(input, &sax, format);
    return {j, sax.errors, sax.messages, ok, sax.balanced()};
}

/// the message of the exception that reading @a input into a JSON value
/// throws, or an empty string if reading succeeds
std::string binary_error_message(const std::vector<std::uint8_t>& input, const json::input_format_t format)
{
    try
    {
        json _;
        switch (format)
        {
            case json::input_format_t::cbor:
                _ = json::from_cbor(input);
                break;
            case json::input_format_t::msgpack:
                _ = json::from_msgpack(input);
                break;
            case json::input_format_t::ubjson:
                _ = json::from_ubjson(input);
                break;
            case json::input_format_t::bjdata:
                _ = json::from_bjdata(input);
                break;
            case json::input_format_t::bson:
                _ = json::from_bson(input);
                break;
            case json::input_format_t::bon8:
                _ = json::from_bon8(input);
                break;
            case json::input_format_t::json:
            default:
                break;
        }
    }
    catch (const json::exception& e)
    {
        return e.what();
    }
    return "";
}

/// a BSON element: its type, its name, and its value
std::vector<std::uint8_t> bson_element(const std::uint8_t type, const std::string& name, const std::vector<std::uint8_t>& value)
{
    std::vector<std::uint8_t> result = {type};
    result.insert(result.end(), name.begin(), name.end());
    result.push_back(0x00);
    result.insert(result.end(), value.begin(), value.end());
    return result;
}

/// a BSON document of the given elements; @a size_offset is added to the
/// size it declares
std::vector<std::uint8_t> bson_document(const std::vector<std::vector<std::uint8_t>>& elements, const int size_offset = 0)
{
    std::vector<std::uint8_t> body;
    for (const auto& element : elements)
    {
        body.insert(body.end(), element.begin(), element.end());
    }
    const auto size = static_cast<std::uint32_t>(static_cast<int>(body.size()) + 5 + size_offset);
    std::vector<std::uint8_t> result = {static_cast<std::uint8_t>(size & 0xFFu), static_cast<std::uint8_t>((size >> 8u) & 0xFFu),
                                        static_cast<std::uint8_t>((size >> 16u) & 0xFFu), static_cast<std::uint8_t>((size >> 24u) & 0xFFu)
                                       };
    result.insert(result.end(), body.begin(), body.end());
    result.push_back(0x00);
    return result;
}

/// a BSON int32 value
std::vector<std::uint8_t> bson_int32(const std::int32_t value)
{
    const auto u = static_cast<std::uint32_t>(value);
    return {static_cast<std::uint8_t>(u & 0xFFu), static_cast<std::uint8_t>((u >> 8u) & 0xFFu),
            static_cast<std::uint8_t>((u >> 16u) & 0xFFu), static_cast<std::uint8_t>((u >> 24u) & 0xFFu)};
}

/// a BSON string value, whose length is @a length_offset off
std::vector<std::uint8_t> bson_string(const std::string& value, const std::int32_t length_offset = 0)
{
    auto result = bson_int32(static_cast<std::int32_t>(value.size() + 1) + length_offset);
    result.insert(result.end(), value.begin(), value.end());
    result.push_back(0x00);
    return result;
}

/// @a count bytes of value 0xAB
std::vector<std::uint8_t> bytes(const std::size_t count)
{
    return std::vector<std::uint8_t>(count, 0xAB);
}

template<typename... Parts>
std::vector<std::uint8_t> concatenated(const std::vector<std::uint8_t>& first, const Parts& ... rest)
{
    std::vector<std::uint8_t> result = first;
    for (const auto& part : std::initializer_list<std::vector<std::uint8_t>> {rest...})
    {
        result.insert(result.end(), part.begin(), part.end());
    }
    return result;
}

/// U+FFFD REPLACEMENT CHARACTER
std::string replacement_character()
{
    return "\xEF\xBF\xBD";
}
}  // namespace

TEST_CASE("regression test - #3989 SAX parse_error() returning true")
{
    SECTION("binary formats complete what was read before the input ends")
    {
        const json j = {{"a", {1, -2, {{"b", "c"}}, json::array()}}, {"d", {{"e", nullptr}, {"f", true}}}, {"g", 1.5}, {"h", json::binary({1, 2, 3})}};

        const std::vector<std::pair<json::input_format_t, std::vector<std::uint8_t>>> encodings =
        {
            {json::input_format_t::cbor, json::to_cbor(j)},
            {json::input_format_t::msgpack, json::to_msgpack(j)},
            {json::input_format_t::ubjson, json::to_ubjson(j)},
            {json::input_format_t::ubjson, json::to_ubjson(j, true, true)},
            {json::input_format_t::bjdata, json::to_bjdata(j)},
            {json::input_format_t::bjdata, json::to_bjdata(j, true, true)},
            {json::input_format_t::bson, json::to_bson(j)},
            {json::input_format_t::bon8, json::to_bon8(j)},
        };

        for (const auto& encoding : encodings)
        {
            const auto format = encoding.first;
            const auto& bytes = encoding.second;
            CAPTURE(format);

            // every prefix is truncated input
            for (std::size_t length = 0; length < bytes.size(); ++length)
            {
                CAPTURE(length);
                const auto result = parse_binary_recovering(std::vector<std::uint8_t>(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(length)), format);
                CHECK(!result.ok);
                CHECK(result.errors == 1);
                CHECK(result.balanced);
            }

            // the complete input is read as usual (binary values do not
            // round-trip through every format, so compare with a plain parse)
            json expected;
            nlohmann::detail::json_sax_dom_parser<json> dom(expected);
            CHECK(json::sax_parse(bytes, &dom, format));
            const auto complete = parse_binary_recovering(bytes, format);
            CHECK(complete.ok);
            CHECK(complete.errors == 0);
            CHECK(complete.value == expected);

            // a byte after the value
            auto trailing_bytes = bytes;
            trailing_bytes.push_back(0x01);
            const auto trailing = parse_binary_recovering(trailing_bytes, format);
            CHECK(!trailing.ok);
            CHECK(trailing.errors == 1);
            CHECK(trailing.value == expected);
        }
    }

    SECTION("containers without an end")
    {
        // these made the readers loop, or read on, after the error
        const auto cbor_array = parse_binary_recovering({0x9F}, json::input_format_t::cbor);
        CHECK(cbor_array.errors == 1);
        CHECK(cbor_array.value == json::array());

        const auto cbor_map = parse_binary_recovering({0xBF, 0x61, 'a'}, json::input_format_t::cbor);
        CHECK(cbor_map.errors == 1);
        CHECK(cbor_map.value == json({{"a", nullptr}}));

        const auto msgpack_array = parse_binary_recovering({0xDD, 0xFF, 0xFF, 0xFF, 0xFF}, json::input_format_t::msgpack);
        CHECK(msgpack_array.errors == 1);
        CHECK(msgpack_array.value == json::array());

        const auto msgpack_map = parse_binary_recovering({0x81, 0xA1, 'a', 0x92, 0x01}, json::input_format_t::msgpack);
        CHECK(msgpack_map.errors == 1);
        CHECK(msgpack_map.value == json({{"a", {1}}}));
    }

    SECTION("BJData ndarray")
    {
        // a 2x3 int8 array with two of its six elements; the annotated array
        // format opens an object and two arrays of its own
        const auto result = parse_binary_recovering({'[', '$', 'i', '#', '[', '$', 'i', '#', 'i', 2, 2, 3, 1, 2}, json::input_format_t::bjdata);
        CHECK(result.errors == 1);
        CHECK(result.balanced);
        CHECK(result.value == json({{"_ArrayType_", "int8"}, {"_ArraySize_", {2, 3}}, {"_ArrayData_", {1, 2}}}));
    }

    SECTION("binary formats repair items whose end is known")
    {
        struct Repair
        {
            json::input_format_t format;
            std::vector<std::uint8_t> input;
            json expected;
            std::size_t errors;
        };

        const std::vector<Repair> repairs =
        {
            // CBOR: tags are ignored (here tag 1 and the self-describe tag 55799)
            {json::input_format_t::cbor, {0x82, 0xC1, 0x05, 0xD9, 0xD9, 0xF7, 0x06}, {5, 6}, 2},
            // CBOR: undefined and other simple values become null
            {json::input_format_t::cbor, {0x84, 0xF7, 0xE0, 0xF8, 0x20, 0x01}, {nullptr, nullptr, nullptr, 1}, 3},
            // CBOR: ill-formed UTF-8 becomes U+FFFD, also in keys
            {json::input_format_t::cbor, {0xA1, 0x61, 0xFF, 0x62, 0xC3, 0x28}, {{replacement_character(), replacement_character() + "("}}, 2},
            // CBOR: members whose key is not a string are skipped, whatever their key and value
            {json::input_format_t::cbor, {0xA4, 0x01, 0x02, 0x82, 0x01, 0x02, 0xA1, 0x61, 'x', 0x9F, 0xFF, 0xC1, 0x01, 0x5F, 0x41, 0x00, 0xFF, 0x61, 'a', 0x03}, {{"a", 3}}, 3},
            {json::input_format_t::cbor, {0xBF, 0xF5, 0xBF, 0x61, 'x', 0x7F, 0x61, 'y', 0xFF, 0xFF, 0x61, 'a', 0x03, 0xFF}, {{"a", 3}}, 1},
            // MessagePack: members whose key is not a string are skipped
            {json::input_format_t::msgpack, {0x84, 0x01, 0x02, 0x81, 0xA1, 'x', 0x01, 0x92, 0x01, 0x02, 0xD4, 0x01, 0x02, 0xC0, 0xA1, 'a', 0x04}, {{"a", 4}}, 3},
            // MessagePack: ill-formed UTF-8 becomes U+FFFD
            {json::input_format_t::msgpack, {0x92, 0xA2, 0xC3, 0x28, 0xA3, 0xE2, 0x82, 'x'}, {replacement_character() + "(", replacement_character() + "x"}, 2},
            // UBJSON: a char that is not ASCII becomes U+FFFD
            {json::input_format_t::ubjson, {'[', 'C', 0x80, 'C', 'A', ']'}, {replacement_character(), "A"}, 1},
            // UBJSON: the longest beginning of a high-precision number is kept
            {json::input_format_t::ubjson, {'[', 'H', 'i', 5, '1', '2', 'a', 'b', 'c', 'H', 'i', 2, '1', '.', 'H', 'i', 3, 'a', 'b', 'c', 'H', 'i', 3, '4', '.', '5', ']'}, {12, 1, nullptr, 4.5}, 3},
            // BJData, too
            {json::input_format_t::bjdata, {'[', 'C', 0xFF, 'H', 'i', 2, '-', '1', 'H', 'i', 2, '-', 'x', ']'}, {replacement_character(), -1, nullptr}, 2},
            // BON8: members whose key is not a string are skipped
            {json::input_format_t::bon8, {0x89, 0x91, 0x92, 0xC9, 0x40, 0x82, 0x91, 0x92, 0x61, 0x93}, {{"a", 3}}, 2},
            {json::input_format_t::bon8, {0x8B, 0x91, 0x85, 0x91, 0xFE, 0xFA, 0x8B, 'x', 0x91, 0xFE, 0x61, 0x93, 0xFE}, {{"a", 3}}, 2},
            // BSON: elements of types the library does not read become null
            {
                json::input_format_t::bson, bson_document(
                {
                    bson_element(0x07, "_id", bytes(12)),                         // ObjectId
                    bson_element(0x09, "date", bytes(8)),                         // UTC datetime
                    bson_element(0x13, "decimal", bytes(16)),                     // 128-bit decimal
                    bson_element(0x0B, "regex", {'a', '+', 0, 'i', 0}),           // regular expression
                    bson_element(0x0D, "code", bson_string("f()")),               // JavaScript code
                    bson_element(0x0E, "symbol", bson_string("s")),               // symbol
                    bson_element(0x0C, "pointer", concatenated(bson_string("c"), bytes(12))), // DBPointer
                    bson_element(0x0F, "scope", concatenated(bson_int32(15), bson_string("g"), bson_document({}))), // code with scope
                    bson_element(0x06, "undefined", {}),                          // undefined
                    bson_element(0xFF, "min", {}),                                // min key
                    bson_element(0x7F, "max", {}),                                // max key
                    bson_element(0x10, "z", bson_int32(7)),
                }),
                {{"_id", nullptr}, {"date", nullptr}, {"decimal", nullptr}, {"regex", nullptr}, {"code", nullptr}, {"symbol", nullptr}, {"pointer", nullptr}, {"scope", nullptr}, {"undefined", nullptr}, {"min", nullptr}, {"max", nullptr}, {"z", 7}},
                11
            },
            // BSON: an element of an unknown type becomes null, and the rest of its document is skipped
            {
                json::input_format_t::bson, bson_document(
                {
                    bson_element(0x03, "inner", bson_document({bson_element(0x10, "a", bson_int32(1)), bson_element(0x42, "x", bytes(3)), bson_element(0x10, "b", bson_int32(2))})),
                    bson_element(0x04, "array", bson_document({bson_element(0x10, "0", bson_int32(1)), bson_element(0x42, "1", bytes(3))})),
                    bson_element(0x10, "after", bson_int32(3)),
                }),
                {{"inner", {{"a", 1}, {"x", nullptr}}}, {"array", {1, nullptr}}, {"after", 3}},
                2
            },
            // BSON: so does a string or byte array whose length cannot be right
            {
                json::input_format_t::bson, bson_document(
                {
                    bson_element(0x03, "inner", bson_document({bson_element(0x02, "s", bson_string("abc", -10)), bson_element(0x10, "b", bson_int32(2))})),
                    bson_element(0x03, "bin", bson_document({bson_element(0x05, "b", concatenated(bson_int32(-1), bytes(1))), bson_element(0x10, "b", bson_int32(2))})),
                    bson_element(0x10, "after", bson_int32(3)),
                }),
                {{"inner", {{"s", nullptr}}}, {"bin", {{"b", nullptr}}}, {"after", 3}},
                2
            },
            // BSON: a string without its terminator, and a document whose size does not match, are kept
            {
                json::input_format_t::bson, bson_document(
                {
                    bson_element(0x02, "s", {2, 0, 0, 0, 'a', 'X'}),
                    bson_element(0x03, "inner", bson_document({bson_element(0x10, "a", bson_int32(1))}, 1)),
                }),
                {{"s", "a"}, {"inner", {{"a", 1}}}},
                2
            },
        };

        for (const auto& repair : repairs)
        {
            CAPTURE(repair.format);
            CAPTURE(repair.input);
            const auto result = parse_binary_recovering(repair.input, repair.format);
            CHECK(!result.ok);
            CHECK(result.balanced);
            CHECK(result.errors == repair.errors);
            CHECK(result.value == repair.expected);
            // the first error is the one reported without recovering
            REQUIRE(!result.messages.empty());
            CHECK(result.messages.front() == binary_error_message(repair.input, repair.format));
        }
    }

    SECTION("binary formats repair numbers that are out of range")
    {
        // CBOR: a negative integer below the range of number_integer_t
        const auto cbor = parse_binary_recovering({0x3B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, json::input_format_t::cbor);
        CHECK(cbor.errors == 1);
        CHECK(cbor.value.is_number_float());
        CHECK(cbor.value.get<double>() == -18446744073709551616.0);

        // UBJSON: a high-precision number too large for number_float_t
        const auto ubjson = parse_binary_recovering({'H', 'i', 5, '1', 'e', '9', '9', '9'}, json::input_format_t::ubjson);
        CHECK(ubjson.errors == 1);
        CHECK(ubjson.value.is_number_float());
        CHECK(std::isinf(ubjson.value.get<double>()));
    }

    SECTION("binary formats stop where the end of an item is not known")
    {
        // a byte that begins no item
        const auto cbor = parse_binary_recovering({0x82, 0x01, 0x1C, 0x02}, json::input_format_t::cbor);
        CHECK(cbor.errors == 1);
        CHECK(cbor.value == json({1}));

        // a key that is no item: the unused MessagePack byte, a CBOR break
        // in a map of known size, and the end of a BON8 container
        const auto msgpack = parse_binary_recovering({0x82, 0xA1, 'a', 0x01, 0xC1, 0x02}, json::input_format_t::msgpack);
        CHECK(msgpack.errors == 1);
        CHECK(msgpack.value == json({{"a", 1}}));
        const auto cbor_break = parse_binary_recovering({0xA2, 0x61, 'a', 0x01, 0xFF, 0x02}, json::input_format_t::cbor);
        CHECK(cbor_break.errors == 1);
        CHECK(cbor_break.value == json({{"a", 1}}));
        const auto bon8 = parse_binary_recovering({0x88, 0x61, 0x91, 0xFE}, json::input_format_t::bon8);
        CHECK(bon8.errors == 1);
        CHECK(bon8.value == json({{"a", 1}}));

        // a skipped member that the input ends in
        const auto truncated = parse_binary_recovering({0xA2, 0x01, 0x82, 0x01}, json::input_format_t::cbor);
        CHECK(truncated.errors == 2);
        CHECK(truncated.balanced);
        CHECK(truncated.value == json::object());

        // a BSON element of an unknown type in a document whose size cannot be right
        const auto bson = parse_binary_recovering(bson_document({bson_element(0x10, "a", bson_int32(1)), bson_element(0x42, "x", bytes(3))}, -10), json::input_format_t::bson);
        CHECK(bson.errors == 1);
        CHECK(bson.value == json({{"a", 1}, {"x", nullptr}}));
    }

    SECTION("changed bytes in binary input")
    {
        const json j = {{"a", {1, -2, {{"b", "c"}}, json::array()}}, {"d", {{"e", nullptr}, {"f", true}}}, {"g", 1.5}, {"h", json::binary({1, 2, 3})}, {"i", "\xC3\xA4"}};

        const std::vector<std::pair<json::input_format_t, std::vector<std::uint8_t>>> encodings =
        {
            {json::input_format_t::cbor, json::to_cbor(j)},
            {json::input_format_t::msgpack, json::to_msgpack(j)},
            {json::input_format_t::ubjson, json::to_ubjson(j)},
            {json::input_format_t::ubjson, json::to_ubjson(j, true, true)},
            {json::input_format_t::bjdata, json::to_bjdata(j)},
            {json::input_format_t::bjdata, json::to_bjdata(j, true, true)},
            {json::input_format_t::bson, json::to_bson(j)},
            {json::input_format_t::bon8, json::to_bon8(j)},
        };
        const std::vector<std::uint8_t> replacements = {0x00, 0x01, 0x7F, 0x80, 0xC1, 0xD9, 0xE0, 0xF7, 0xFE, 0xFF};

        for (const auto& encoding : encodings)
        {
            const auto format = encoding.first;
            const auto& original = encoding.second;
            CAPTURE(format);

            std::vector<std::vector<std::uint8_t>> inputs;
            for (std::size_t position = 0; position < original.size(); ++position)
            {
                for (const auto replacement : replacements)
                {
                    auto changed = original;
                    changed[position] = replacement;
                    inputs.push_back(changed);
                }
                auto removed = original;
                removed.erase(removed.begin() + static_cast<std::ptrdiff_t>(position));
                inputs.push_back(removed);
            }

            for (const auto& input : inputs)
            {
                CAPTURE(input);
                const auto result = parse_binary_recovering(input, format);
                CHECK(result.balanced);
                CHECK(result.errors <= input.size() + 1);
                // an error is reported exactly if reading into a JSON value
                // fails, and the first one is the same
                const auto message = binary_error_message(input, format);
                CHECK(result.ok == message.empty());
                if (!result.ok && result.errors < 100)
                {
                    CHECK(result.messages.front() == message);
                }
            }
        }
    }

    SECTION("JSON text")
    {
        // the parser stopped, but reported success
        json j;
        RecoveringParser sax(j);
        CHECK(!json::sax_parse("[1,2,3,]", &sax));
        CHECK(sax.errors == 1);
        CHECK(j == json({1, 2, 3}));
    }

    SECTION("the SAX parsers of the library stop")
    {
        json _;
        CHECK(json::from_cbor(std::vector<std::uint8_t> {0x9F}, true, false).is_discarded());
        CHECK_THROWS_WITH_AS(_ = json::from_cbor(std::vector<std::uint8_t> {0x9F}), "[json.exception.parse_error.110] parse error at byte 2: syntax error while parsing CBOR value: unexpected end of input", json::parse_error&);
        CHECK(json::parse("[1,2,3,]", nullptr, false).is_discarded());
        CHECK(!json::accept("[1,2,3,]"));
    }
}

DOCTEST_CLANG_SUPPRESS_WARNING_POP
