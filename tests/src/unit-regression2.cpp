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
            dump_test.dump(-1, ' ', true, nlohmann::json::error_handler_t::replace);
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

}

DOCTEST_CLANG_SUPPRESS_WARNING_POP
