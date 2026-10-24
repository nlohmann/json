//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// cmake/test.cmake builds a unit test with C++ standards beyond C++11 only if the
// source file mentions the corresponding version macro. To avoid rebuilding this
// large file for every standard, tests that depend on the standard version (e.g.,
// those using JSON_HAS_FILESYSTEM, JSON_HAS_RANGES, or JSON_HAS_THREE_WAY_COMPARISON)
// go into a separate file unit-regression2-cpp<NN>.cpp. This file stays C++11-only.

#include "doctest_compatibility.h"

// for some reason including this after the json header leads to linker errors with VS 2017...
#include <locale>

// skip tests if JSON_DISABLE_TUPLE_REFERENCE_CONVERSION=1 (#2226)
#if defined(JSON_DISABLE_TUPLE_REFERENCE_CONVERSION) && (JSON_DISABLE_TUPLE_REFERENCE_CONVERSION == 1)
    #define SKIP_TESTS_FOR_TUPLE_REFERENCE_CONVERSION
#endif

// clang before 4 and GCC before 5 cannot create a std::tuple of basic_json
// references at all, with or without JSON_DISABLE_TUPLE_REFERENCE_CONVERSION:
// the tuple constructors make them instantiate basic_json's conversion operator
// for libstdc++'s internal tuple bases, which fails hard
#if (defined(__clang__) && __clang_major__ < 4) || (!defined(__clang__) && defined(__GNUC__) && __GNUC__ < 5)
    #define SKIP_TESTS_FOR_JSON_REFERENCE_TUPLES
#endif

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#include <cstdio>
#include <cstdlib>
#include <list>
#include <new>
#include <tuple>
#include <type_traits>
#include <utility>

#include "test_utils.hpp"

/////////////////////////////////////////////////////////////////////
// for #4825 - explicitly instantiating basic_json must compile; this
// forces instantiation of binary_writer::write_bjdata_ndarray, whose
// static_cast<string_t> was ambiguous under explicit instantiation on
// C++17. Merely compiling this translation unit is the regression test.
/////////////////////////////////////////////////////////////////////
template class nlohmann::basic_json<>;

// NLOHMANN_JSON_SERIALIZE_ENUM uses a static std::pair
DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wexit-time-destructors")

/////////////////////////////////////////////////////////////////////
// for #1021
/////////////////////////////////////////////////////////////////////

using float_json = nlohmann::json::with_float_t<float>;

#if (defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)) && !defined(JSON_NOEXCEPTION)
namespace
{
// An allocator whose allocate() can be told to fail on demand, so tests can
// check that ~basic_json() tolerates - in fact, after #5135, never even
// triggers - an allocation failure. This replaces an earlier version of
// this test that overrode the process-wide ::operator new/::operator
// delete, which affected every allocation in the whole unit-regression2
// binary rather than just the values under test.
std::size_t failing_allocator_allocations = 0;
std::size_t failing_allocator_deallocations = 0;
bool fail_next_allocation = false;

template<class T>
struct failing_allocator : std::allocator<T>
{
    using std::allocator<T>::allocator;

    failing_allocator() noexcept = default;
    template<class U>
    failing_allocator(const failing_allocator<U>& /*unused*/) noexcept {} // NOLINT(google-explicit-constructor)

    T* allocate(std::size_t n)
    {
        if (fail_next_allocation)
        {
            fail_next_allocation = false;
            throw std::bad_alloc();
        }
        ++failing_allocator_allocations;
        return std::allocator<T>::allocate(n);
    }

    void deallocate(T* p, std::size_t n)
    {
        ++failing_allocator_deallocations;
        std::allocator<T>::deallocate(p, n);
    }

    template<class U>
    struct rebind
    {
        using other = failing_allocator<U>;
    };
};

using failing_json = nlohmann::json::with_allocator_t<failing_allocator>;
using failing_ordered_json = nlohmann::ordered_json::with_allocator_t<failing_allocator>;

// builds `depth` levels of nesting around a scalar, iteratively (never
// recursing: each wrap only moves the previous, already-built value, which
// is O(1)), each level an array or an object depending on `nest_objects`
template<class BasicJsonType>
BasicJsonType make_deep_nest(std::size_t depth, bool nest_objects)
{
    BasicJsonType v = 0;
    for (std::size_t i = 0; i < depth; ++i)
    {
        if (nest_objects)
        {
            BasicJsonType wrapper = BasicJsonType::object();
            wrapper["x"] = std::move(v);
            v = std::move(wrapper);
        }
        else
        {
            BasicJsonType wrapper = BasicJsonType::array();
            wrapper.push_back(std::move(v));
            v = std::move(wrapper);
        }
    }
    return v;
}
} // namespace
#endif

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

// NOLINTNEXTLINE(misc-const-correctness): this is a false positive
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
// for #2982
/////////////////////////////////////////////////////////////////////

template<class T>
class my_allocator_2982 : public std::allocator<T>
{
  public:
    using std::allocator<T>::allocator;

    my_allocator_2982() = default;
    template<class U> my_allocator_2982(const my_allocator_2982<U>& /*unused*/) { }

    template <class U>
    struct rebind
    {
        using other = my_allocator_2982<U>;
    };
};

/////////////////////////////////////////////////////////////////////
// for #3669
/////////////////////////////////////////////////////////////////////

// mimics boost::optional's converting constructor, whose SFINAE check asks
// whether T is constructible from const U&
template<class T, class Arg>
struct issue3669_is_constructible
{
    template<class T2, class A2, class = decltype(T2(std::declval<A2>()))>
    static char test(int);
    template<class, class>
    static long test(...);
    static constexpr bool value = sizeof(test<T, Arg>(0)) == 1;
};

template<class T>
class issue3669_optional
{
  public:
    issue3669_optional() = default;
    template<class U>
    issue3669_optional(const issue3669_optional<U>& /*unused*/, // NOLINT(google-explicit-constructor,hicpp-explicit-conversions)
                       typename std::enable_if<issue3669_is_constructible<T, const U&>::value, bool>::type /*unused*/ = true) {}
};

class Issue3669Dummy
{
  public:
    explicit Issue3669Dummy(const json& /*unused*/) {}
};

class Issue3669Holder
{
    issue3669_optional<Issue3669Dummy> d{};

    // GCC < 11 (C++11/14) rejects a free to_json(json&, const Issue3669Holder&)
    // here, because ADL for Issue3669Dummy finds it and closes an instantiation
    // cycle; a hidden friend is only visible to ADL for Issue3669Holder
    friend void to_json(json& j, const Issue3669Holder& h)
    {
        static_cast<void>(h.d); // silence -Wunused-private-field
        j = "holder";
    }
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
        const json j = json::from_msgpack(data.begin(), data.end());
        // dump() is nodiscard; this only checks that dumping does not throw
        CHECK_NOTHROW(
            utils::ignore_return_value(
                j.dump(4,                             // Indent
                       ' ',                           // Indent char
                       false,                         // Ensure ascii
                       json::error_handler_t::strict  // Error
                      )));
    }

#ifndef SKIP_TESTS_FOR_TUPLE_REFERENCE_CONVERSION
    SECTION("issue #2226 - std::tuple dangling reference - implicit conversion")
    {
        // by default, a one-element tuple holding a json reference converts to
        // a one-element array; JSON_DISABLE_TUPLE_REFERENCE_CONVERSION removes
        // this conversion (see unit-disable-tuple-reference-conversion.cpp)
        const json j = true;
        CHECK(std::is_constructible<json, std::tuple<const json&>>::value);
#ifndef SKIP_TESTS_FOR_JSON_REFERENCE_TUPLES
        CHECK(json(std::forward_as_tuple(j)) == json::array({true}));
#endif
    }
#endif

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
        std::vector<std::uint8_t, my_allocator_2982<std::uint8_t>> my_vector;
        const json j = {1, 2, 3, 4};
        json::to_cbor(j, my_vector);
        json k = json::from_cbor(my_vector);
        CHECK(j == k);
    }

    SECTION("issue #4552 - UTF-8 invalid characters are not always ignored when dumping with error_handler_t::ignore")
    {
        json node;
        node["test"] = "test\334\005";
        CHECK(node.dump(-1, ' ', false, json::error_handler_t::ignore) == "{\"test\":\"test\\u0005\"}");
        CHECK(node.dump(-1, ' ', false, json::error_handler_t::keep) == "{\"test\":\"test\334\\u0005\"}");
        CHECK(node.dump(-1, ' ', true, json::error_handler_t::keep) == "{\"test\":\"test\334\\u0005\"}");
    }

    SECTION("issue #3669 - invalid use of incomplete type with optional member and to_json")
    {
        const Issue3669Holder h{};
        const Issue3669Holder h2(h); // NOLINT(performance-unnecessary-copy-initialization)
        const json j = h2;
        CHECK(j == "holder");
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

#if (defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)) && !defined(JSON_NOEXCEPTION)
TEST_CASE("regression test #5135 - destructor never allocates, even under memory pressure")
{
    // Before the fix, ~basic_json() flattened a nested array/object into a
    // heap-allocated std::vector to avoid recursing; that allocation could
    // itself throw bad_alloc, which escapes a noexcept destructor and
    // terminates the program. destroy() no longer allocates anything, so
    // none of the sections below ever observe fail_next_allocation being
    // consumed: CHECK(fail_next_allocation) confirms it was never touched.

    SECTION("the original report: a small, mixed array/object nest")
    {
        failing_allocator_allocations = 0;
        failing_allocator_deallocations = 0;
        {
            const failing_json j = failing_json::array(
            {
                failing_json::array({1, 2}),
                failing_json::object({{"key", failing_json::array({3})}})
            });
            fail_next_allocation = true;
        } // j is destroyed here, with every further allocation set to fail

        CHECK(fail_next_allocation);
        fail_next_allocation = false;
        CHECK(failing_allocator_deallocations > 0);
    }

    SECTION("100000-deep nested array")
    {
        std::size_t allocations_before = 0;
        {
            const auto j = make_deep_nest<failing_json>(100000, false);
            allocations_before = failing_allocator_allocations;
            fail_next_allocation = true;
        }

        CHECK(fail_next_allocation);
        fail_next_allocation = false;
        CHECK(failing_allocator_allocations == allocations_before);
    }

    SECTION("100000-deep nested object")
    {
        std::size_t allocations_before = 0;
        {
            const auto j = make_deep_nest<failing_json>(100000, true);
            allocations_before = failing_allocator_allocations;
            fail_next_allocation = true;
        }

        CHECK(fail_next_allocation);
        fail_next_allocation = false;
        CHECK(failing_allocator_allocations == allocations_before);
    }

    SECTION("100000-deep nested ordered_json")
    {
        std::size_t allocations_before = 0;
        {
            const auto j = make_deep_nest<failing_ordered_json>(100000, true);
            allocations_before = failing_allocator_allocations;
            fail_next_allocation = true;
        }

        CHECK(fail_next_allocation);
        fail_next_allocation = false;
        CHECK(failing_allocator_allocations == allocations_before);
    }

    SECTION("wide and deep: 1000 arrays of 1000 elements, each a small nested object")
    {
        std::size_t allocations_before = 0;
        {
            failing_json wide = failing_json::array();
            for (std::size_t i = 0; i < 1000; ++i)
            {
                failing_json inner = failing_json::array();
                for (std::size_t k = 0; k < 1000; ++k)
                {
                    inner.push_back(failing_json::object({{"a", 1}, {"b", failing_json::array({1, 2, 3})}}));
                }
                wide.push_back(std::move(inner));
            }

            allocations_before = failing_allocator_allocations;
            fail_next_allocation = true;
        }

        CHECK(fail_next_allocation);
        fail_next_allocation = false;
        CHECK(failing_allocator_allocations == allocations_before);
    }
}
#endif

namespace
{
// a single-element chain of `depth` arrays, built iteratively (never
// recursing: each wrap only moves the previous, already-built value)
template<class BasicJsonType>
BasicJsonType make_single_chain(std::size_t depth)
{
    BasicJsonType v = 1;
    for (std::size_t i = 0; i < depth; ++i)
    {
        BasicJsonType wrapper = BasicJsonType::array();
        wrapper.push_back(std::move(v));
        v = std::move(wrapper);
    }
    return v;
}

// copies value first, to make sure nothing was corrupted by building it,
// then lets both the copy and the original destruct via normal scope exit
template<class BasicJsonType>
void check_destroy_edge_case(const BasicJsonType& value)
{
    const BasicJsonType copy = value; // NOLINT(performance-unnecessary-copy-initialization): the copy is the point
    CHECK(copy == value);
}
} // namespace

TEST_CASE_TEMPLATE("regression test #5135 - destroy() edge cases", BasicJsonType, json, ordered_json)
{
    using binary_t = typename BasicJsonType::binary_t;

    SECTION("mix of empty objects, empty arrays, non-empty containers, and scalars")
    {
        BasicJsonType root = BasicJsonType::array();
        root.push_back(BasicJsonType::object());
        root.push_back(BasicJsonType::array());
        root.push_back(BasicJsonType::object({{"k", 1}}));
        root.push_back(BasicJsonType::array({1, 2, 3}));
        root.push_back(nullptr);
        root.push_back(true);
        root.push_back(42);
        root.push_back(3.14);
        root.push_back("a string");
        root.push_back(BasicJsonType(binary_t({1, 2, 3})));
        check_destroy_edge_case(root);
    }

    SECTION("container child in first position only")
    {
        BasicJsonType root = BasicJsonType::array({BasicJsonType::array({1, 2}), 3, 4, 5});
        check_destroy_edge_case(root);
    }

    SECTION("container child in last position only")
    {
        BasicJsonType root = BasicJsonType::array({1, 2, 3, BasicJsonType::array({4, 5})});
        check_destroy_edge_case(root);
    }

    SECTION("container children in first and last position")
    {
        BasicJsonType root = BasicJsonType::array({BasicJsonType::array({1}), 2, 3, BasicJsonType::array({4})});
        check_destroy_edge_case(root);
    }

    SECTION("single-element chain, 1000 levels deep")
    {
        auto root = make_single_chain<BasicJsonType>(1000);
        check_destroy_edge_case(root);
    }

    SECTION("top-level empty array")
    {
        BasicJsonType root = BasicJsonType::array();
        check_destroy_edge_case(root);
    }

    SECTION("top-level empty object")
    {
        BasicJsonType root = BasicJsonType::object();
        check_destroy_edge_case(root);
    }

    SECTION("object whose last child is a non-empty array whose last child is an empty object")
    {
        BasicJsonType inner_array = BasicJsonType::array({1, 2, BasicJsonType::object()});
        BasicJsonType root = BasicJsonType::object({{"a", 1}, {"b", inner_array}});
        check_destroy_edge_case(root);
    }

    SECTION("destruction via erase() on a deeply nested child")
    {
        BasicJsonType root = BasicJsonType::array();
        root.push_back(make_single_chain<BasicJsonType>(500));
        root.push_back(BasicJsonType::object({{"k", BasicJsonType::array({1, 2, 3})}}));
        // erase() must destroy the removed subtree without recursing or
        // allocating beyond what erase() itself needs
        root.erase(0);
        CAPTURE(root.size())
        CHECK(root.size() == 1);
    }

    SECTION("destruction via assignment on a deep tree")
    {
        auto root = make_single_chain<BasicJsonType>(2000);
        // assigning a new value destroys the old one in place
        root = nullptr;
        CHECK(root.is_null());
    }
}

DOCTEST_CLANG_SUPPRESS_WARNING_POP
