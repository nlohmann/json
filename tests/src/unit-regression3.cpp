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

// This file continues unit-regression2.cpp, which the MinGW linker cannot
// relocate once it grows past a certain size ("relocation truncated to fit").
// Keep it building for the same standards as that file:
// JSON_HAS_CPP_17 (do not remove; see note at top of file)
// JSON_HAS_CPP_20 (do not remove; see note at top of file)

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#ifdef JSON_HAS_CPP_17
    #include <any>
    #include <variant>
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

#if JSON_HAS_RANGES == 1
    #include <ranges>
#endif

// NLOHMANN_JSON_SERIALIZE_ENUM uses a static std::pair
DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wexit-time-destructors")

TEST_CASE_TEMPLATE("issue #4798 - nlohmann::json::to_msgpack() encode float NaN as double", T, double, float) // NOLINT(readability-math-missing-parentheses, bugprone-throwing-static-initialization)
{
    // With issue #4798, we encode NaN, infinity, and -infinity as float instead
    // of double to allow for smaller encodings.
    const json jx = std::numeric_limits<T>::quiet_NaN();
    const json jy = std::numeric_limits<T>::infinity();
    const json jz = -std::numeric_limits<T>::infinity();

    /////////////////////////////////////////////////////////////////////////
    // MessagePack
    /////////////////////////////////////////////////////////////////////////

    // expected MessagePack values
    const std::vector<std::uint8_t> msgpack_x = {{0xCA, 0x7F, 0xC0, 0x00, 0x00}};
    const std::vector<std::uint8_t> msgpack_y = {{0xCA, 0x7F, 0x80, 0x00, 0x00}};
    const std::vector<std::uint8_t> msgpack_z = {{0xCA, 0xFF, 0x80, 0x00, 0x00}};

    CHECK(json::to_msgpack(jx) == msgpack_x);
    CHECK(json::to_msgpack(jy) == msgpack_y);
    CHECK(json::to_msgpack(jz) == msgpack_z);

    CHECK(std::isnan(json::from_msgpack(msgpack_x).get<T>()));
    CHECK(json::from_msgpack(msgpack_y).get<T>() == std::numeric_limits<T>::infinity());
    CHECK(json::from_msgpack(msgpack_z).get<T>() == -std::numeric_limits<T>::infinity());

    // Make sure the other MessagePakc encodings for NaN, infinity, and
    // -infinity are still supported.
    const std::vector<std::uint8_t> msgpack_x_2 = {{0xCB, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    const std::vector<std::uint8_t> msgpack_y_2 = {{0xCB, 0x7F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    const std::vector<std::uint8_t> msgpack_z_2 = {{0xCB, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    CHECK(std::isnan(json::from_msgpack(msgpack_x_2).get<T>()));
    CHECK(json::from_msgpack(msgpack_y_2).get<T>() == std::numeric_limits<T>::infinity());
    CHECK(json::from_msgpack(msgpack_z_2).get<T>() == -std::numeric_limits<T>::infinity());

    /////////////////////////////////////////////////////////////////////////
    // CBOR
    /////////////////////////////////////////////////////////////////////////

    // expected CBOR values
    const std::vector<std::uint8_t> cbor_x = {{0xF9, 0x7E, 0x00}};
    const std::vector<std::uint8_t> cbor_y = {{0xF9, 0x7C, 0x00}};
    const std::vector<std::uint8_t> cbor_z = {{0xF9, 0xfC, 0x00}};

    CHECK(json::to_cbor(jx) == cbor_x);
    CHECK(json::to_cbor(jy) == cbor_y);
    CHECK(json::to_cbor(jz) == cbor_z);

    CHECK(std::isnan(json::from_cbor(cbor_x).get<T>()));
    CHECK(json::from_cbor(cbor_y).get<T>() == std::numeric_limits<T>::infinity());
    CHECK(json::from_cbor(cbor_z).get<T>() == -std::numeric_limits<T>::infinity());

    // Make sure the other CBOR encodings for NaN, infinity, and -infinity are
    // still supported.
    const std::vector<std::uint8_t> cbor_x_2 = {{0xFA, 0x7F, 0xC0, 0x00, 0x00}};
    const std::vector<std::uint8_t> cbor_y_2 = {{0xFA, 0x7F, 0x80, 0x00, 0x00}};
    const std::vector<std::uint8_t> cbor_z_2 = {{0xFA, 0xFF, 0x80, 0x00, 0x00}};
    const std::vector<std::uint8_t> cbor_x_3 = {{0xFB, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    const std::vector<std::uint8_t> cbor_y_3 = {{0xFB, 0x7F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    const std::vector<std::uint8_t> cbor_z_3 = {{0xFB, 0xFF, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
    CHECK(std::isnan(json::from_cbor(cbor_x_2).get<T>()));
    CHECK(json::from_cbor(cbor_y_2).get<T>() == std::numeric_limits<T>::infinity());
    CHECK(json::from_cbor(cbor_z_2).get<T>() == -std::numeric_limits<T>::infinity());
    CHECK(std::isnan(json::from_cbor(cbor_x_3).get<T>()));
    CHECK(json::from_cbor(cbor_y_3).get<T>() == std::numeric_limits<T>::infinity());
    CHECK(json::from_cbor(cbor_z_3).get<T>() == -std::numeric_limits<T>::infinity());
}

TEST_CASE("regression test #5074 - portable workaround for single-element brace init")
{
    json const j_obj = {{"key", "value"}};

    json const j = json::array({j_obj});
    CHECK(j.is_array());
    CHECK(j.size() == 1);
    CHECK(j[0] == j_obj);
}

#if defined(JSON_BRACE_INIT_COPY_SEMANTICS) && (JSON_BRACE_INIT_COPY_SEMANTICS == 1)
TEST_CASE("regression test #5074 - single-element brace init with JSON_BRACE_INIT_COPY_SEMANTICS")
{
    // with JSON_BRACE_INIT_COPY_SEMANTICS: single-element brace init copies/moves
    json const j_obj = {{"key", "value"}, {"num", 42}};
    json const j_arr = {1, 2, 3};

    // object: brace init copies instead of wrapping
    json const j1{j_obj};
    CHECK(j1.is_object());
    CHECK(j1 == j_obj);

    // array: brace init copies instead of wrapping
    json const j2{j_arr};
    CHECK(j2.is_array());
    CHECK(j2.size() == 3);
    CHECK(j2 == j_arr);

    // primitives still work as initializer lists
    json const j3{true};
    CHECK(j3.is_boolean());

    json const j4{42};
    CHECK(j4.is_number_integer());
}
#endif

struct Example_5122
{
    float b = 2;
    nlohmann::ordered_map<std::string, std::string> c{}; // NOLINT(readability-redundant-member-init): needed for GCC -Weffc++
    int a = 1;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Example_5122, b, c, a)
};

TEST_CASE("regression test #5122 - from_json into types holding nlohmann::ordered_map")
{
    Example_5122 src;
    src.c.emplace("first", "1");
    src.c.emplace("second", "2");

    ordered_json const j = src;
    Example_5122 const dst = j.get<Example_5122>();

    CHECK(dst.b == src.b);
    CHECK(dst.a == src.a);
    REQUIRE(dst.c.size() == src.c.size());
    auto src_it = src.c.begin();
    auto dst_it = dst.c.begin();
    for (; src_it != src.c.end(); ++src_it, ++dst_it)
    {
        CHECK(dst_it->first == src_it->first);
        CHECK(dst_it->second == src_it->second);
    }
}

// -Wself-assign-overloaded was introduced in Clang 7. Gate the pragma on
// __has_warning so older Clang versions do not error with "unknown warning
// group". The __has_warning check has to stay inside the __clang__ branch
// because GCC does not provide it and would tokenize-error on the argument.
#if defined(__clang__) && defined(__has_warning)
    #if __has_warning("-Wself-assign-overloaded")
        DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
        DOCTEST_CLANG_SUPPRESS_WARNING("-Wself-assign-overloaded")
    #endif
#endif

TEST_CASE("regression test #5122 - nlohmann::ordered_map copy-assignment is self-assignment safe")
{
    nlohmann::ordered_map<std::string, std::string> m;
    m.emplace("first", "1");
    m.emplace("second", "2");

    // Insertion order is preserved by ordered_map, so we can check it directly.
    m = m;

    REQUIRE(m.size() == 2);
    auto it = m.begin();
    CHECK(it->first == "first");
    CHECK(it->second == "1");
    ++it;
    CHECK(it->first == "second");
    CHECK(it->second == "2");
}

#if defined(__clang__) && defined(__has_warning)
    #if __has_warning("-Wself-assign-overloaded")
        DOCTEST_CLANG_SUPPRESS_WARNING_POP
    #endif
#endif

TEST_CASE("regression test #5122 - nlohmann::ordered_map move-assignment transfers contents")
{
    nlohmann::ordered_map<std::string, std::string> src;
    src.emplace("first", "1");
    src.emplace("second", "2");

    nlohmann::ordered_map<std::string, std::string> dst;
    dst.emplace("stale", "x");
    dst = std::move(src);

    REQUIRE(dst.size() == 2);
    auto it = dst.begin();
    CHECK(it->first == "first");
    CHECK(it->second == "1");
    ++it;
    CHECK(it->first == "second");
    CHECK(it->second == "2");

    // Re-assigning into the moved-from object must leave it in a usable state.
    src = nlohmann::ordered_map<std::string, std::string> {};
    src.emplace("after-move", "3");
    REQUIRE(src.size() == 1);
    CHECK(src.begin()->first == "after-move");
}

// Stand-in for a third-party library (e.g., Eigen as of 3.4, which added
// STL-compatible begin()/end() to its vector types), living in its own
// namespace with its own to_json overload for its vector type.
namespace issue_4320_eigen
{
// "array-compatible" from the library's point of view (it has begin()/end()),
// but for which this (fake) third-party namespace provides its own to_json.
struct vector3
{
    double v[3]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-use-default-member-init,modernize-use-default-member-init)
    vector3(double x, double y, double z) : v{x, y, z} {} // NOLINT(hicpp-member-init,cppcoreguidelines-pro-type-member-init)
    double x() const
    {
        return v[0];
    }
    double y() const
    {
        return v[1];
    }
    double z() const
    {
        return v[2];
    }
    double* begin()
    {
        return v;
    }
    double* end()
    {
        return v + 3;
    }
    const double* begin() const
    {
        return v;
    }
    const double* end() const
    {
        return v + 3;
    }
};

inline void to_json(json& j, const vector3& v) // NOLINT(misc-use-internal-linkage)
{
    j = {{"x", v.x()}, {"y", v.y()}, {"z", v.z()}};
}
} // namespace issue_4320_eigen

// The user's own namespace, using the (fake) Eigen type as an implementation
// detail behind a payload type that has nothing to do with vectors/arrays.
namespace issue_4320
{
// Publicly derives from issue_4320_eigen::vector3 but does *not* define its
// own to_json - it is only ever used as a temporary to reach the base
// class's to_json via ADL.
struct vector3_wrapper : issue_4320_eigen::vector3
{
    using issue_4320_eigen::vector3::vector3;
};

struct payload
{
    double x, y, z;
};

inline vector3_wrapper to_eigen(const payload& p) // NOLINT(misc-use-internal-linkage)
{
    return {p.x, p.y, p.z};
}

inline void to_json(json& j, const payload& p) // NOLINT(misc-use-internal-linkage)
{
    // Unqualified call, passing a *derived* vector3_wrapper: relies on ADL
    // finding issue_4320_eigen::to_json(json&, const vector3&) through the
    // vector3 base class, via a derived-to-base conversion. Must NOT resolve
    // to the library's own generic array-compatible to_json (an exact-match
    // template for vector3_wrapper, since it also has begin()/end()), which
    // would serialize this as [x, y, z] instead of {"x":x, "y":y, "z":z}.
    to_json(j, to_eigen(p));
}
} // namespace issue_4320

TEST_CASE("issue #4320 - custom base class must not leak nlohmann::detail into ADL")
{
    // Before the fix, basic_json unconditionally derived from a type living in
    // nlohmann::detail (json_default_base), which made nlohmann::detail an
    // associated namespace of every basic_json for ADL purposes. That leaked
    // the library's internal generic-array to_json overload into unqualified
    // to_json() calls made from user code, silently bypassing user-defined
    // to_json overloads reached via a derived-to-base conversion.
    const issue_4320::payload p{1.0, 2.0, 3.0};

    json j;
    to_json(j, p);
    CHECK(j == json({{"x", 1.0}, {"y", 2.0}, {"z", 3.0}}));
}

TEST_CASE("issue #5338 - truncated CBOR tagged binary subtype is rejected")
{
    const std::vector<std::vector<std::uint8_t>> truncated_tags =
    {
        {0xD8},
        {0xD9, 0x00},
        {0xDA, 0x00, 0x00, 0x00},
        {0xDB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
    };

    for (const auto& data : truncated_tags)
    {
        CAPTURE(data);
        for (const auto tag_handler :
                {
                    json::cbor_tag_handler_t::ignore, json::cbor_tag_handler_t::store
                })
        {
            CAPTURE(tag_handler);
            const auto result = json::from_cbor(data, true, false, tag_handler);
            CHECK(result.is_discarded());
        }
    }
}

/////////////////////////////////////////////////////////////////////
// for #3171
/////////////////////////////////////////////////////////////////////

struct for_3171_base // NOLINT(cppcoreguidelines-special-member-functions)
{
    for_3171_base(const std::string& /*unused*/ = {}) {}
    virtual ~for_3171_base();

    for_3171_base(const for_3171_base& other) // NOLINT(hicpp-use-equals-default,modernize-use-equals-default)
        : str(other.str)
    {}

    for_3171_base& operator=(const for_3171_base& other)
    {
        if (this != &other)
        {
            str = other.str;
        }
        return *this;
    }

    for_3171_base(for_3171_base&& other) noexcept
        : str(std::move(other.str))
    {}

    for_3171_base& operator=(for_3171_base&& other) noexcept
    {
        if (this != &other)
        {
            str = std::move(other.str);
        }
        return *this;
    }

    virtual void _from_json(const json& j)
    {
        j.at("str").get_to(str);
    }

    std::string str{}; // NOLINT(readability-redundant-member-init)
};

for_3171_base::~for_3171_base() = default;

struct for_3171_derived : public for_3171_base
{
    for_3171_derived() = default;
    ~for_3171_derived() override;
    explicit for_3171_derived(const std::string& /*unused*/) { }

    for_3171_derived(const for_3171_derived& other) // NOLINT(hicpp-use-equals-default,modernize-use-equals-default)
        : for_3171_base(other)
    {}

    for_3171_derived& operator=(const for_3171_derived& other)
    {
        if (this != &other)
        {
            for_3171_base::operator=(other); // Call base class assignment operator
        }
        return *this;
    }

    for_3171_derived(for_3171_derived&& other) noexcept
        : for_3171_base(std::move(other))
    {}

    for_3171_derived& operator=(for_3171_derived&& other) noexcept
    {
        if (this != &other)
        {
            for_3171_base::operator=(std::move(other)); // Call base class move assignment operator
        }
        return *this;
    }
};

for_3171_derived::~for_3171_derived() = default;

inline void from_json(const json& j, for_3171_base& tb) // NOLINT(misc-use-internal-linkage)
{
    tb._from_json(j);
}

/////////////////////////////////////////////////////////////////////
// for #3312
/////////////////////////////////////////////////////////////////////

#ifdef JSON_HAS_CPP_20
struct for_3312
{
    std::string name;
};

inline void from_json(const json& j, for_3312& obj) // NOLINT(misc-use-internal-linkage)
{
    j.at("name").get_to(obj.name);
}
#endif

/////////////////////////////////////////////////////////////////////
// for #3204
/////////////////////////////////////////////////////////////////////

struct for_3204_foo
{
    for_3204_foo() = default;
    explicit for_3204_foo(std::string /*unused*/) {} // NOLINT(performance-unnecessary-value-param)
};

struct for_3204_bar
{
    enum constructed_from_t // NOLINT(cppcoreguidelines-use-enum-class)
    {
        constructed_from_none = 0,
        constructed_from_foo = 1,
        constructed_from_json = 2
    };

    explicit for_3204_bar(std::function<void(for_3204_foo)> /*unused*/) noexcept // NOLINT(performance-unnecessary-value-param)
        : constructed_from(constructed_from_foo) {}
    explicit for_3204_bar(std::function<void(json)> /*unused*/) noexcept // NOLINT(performance-unnecessary-value-param)
        : constructed_from(constructed_from_json) {}

    constructed_from_t constructed_from = constructed_from_none;
};

/////////////////////////////////////////////////////////////////////
// for #3333
/////////////////////////////////////////////////////////////////////

struct for_3333 final
{
    for_3333(int x_ = 0, int y_ = 0) : x(x_), y(y_) {}

    template <class T>
    for_3333(const T& /*unused*/)
    {
        CHECK(false);
    }

    int x = 0;
    int y = 0;
};

template <>
inline for_3333::for_3333(const json& j)
    : for_3333(j.value("x", 0), j.value("y", 0))
{}

/////////////////////////////////////////////////////////////////////
// for #3810
/////////////////////////////////////////////////////////////////////

struct Example_3810
{
    int bla{};

    Example_3810() = default;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Example_3810, bla) // NOLINT(misc-use-internal-linkage)

/////////////////////////////////////////////////////////////////////
// for #4740
/////////////////////////////////////////////////////////////////////

#ifdef JSON_HAS_CPP_17
struct Example_4740
{
    std::optional<std::string> host = std::nullopt;
    std::optional<int> port = std::nullopt;
    NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(Example_4740, host, port)
};
#endif

TEST_CASE("regression tests 2 (continued)")
{
    SECTION("issue #3171 - if class is_constructible from std::string wrong from_json overload is being selected, compilation failed")
    {
        const json j{{ "str", "value"}};

        // failed with: error: no match for ‘operator=’ (operand types are ‘for_3171_derived’ and ‘const nlohmann::basic_json<>::string_t’
        //                                               {aka ‘const std::__cxx11::basic_string<char>’})
        //                  s = *j.template get_ptr<const typename BasicJsonType::string_t*>();
        auto td = j.get<for_3171_derived>();

        CHECK(td.str == "value");
    }

#ifdef JSON_HAS_CPP_20
    SECTION("issue #3312 - Parse to custom class from unordered_json breaks on G++11.2.0 with C++20")
    {
        // see test for #3171
        const ordered_json j = {{"name", "class"}};
        for_3312 obj{};

        j.get_to(obj);

        CHECK(obj.name == "class");
    }
#endif

#if defined(JSON_HAS_CPP_17) && JSON_USE_IMPLICIT_CONVERSIONS
    SECTION("issue #3428 - Error occurred when converting nlohmann::json to std::any")
    {
        const json j;
        const std::any a1 = j;
        std::any&& a2 = j;

        CHECK(a1.type() == typeid(j));
        CHECK(a2.type() == typeid(j));
    }
#endif

    SECTION("issue #3204 - ambiguous regression")
    {
        const for_3204_bar bar_from_foo([](for_3204_foo) noexcept {}); // NOLINT(performance-unnecessary-value-param)
        const for_3204_bar bar_from_json([](json) noexcept {}); // NOLINT(performance-unnecessary-value-param)

        CHECK(bar_from_foo.constructed_from == for_3204_bar::constructed_from_foo);
        CHECK(bar_from_json.constructed_from == for_3204_bar::constructed_from_json);
    }

    SECTION("issue #3333 - Ambiguous conversion from nlohmann::basic_json<> to custom class")
    {
        const json j
        {
            {"x", 1},
            {"y", 2}
        };
        const for_3333 p = j;

        CHECK(p.x == 1);
        CHECK(p.y == 2);
    }

    SECTION("issue #3810 - ordered_json doesn't support construction from C array of custom type")
    {
        Example_3810 states[45]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)

        // fix "not used" warning
        states[0].bla = 1;

        const auto* const expected = R"([{"bla":1},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0},{"bla":0}])";

        // This works:
        nlohmann::json j;
        j["test"] = states;
        CHECK(j["test"].dump() == expected);

        // This doesn't compile:
        nlohmann::ordered_json oj;
        oj["test"] = states;
        CHECK(oj["test"].dump() == expected);
    }

#ifdef JSON_HAS_CPP_17
    SECTION("issue #4740 - build issue with std::optional")
    {
        const auto t1 = Example_4740();
        const auto j1 = nlohmann::json(t1);
        CHECK(j1.dump() == "{\"host\":null,\"port\":null}");
        const auto t2 = j1.get<Example_4740>();
        CHECK(!t2.host.has_value());
        CHECK(!t2.port.has_value());

        // improve coverage
        auto t3 = Example_4740();
        t3.port = 80;
        t3.host = "example.com";
        const auto j2 = nlohmann::json(t3);
        CHECK(j2.dump() == "{\"host\":\"example.com\",\"port\":80}");
        const auto t4 = j2.get<Example_4740>();
        CHECK(t4.host.has_value());
        CHECK(t4.port.has_value());
    }
#endif

#if !defined(_MSVC_LANG)
    // MSVC returns garbage on invalid enum values, so this test is excluded
    // there.
    SECTION("issue #4762 - json exception 302 with unhelpful explanation : type must be number, but is number")
    {
        // In #4762, the main issue was that a json object with an invalid type
        // returned "number" as type_name(), because this was the default case.
        // This test makes sure we now return "invalid" instead.
        json j;
        j.m_data.m_type = static_cast<json::value_t>(100); // NOLINT(clang-analyzer-optin.core.EnumCastOutOfRange)
        CHECK(j.type_name() == "invalid");
    }
#endif

#ifdef JSON_HAS_CPP_17
    SECTION("issue #4804: from_cbor incompatible with std::vector<std::byte> as binary_t")
    {
        const std::vector<std::uint8_t> data = {0x80};
        const auto decoded = json_4804::from_cbor(data);
        CHECK((decoded == json_4804::array()));
    }

    SECTION("discussion #4209 - custom BinaryType direct assignment and round-tripping")
    {
        // Test that assigning a custom BinaryType directly creates a binary value, not an array
        const std::vector<std::byte> original{std::byte{1}, std::byte{2}, std::byte{3}};
        const json_4804 j = original;
        CHECK(j.is_binary());
        CHECK(!j.is_array());

        // Test round-tripping: extracting the binary value back as the custom container type
        const auto extracted = j.get<std::vector<std::byte>>();
        CHECK(extracted == original);

        // Test that the default json alias behavior is unchanged: std::vector<uint8_t> -> array
        const json default_json = std::vector<std::uint8_t> {1, 2, 3};
        CHECK(default_json.is_array());
        CHECK(!default_json.is_binary());
    }

    SECTION("discussion #4209 - custom BinaryType extraction from parsed array")
    {
        // Test that extracting a custom BinaryType from a parsed JSON array still works
        // (not just from a binary-typed node)
        const auto j = json_4804::parse("[1,2,3]");
        CHECK(j.is_array());
        CHECK(!j.is_binary());

        // Extracting as custom BinaryType should work from arrays
        const auto extracted = j.get<std::vector<std::byte>>();
        CHECK(extracted.size() == 3);
        CHECK(extracted[0] == std::byte{1});
        CHECK(extracted[1] == std::byte{2});
        CHECK(extracted[2] == std::byte{3});
    }

    SECTION("issue #5046 - implicit conversion of return json to std::optional no longer implicit")
    {
        const json jval{};
        auto GetValue = [](const json & valRoot) -> std::optional<json>
        {
            if (valRoot.contains("default"))
            {
                return valRoot.at("default");
            }
            return std::nullopt;
        };
        auto result = GetValue(jval);
        CHECK(!result.has_value());
    }
#endif

#if JSON_HAS_RANGES == 1
    SECTION("issue #4440 - assert when using std::views::filter and GCC 10")
    {
        auto noOpFilter = std::views::filter([](auto&&) noexcept
        {
            return true;
        });
        json j = {1, 2, 3};
        auto filtered = j | noOpFilter;
        CHECK(*filtered.begin() == 1);
    }
#endif

#if JSON_HAS_RANGES && !defined(__MINGW32__)
    SECTION("issue #4916 - constructing array from C++20 ranges view does not work")
    {
        std::vector<int> nums{1, 2, 37, 42, 21};
        auto filteredNums = nums | std::views::filter([](int i)
        {
            return i > 10;
        });
        json const j(filteredNums);
        CHECK(j.type() == json::value_t::array);
        CHECK(j == json({37, 42, 21}));
    }
#endif

    // owning_view is not available in libstdc++ < 12
#if JSON_HAS_RANGES && !defined(__MINGW32__) && !(defined(__GLIBCXX__) && _GLIBCXX_RELEASE < 12)
    SECTION("issue #4916 - constructing array from prvalue C++20 ranges view (owning_view)")
    {
        json const j(std::vector<int> {1, 2, 37, 42, 21} | std::views::filter([](int i)
        {
            return i > 10;
        }));
        CHECK(j.type() == json::value_t::array);
        CHECK(j == json({37, 42, 21}));
    }
#endif

#if JSON_HAS_RANGES && !defined(__MINGW32__)
    SECTION("issue #4916 - constructing array from C++20 transform view (prvalue elements)")
    {
        std::vector<int> nums{1, 2, 3};
        auto t = nums | std::views::transform([](int i) noexcept
        {
            return i * 2;
        });
        json const j(t);
        CHECK(j.type() == json::value_t::array);
        CHECK(j == json({2, 4, 6}));
    }
#endif
}

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

/////////////////////////////////////////////////////////////////////
// for #3077
/////////////////////////////////////////////////////////////////////

class FooAlloc
{};

class Foo
{
  public:
    explicit Foo(const FooAlloc& /* unused */ = FooAlloc()) {}

    bool value = false;
};

class FooBar
{
  public:
    Foo foo{}; // NOLINT(readability-redundant-member-init)
};

inline void from_json(const nlohmann::json& j, FooBar& fb) // NOLINT(misc-use-internal-linkage)
{
    j.at("value").get_to(fb.foo.value);
}


TEST_CASE("regression tests 2 (continued 2)")
{
    SECTION("issue #2067 - cannot serialize binary data to text JSON")
    {
        const std::array<unsigned char, 23> data = {{0x81, 0xA4, 0x64, 0x61, 0x74, 0x61, 0xC4, 0x0F, 0x33, 0x30, 0x30, 0x32, 0x33, 0x34, 0x30, 0x31, 0x30, 0x37, 0x30, 0x35, 0x30, 0x31, 0x30}};
        const json j = json::from_msgpack(data.data(), data.size());
        CHECK_NOTHROW(
            j.dump(4,                             // Indent
                   ' ',                           // Indent char
                   false,                         // Ensure ascii
                   json::error_handler_t::strict  // Error
                  ));
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
        const auto s = std::as_bytes(std::span(DATA));
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

#if JSON_HAS_FILESYSTEM || JSON_HAS_EXPERIMENTAL_FILESYSTEM
    // JSON_HAS_CPP_17 (do not remove; see note at top of file)
    SECTION("issue #3070 - Version 3.10.3 breaks backward-compatibility with 3.10.2 ")
    {
        nlohmann::detail::std_fs::path text_path("/tmp/text.txt");
        const json j(text_path);

        const auto j_path = j.get<nlohmann::detail::std_fs::path>();
        CHECK(j_path == text_path);

#if DOCTEST_CLANG || DOCTEST_GCC >= DOCTEST_COMPILER(8, 4, 0)
        // only known to work on Clang and GCC >=8.4
        CHECK_THROWS_WITH_AS(nlohmann::detail::std_fs::path(json(1)), "[json.exception.type_error.302] type must be string, but is number", json::type_error);
#endif
    }
#endif

    SECTION("issue #3077 - explicit constructor with default does not compile")
    {
        json j;
        j[0]["value"] = true;
        std::vector<FooBar> foo;
        j.get_to(foo);
    }

    SECTION("issue #3108 - ordered_json doesn't support range based erase")
    {
        ordered_json j = {1, 2, 2, 4};

        auto last = std::unique(j.begin(), j.end());
        j.erase(last, j.end());

        CHECK(j.dump() == "[1,2,4]");

        j.erase(std::remove_if(j.begin(), j.end(), [](const ordered_json & val)
        {
            return val == 2;
        }), j.end());

        CHECK(j.dump() == "[1,4]");
    }

    SECTION("issue #3343 - json and ordered_json are not interchangeable")
    {
        json::object_t jobj({ { "product", "one" } });
        ordered_json::object_t ojobj({{"product", "one"}});

        auto jit = jobj.begin();
        auto ojit = ojobj.begin();

        CHECK(jit->first == ojit->first);
        CHECK(jit->second.get<std::string>() == ojit->second.get<std::string>());
    }

}

TEST_CASE("issue #5402 - update(merge_objects=true) overwrites a primitive with an object")
{
    json t = {{"k", 1}};
    t.update(json{{"k", {{"x", 2}}}}, true);
    CHECK(t == json({{"k", {{"x", 2}}}}));

    json mixed = {{"keep", {{"a", 1}}}, {"replace", 1}};
    mixed.update(json{{"keep", {{"b", 2}}}, {"replace", {{"x", 2}}}}, true);
    CHECK(mixed == json({{"keep", {{"a", 1}, {"b", 2}}}, {"replace", {{"x", 2}}}}));
}

DOCTEST_CLANG_SUPPRESS_WARNING_POP
