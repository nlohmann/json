//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-FileCopyrightText: 2018 Vitaliy Manushkin <agri@akamo.info>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

// NLOHMANN_JSON_SERIALIZE_ENUM_STRICT uses a static std::pair
DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wexit-time-destructors")

/* forward declarations */
class alt_string;
bool operator<(const char* op1, const alt_string& op2) noexcept; // NOLINT(misc-use-internal-linkage)
void int_to_string(alt_string& target, std::size_t value); // NOLINT(misc-use-internal-linkage)

/*
 * This is virtually a string class.
 * It covers std::string under the hood.
 *
 * It deliberately does not provide c_str(), back(), find(str, pos), replace(),
 * or substr(): the library must not rely on them. Do not add members here
 * without checking that the library actually needs them.
 */
class alt_string
{
  public:
    using value_type = std::string::value_type;

    static constexpr auto npos = (std::numeric_limits<std::size_t>::max)();

    alt_string(const char* str): str_impl(str) {}
    alt_string(const char* str, std::size_t count): str_impl(str, count) {}
    alt_string(size_t count, char chr): str_impl(count, chr) {}
    alt_string() = default;

    alt_string& append(char ch)
    {
        str_impl.push_back(ch);
        return *this;
    }

    alt_string& append(const alt_string& str)
    {
        str_impl.append(str.str_impl);
        return *this;
    }

    alt_string& append(const char* s, std::size_t length)
    {
        str_impl.append(s, length);
        return *this;
    }

    void push_back(char c)
    {
        str_impl.push_back(c);
    }

    template <typename op_type>
    bool operator==(const op_type& op) const
    {
        return str_impl == op;
    }

    bool operator==(const alt_string& op) const
    {
        return str_impl == op.str_impl;
    }

    template <typename op_type>
    bool operator!=(const op_type& op) const
    {
        return str_impl != op;
    }

    bool operator!=(const alt_string& op) const
    {
        return str_impl != op.str_impl;
    }

    std::size_t size() const noexcept
    {
        return str_impl.size();
    }

    void resize (std::size_t n)
    {
        str_impl.resize(n);
    }

    void resize (std::size_t n, char c)
    {
        str_impl.resize(n, c);
    }

    template <typename op_type>
    bool operator<(const op_type& op) const noexcept
    {
        return str_impl < op;
    }

    bool operator<(const alt_string& op) const noexcept
    {
        return str_impl < op.str_impl;
    }

    char& operator[](std::size_t index)
    {
        return str_impl[index];
    }

    const char& operator[](std::size_t index) const
    {
        return str_impl[index];
    }

    void clear()
    {
        str_impl.clear();
    }

    const value_type* data() const
    {
        return str_impl.data();
    }

    bool empty() const
    {
        return str_impl.empty();
    }

    std::size_t find_first_of(char c, std::size_t pos = 0) const
    {
        return str_impl.find_first_of(c, pos);
    }

    void reserve( std::size_t new_cap = 0 )
    {
        str_impl.reserve(new_cap);
    }

  private:
    std::string str_impl {}; // NOLINT(readability-redundant-member-init)

    friend bool operator<(const char* /*op1*/, const alt_string& /*op2*/) noexcept;
};

void int_to_string(alt_string& target, std::size_t value)
{
    target = std::to_string(value).c_str();
}

using alt_json = nlohmann::basic_json <
                 std::map,
                 std::vector,
                 alt_string,
                 bool,
                 std::int64_t,
                 std::uint64_t,
                 double,
                 std::allocator,
                 nlohmann::adl_serializer >;

bool operator<(const char* op1, const alt_string& op2) noexcept
{
    return op1 < op2.str_impl;
}

enum class alt_color { red, green }; // NOLINT(misc-use-internal-linkage)

// NOLINTNEXTLINE(misc-use-internal-linkage,misc-const-correctness,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) - false positive
NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(alt_color,
{
    {alt_color::red, "red"},
    {alt_color::green, "green"},
})

TEST_CASE("alternative string type")
{
    SECTION("binary formats")
    {
        alt_json doc;
        doc["pi"] = 3.141;
        doc["happy"] = true;
        doc["list"] = {1, 2, 3};

        CHECK(alt_json::from_cbor(alt_json::to_cbor(doc)) == doc);
        CHECK(alt_json::from_msgpack(alt_json::to_msgpack(doc)) == doc);
        CHECK(alt_json::from_bon8(alt_json::to_bon8(doc)) == doc);
        // BSON is not covered: it additionally needs string_t::find(value_type),
        // which alt_string does not provide
        CHECK(alt_json::from_ubjson(alt_json::to_ubjson(doc)) == doc);

        // a UBJSON high-precision number is parsed into a std::string that the
        // reader has to hand to the SAX interface as an alt_string
        const std::vector<uint8_t> high_precision =
        {
            'H', 'i', 0x16, '3', '.', '1', '4', '1', '5', '9', '2', '6', '5', '3',
            '5', '8', '9', '7', '9', '3', '2', '3', '8', '4', '6'
        };
        const auto number = alt_json::from_ubjson(high_precision);
        CHECK(number.is_number_float());
        CHECK(number.get<double>() == doctest::Approx(3.14159265358979323846));
    }

    SECTION("dump")
    {
        {
            alt_json doc;
            doc["pi"] = 3.141;
            const alt_string dump = doc.dump();
            CHECK(dump == R"({"pi":3.141})");
        }

        {
            alt_json doc;
            doc["happy"] = true;
            const alt_string dump = doc.dump();
            CHECK(dump == R"({"happy":true})");
        }

        {
            alt_json doc;
            doc["name"] = "I'm Batman";
            const alt_string dump = doc.dump();
            CHECK(dump == R"({"name":"I'm Batman"})");
        }

        {
            alt_json doc;
            doc["nothing"] = nullptr;
            const alt_string dump = doc.dump();
            CHECK(dump == R"({"nothing":null})");
        }

        {
            alt_json doc;
            doc["answer"]["everything"] = 42;
            const alt_string dump = doc.dump();
            CHECK(dump == R"({"answer":{"everything":42}})");
        }

        {
            alt_json doc;
            doc["list"] = { 1, 0, 2 };
            const alt_string dump = doc.dump();
            CHECK(dump == R"({"list":[1,0,2]})");
        }

        {
            alt_json doc;
            doc["object"] = { {"currency", "USD"}, {"value", 42.99} };
            const alt_string dump = doc.dump();
            CHECK(dump == R"({"object":{"currency":"USD","value":42.99}})");
        }
    }

    SECTION("parse")
    {
        auto doc = alt_json::parse(R"({"foo": "bar"})");
        const alt_string dump = doc.dump();
        CHECK(dump == R"({"foo":"bar"})");
    }

    SECTION("items")
    {
        auto doc = alt_json::parse(R"({"foo": "bar"})");

        for (const auto& item : doc.items())
        {
            CHECK(item.key() == "foo");
            CHECK(item.value() == "bar");
        }

        auto doc_array = alt_json::parse(R"(["foo", "bar"])");

        for (const auto& item : doc_array.items())
        {
            if (item.key() == "0" )
            {
                CHECK( item.value() == "foo" );
            }
            else if (item.key() == "1" )
            {
                CHECK(item.value() == "bar");
            }
            else
            {
                CHECK(false);
            }
        }
    }

    SECTION("equality")
    {
        alt_json doc;
        doc["Who are you?"] = "I'm Batman";

        CHECK("I'm Batman" == doc["Who are you?"]);
        CHECK(doc["Who are you?"]  == "I'm Batman");
        CHECK_FALSE("I'm Batman" != doc["Who are you?"]);
        CHECK_FALSE(doc["Who are you?"]  != "I'm Batman");

        CHECK("I'm Bruce Wayne" != doc["Who are you?"]);
        CHECK(doc["Who are you?"]  != "I'm Bruce Wayne");
        CHECK_FALSE("I'm Bruce Wayne" == doc["Who are you?"]);
        CHECK_FALSE(doc["Who are you?"]  == "I'm Bruce Wayne");

        {
            const alt_json& const_doc = doc;

            CHECK("I'm Batman" == const_doc["Who are you?"]);
            CHECK(const_doc["Who are you?"] == "I'm Batman");
            CHECK_FALSE("I'm Batman" != const_doc["Who are you?"]);
            CHECK_FALSE(const_doc["Who are you?"] != "I'm Batman");

            CHECK("I'm Bruce Wayne" != const_doc["Who are you?"]);
            CHECK(const_doc["Who are you?"] != "I'm Bruce Wayne");
            CHECK_FALSE("I'm Bruce Wayne" == const_doc["Who are you?"]);
            CHECK_FALSE(const_doc["Who are you?"] == "I'm Bruce Wayne");
        }
    }

    SECTION("JSON pointer")
    {
        // Direct conversion from a json literal to alt_json is not supported due to issue #3425:
        // alt_json's string_t (alt_string) is not directly constructible from std::string, so the
        // cross-basic_json conversion falls back to the array-conversion path, incorrectly representing
        // objects as arrays of [key, value] pairs and strings as arrays of character codes.
        // See https://github.com/nlohmann/json/issues/3425 for details.
        // Workaround: use alt_json::parse() instead of implicit conversion.
        auto j = alt_json::parse(R"({"foo": ["bar", "baz"]})");

        CHECK(j.at(alt_json::json_pointer("/foo/0")) == j["foo"][0]);
        CHECK(j.at(alt_json::json_pointer("/foo/1")) == j["foo"][1]);

        // RFC 6901 escaping works without string_t::find(str, pos), replace(),
        // and substr()
        auto j2 = alt_json::parse(R"({"a/b": 1, "m~n": 2, "~/~~//": 3})");
        CHECK(j2.at(alt_json::json_pointer("/a~1b")) == 1);
        CHECK(j2.at(alt_json::json_pointer("/m~0n")) == 2);
        CHECK(j2.at(alt_json::json_pointer("/~0~1~0~0~1~1")) == 3);
        CHECK(alt_json::json_pointer("/~0~1~0~0~1~1").to_string() == alt_string("/~0~1~0~0~1~1"));
        CHECK(j2.flatten().unflatten() == j2);
    }

    SECTION("contains(json_pointer)")
    {
        // contains(json_pointer) must compile and work with a string_t that has
        // no c_str() and no comparison with const char* (see #5666)
        auto j = alt_json::parse(R"({"foo": ["bar", "baz"]})");

        // present: object key and array indices
        CHECK(j.contains(alt_json::json_pointer("/foo")));
        CHECK(j.contains(alt_json::json_pointer("/foo/0")));
        CHECK(j.contains(alt_json::json_pointer("/foo/1")));

        // missing: absent object key and out-of-range array index
        CHECK_FALSE(j.contains(alt_json::json_pointer("/bar")));
        CHECK_FALSE(j.contains(alt_json::json_pointer("/foo/2")));

        // "-" always fails the range check
        CHECK_FALSE(j.contains(alt_json::json_pointer("/foo/-")));

        // an array index must not have a leading zero
        CHECK_FALSE(j.contains(alt_json::json_pointer("/foo/01")));

        // a reference token that is not a number
        CHECK_FALSE(j.contains(alt_json::json_pointer("/foo/bar")));
    }

    SECTION("operator/(std::size_t)")
    {
        // json_pointer::operator/=(std::size_t) must compile without string_t
        // being constructible from std::string (see #5666)
        auto j = alt_json::parse(R"({"foo": ["bar", "baz"]})");

        CHECK(j.at(alt_json::json_pointer("/foo") / std::size_t(0)) == j["foo"][0]);
        CHECK(j.at(alt_json::json_pointer("/foo") / std::size_t(1)) == j["foo"][1]);
    }

    SECTION("patch")
    {
        alt_json const patch1 = alt_json::parse(R"([{ "op": "add", "path": "/a/b", "value": [ "foo", "bar" ] }])");
        alt_json const doc1 = alt_json::parse(R"({ "a": { "foo": 1 } })");

        CHECK_NOTHROW(doc1.patch(patch1));
        alt_json doc1_ans = alt_json::parse(R"(
                                            {
                                                "a": {
                                                    "foo": 1,
                                                    "b": [ "foo", "bar" ]
                                                }
                                            }
                                           )");
        CHECK(doc1.patch(patch1) == doc1_ans);
    }

    SECTION("diff")
    {
        alt_json const j1 = {"foo", "bar", "baz"};
        alt_json const j2 = {"foo", "bam"};
        CHECK(alt_json::diff(j1, j2).dump() == "[{\"op\":\"replace\",\"path\":\"/1\",\"value\":\"bam\"},{\"op\":\"remove\",\"path\":\"/2\"}]");
    }

    SECTION("flatten")
    {
        // a JSON value
        const alt_json j = alt_json::parse(R"({"foo": ["bar", "baz"]})");
        const auto j2 = j.flatten();
        CHECK(j2.dump() == R"({"/foo/0":"bar","/foo/1":"baz"})");
    }

    SECTION("conversion between basic_json specializations (#2649)")
    {
        // explicit conversions are always possible
        CHECK(std::is_constructible<nlohmann::json, alt_json>::value);
        CHECK(std::is_constructible<alt_json, nlohmann::json>::value);
        CHECK(std::is_constructible<nlohmann::json, nlohmann::ordered_json>::value);
        CHECK(std::is_constructible<nlohmann::ordered_json, nlohmann::json>::value);

        // specializations with the same string type are implicitly convertible
        CHECK(std::is_convertible<nlohmann::ordered_json, nlohmann::json>::value);
        CHECK(std::is_convertible<nlohmann::json, nlohmann::ordered_json>::value);

        // specializations with different string types are only implicitly convertible
        // if implicit conversions are enabled
#if JSON_USE_IMPLICIT_CONVERSIONS
        CHECK(std::is_convertible<alt_json, nlohmann::json>::value);
        CHECK(std::is_convertible<nlohmann::json, alt_json>::value);
#else
        CHECK_FALSE(std::is_convertible<alt_json, nlohmann::json>::value);
        CHECK_FALSE(std::is_convertible<nlohmann::json, alt_json>::value);
#endif

        // get<BasicJsonType>() works in either case
        const nlohmann::json j = {{"foo", 1}, {"bar", true}};
        CHECK(j.get<nlohmann::ordered_json>() == nlohmann::ordered_json(j));
        // (only a number is converted here, as objects and strings are affected by #3425)
        CHECK(nlohmann::json(42).get<alt_json>() == 42);
        CHECK(alt_json(nlohmann::json(42)) == 42);

        // get_to() also works in either case
        alt_json a;
        nlohmann::json(42).get_to(a);
        CHECK(a == 42);
    }

    SECTION("strict enum")
    {
        // regression test for #5667: NLOHMANN_JSON_SERIALIZE_ENUM_STRICT's from_json
        // built its exception message with "..." + j.dump(), which does not compile
        // when j.dump() returns a custom string_t (here alt_string) instead of
        // std::string
        alt_json doc;
        doc = "red";
        CHECK(doc.get<alt_color>() == alt_color::red);

        alt_json _;
        doc = "blue";
        CHECK_THROWS_WITH_AS(_ = doc.get<alt_color>(), "[json.exception.out_of_range.410] enum value out of range for alt_color: \"blue\"", alt_json::out_of_range&);
    }
}

DOCTEST_CLANG_SUPPRESS_WARNING_POP
