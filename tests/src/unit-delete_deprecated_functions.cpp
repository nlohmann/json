//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// This file tests the opt-in JSON_DELETE_DEPRECATED_FUNCTIONS, so it defines the
// macro itself instead of relying on the build configuration.
#ifdef JSON_DELETE_DEPRECATED_FUNCTIONS
    #undef JSON_DELETE_DEPRECATED_FUNCTIONS
#endif
#define JSON_DELETE_DEPRECATED_FUNCTIONS 1

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <cstddef>
#include <cstdint>
#include <istream>
#include <ostream>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>

namespace
{
template<typename...>
struct make_void
{
    using type = void;
};

template<typename... Ts>
using void_t = typename make_void<Ts...>::type;

// A deleted function is still found by overload resolution, but naming it in an
// unevaluated operand is ill-formed, so each of the following traits is false
// exactly if the expression selects a deleted (or no) function.
#define JSON_TEST_DETECT(name, expr)                                 \
    template<typename J, typename = void>                            \
    struct name : std::false_type {};                                \
    template<typename J>                                             \
    struct name<J, void_t<decltype(expr)>> : std::true_type {}

using ptr_t = const std::uint8_t*;

JSON_TEST_DETECT(from_cbor_ptr_len, J::from_cbor(std::declval<ptr_t>(), std::declval<std::size_t>()));
JSON_TEST_DETECT(from_msgpack_ptr_len, J::from_msgpack(std::declval<ptr_t>(), std::declval<std::size_t>()));
JSON_TEST_DETECT(from_ubjson_ptr_len, J::from_ubjson(std::declval<ptr_t>(), std::declval<std::size_t>()));
JSON_TEST_DETECT(from_bjdata_ptr_len, J::from_bjdata(std::declval<ptr_t>(), std::declval<std::size_t>()));
JSON_TEST_DETECT(from_bon8_ptr_len, J::from_bon8(std::declval<ptr_t>(), std::declval<std::size_t>()));
JSON_TEST_DETECT(from_bson_ptr_len, J::from_bson(std::declval<ptr_t>(), std::declval<std::size_t>()));

JSON_TEST_DETECT(from_cbor_ptr_ptr, J::from_cbor(std::declval<ptr_t>(), std::declval<ptr_t>()));
JSON_TEST_DETECT(from_msgpack_ptr_ptr, J::from_msgpack(std::declval<ptr_t>(), std::declval<ptr_t>()));
JSON_TEST_DETECT(from_ubjson_ptr_ptr, J::from_ubjson(std::declval<ptr_t>(), std::declval<ptr_t>()));
JSON_TEST_DETECT(from_bjdata_ptr_ptr, J::from_bjdata(std::declval<ptr_t>(), std::declval<ptr_t>()));
JSON_TEST_DETECT(from_bon8_ptr_ptr, J::from_bon8(std::declval<ptr_t>(), std::declval<ptr_t>()));
JSON_TEST_DETECT(from_bson_ptr_ptr, J::from_bson(std::declval<ptr_t>(), std::declval<ptr_t>()));

JSON_TEST_DETECT(from_cbor_init_list, J::from_cbor({std::declval<ptr_t>(), std::declval<std::size_t>()}));
JSON_TEST_DETECT(from_msgpack_init_list, J::from_msgpack({std::declval<ptr_t>(), std::declval<std::size_t>()}));
JSON_TEST_DETECT(from_ubjson_init_list, J::from_ubjson({std::declval<ptr_t>(), std::declval<std::size_t>()}));
JSON_TEST_DETECT(from_bson_init_list, J::from_bson({std::declval<ptr_t>(), std::declval<std::size_t>()}));

JSON_TEST_DETECT(parse_init_list, J::parse({std::declval<ptr_t>(), std::declval<std::size_t>()}));
JSON_TEST_DETECT(accept_init_list, J::accept({std::declval<ptr_t>(), std::declval<std::size_t>()}));
JSON_TEST_DETECT(sax_parse_init_list, J::sax_parse({std::declval<ptr_t>(), std::declval<std::size_t>()}, std::declval<nlohmann::json_sax<J>*>()));
JSON_TEST_DETECT(parse_ptr_ptr, J::parse(std::declval<ptr_t>(), std::declval<ptr_t>()));

JSON_TEST_DETECT(iterator_wrapper, J::iterator_wrapper(std::declval<J&>()));
JSON_TEST_DETECT(iterator_wrapper_const, J::iterator_wrapper(std::declval<const J&>()));
JSON_TEST_DETECT(items, std::declval<J&>().items());

JSON_TEST_DETECT(json_ltlt_istream, std::declval<J&>() << std::declval<std::istream&>());
JSON_TEST_DETECT(istream_gtgt_json, std::declval<std::istream&>() >> std::declval<J&>());
JSON_TEST_DETECT(json_gtgt_ostream, std::declval<const J&>() >> std::declval<std::ostream&>());
JSON_TEST_DETECT(ostream_ltlt_json, std::declval<std::ostream&>() << std::declval<const J&>());

JSON_TEST_DETECT(ptr_eq_ptr, std::declval<const typename J::json_pointer&>() == std::declval<const typename J::json_pointer&>());
JSON_TEST_DETECT(ptr_ne_ptr, std::declval<const typename J::json_pointer&>() != std::declval<const typename J::json_pointer&>());
JSON_TEST_DETECT(ptr_eq_string, std::declval<const typename J::json_pointer&>() == std::declval<const std::string&>());
JSON_TEST_DETECT(string_eq_ptr, std::declval<const std::string&>() == std::declval<const typename J::json_pointer&>());
JSON_TEST_DETECT(ptr_eq_c_string, std::declval<const typename J::json_pointer&>() == std::declval<const char*>());
JSON_TEST_DETECT(c_string_eq_ptr, std::declval<const char*>() == std::declval<const typename J::json_pointer&>());
JSON_TEST_DETECT(ptr_ne_string, std::declval<const typename J::json_pointer&>() != std::declval<const std::string&>());
JSON_TEST_DETECT(string_ne_ptr, std::declval<const std::string&>() != std::declval<const typename J::json_pointer&>());
JSON_TEST_DETECT(ptr_to_string, std::declval<const typename J::json_pointer&>().to_string());

// json_pointer with a basic_json type as template argument
template<typename J>
using legacy_ptr_t = const nlohmann::json_pointer<J>& ;
JSON_TEST_DETECT(legacy_ptr_value, std::declval<const J&>().value(std::declval<legacy_ptr_t<J>>(), 0));
JSON_TEST_DETECT(legacy_ptr_value_rvalue, std::declval<const J&>().value(std::declval<legacy_ptr_t<J>>(), std::string()));
JSON_TEST_DETECT(legacy_ptr_contains, std::declval<const J&>().contains(std::declval<legacy_ptr_t<J>>()));
JSON_TEST_DETECT(legacy_ptr_subscript, std::declval<J&>()[std::declval<legacy_ptr_t<J>>()]);
JSON_TEST_DETECT(legacy_ptr_subscript_const, std::declval<const J&>()[std::declval<legacy_ptr_t<J>>()]);
JSON_TEST_DETECT(legacy_ptr_at, std::declval<J&>().at(std::declval<legacy_ptr_t<J>>()));
JSON_TEST_DETECT(legacy_ptr_at_const, std::declval<const J&>().at(std::declval<legacy_ptr_t<J>>()));
JSON_TEST_DETECT(ptr_value, std::declval<const J&>().value(std::declval<const typename J::json_pointer&>(), 0));
JSON_TEST_DETECT(ptr_at, std::declval<J&>().at(std::declval<const typename J::json_pointer&>()));

#undef JSON_TEST_DETECT
} // namespace

TEST_CASE("JSON_DELETE_DEPRECATED_FUNCTIONS")
{
    // MSVC 2015 does not treat selecting a deleted function in decltype as a
    // substitution failure, so the traits cannot tell deleted functions apart
    // there; calling them still fails to compile
#if !(defined(_MSC_VER) && _MSC_VER < 1910)
    SECTION("from_* with a pointer and a length")
    {
        // the overloads are deleted rather than removed, so the length cannot
        // silently bind to the strict parameter of from_*(InputType&&, bool)
        CHECK_FALSE(from_cbor_ptr_len<json>::value);
        CHECK_FALSE(from_msgpack_ptr_len<json>::value);
        CHECK_FALSE(from_ubjson_ptr_len<json>::value);
        CHECK_FALSE(from_bjdata_ptr_len<json>::value);
        CHECK_FALSE(from_bon8_ptr_len<json>::value);
        CHECK_FALSE(from_bson_ptr_len<json>::value);

        // the replacement
        CHECK(from_cbor_ptr_ptr<json>::value);
        CHECK(from_msgpack_ptr_ptr<json>::value);
        CHECK(from_ubjson_ptr_ptr<json>::value);
        CHECK(from_bjdata_ptr_ptr<json>::value);
        CHECK(from_bon8_ptr_ptr<json>::value);
        CHECK(from_bson_ptr_ptr<json>::value);
    }

    SECTION("initializer lists of a pointer and a length")
    {
        CHECK_FALSE(from_cbor_init_list<json>::value);
        CHECK_FALSE(from_msgpack_init_list<json>::value);
        CHECK_FALSE(from_ubjson_init_list<json>::value);
        CHECK_FALSE(from_bson_init_list<json>::value);
        CHECK_FALSE(parse_init_list<json>::value);
        CHECK_FALSE(accept_init_list<json>::value);
        CHECK_FALSE(sax_parse_init_list<json>::value);

        // the replacement
        CHECK(parse_ptr_ptr<json>::value);
    }

    SECTION("iterator_wrapper")
    {
        CHECK_FALSE(iterator_wrapper<json>::value);
        CHECK_FALSE(iterator_wrapper_const<json>::value);

        // the replacement
        CHECK(items<json>::value);
    }

    SECTION("stream operators with reversed operands")
    {
        CHECK_FALSE(json_ltlt_istream<json>::value);
        CHECK_FALSE(json_gtgt_ostream<json>::value);

        // the replacement
        CHECK(istream_gtgt_json<json>::value);
        CHECK(ostream_ltlt_json<json>::value);
    }

    SECTION("json_pointer")
    {
        // conversion to a string
        CHECK_FALSE(std::is_constructible<std::string, json::json_pointer>::value);
        CHECK_FALSE(std::is_convertible<json::json_pointer, std::string>::value);

        // comparison with a string
        CHECK_FALSE(ptr_eq_string<json>::value);
        CHECK_FALSE(string_eq_ptr<json>::value);
        CHECK_FALSE(ptr_eq_c_string<json>::value);
        CHECK_FALSE(c_string_eq_ptr<json>::value);
        CHECK_FALSE(ptr_ne_string<json>::value);
        CHECK_FALSE(string_ne_ptr<json>::value);

        // the replacement
        CHECK(ptr_to_string<json>::value);
        CHECK(ptr_eq_ptr<json>::value);
        CHECK(ptr_ne_ptr<json>::value);
    }

    SECTION("json_pointer with a basic_json type as template argument")
    {
        CHECK_FALSE(legacy_ptr_value<json>::value);
        CHECK_FALSE(legacy_ptr_value_rvalue<json>::value);
        CHECK_FALSE(legacy_ptr_contains<json>::value);
        CHECK_FALSE(legacy_ptr_subscript<json>::value);
        CHECK_FALSE(legacy_ptr_subscript_const<json>::value);
        CHECK_FALSE(legacy_ptr_at<json>::value);
        CHECK_FALSE(legacy_ptr_at_const<json>::value);

        // the replacement
        CHECK(ptr_value<json>::value);
        CHECK(ptr_at<json>::value);
    }

#endif

    SECTION("the non-deprecated functions still work")
    {
        const json j = {{"a", {1, 2}}};
        const auto cbor = json::to_cbor(j);
        CHECK(json::from_cbor(cbor.data(), cbor.data() + cbor.size()) == j);

        const json::json_pointer ptr("/a/1");
        CHECK(ptr == json::json_pointer("/a/1"));
        CHECK(ptr.to_string() == "/a/1");
        CHECK(j[ptr] == 2);
        CHECK(j.at(ptr) == 2);
        CHECK(j.value(ptr, 0) == 2);
        CHECK(j.contains(ptr));

        std::ostringstream os;
        os << j;
        CHECK(os.str() == R"({"a":[1,2]})");
        std::istringstream is(os.str());
        json parsed;
        is >> parsed;
        CHECK(parsed == j);
    }
}
