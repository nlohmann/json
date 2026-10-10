//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <type_traits>
#include <vector>

#if JSON_HAS_THREE_WAY_COMPARISON
    #include <compare>
#endif

namespace custom_number_types
{

// a signed integer of class type: std::is_signed is only true for arithmetic
// types, so the library has to take the signedness from std::numeric_limits,
// as it does for 128-bit and multiprecision integer classes such as
// absl::int128 or boost::multiprecision::cpp_int
class class_int
{
  public:
    // trivial, like the 128-bit integer classes: the value is stored in a union
    class_int() = default;

    // implicit from built-in integers and explicit from floats, like absl::int128
    template<typename T, typename std::enable_if<std::is_integral<T>::value, int>::type = 0>
    class_int(T v) : value(static_cast<std::int64_t>(v)) {} // NOLINT(google-explicit-constructor,hicpp-explicit-conversions)

    template<typename T, typename std::enable_if<std::is_floating_point<T>::value, int>::type = 0>
    explicit class_int(T v) : value(static_cast<std::int64_t>(v)) {}

    template<typename T, typename std::enable_if<std::is_arithmetic<T>::value, int>::type = 0>
    explicit operator T() const
    {
        return static_cast<T>(value);
    }

    friend bool operator==(class_int lhs, class_int rhs)
    {
        return lhs.value == rhs.value;
    }
    friend bool operator!=(class_int lhs, class_int rhs)
    {
        return lhs.value != rhs.value;
    }
    friend bool operator<(class_int lhs, class_int rhs)
    {
        return lhs.value < rhs.value;
    }
#if JSON_HAS_THREE_WAY_COMPARISON
    friend std::strong_ordering operator<=>(class_int lhs, class_int rhs) // *NOPAD*
    {
        return lhs.value <=> rhs.value; // *NOPAD*
    }
#endif

  private:
    std::int64_t value;
};

} // namespace custom_number_types

using custom_number_types::class_int;

namespace std
{
// only the members the library uses
template<>
class numeric_limits<class_int>
{
  public:
    static constexpr bool is_signed = true;
    static constexpr int digits = std::numeric_limits<std::int64_t>::digits;
};
} // namespace std

namespace
{

using class_int_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, class_int, std::uint64_t, double>;

class_int_json make_class_int(std::int64_t v)
{
    class_int_json j(class_int_json::value_t::number_integer);
    j.get_ref<class_int&>() = class_int(v);
    return j;
}

} // namespace

// the serializer cannot print an integer of class type, so doctest must not
// try when an assertion fails
namespace doctest
{
template<>
struct StringMaker<class_int_json>
{
    static String convert(const class_int_json& j)
    {
        return j.type_name();
    }
};
} // namespace doctest

// __int128 as number type needs the std::numeric_limits (for the range checks)
// and std::is_integral (for the serializer) specializations, which libc++
// always provides and libstdc++ only outside strict ISO modes; the MSVC
// standard library has none
#if defined(__SIZEOF_INT128__) && (defined(_LIBCPP_VERSION) || defined(__GLIBCXX_TYPE_INT_N_0))
    #define JSON_TEST_INT128_NUMBER_TYPES 1
#else
    #define JSON_TEST_INT128_NUMBER_TYPES 0
#endif

#if JSON_TEST_INT128_NUMBER_TYPES
namespace
{

// __extension__ keeps -Wpedantic from flagging the non-standard type
__extension__ typedef __int128 int128; // NOLINT(modernize-use-using)
__extension__ typedef unsigned __int128 uint128; // NOLINT(modernize-use-using)

static_assert(std::numeric_limits<int128>::digits == 127 && std::numeric_limits<uint128>::digits == 128 &&
              std::is_integral<int128>::value && std::is_integral<uint128>::value,
              "__int128 is not fully supported by the standard library");

using wide_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, int128, uint128, double>;

wide_json make_int(int128 v)
{
    wide_json j(wide_json::value_t::number_integer);
    j.get_ref<int128&>() = v;
    return j;
}

wide_json make_uint(uint128 v)
{
    wide_json j(wide_json::value_t::number_unsigned);
    j.get_ref<uint128&>() = v;
    return j;
}

wide_json wrap(const wide_json& value)
{
    wide_json o(wide_json::value_t::object);
    o["v"] = value;
    return o;
}

} // namespace

TEST_CASE("custom number types: integers beyond 64 bits")
{
    using out_of_range = wide_json::out_of_range;

    const int128 two_64 = static_cast<int128>(1) << 64;
    const int128 two_100 = static_cast<int128>(1) << 100;
    const int128 max_int64 = (std::numeric_limits<std::int64_t>::max)();
    const int128 min_int64 = (std::numeric_limits<std::int64_t>::min)();
    const uint128 max_uint64 = (std::numeric_limits<std::uint64_t>::max)();

    // before the range checks, these values were silently truncated, e.g.,
    // 2^100 was written as 0
    const wide_json int_big = make_int(two_100);
    const wide_json int_big_negative = make_int(-two_100);
    const wide_json uint_big = make_uint(static_cast<uint128>(two_100));
    std::vector<std::uint8_t> _;

    SECTION("CBOR")
    {
        CHECK_THROWS_WITH_AS(_ = wide_json::to_cbor(int_big), "[json.exception.out_of_range.407] integer number 1267650600228229401496703205376 cannot be represented by CBOR as it does not fit [-2^64, 2^64-1]", out_of_range&);
        CHECK_THROWS_WITH_AS(_ = wide_json::to_cbor(int_big_negative), "[json.exception.out_of_range.407] integer number -1267650600228229401496703205376 cannot be represented by CBOR as it does not fit [-2^64, 2^64-1]", out_of_range&);
        CHECK_THROWS_WITH_AS(_ = wide_json::to_cbor(uint_big), "[json.exception.out_of_range.407] integer number 1267650600228229401496703205376 cannot be represented by CBOR as it does not fit uint64", out_of_range&);
        CHECK_THROWS_AS(_ = wide_json::to_cbor(make_int(two_64)), out_of_range&);
        CHECK_THROWS_AS(_ = wide_json::to_cbor(make_int(-two_64 - 1)), out_of_range&);
        CHECK_THROWS_AS(_ = wide_json::to_cbor(make_uint(static_cast<uint128>(max_uint64) + 1)), out_of_range&);

        // CBOR's integers cover [-2^64, 2^64-1]
        CHECK(wide_json::to_cbor(make_int(two_64 - 1)) == std::vector<std::uint8_t>({0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}));
        CHECK(wide_json::to_cbor(make_int(-two_64)) == std::vector<std::uint8_t>({0x3B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}));
        CHECK(wide_json::to_cbor(make_uint(max_uint64)) == std::vector<std::uint8_t>({0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}));
    }

    SECTION("MessagePack")
    {
        CHECK_THROWS_WITH_AS(_ = wide_json::to_msgpack(int_big), "[json.exception.out_of_range.407] integer number 1267650600228229401496703205376 cannot be represented by MessagePack as it does not fit [-2^63, 2^64-1]", out_of_range&);
        CHECK_THROWS_WITH_AS(_ = wide_json::to_msgpack(int_big_negative), "[json.exception.out_of_range.407] integer number -1267650600228229401496703205376 cannot be represented by MessagePack as it does not fit [-2^63, 2^64-1]", out_of_range&);
        CHECK_THROWS_WITH_AS(_ = wide_json::to_msgpack(uint_big), "[json.exception.out_of_range.407] integer number 1267650600228229401496703205376 cannot be represented by MessagePack as it does not fit uint64", out_of_range&);
        CHECK_THROWS_AS(_ = wide_json::to_msgpack(make_int(two_64)), out_of_range&);
        CHECK_THROWS_AS(_ = wide_json::to_msgpack(make_int(min_int64 - 1)), out_of_range&);

        // MessagePack's integers cover [-2^63, 2^64-1]
        CHECK(wide_json::to_msgpack(make_int(two_64 - 1)) == std::vector<std::uint8_t>({0xCF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}));
        CHECK(wide_json::to_msgpack(make_int(min_int64)) == std::vector<std::uint8_t>({0xD3, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}));
        CHECK(wide_json::to_msgpack(make_uint(max_uint64)) == std::vector<std::uint8_t>({0xCF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}));
    }

    SECTION("BSON")
    {
        CHECK_THROWS_WITH_AS(_ = wide_json::to_bson(wrap(int_big)), "[json.exception.out_of_range.407] integer number 1267650600228229401496703205376 cannot be represented by BSON as it does not fit int64", out_of_range&);
        CHECK_THROWS_WITH_AS(_ = wide_json::to_bson(wrap(int_big_negative)), "[json.exception.out_of_range.407] integer number -1267650600228229401496703205376 cannot be represented by BSON as it does not fit int64", out_of_range&);
        CHECK_THROWS_WITH_AS(_ = wide_json::to_bson(wrap(uint_big)), "[json.exception.out_of_range.407] integer number 1267650600228229401496703205376 cannot be represented by BSON as it does not fit uint64", out_of_range&);
        CHECK_THROWS_AS(_ = wide_json::to_bson(wrap(make_int(max_int64 + 1))), out_of_range&);
        CHECK_THROWS_AS(_ = wide_json::to_bson(wrap(make_int(min_int64 - 1))), out_of_range&);

        // nested values are checked as well, before anything is written
        wide_json nested(wide_json::value_t::object);
        nested["a"] = wide_json::array({wrap(int_big)});
        std::vector<std::uint8_t> out;
        CHECK_THROWS_AS(wide_json::to_bson(nested, out), out_of_range&);
        CHECK(out.empty());

        CHECK(wide_json::from_bson(wide_json::to_bson(wrap(make_int(max_int64)))) == wrap(make_int(max_int64)));
        CHECK(wide_json::from_bson(wide_json::to_bson(wrap(make_int(min_int64)))) == wrap(make_int(min_int64)));
        CHECK_NOTHROW(wide_json::to_bson(wrap(make_uint(max_uint64))));
    }

    SECTION("BON8")
    {
        CHECK_THROWS_WITH_AS(_ = wide_json::to_bon8(int_big), "[json.exception.out_of_range.407] integer number 1267650600228229401496703205376 cannot be represented by BON8 as it does not fit int64", out_of_range&);
        CHECK_THROWS_WITH_AS(_ = wide_json::to_bon8(int_big_negative), "[json.exception.out_of_range.407] integer number -1267650600228229401496703205376 cannot be represented by BON8 as it does not fit int64", out_of_range&);
        CHECK_THROWS_WITH_AS(_ = wide_json::to_bon8(uint_big), "[json.exception.out_of_range.407] integer number 1267650600228229401496703205376 cannot be represented by BON8 as it does not fit int64", out_of_range&);
        CHECK_THROWS_AS(_ = wide_json::to_bon8(make_int(max_int64 + 1)), out_of_range&);
        CHECK_THROWS_AS(_ = wide_json::to_bon8(make_int(min_int64 - 1)), out_of_range&);

        CHECK(wide_json::from_bon8(wide_json::to_bon8(make_int(max_int64))) == make_int(max_int64));
        CHECK(wide_json::from_bon8(wide_json::to_bon8(make_int(min_int64))) == make_int(min_int64));
    }

    SECTION("UBJSON and BJData")
    {
        // integers beyond 64 bits are written exactly as high-precision numbers
        const std::string digits = "1267650600228229401496703205376";
        std::vector<std::uint8_t> expected = {'H', 'i', static_cast<std::uint8_t>(digits.size())};
        expected.insert(expected.end(), digits.begin(), digits.end());
        CHECK(wide_json::to_ubjson(int_big) == expected);
        CHECK(wide_json::to_ubjson(uint_big) == expected);
        CHECK(wide_json::to_bjdata(int_big) == expected);
        // BJData's uint64 marker 'M' was used for any unsigned value beyond
        // int64, which truncated the ones beyond 64 bits
        CHECK(wide_json::to_bjdata(uint_big) == expected);

        // the uint64 marker is still used where the value fits
        CHECK(wide_json::to_bjdata(make_uint(max_uint64)) == std::vector<std::uint8_t>({'M', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}));

        // the elements of an optimized container are written the same way;
        // BJData does not allow 'H' as the type of an optimized container
        std::vector<std::uint8_t> expected_ubjson_array = {'[', '$', 'H', '#', 'i', 2};
        std::vector<std::uint8_t> expected_bjdata_array = {'[', '#', 'i', 2};
        for (int i = 0; i < 2; ++i)
        {
            expected_ubjson_array.insert(expected_ubjson_array.end(), expected.begin() + 1, expected.end());
            expected_bjdata_array.insert(expected_bjdata_array.end(), expected.begin(), expected.end());
        }
        CHECK(wide_json::to_ubjson(wide_json::array({uint_big, uint_big}), true, true) == expected_ubjson_array);
        CHECK(wide_json::to_bjdata(wide_json::array({uint_big, uint_big}), true, true) == expected_bjdata_array);
    }

    SECTION("BJData ND-array")
    {
        // an ND-array element beyond 64 bits does not fit any dtype, so the
        // annotated object is written as a plain object instead of truncating
        // the element into range
        wide_json element(wide_json::value_t::object);
        element["_ArrayType_"] = "uint8";
        element["_ArraySize_"] = wide_json::array({make_uint(2), make_uint(1)});
        element["_ArrayData_"] = wide_json::array({make_uint(1), make_uint(static_cast<uint128>(two_64) + 1)});
        const auto element_bytes = wide_json::to_bjdata(element, true, true);
        REQUIRE(!element_bytes.empty());
        CHECK(element_bytes[0] == '{');

        wide_json signed_element = element;
        signed_element["_ArrayType_"] = "int8";
        signed_element["_ArrayData_"] = wide_json::array({make_int(1), make_int(-two_64 + 1)});
        const auto signed_element_bytes = wide_json::to_bjdata(signed_element, true, true);
        REQUIRE(!signed_element_bytes.empty());
        CHECK(signed_element_bytes[0] == '{');

        // the same for a dimension beyond 64 bits, which wrapped into a
        // dimension matching the size of _ArrayData_ (here: 1)
        wide_json dimension = element;
        dimension["_ArraySize_"] = wide_json::array({make_uint(2), make_uint(static_cast<uint128>(two_64) + 1)});
        dimension["_ArrayData_"] = wide_json::array({make_uint(1), make_uint(2)});
        const auto dimension_bytes = wide_json::to_bjdata(dimension, true, true);
        REQUIRE(!dimension_bytes.empty());
        CHECK(dimension_bytes[0] == '{');

        // in range, the ND-array is still written
        wide_json fits = element;
        fits["_ArrayData_"] = wide_json::array({make_uint(1), make_uint(2)});
        const auto fits_bytes = wide_json::to_bjdata(fits, true, true);
        REQUIRE(!fits_bytes.empty());
        CHECK(fits_bytes[0] == '[');
    }
}

#endif

TEST_CASE("custom number types")
{
    SECTION("signed integer of class type compared with a float")
    {
        // std::is_signed is false for a class type, which made the comparison
        // treat any float below zero as less than every integer
        const class_int_json minus_five = make_class_int(-5);
        const class_int_json minus_two = make_class_int(-2);
        const class_int_json five = make_class_int(5);
        const class_int_json minus_two_and_a_half = -2.5;
        const class_int_json two_and_a_half = 2.5;
        const class_int_json huge_negative = -1e30;
        const class_int_json huge_positive = 1e30;

        CHECK(minus_five < minus_two_and_a_half);
        CHECK_FALSE(minus_two_and_a_half < minus_five);
        CHECK(minus_two_and_a_half > minus_five);
        CHECK(minus_five <= minus_two_and_a_half);
        CHECK(minus_two_and_a_half >= minus_five);
        CHECK(minus_five != minus_two_and_a_half);

        CHECK(minus_two_and_a_half < minus_two);
        CHECK_FALSE(minus_two < minus_two_and_a_half);

        CHECK(two_and_a_half < five);
        CHECK(minus_five < two_and_a_half);

        // floats beyond the integer's range
        CHECK(huge_negative < minus_five);
        CHECK_FALSE(minus_five < huge_negative);
        CHECK(five < huge_positive);
        CHECK_FALSE(huge_positive < five);

        // equality
        const class_int_json minus_two_float = -2.0;
        CHECK(minus_two == minus_two_float);
        CHECK(minus_two_float == minus_two);
    }

}
