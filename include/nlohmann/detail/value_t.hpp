//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cmath> // isnan, ldexp, trunc
#include <cstddef> // size_t
#include <cstdint> // uint8_t
#include <limits> // numeric_limits
#include <string> // string
#include <type_traits> // is_signed

#include <nlohmann/detail/macro_scope.hpp>
#if JSON_HAS_THREE_WAY_COMPARISON
    #include <compare> // partial_ordering
#endif

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

///////////////////////////
// JSON type enumeration //
///////////////////////////

/*!
@brief the JSON type enumeration

This enumeration collects the different JSON types. It is internally used to
distinguish the stored values, and the functions @ref basic_json::is_null(),
@ref basic_json::is_object(), @ref basic_json::is_array(),
@ref basic_json::is_string(), @ref basic_json::is_boolean(),
@ref basic_json::is_number() (with @ref basic_json::is_number_integer(),
@ref basic_json::is_number_unsigned(), and @ref basic_json::is_number_float()),
@ref basic_json::is_discarded(), @ref basic_json::is_primitive(), and
@ref basic_json::is_structured() rely on it.

@note There are three enumeration entries (number_integer, number_unsigned, and
number_float), because the library distinguishes these three types for numbers:
@ref basic_json::number_unsigned_t is used for unsigned integers,
@ref basic_json::number_integer_t is used for signed integers, and
@ref basic_json::number_float_t is used for floating-point numbers or to
approximate integers which do not fit in the limits of their respective type.

@sa see @ref basic_json::basic_json(const value_t value_type) -- create a JSON
value with the default value for a given type

@since version 1.0.0
*/
enum class value_t : std::uint8_t
{
    null,             ///< null value
    object,           ///< object (unordered set of name/value pairs)
    array,            ///< array (ordered collection of values)
    string,           ///< string value
    boolean,          ///< boolean value
    number_integer,   ///< number value (signed integer)
    number_unsigned,  ///< number value (unsigned integer)
    number_float,     ///< number value (floating-point)
    binary,           ///< binary array (ordered collection of bytes)
    discarded         ///< discarded by the parser callback function
};

/*!
@brief comparison operator for JSON types

Returns an ordering that is similar to Python:
- order: null < boolean < number < object < array < string < binary
- furthermore, each type is not smaller than itself
- discarded values are not comparable
- binary is represented as a b"" string in python and directly comparable to a
  string; however, making a binary array directly comparable with a string would
  be surprising behavior in a JSON file.

@since version 1.0.0
*/
#if JSON_HAS_THREE_WAY_COMPARISON
    inline std::partial_ordering operator<=>(const value_t lhs, const value_t rhs) noexcept // *NOPAD*
#else
    inline bool operator<(const value_t lhs, const value_t rhs) noexcept
#endif
{
    static constexpr std::array<std::uint8_t, 9> order = {{
            0 /* null */, 3 /* object */, 4 /* array */, 5 /* string */,
            1 /* boolean */, 2 /* integer */, 2 /* unsigned */, 2 /* float */,
            6 /* binary */
        }
    };

    const auto l_index = static_cast<std::size_t>(lhs);
    const auto r_index = static_cast<std::size_t>(rhs);
#if JSON_HAS_THREE_WAY_COMPARISON
    if (l_index < order.size() && r_index < order.size())
    {
        return order[l_index] <=> order[r_index]; // *NOPAD*
    }
    return std::partial_ordering::unordered;
#else
    return l_index < order.size() && r_index < order.size() && order[l_index] < order[r_index];
#endif
}

// GCC selects the built-in operator< over an operator rewritten from
// a user-defined spaceship operator
// Clang, MSVC, and ICC select the rewritten candidate
// (see GCC bug https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105200)
#if JSON_HAS_THREE_WAY_COMPARISON && defined(__GNUC__)
inline bool operator<(const value_t lhs, const value_t rhs) noexcept
{
    return std::is_lt(lhs <=> rhs); // *NOPAD*
}
#endif


/*!
@brief compare an integer with a floating point number without precision loss

Widening the integer to the floating point type loses precision beyond the
float's mantissa, which makes equality intransitive: both 2^63-2 and 2^63-1
round to 2^63, so each compares equal to that float while differing from each
other. Ordering built on that is not a strict weak ordering, so sorting such
values, or using them as keys in an ordered container, is undefined behavior.

Returns a value to be compared against zero with the original operator, which
reproduces the exact ordering. A NaN operand is returned as is, so comparing it
against zero keeps NaN's semantics: false for the relational operators and
unordered for `<=>`.
*/
template<typename IntegerType, typename FloatType>
FloatType compare_integer_with_float(const IntegerType i, const FloatType f) noexcept
{
    const auto ordered = [](int c) noexcept
    {
        return static_cast<FloatType>(c);
    };

    if (std::isnan(f))
    {
        return f;
    }

    // values of IntegerType lie in [-bound, bound) when signed and in
    // [0, bound) when unsigned; digits excludes the sign bit, so bound is a
    // power of two that the float represents exactly
    const FloatType bound = std::ldexp(static_cast<FloatType>(1), std::numeric_limits<IntegerType>::digits);
    if (f >= bound)
    {
        return ordered(-1);
    }
    if (std::is_signed<IntegerType>::value ? (f < -bound) : (f < static_cast<FloatType>(0)))
    {
        return ordered(1);
    }

    // f is now within the integer's range, so truncating it is exact
    const FloatType truncated = std::trunc(f);
    const auto as_integer = static_cast<IntegerType>(truncated);
    if (i != as_integer)
    {
        return ordered(i < as_integer ? -1 : 1);
    }

    // the integer parts agree, so any fractional part decides
    const FloatType fraction = f - truncated;
    if (fraction > static_cast<FloatType>(0))
    {
        return ordered(-1);
    }
    if (fraction < static_cast<FloatType>(0))
    {
        return ordered(1);
    }
    return ordered(0);
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
