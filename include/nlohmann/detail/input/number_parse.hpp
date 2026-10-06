//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2021 The fast_float authors <https://github.com/fastfloat/fast_float>
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cfloat> // FLT_EVAL_METHOD
#include <clocale> // localeconv
#include <cstddef> // size_t
#include <cstdint> // int64_t, uint64_t
#include <cstdlib> // strtof, strtod, strtold
#include <cstring> // memcpy
#include <limits> // numeric_limits
#include <string> // string
#include <type_traits> // conditional, integral_constant, true_type, false_type
#include <utility> // move

#include <nlohmann/detail/bit_ops.hpp>
#include <nlohmann/detail/input/pow5_table.hpp>
#include <nlohmann/detail/macro_scope.hpp>

// std::from_chars lives in <charconv>, but being in C++17 mode does not
// guarantee the header exists: GCC 7 sets __cplusplus to C++17 yet ships no
// <charconv> (added in GCC 8; floating-point support in GCC 11). Guard the
// include with __has_include so such toolchains fall back to the scalar path.
#if defined(JSON_HAS_CPP_17) && defined(__has_include)
    #if __has_include(<charconv>)
        #include <charconv> // from_chars (only used when __cpp_lib_to_chars is defined)
        #include <system_error> // errc
    #endif
#endif

// This file contains the value-conversion helpers used by the lexer to turn an
// already-validated number token into a value. Integers and binary32/binary64
// floats (float, double, and long double where it is binary64) are converted
// by the library itself, without the locale/errno overhead of
// std::strtoull/std::strtod and correctly rounded; other long double formats
// use std::from_chars or std::strtold. They are free functions so the lexer
// stays focused on scanning (see lexer::convert_number()) and so that other
// parsers of JSON text can convert tokens exactly like it does.

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/*!
@brief fast integer parser for an already-validated unsigned integer

The number scanner has already checked that [first, last) is a valid JSON
integer, so this only needs to accumulate the digits and detect overflow. This
avoids the locale/errno machinery of std::strtoull, which dominates
integer-heavy inputs.

@param[in]  first   pointer to the first character (a digit)
@param[in]  last    pointer past the last character
@param[out] value   the parsed value on success
@return true if the value fit into @a NumberUnsignedType; false on overflow, in
        which case the caller falls back to floating-point parsing (matching the
        previous std::strtoull behavior)
*/
template<typename NumberUnsignedType>
bool parse_integer_unsigned(const char* first, const char* last, NumberUnsignedType& value) noexcept
{
    // accumulate in the widest unsigned type used by the previous strtoull
    // path so the overflow behavior is unchanged for custom number types
    std::uint64_t x = 0;
    constexpr std::uint64_t cutoff = (std::numeric_limits<std::uint64_t>::max)() / 10u;
    constexpr std::uint64_t cutlim = (std::numeric_limits<std::uint64_t>::max)() % 10u;
    for (const char* p = first; p != last; ++p)
    {
        const auto digit = static_cast<std::uint64_t>(static_cast<unsigned char>(*p) - static_cast<unsigned char>('0'));
        if (JSON_HEDLEY_UNLIKELY(x > cutoff || (x == cutoff && digit > cutlim)))
        {
            return false;
        }
        x = (x * 10u) + digit;
    }
    value = static_cast<NumberUnsignedType>(x);
    // reject values that do not round-trip into a narrower NumberUnsignedType
    return static_cast<std::uint64_t>(value) == x;
}

/*!
@brief fast integer parser for an already-validated negative integer

@param[in]  first   pointer to the leading '-'
@param[in]  last    pointer past the last character
@param[out] value   the parsed (negative) value on success
@return true on success; false on overflow (caller falls back to float)
*/
template<typename NumberIntegerType>
bool parse_integer_signed(const char* first, const char* last, NumberIntegerType& value) noexcept
{
    // the state machine only reaches the signed path via a leading '-'
    JSON_ASSERT(first != last && *first == '-');
    std::uint64_t magnitude = 0;
    // |INT64_MIN| == INT64_MAX + 1; this is the largest admissible magnitude
    constexpr std::uint64_t limit = static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()) + 1u;
    for (const char* p = first + 1; p != last; ++p)
    {
        const auto digit = static_cast<std::uint64_t>(static_cast<unsigned char>(*p) - static_cast<unsigned char>('0'));
        if (JSON_HEDLEY_UNLIKELY(magnitude > (limit - digit) / 10u))
        {
            return false;
        }
        magnitude = (magnitude * 10u) + digit;
    }
    const std::int64_t x = (magnitude == limit)
                           ? (std::numeric_limits<std::int64_t>::min)()
                           : -static_cast<std::int64_t>(magnitude);
    value = static_cast<NumberIntegerType>(x);
    // reject values that do not round-trip into a narrower NumberIntegerType
    return static_cast<std::int64_t>(value) == x;
}

/*!
@brief parameters of the IEEE-754 binary32 and binary64 formats for the float
       conversion (after fast_float's binary_format)
*/
template<int Digits>
struct ieee_binary_format;

template<>
struct ieee_binary_format<24> // binary32
{
    static constexpr int mantissa_bits() noexcept
    {
        return 23;
    }
    static constexpr int sign_bit() noexcept
    {
        return 31;
    }
    static constexpr int minimum_exponent() noexcept
    {
        return -127;
    }
    static constexpr int infinite_power() noexcept
    {
        return 0xFF;
    }
    // w * 10^q with w < 2^64 is below half the smallest subnormal number for
    // q < smallest_power_of_ten() and at least infinity for q > largest_power_of_ten()
    static constexpr int smallest_power_of_ten() noexcept
    {
        return -64;
    }
    static constexpr int largest_power_of_ten() noexcept
    {
        return 38;
    }
    // w * 10^q can only be exactly between two numbers for q in this range
    static constexpr int min_exponent_round_to_even() noexcept
    {
        return -17;
    }
    static constexpr int max_exponent_round_to_even() noexcept
    {
        return 10;
    }
    // Clinger's fast path: w and 10^|q| are exact
    static constexpr int max_exponent_fast_path() noexcept
    {
        return 10;
    }
    static constexpr std::uint64_t max_mantissa_fast_path() noexcept
    {
        return std::uint64_t{2} << 23u;
    }
    // a midpoint between two numbers has at most this many significant digits
    static constexpr std::int64_t max_digits() noexcept
    {
        return 114;
    }
};

template<>
struct ieee_binary_format<53> // binary64
{
    static constexpr int mantissa_bits() noexcept
    {
        return 52;
    }
    static constexpr int sign_bit() noexcept
    {
        return 63;
    }
    static constexpr int minimum_exponent() noexcept
    {
        return -1023;
    }
    static constexpr int infinite_power() noexcept
    {
        return 0x7FF;
    }
    static constexpr int smallest_power_of_ten() noexcept
    {
        return -342;
    }
    static constexpr int largest_power_of_ten() noexcept
    {
        return 308;
    }
    static constexpr int min_exponent_round_to_even() noexcept
    {
        return -4;
    }
    static constexpr int max_exponent_round_to_even() noexcept
    {
        return 23;
    }
    static constexpr int max_exponent_fast_path() noexcept
    {
        return 22;
    }
    static constexpr std::uint64_t max_mantissa_fast_path() noexcept
    {
        return std::uint64_t{2} << 52u;
    }
    static constexpr std::int64_t max_digits() noexcept
    {
        return 769;
    }
};

/*!
@brief whether @a FloatType is IEEE-754 binary32 or binary64

These formats (float, double, and long double where it is binary64, e.g.
with MSVC or on Apple arm64) are converted by parse_float_native(). The
predicate is the one the serializer uses to choose Grisu2.
*/
template<typename FloatType>
struct has_native_float_format
{
    static constexpr bool value =
        (std::numeric_limits<FloatType>::is_iec559 && std::numeric_limits<FloatType>::digits == 24 && std::numeric_limits<FloatType>::max_exponent == 128) ||
        (std::numeric_limits<FloatType>::is_iec559 && std::numeric_limits<FloatType>::digits == 53 && std::numeric_limits<FloatType>::max_exponent == 1024);
};

/// the C++ type (float or double) that holds a binary32 or binary64 @a FloatType
template<typename FloatType>
using native_float_t = typename std::conditional<std::numeric_limits<FloatType>::digits == 24, float, double>::type;

/// the value of the eight ASCII digits in @a v (see read_eight_bytes()), three
/// multiplications instead of eight (after simdjson and fast_float)
inline std::uint32_t parse_eight_digits(std::uint64_t v) noexcept
{
    v = ((v & 0x0F0F0F0F0F0F0F0Fu) * 2561u) >> 8u;
    v = ((v & 0x00FF00FF00FF00FFu) * 6553601u) >> 16u;
    return static_cast<std::uint32_t>(((v & 0x0000FFFF0000FFFFu) * 42949672960001u) >> 32u);
}

/// whether [first, last) contains a digit other than '0'
inline bool has_nonzero_digit(const char* first, const char* last) noexcept
{
    for (; first != last; ++first)
    {
        if (*first != '0')
        {
            return true;
        }
    }
    return false;
}

/// the value of the validated exponent digits [+-]?[0-9]+ in [first, last),
/// saturated far beyond every range
inline std::int64_t parse_float_exponent(const char* first, const char* last) noexcept
{
    const bool negative = *first == '-';
    first += (*first == '-' || *first == '+') ? 1 : 0;
    constexpr std::int64_t saturation = 100000000000000000; // 10^17
    std::int64_t value = 0;
    for (; first != last; ++first)
    {
        if (value < saturation)
        {
            value = (value * 10) + (*first - '0');
        }
    }
    return negative ? -value : value;
}

/// a float token as w * 10^exponent, see parse_float_significand()
struct float_significand
{
    std::uint64_t w = 0;         ///< the first (at most 19) significant digits
    std::int64_t exponent = 0;   ///< the decimal exponent of the last digit in w
    bool negative = false;       ///< whether the token starts with '-'
    bool truncated = false;      ///< whether nonzero digits follow the ones in w
};

/*!
@brief split a validated number token into sign, significand, and exponent

The lexer has validated the token against the JSON grammar and knows where its
parts are, so this needs no character classification: the integer part ends at
@a decimal_point_position (or @a mantissa_end), the fraction at @a mantissa_end,
and an exponent follows. At most 19 significant digits are kept; the value then
lies in [w, w + 1) * 10^exponent, and is exactly w * 10^exponent unless
truncated is set.

@param[in] first                   pointer to the first character of the token
@param[in] last                    pointer past the last character
@param[in] decimal_point_position  index of the '.' in the token, or
                                   std::string::npos if there is none
@param[in] mantissa_end            index of the 'e'/'E', or the token length
*/
inline float_significand parse_float_significand(const char* first, const char* last,
        std::size_t decimal_point_position, std::size_t mantissa_end) noexcept
{
    float_significand s;
    const char* p = first;
    s.negative = *p == '-';
    p += s.negative ? 1 : 0;
    const bool has_dot = decimal_point_position != std::string::npos;
    const char* const mantissa_last = first + mantissa_end;
    const char* const integer_last = has_dot ? first + decimal_point_position : mantissa_last;

    std::uint64_t w = 0;
    int remaining = 19; // digits that still fit into w
    if (*p != '0') // the integer part is "0" or [1-9][0-9]*
    {
        while (remaining >= 8 && integer_last - p >= 8)
        {
            w = (w * 100000000u) + parse_eight_digits(read_eight_bytes(p));
            p += 8;
            remaining -= 8;
        }
        for (; remaining > 0 && p != integer_last; ++p, --remaining)
        {
            w = (w * 10u) + static_cast<std::uint64_t>(*p - '0');
        }
        s.exponent = integer_last - p;
        s.truncated = has_nonzero_digit(p, integer_last);
    }

    if (has_dot)
    {
        p = integer_last + 1;
        if (w == 0)
        {
            // zeros after the decimal point of "0." are not significant
            const char* const zeros = p;
            while (p != mantissa_last && *p == '0')
            {
                ++p;
            }
            s.exponent -= p - zeros;
        }
        const char* const digits = p;
        while (remaining >= 8 && mantissa_last - p >= 8)
        {
            w = (w * 100000000u) + parse_eight_digits(read_eight_bytes(p));
            p += 8;
            remaining -= 8;
        }
        for (; remaining > 0 && p != mantissa_last; ++p, --remaining)
        {
            w = (w * 10u) + static_cast<std::uint64_t>(*p - '0');
        }
        s.exponent -= p - digits;
        s.truncated = s.truncated || has_nonzero_digit(p, mantissa_last);
    }

    if (mantissa_last != last)
    {
        s.exponent += parse_float_exponent(mantissa_last + 1, last);
    }
    s.w = w;
    return s;
}

/*!
@brief the bits of the float nearest to w * 10^q (Eisel-Lemire)

The algorithm of Daniel Lemire, "Number Parsing at a Gigabyte per Second"
(Software: Practice and Experience, 2021), after fast_float's compute_float
(used under the MIT license). With a 128-bit approximation of 5^q, the product
is always sufficient to round correctly for w < 2^64 (Noble Mushtak and Daniel
Lemire, "Fast number parsing without fallback", Software: Practice and
Experience, 2023). Only integer arithmetic is used, so the result does not
depend on the floating-point environment.

It is always inlined, like decimal_to_float(), so that hot loops of callers
keep the whole conversion inline.

@tparam Format  ieee_binary_format<24> (binary32) or ieee_binary_format<53> (binary64)
@param[in] q  decimal exponent
@param[in] w  significand
@return the IEEE-754 bits of the positive result (0 for underflow, infinity
        for overflow)
*/
template<typename Format>
JSON_HEDLEY_ALWAYS_INLINE std::uint64_t eisel_lemire(std::int64_t q, std::uint64_t w) noexcept
{
    constexpr int mantissa_bits = Format::mantissa_bits();
    constexpr std::uint64_t infinity = static_cast<std::uint64_t>(Format::infinite_power()) << mantissa_bits;
    if (w == 0 || q < Format::smallest_power_of_ten())
    {
        return 0;
    }
    if (q > Format::largest_power_of_ten())
    {
        return infinity;
    }

    const int lz = count_leading_zeros(w);
    w <<= static_cast<unsigned>(lz);
    const auto index = static_cast<std::size_t>(2 * (q - pow5_128_smallest_power));
    uint128_parts product = full_multiplication(w, pow5_128()[index]);
    constexpr std::uint64_t precision_mask = 0xFFFFFFFFFFFFFFFFu >> (mantissa_bits + 3);
    if ((product.high & precision_mask) == precision_mask)
    {
        // the lower bits may carry into the result: use the next 64 bits of 5^q
        const uint128_parts second = full_multiplication(w, pow5_128()[index + 1]);
        product.low += second.high;
        if (second.high > product.low)
        {
            ++product.high;
        }
    }

    const auto upperbit = static_cast<int>(product.high >> 63u);
    const int shift = upperbit + 64 - mantissa_bits - 3;
    std::uint64_t mantissa = product.high >> static_cast<unsigned>(shift);
    // floor(log2(10^q)) + 63 + bias, with log2(10) ~ 217706 / 2^16
    std::int64_t power2 = (((152170 + 65536) * q) >> 16) + 63 + upperbit - lz - Format::minimum_exponent();

    if (power2 <= 0) // subnormal
    {
        if (-power2 + 1 >= 64)
        {
            return 0;
        }
        mantissa >>= static_cast<unsigned>(-power2 + 1);
        // no tie is possible here: that needs a small |q|
        mantissa += (mantissa & 1u);
        mantissa >>= 1u;
        // rounding up may produce the smallest normal number
        power2 = (mantissa < (std::uint64_t{1} << mantissa_bits)) ? 0 : 1;
        return (mantissa & ((std::uint64_t{1} << mantissa_bits) - 1)) | (static_cast<std::uint64_t>(power2) << mantissa_bits);
    }

    // a value exactly between two floats rounds to even; this can only
    // happen for small |q|, where 5^q is exact
    if (product.low <= 1 && q >= Format::min_exponent_round_to_even() && q <= Format::max_exponent_round_to_even()
            && (mantissa & 3u) == 1 && (mantissa << static_cast<unsigned>(shift)) == product.high)
    {
        mantissa &= ~std::uint64_t{1};
    }
    mantissa += (mantissa & 1u);
    mantissa >>= 1u;
    if (mantissa >= (std::uint64_t{2} << mantissa_bits))
    {
        mantissa = std::uint64_t{1} << mantissa_bits;
        ++power2;
    }
    mantissa &= ~(std::uint64_t{1} << mantissa_bits);
    if (power2 >= Format::infinite_power())
    {
        return infinity;
    }
    return mantissa | (static_cast<std::uint64_t>(power2) << mantissa_bits);
}

/// an unsigned integer of up to 4096 bits for digit_comparison() (32-bit limbs,
/// so only 32x32->64-bit multiplications are needed)
class float_bigint
{
  public:
    explicit float_bigint(std::uint64_t value) noexcept
    {
        for (; value != 0; value >>= 32u)
        {
            limbs[count++] = static_cast<std::uint32_t>(value);
        }
    }

    /// *this = *this * factor + summand
    void multiply_add(std::uint32_t factor, std::uint32_t summand) noexcept
    {
        std::uint64_t carry = summand;
        for (std::size_t i = 0; i < count; ++i)
        {
            const std::uint64_t product = (static_cast<std::uint64_t>(limbs[i]) * factor) + carry;
            limbs[i] = static_cast<std::uint32_t>(product);
            carry = product >> 32u;
        }
        if (carry != 0)
        {
            JSON_ASSERT(count < limbs.size());
            limbs[count++] = static_cast<std::uint32_t>(carry);
        }
    }

    /// *this = *this * 5^n
    void multiply_power_of_five(std::int64_t n) noexcept
    {
        static const std::array<std::uint32_t, 14> powers =
        {
            {1u, 5u, 25u, 125u, 625u, 3125u, 15625u, 78125u, 390625u, 1953125u, 9765625u, 48828125u, 244140625u, 1220703125u}
        };
        for (; n >= 13; n -= 13)
        {
            multiply_add(powers[13], 0);
        }
        multiply_add(powers[static_cast<std::size_t>(n)], 0);
    }

    /// *this = *this * 2^n
    void shift_left(std::int64_t n) noexcept
    {
        if (count == 0)
        {
            return;
        }
        const auto limb_shift = static_cast<std::size_t>(n / 32);
        const auto bit_shift = static_cast<unsigned>(n % 32);
        JSON_ASSERT(count + limb_shift + 1 <= limbs.size());
        if (bit_shift != 0)
        {
            std::uint32_t carry = 0;
            for (std::size_t i = 0; i < count; ++i)
            {
                const std::uint32_t limb = limbs[i];
                limbs[i] = (limb << bit_shift) | carry;
                carry = limb >> (32u - bit_shift);
            }
            if (carry != 0)
            {
                limbs[count++] = carry;
            }
        }
        if (limb_shift != 0)
        {
            for (std::size_t i = count; i-- > 0;)
            {
                limbs[i + limb_shift] = limbs[i];
            }
            for (std::size_t i = 0; i < limb_shift; ++i)
            {
                limbs[i] = 0;
            }
            count += limb_shift;
        }
    }

    /// -1, 0, or 1 if *this is less than, equal to, or greater than @a other
    int compare(const float_bigint& other) const noexcept
    {
        if (count != other.count)
        {
            return count < other.count ? -1 : 1;
        }
        for (std::size_t i = count; i-- > 0;)
        {
            if (limbs[i] != other.limbs[i])
            {
                return limbs[i] < other.limbs[i] ? -1 : 1;
            }
        }
        return 0;
    }

  private:
    std::array<std::uint32_t, 128> limbs{{}};
    std::size_t count = 0;
};

/*!
@brief round a token exactly when eisel_lemire() cannot decide (slow path)

The value v of the token lies strictly between two adjacent floats, whose
lower one has the bits @a lower, and the result depends on whether v is below,
at, or above the midpoint m between them. Both are compared exactly as big
integers: v = D * 10^s with the significant digits D (at most
Format::max_digits() of them, more than any midpoint has; further nonzero
digits only put v above m) and m = (2 * mantissa + 1) * 2^(e - 1). This is the
digit comparison of fast_float (Daniel Lemire and contributors, used under the
MIT license), simplified by starting from the two candidates.

@param[in] first  pointer to the first character of the token
@param[in] last   pointer past the last character
@param[in] lower  the bits of the float below v
@return the bits of the correctly rounded result
*/
template<typename Format>
std::uint64_t digit_comparison(const char* first, const char* last, std::uint64_t lower) noexcept
{
    const char* p = first + ((*first == '-') ? 1 : 0);

    // D, in chunks of up to 9 digits, and s
    float_bigint digits(0);
    std::int64_t count = 0;
    std::int64_t point = 0; // the value is 0.D... * 10^point
    bool truncated = false;
    std::uint32_t chunk = 0;
    int chunk_digits = 0;
    static const std::array<std::uint32_t, 10> powers_of_ten = {{1u, 10u, 100u, 1000u, 10000u, 100000u, 1000000u, 10000000u, 100000000u, 1000000000u}};
    const auto append = [&](char c) noexcept
    {
        if (count < Format::max_digits())
        {
            chunk = (chunk * 10u) + static_cast<std::uint32_t>(c - '0');
            ++count;
            if (++chunk_digits == 9)
            {
                digits.multiply_add(powers_of_ten[9], chunk);
                chunk = 0;
                chunk_digits = 0;
            }
        }
        else
        {
            truncated = truncated || c != '0';
        }
    };
    bool significant = false;
    for (; p != last && *p >= '0' && *p <= '9'; ++p)
    {
        significant = significant || *p != '0';
        if (significant)
        {
            append(*p);
            ++point;
        }
    }
    if (p != last && *p == '.')
    {
        for (++p; p != last && *p >= '0' && *p <= '9'; ++p)
        {
            significant = significant || *p != '0';
            if (significant)
            {
                append(*p);
            }
            else
            {
                --point;
            }
        }
    }
    if (chunk_digits != 0)
    {
        digits.multiply_add(powers_of_ten[static_cast<std::size_t>(chunk_digits)], chunk);
    }
    if (p != last)
    {
        point += parse_float_exponent(p + 1, last);
    }
    const std::int64_t s = point - count; // v = D * 10^s

    // the midpoint above the lower candidate
    constexpr int mantissa_bits = Format::mantissa_bits();
    const std::uint64_t exponent_field = lower >> mantissa_bits;
    std::uint64_t mantissa = lower & ((std::uint64_t{1} << mantissa_bits) - 1);
    std::int64_t e = 1 + Format::minimum_exponent() - mantissa_bits; // of the smallest subnormal number
    if (exponent_field != 0)
    {
        mantissa |= std::uint64_t{1} << mantissa_bits;
        e += static_cast<std::int64_t>(exponent_field) - 1;
    }
    float_bigint midpoint((2 * mantissa) + 1);
    const std::int64_t midpoint_exponent = e - 1; // m = midpoint * 2^midpoint_exponent

    // compare D * 5^s * 2^s with midpoint * 2^midpoint_exponent
    if (s >= 0)
    {
        digits.multiply_power_of_five(s);
    }
    else
    {
        midpoint.multiply_power_of_five(-s);
    }
    const std::int64_t shift = s - midpoint_exponent;
    if (shift >= 0)
    {
        digits.shift_left(shift);
    }
    else
    {
        midpoint.shift_left(-shift);
    }
    const int order = digits.compare(midpoint);
    const bool round_up = order > 0 || (order == 0 && (truncated || (mantissa & 1u) != 0));
    return lower + (round_up ? 1u : 0u);
}

/// the double with the IEEE-754 bits @a bits
inline void float_from_bits(std::uint64_t bits, double& value) noexcept
{
    static_assert(sizeof(double) == sizeof(std::uint64_t), "double must have 64 bits");
    std::memcpy(&value, &bits, sizeof(value));
}

/// the float with the IEEE-754 bits @a bits (the lower 32)
inline void float_from_bits(std::uint64_t bits, float& value) noexcept
{
    static_assert(sizeof(float) == sizeof(std::uint32_t), "float must have 32 bits");
    const auto bits32 = static_cast<std::uint32_t>(bits);
    std::memcpy(&value, &bits32, sizeof(value));
}

/// the powers of ten that are exact in binary64 (up to 10^22)
inline double exact_power_of_ten(std::int64_t n, double /*tag*/) noexcept
{
    static const std::array<double, 23> powers =
    {
        {
            1e0, 1e1, 1e2, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10, 1e11,
            1e12, 1e13, 1e14, 1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22
        }
    };
    return powers[static_cast<std::size_t>(n)];
}

/// the powers of ten that are exact in binary32 (up to 10^10)
inline float exact_power_of_ten(std::int64_t n, float /*tag*/) noexcept
{
    static const std::array<float, 11> powers =
    {
        {1e0f, 1e1f, 1e2f, 1e3f, 1e4f, 1e5f, 1e6f, 1e7f, 1e8f, 1e9f, 1e10f}
    };
    return powers[static_cast<std::size_t>(n)];
}

/*!
@brief the binary32/binary64 value of a significand that was not truncated

The result is (-1)^negative * w * 10^exponent, correctly rounded (ties to
even): with Clinger's fast path where w and 10^|exponent| are exact, so that a
single floating-point operation rounds (only where intermediate results are not
kept in extended precision, see FLT_EVAL_METHOD), and with eisel_lemire()
otherwise. A value too large for the type becomes ±infinity, a value too small
±0.

This is the core of the conversion that other parsers of JSON text share: they
can split a token themselves and still get the lexer's result. It is always
inlined, so that their hot loops keep the whole conversion inline.

@param[in] s  the significand, with s.truncated == false
*/
template<typename FloatType>
JSON_HEDLEY_ALWAYS_INLINE FloatType decimal_to_float(const float_significand& s) noexcept
{
    using result_type = native_float_t<FloatType>;
    using format = ieee_binary_format<std::numeric_limits<FloatType>::digits>;
    JSON_ASSERT(!s.truncated);

#if !defined(FLT_EVAL_METHOD) || FLT_EVAL_METHOD == 0
    if (s.exponent >= -format::max_exponent_fast_path() && s.exponent <= format::max_exponent_fast_path()
            && s.w <= format::max_mantissa_fast_path())
    {
        auto value = static_cast<result_type>(s.w);
        if (s.exponent < 0)
        {
            value /= exact_power_of_ten(-s.exponent, result_type{});
        }
        else
        {
            value *= exact_power_of_ten(s.exponent, result_type{});
        }
        const FloatType result = s.negative ? -value : value;
        return result;
    }
#endif

    result_type value{};
    float_from_bits(eisel_lemire<format>(s.exponent, s.w) | (s.negative ? (std::uint64_t{1} << format::sign_bit()) : 0u), value);
    const FloatType result = value;
    return result;
}

/*!
@brief convert a validated number token to the nearest binary32/binary64 value

The conversion is correctly rounded (ties to even) and independent of the
locale and of the C and C++ libraries:
1. parse_float_significand() splits the token into w * 10^q.
2. If no digits were dropped, decimal_to_float() rounds w * 10^q (Clinger's
   fast path or Eisel-Lemire).
3. Otherwise, the value lies in [w, w + 1) * 10^q: if eisel_lemire() rounds
   both ends to the same value, so does the token (in all but rare cases).
4. Otherwise, digit_comparison() compares the token exactly with the midpoint
   between the two candidates.
A value too large for the type becomes ±infinity (the parser reports
out_of_range.406), a value too small ±0.

@param[in] first                   pointer to the first character of the token
@param[in] last                    pointer past the last character
@param[in] decimal_point_position  index of the '.' in the token, or
                                   std::string::npos if there is none
@param[in] mantissa_end            index of the 'e'/'E', or the token length
*/
template<typename FloatType>
FloatType parse_float_native(const char* first, const char* last,
                             std::size_t decimal_point_position, std::size_t mantissa_end) noexcept
{
    using result_type = native_float_t<FloatType>;
    using format = ieee_binary_format<std::numeric_limits<FloatType>::digits>;
    static_assert(std::numeric_limits<result_type>::digits == std::numeric_limits<FloatType>::digits, "unexpected float format");

    const float_significand s = parse_float_significand(first, last, decimal_point_position, mantissa_end);
    if (JSON_HEDLEY_LIKELY(!s.truncated))
    {
        return decimal_to_float<FloatType>(s);
    }

    std::uint64_t bits = eisel_lemire<format>(s.exponent, s.w);
    if (JSON_HEDLEY_UNLIKELY(bits != eisel_lemire<format>(s.exponent, s.w + 1)))
    {
        bits = digit_comparison<format>(first, last, bits);
    }
    result_type value{};
    float_from_bits(bits | (s.negative ? (std::uint64_t{1} << format::sign_bit()) : 0u), value);
    const FloatType result = value;
    return result;
}

/*!
@brief parse a float with std::from_chars when available

Only used for the formats parse_float_native() does not convert (long double
formats other than binary64). std::from_chars is locale-independent and
correctly rounded. It is used only when __cpp_lib_to_chars indicates full
floating-point support and only when it consumes the entire token ([first,
last)). An under-/overflow (result_out_of_range) also declines, so the
caller's strtold fallback supplies the well-defined ±inf/0 result the parser
expects (side-stepping the P4168 divergence between implementations).

@return true if the value was parsed exactly and fully; false to fall back
*/
template<typename FloatType>
bool parse_float_from_chars(const char* first, const char* last, FloatType& out) noexcept
{
    // JSON_HAS_CPP_17 must gate the use as well as the <charconv> include above:
    // some standard libraries (e.g. libstdc++ 15) define __cpp_lib_to_chars even
    // in C++14 mode, where <charconv> is not included.
#if defined(JSON_HAS_CPP_17) && defined(__cpp_lib_to_chars)
    const auto result = std::from_chars(first, last, out);
    return result.ec == std::errc() && result.ptr == last;
#else
    static_cast<void>(first);
    static_cast<void>(last);
    static_cast<void>(out);
    return false;
#endif
}

/// binary32 and binary64: the library's own conversion, which always succeeds
template<typename FloatType>
bool convert_float_fast(const char* first, const char* last, std::size_t decimal_point_position,
                        std::size_t mantissa_end, FloatType& value, std::true_type /*native*/) noexcept
{
    value = parse_float_native<FloatType>(first, last, decimal_point_position, mantissa_end);
    return true;
}

/// other formats (long double on x87, binary128, double-double): std::from_chars, if available
template<typename FloatType>
bool convert_float_fast(const char* first, const char* last, std::size_t /*decimal_point_position*/,
                        std::size_t /*mantissa_end*/, FloatType& value, std::false_type /*native*/) noexcept
{
    return parse_float_from_chars(first, last, value);
}

/*!
@brief convert a validated float token without the C library, if possible

float, double, and long double where it is binary64 are always converted, by
parse_float_native(). Other long double formats are converted with
std::from_chars where the standard library supports it.

@param[in]  first                   pointer to the first character of the token
@param[in]  last                    pointer past the last character
@param[in]  decimal_point_position  index of the '.' in the token, or
                                    std::string::npos if there is none
@param[in]  mantissa_end            offset just past the last mantissa byte (the
                                    index of 'e'/'E', or the token length)
@param[out] value                   the converted value on success
@return true if the value was converted; false if convert_float_locale_aware()
        must convert it
*/
template<typename FloatType>
bool convert_float_fast(const char* first, const char* last, std::size_t decimal_point_position,
                        std::size_t mantissa_end, FloatType& value) noexcept
{
    return convert_float_fast(first, last, decimal_point_position, mantissa_end, value,
                              std::integral_constant<bool, has_native_float_format<FloatType>::value> {});
}

/// std::strtof, std::strtod, or std::strtold, chosen by the type of @a f
JSON_HEDLEY_NON_NULL(2)
inline void strtof_by_type(float& f, const char* str, char** endptr) noexcept
{
    f = std::strtof(str, endptr);
}

/// std::strtof, std::strtod, or std::strtold, chosen by the type of @a f
JSON_HEDLEY_NON_NULL(2)
inline void strtof_by_type(double& f, const char* str, char** endptr) noexcept
{
    f = std::strtod(str, endptr);
}

/// std::strtof, std::strtod, or std::strtold, chosen by the type of @a f
JSON_HEDLEY_NON_NULL(2)
inline void strtof_by_type(long double& f, const char* str, char** endptr) noexcept
{
    f = std::strtold(str, endptr);
}

/// return the decimal point of the current locale (it may be longer than one byte)
inline std::string get_decimal_point()
{
    const auto* loc = localeconv();
    JSON_ASSERT(loc != nullptr);
    return (loc->decimal_point == nullptr || *loc->decimal_point == '\0') ? "." : loc->decimal_point;
}

/*!
@brief convert a validated float token with strtof/strtod/strtold

Only used for what convert_float_fast() does not convert: long double formats
other than binary64 where std::from_chars is unavailable or reports an under-
or overflow, and floating-point types that are not IEEE-754 (see
has_native_float_format).

These functions expect the decimal point of the *current* locale, so it is
looked up right before the conversion instead of once when the lexer is
constructed: a locale change in between (by a parser callback, a SAX
handler, or another thread) must not truncate the value (#5198). A
single-byte decimal point is substituted in place and restored afterwards,
because the token is also handed to the SAX interface. A longer one (e.g.,
the two-byte U+066B of ar_EG.UTF-8 or fa_IR.UTF-8) is put into a copy of the
token instead (#5660).

The token has been validated before, so if the conversion stops early and
the decimal point changed in the meantime, the locale changed between the
lookup and the call, and the conversion is repeated with the new decimal
point. If it did not change, the value strtod parsed up to that point is
kept.

Note that changing the locale in another thread *while* strtod runs is
undefined behavior of the C library, which this function cannot prevent.

@param[in,out] token                   the token with '.' as decimal point; a
                                       single-byte decimal point is put in
                                       place during the conversion and
                                       restored afterwards (data() must be
                                       NUL-terminated)
@param[in]     decimal_point_position  index of the '.' in @a token, or
                                       std::string::npos if there is none
@param[out]    value                   the converted value
*/
template<typename StringType, typename FloatType>
void convert_float_locale_aware(StringType& token, std::size_t decimal_point_position, FloatType& value)
{
    const bool has_dot = decimal_point_position != std::string::npos;
    std::string decimal_point = get_decimal_point();
    for (;;)
    {
        char* endptr = nullptr; // NOLINT(misc-const-correctness,cppcoreguidelines-pro-type-vararg,hicpp-vararg)
        bool complete = false;
        if (!has_dot || decimal_point.size() == 1)
        {
            const bool substitute = has_dot && decimal_point[0] != '.';
            if (substitute)
            {
                token[decimal_point_position] = static_cast<typename StringType::value_type>(decimal_point[0]);
            }
            strtof_by_type(value, token.data(), &endptr);
            if (substitute)
            {
                // the caller hands the token on (e.g. to the SAX interface) with '.'
                token[decimal_point_position] = '.';
            }
            complete = endptr == token.data() + token.size();
        }
        else
        {
            std::string copy(token.data(), token.size());
            copy.replace(decimal_point_position, 1, decimal_point);
            strtof_by_type(value, copy.c_str(), &endptr);
            complete = endptr == copy.c_str() + copy.size();
        }

        if (JSON_HEDLEY_LIKELY(complete))
        {
            return;
        }

        // retry only if the locale changed; otherwise, this would loop forever
        std::string current_decimal_point = get_decimal_point();
        if (current_decimal_point == decimal_point)
        {
            return;
        }
        decimal_point = std::move(current_decimal_point);
    }
}

/*!
@brief convert a validated float token like the lexer does

For parsers of JSON text other than the lexer, which converts its own token
buffer in place. float, double, and long double where it is binary64 are
converted without allocation and independent of the locale; only other long
double formats that std::from_chars does not support need a copy of the token
for convert_float_locale_aware().

@param[in] first                   pointer to the first character of the token
@param[in] last                    pointer past the last character
@param[in] decimal_point_position  index of the '.' in the token, or
                                   std::string::npos if there is none
@param[in] mantissa_end            index of the 'e'/'E', or the token length
@return the value, ±infinity if it overflows
*/
template<typename FloatType>
FloatType convert_float(const char* first, const char* last, std::size_t decimal_point_position, std::size_t mantissa_end)
{
    FloatType value{};
    if (!convert_float_fast(first, last, decimal_point_position, mantissa_end, value))
    {
        std::string token(first, last);
        convert_float_locale_aware(token, decimal_point_position, value);
    }
    return value;
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
