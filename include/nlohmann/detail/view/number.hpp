//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t
#include <cstdint> // int64_t, uint64_t
#include <limits> // numeric_limits
#include <string> // string
#include <type_traits> // integral_constant

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>
#include <nlohmann/detail/view/scan.hpp>
#include <nlohmann/detail/view/simd.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/*!
@brief locate the decimal point and the end of the mantissa of a float token

Also checks that the token is a JSON number. Tokens of the parser and of edits
always are; an image loaded with image_check::bounds can hold any bytes, which
must not reach the conversion (it expects a well-formed token).
*/
inline bool float_token_layout(const char* first, const char* last, std::size_t& dot, std::size_t& mantissa_end) noexcept
{
    const auto digit = [last](const char* q)
    {
        return q != last && is_digit(static_cast<unsigned char>(*q));
    };
    const char* p = first;
    p += (p != last && *p == '-') ? 1 : 0;
    if (!digit(p) || (*p == '0' && digit(p + 1)))
    {
        return false;
    }
    do
    {
        ++p;
    }
    while (digit(p));
    dot = std::string::npos;
    if (p != last && *p == '.')
    {
        dot = static_cast<std::size_t>(p - first);
        if (!digit(++p))
        {
            return false;
        }
        do
        {
            ++p;
        }
        while (digit(p));
    }
    mantissa_end = static_cast<std::size_t>(p - first);
    if (p != last && (*p == 'e' || *p == 'E'))
    {
        ++p;
        p += (p != last && (*p == '+' || *p == '-')) ? 1 : 0;
        if (!digit(p))
        {
            return false;
        }
        do
        {
            ++p;
        }
        while (digit(p));
    }
    return p == last;
}

/*!
@brief the value of the float token of a node, as parse() converts it

Uses the lexer's conversion (detail::convert_float), so that the values are
bit-identical to parse(): float and double are converted without allocation
and independent of the locale. A token that is not a JSON number (only in a
damaged image loaded with image_check::bounds) yields 0.
*/
template<typename FloatType>
NLOHMANN_VIEW_NOINLINE FloatType float_value(const char* first, const node& n)
{
    const char* const last = first + n.len;
    std::size_t dot = 0;
    std::size_t mantissa_end = 0;
    if (NLOHMANN_VIEW_UNLIKELY(!float_token_layout(first, last, dot, mantissa_end)))
    {
        return FloatType{};
    }
    return convert_float<FloatType>(first, last, dot, mantissa_end);
}

#if NLOHMANN_VIEW_VECTOR
/*!
@brief the value of the first 16 digits of a run of digits with a point after
int_digits of them (or none, if int_digits >= 16)

The 17 bytes at p are read at once: the bytes after the point move down by one,
then pairs, quadruples, and octets of digits are combined by multiplications
(after simdjson). The bytes [p, p + 32) must be readable. Bytes that are not
digits (only in a damaged image loaded with image_check::bounds) give a wrong
value, but no undefined behavior.
*/
NLOHMANN_VIEW_ALWAYS_INLINE std::uint64_t sixteen_digits(const unsigned char* p, unsigned int_digits) noexcept
{
#if NLOHMANN_VIEW_NEON
    const uint8x16_t low = vld1q_u8(p);
    const uint8x16_t index = vcombine_u8(vcreate_u8(0x0706050403020100u), vcreate_u8(0x0F0E0D0C0B0A0908u));
    const uint8x16_t before_point = vcltq_u8(index, vdupq_n_u8(static_cast<std::uint8_t>(int_digits)));
    const uint8x16_t digits = vsubq_u8(vbslq_u8(before_point, low, vextq_u8(low, vld1q_u8(p + 16), 1)), vdupq_n_u8('0'));
    const uint16x8_t twos = vpaddlq_u8(vmulq_u8(digits, vreinterpretq_u8_u16(vdupq_n_u16(0x010A))));
    const uint32x4_t fours = vpaddlq_u16(vmulq_u16(twos, vreinterpretq_u16_u32(vdupq_n_u32(0x00010064))));
    const uint64x2_t eights = vpaddlq_u32(vmulq_u32(fours, vreinterpretq_u32_u64(vdupq_n_u64(0x0000000100002710u))));
    return (vgetq_lane_u64(eights, 0) * 100000000u) + vgetq_lane_u64(eights, 1);
#else
    // NOLINTBEGIN(portability-simd-intrinsics)
    const __m128i low = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(p))); // NOLINT(bugprone-casting-through-void)
    const __m128i high = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(p + 16))); // NOLINT(bugprone-casting-through-void)
    const __m128i before_point = _mm_cmpgt_epi8(_mm_set1_epi8(static_cast<char>(int_digits)), _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15));
    const __m128i moved = _mm_or_si128(_mm_srli_si128(low, 1), _mm_slli_si128(high, 15));
    const __m128i digits = _mm_sub_epi8(_mm_or_si128(_mm_and_si128(before_point, low), _mm_andnot_si128(before_point, moved)), _mm_set1_epi8('0'));
    // (16-bit lanes: SSE2 has no multiply-add of bytes)
    const __m128i tens = _mm_setr_epi16(10, 1, 10, 1, 10, 1, 10, 1);
    const __m128i twos = _mm_packs_epi32(_mm_madd_epi16(_mm_unpacklo_epi8(digits, _mm_setzero_si128()), tens),
                                         _mm_madd_epi16(_mm_unpackhi_epi8(digits, _mm_setzero_si128()), tens));
    const __m128i fours = _mm_madd_epi16(twos, _mm_setr_epi16(100, 1, 100, 1, 100, 1, 100, 1));
    const __m128i eights = _mm_madd_epi16(_mm_packs_epi32(fours, fours), _mm_setr_epi16(10000, 1, 10000, 1, 10000, 1, 10000, 1));
    const auto upper = static_cast<std::uint32_t>(_mm_cvtsi128_si32(eights));
    const auto lower = static_cast<std::uint32_t>(_mm_cvtsi128_si32(_mm_srli_si128(eights, 4)));
    // NOLINTEND(portability-simd-intrinsics)
    return (std::uint64_t{upper} * 100000000u) + lower;
#endif
}
#endif

/*!
@brief the digits of a float token with at most 19 digits, from its layout

The digit layout recorded while parsing says where the integer digits, the
fraction digits, and the exponent are, so the digits are read eight at a
time without scanning (with SIMD, a token of 16 to 19 digits sixteen at a
time).

@param[in] p  first character of the token
@param[in] e  end of the token
@param[in] limit  end of the readable memory (the source text)
*/
NLOHMANN_VIEW_ALWAYS_INLINE float_significand layout_decimal(const unsigned char* p, const unsigned char* e, unsigned int_digits, unsigned frac_digits, const unsigned char* limit) noexcept
{
    const bool negative = *p == '-';
    p += negative ? 1 : 0;
    std::uint64_t w = 0;
    std::int64_t q = 0;
#if NLOHMANN_VIEW_VECTOR
    const unsigned count = int_digits + frac_digits;
    if (count >= 16 && limit - p >= 32)
    {
        // (the point, if any, follows the integer digits; the digits after
        // the first 16 are at most three)
        w = sixteen_digits(p, int_digits);
        for (unsigned i = 16; i < count; ++i)
        {
            w = (w * 10) + static_cast<std::uint64_t>(p[i + (i >= int_digits ? 1 : 0)] - '0');
        }
        p += count + (frac_digits != 0 ? 1 : 0);
        q = -static_cast<std::int64_t>(frac_digits);
    }
    else
#endif
    {
        w = parse_upto19(p, int_digits, limit);
        p += int_digits;
        if (frac_digits != 0)
        {
            w = (w * int_pow10(frac_digits)) + parse_upto19(p + 1, frac_digits, limit);
            p += 1 + frac_digits;
            q = -static_cast<std::int64_t>(frac_digits);
        }
    }
    if (p != e)
    {
        // [eE][+-]digits; huge exponents saturate (the parser rejected
        // overflow). The token is not read beyond e, and the digits are taken
        // as unsigned, so that a token that is not well-formed (a damaged
        // image loaded with image_check::bounds) yields a wrong value, but no
        // overflow.
        ++p;
        const bool exp_negative = p != e && *p == '-';
        p += (p != e && (*p == '-' || *p == '+')) ? 1 : 0;
        std::int64_t exp_value = 0;
        for (; p != e; ++p)
        {
            if (exp_value < 0x10000000)
            {
                exp_value = (exp_value * 10) + static_cast<unsigned char>(*p - '0');
            }
        }
        q += exp_negative ? -exp_value : exp_value;
    }

    float_significand d;
    d.w = w;
    d.exponent = q;
    d.negative = negative;
    return d;
}

/*!
@brief the value of a float token with at most 19 digits, from its layout

The result is correctly rounded by the lexer's conversion
(detail::decimal_to_float(): Clinger's fast path where both operands are
exact, else the Eisel-Lemire algorithm, which needs no fallback for up to 19
digits), so it is the value parse() produces. Tokens of 16 or more digits go
to Eisel-Lemire directly: the fast path takes few of them (none of 17 digits),
and its check is a branch that data like GeoJSON coordinates mispredicts.
*/
template<typename FloatType>
NLOHMANN_VIEW_ALWAYS_INLINE FloatType layout_float(const unsigned char* p, const unsigned char* e, unsigned int_digits, unsigned frac_digits, const unsigned char* limit) noexcept
{
    const float_significand d = layout_decimal(p, e, int_digits, frac_digits, limit);
    if (int_digits + frac_digits >= 16)
    {
        using format = ieee_binary_format<std::numeric_limits<FloatType>::digits>;
        native_float_t<FloatType> value{};
        float_from_bits(eisel_lemire<format>(d.exponent, d.w) | (d.negative ? (std::uint64_t{1} << format::sign_bit()) : 0u), value);
        return value;
    }
    return decimal_to_float<FloatType>(d);
}

/// the value of a float set by an edit: its token (the shortest round-trip
/// text, or "nan", "inf", "-inf") in the edit arena
template<typename FloatType>
NLOHMANN_VIEW_NOINLINE FloatType edited_float(const char* token, const node& n)
{
    if (token[0] == 'n')
    {
        return std::numeric_limits<FloatType>::quiet_NaN();
    }
    if (token[0] == 'i' || (token[0] == '-' && token[1] == 'i'))
    {
        return token[0] == 'i' ? std::numeric_limits<FloatType>::infinity() : -std::numeric_limits<FloatType>::infinity();
    }
    return float_value<FloatType>(token, n);
}

#if NLOHMANN_VIEW_VECTOR
/// eisel_lemire() for the token w * 10^q of coordinate_float()
template<typename Format>
NLOHMANN_VIEW_ALWAYS_INLINE std::uint64_t coordinate_bits(std::int64_t q, std::uint64_t w, Format /*format*/) noexcept
{
    return eisel_lemire<Format>(q, w);
}

/*!
@brief (binary64) eisel_lemire() without the cases that tokens of 16 or 17
digits with 5 or more after the point cannot reach: a value of 0, a
subnormal, an infinity, or a tie (q < -4)
*/
NLOHMANN_VIEW_ALWAYS_INLINE std::uint64_t coordinate_bits(std::int64_t q, std::uint64_t w, ieee_binary_format<53> format) noexcept
{
    if (NLOHMANN_VIEW_UNLIKELY(w == 0 || q > -5))
    {
        return eisel_lemire<ieee_binary_format<53>>(q, w);
    }
    static_cast<void>(format);
    const int lz = count_leading_zeros(w);
    const std::uint64_t normalized = w << static_cast<unsigned>(lz);
    const auto index = static_cast<std::size_t>(2 * (q - pow5_128_smallest_power));
    const uint128_parts product = full_multiplication(normalized, pow5_128()[index]);
    std::uint64_t high = product.high;
    if (NLOHMANN_VIEW_UNLIKELY((high & 0x1FFu) == 0x1FFu))
    {
        // (the lower bits may carry into the result)
        const std::uint64_t second = full_multiplication(normalized, pow5_128()[index + 1]).high;
        high += product.low + second < product.low ? 1u : 0u;
    }
    const auto upperbit = static_cast<unsigned>(high >> 63u);
    std::uint64_t mantissa = high >> (upperbit + 9);
    std::uint64_t power2 = static_cast<std::uint64_t>(((217706 * q) >> 16) + 63 + static_cast<std::int64_t>(upperbit) - lz + 1023);
    mantissa = (mantissa + (mantissa & 1u)) >> 1u;
    const bool carry = mantissa >= (std::uint64_t{2} << 52u);
    mantissa = carry ? (std::uint64_t{1} << 52u) : mantissa;
    power2 += carry ? 1u : 0u;
    return (mantissa & ~(std::uint64_t{1} << 52u)) | (power2 << 52u);
}

/*!
@brief (binary32 and binary64) the value of a float token of the source with
16 or 17 digits, a point, and no exponent, the shape of most coordinates
written with full precision; whether the token of n has this shape

These tokens skip the general layout of layout_decimal(): no digits beyond
the 17th, no exponent (and Eisel-Lemire directly, as in layout_float()).
*/
template<typename FloatType>
NLOHMANN_VIEW_ALWAYS_INLINE bool coordinate_float(const document_data& d, const node& n, FloatType& value) noexcept
{
    const unsigned int_digits = n.extra & 0xFFu;
    const unsigned frac_digits = n.extra >> 8u;
    const unsigned count = int_digits + frac_digits;
    const auto* const first = reinterpret_cast<const unsigned char*>(d.src + n.off); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    const unsigned negative = first[0] == '-' ? 1u : 0u;
    if (count - 16u > 1u || frac_digits == 0 || n.len != negative + count + 1 || d.size - n.off < 33)
    {
        return false;
    }
    const unsigned char* const digits = first + negative;
    const std::uint64_t w = sixteen_digits(digits, int_digits);
    // (the 17th digit follows the point)
    const std::uint64_t w17 = (w * 10) + static_cast<std::uint64_t>(digits[17] - '0');
    using format = ieee_binary_format<std::numeric_limits<FloatType>::digits>;
    native_float_t<FloatType> result{};
    float_from_bits(coordinate_bits(-static_cast<std::int64_t>(frac_digits), count == 17 ? w17 : w, format{}) | (static_cast<std::uint64_t>(negative) << format::sign_bit()), result);
    value = result;
    return true;
}

#endif

/// the value of the float token of a node, as parse() converts it; floats and
/// doubles with at most 19 digits are converted from the digit layout
template<typename FloatType>
FloatType float_value(const document_data& d, const node& n)
{
    if (NLOHMANN_VIEW_UNLIKELY((n.flags & node_flags::storage) == node_flags::edited))
    {
        return edited_float<FloatType>(d.str(n), n);
    }
    return float_value<FloatType>(d, n, std::integral_constant<bool, has_native_float_format<FloatType>::value> {});
}

template<typename FloatType>
FloatType float_value(const document_data& d, const node& n, std::true_type /*binary32 or binary64*/)
{
#if NLOHMANN_VIEW_VECTOR
    FloatType value {};
    if (coordinate_float(d, n, value))
    {
        return value;
    }
#endif
    const unsigned int_digits = n.extra & 0xFFu;
    const unsigned frac_digits = n.extra >> 8u;
    if (NLOHMANN_VIEW_LIKELY(int_digits + frac_digits <= 19)) // (255 marks "many")
    {
        // (a float token not written by an edit is in the text)
        const auto* const first = reinterpret_cast<const unsigned char*>(d.src + n.off); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        return layout_float<FloatType>(first, first + n.len, int_digits, frac_digits, reinterpret_cast<const unsigned char*>(d.src + d.size)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }
    return float_value<FloatType>(d.str(n), n);
}

template<typename FloatType>
FloatType float_value(const document_data& d, const node& n, std::false_type /*other*/)
{
    return float_value<FloatType>(d.str(n), n);
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
