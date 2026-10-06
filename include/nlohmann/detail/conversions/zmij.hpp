//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2025 Victor Zverovich <https://github.com/vitaut/zmij>
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cstddef> // size_t
#include <cstdint> // uint32_t, uint64_t

#include <nlohmann/detail/abi_macros.hpp>
#include <nlohmann/detail/bit_ops.hpp>
#include <nlohmann/detail/input/pow5_table.hpp>
#include <nlohmann/detail/macro_scope.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/*!
@brief the shortest decimal representation of a double

A C++11 port of the conversion of Zmij by Victor Zverovich
(https://github.com/vitaut/zmij, MIT license): the shortest decimal in the
rounding interval of a double, the closest one if there are several. Zmij
credits Xiang JunBo (producing the shorter candidate without a division) and
Dougall Johnson (the compressed powers of ten). The powers of ten are taken
from the table for number parsing (pow5_table.hpp) where it holds them, and
computed from the compressed tables of Zmij beyond it.
*/
namespace zmij
{

/// significand * 10^exponent
struct decimal
{
    std::uint64_t significand;
    int exponent;
};

/// the compressed powers of ten of Zmij
inline const std::array<std::uint64_t, 28>& pow10_minor() noexcept
{
    static const std::array<std::uint64_t, 28> table =
    {
        {
            0x8000000000000000u, 0xa000000000000000u, 0xc800000000000000u, 0xfa00000000000000u, 0x9c40000000000000u,
            0xc350000000000000u, 0xf424000000000000u, 0x9896800000000000u, 0xbebc200000000000u, 0xee6b280000000000u,
            0x9502f90000000000u, 0xba43b74000000000u, 0xe8d4a51000000000u, 0x9184e72a00000000u, 0xb5e620f480000000u,
            0xe35fa931a0000000u, 0x8e1bc9bf04000000u, 0xb1a2bc2ec5000000u, 0xde0b6b3a76400000u, 0x8ac7230489e80000u,
            0xad78ebc5ac620000u, 0xd8d726b7177a8000u, 0x878678326eac9000u, 0xa968163f0a57b400u, 0xd3c21bcecceda100u,
            0x84595161401484a0u, 0xa56fa5b99019a5c8u, 0xcecb8f27f4200f3au
        }
    };
    return table;
}

/// (high, low) pairs
inline const std::array<std::uint64_t, 50>& pow10_major() noexcept
{
    static const std::array<std::uint64_t, 50> table =
    {
        {
            0xaddcb9e83c6b1793u, 0xdf4abe242a1bbf3eu, 0xaf8e5410288e1b6fu, 0x07ecf0ae5ee44ddau, 0xb1442798f49ffb4au, 0x99cd11cfdf41779du,
            0xb2fe3f0b8599ef07u, 0x861fa7e6dcb4aa15u, 0xb4bca50b065abe63u, 0x0fed077a756b53aau, 0xb67f6455292cbf08u, 0x1a3bc84c17b1d543u,
            0xb84687c269ef3bfbu, 0x3d5d514f40eea742u, 0xba121a4650e4ddebu, 0x92f34d62616ce413u, 0xbbe226efb628afeau, 0x890489f70a55368cu,
            0xbdb6b8e905cb600fu, 0x5400e987bbc1c921u, 0xbf8fdb78849a5f96u, 0xde98520472bdd034u, 0xc16d9a0095928a27u, 0x75b7053c0f178294u,
            0xc350000000000000u, 0x0000000000000000u, 0xc5371912364ce305u, 0x6c28000000000000u, 0xc722f0ef9d80aad6u, 0x424d3ad2b7b97ef6u,
            0xc913936dd571c84cu, 0x03bc3a19cd1e38eau, 0xcb090c8001ab551cu, 0x5cadf5bfd3072cc6u, 0xcd036837130890a1u, 0x36dba887c37a8c10u,
            0xcf02b2c21207ef2eu, 0x94f967e45e03f4bcu, 0xd106f86e69d785c7u, 0xe13336d701beba52u, 0xd31045a8341ca07cu, 0x1ede48111209a051u,
            0xd51ea6fa85785631u, 0x552a74227f3ea566u, 0xd732290fbacaf133u, 0xa97c177947ad4096u, 0xd94ad8b1c7380874u, 0x18375281ae7822bdu,
            0xdb68c2ca82ed2a05u, 0xa67398db9f6820e1u
        }
    };
    return table;
}

/// one bit per power: whether the computed value is one unit too large
inline const std::array<std::uint32_t, 21>& pow10_fixups() noexcept
{
    static const std::array<std::uint32_t, 21> table =
    {
        {
            0x8d8fc810u, 0x06100293u, 0x19000000u, 0x00100000u, 0x00000908u, 0x00000000u, 0x04e00300u, 0x3807e0b2u, 0x3d83d793u, 0x0006f5ccu,
            0x00000000u, 0xffff0000u, 0x8076337du, 0x4ff45ba0u, 0x09405033u, 0x034376d9u, 0x09000000u, 0x4e100501u, 0x076d14dcu, 0xf964f45eu,
            0x0000003du
        }
    };
    return table;
}

/// the 128-bit significand of 10^k, rounded down, for k in [-307, 341]
/// (compute_pow10 of Zmij)
inline uint128_parts compute_pow10(int k) noexcept
{
    const auto i = static_cast<unsigned>(k + 307);
    const std::uint64_t m = pow10_minor()[(i + 24) % 28];
    const std::size_t j = 2 * static_cast<std::size_t>((i + 24) / 28);
    const std::uint64_t h_hi = pow10_major()[j];
    const std::uint64_t h_lo = pow10_major()[j + 1];
    const std::uint64_t h1 = full_multiplication(h_lo, m).high;
    const std::uint64_t c0 = h_lo * m;
    const std::uint64_t c1 = h1 + (h_hi * m);
    const std::uint64_t c2 = (c1 < h1 ? 1u : 0u) + full_multiplication(h_hi, m).high;
    uint128_parts r{};
    if ((c2 >> 63u) != 0)
    {
        r.high = c2;
        r.low = c1;
    }
    else
    {
        r.high = (c2 << 1u) | (c1 >> 63u);
        r.low = (c1 << 1u) | (c0 >> 63u);
    }
    r.low -= (pow10_fixups()[i >> 5u] >> (i & 31u)) & 1u;
    return r;
}

/// The 128-bit significand of 10^k, rounded down, for k in [-342, 341].
/// Up to 10^308, the table for number parsing holds the same significands
/// (those of 5^k), except for k in [-27, -1], where it holds them one unit
/// larger (as the Eisel-Lemire algorithm needs them).
inline uint128_parts pow10(int k) noexcept
{
    if (k > pow5_128_largest_power)
    {
        return compute_pow10(k); // (only for the smallest doubles)
    }
    const auto i = 2 * static_cast<std::size_t>(k - pow5_128_smallest_power);
    uint128_parts r{pow5_128()[i + 1], pow5_128()[i]};
    const std::uint64_t adjust = static_cast<unsigned>(k + 27) < 27u ? 1u : 0u;
    r.high -= r.low < adjust ? 1u : 0u;
    r.low -= adjust;
    return r;
}

/// (x_hi * 2^64 + x_lo) * y >> 64, as 128 bits
inline uint128_parts umul192_hi128(std::uint64_t x_hi, std::uint64_t x_lo, std::uint64_t y) noexcept
{
    const uint128_parts p = full_multiplication(x_hi, y);
    uint128_parts r{};
    r.low = p.low + full_multiplication(x_lo, y).high;
    r.high = p.high + (r.low < p.low ? 1u : 0u);
    return r;
}

/// (x * y + c) >> 64
inline std::uint64_t umul128_add_hi64(std::uint64_t x, std::uint64_t y, std::uint64_t c) noexcept
{
    const uint128_parts p = full_multiplication(x, y);
    return p.high + (p.low + c < p.low ? 1u : 0u);
}

/// the result of Zmij: the shorter candidate and, if that is outside the
/// rounding interval, the digit after it (16 bytes: returned in registers)
struct shortest_decimal
{
    std::uint64_t integral;  ///< the shorter candidate (15 or 16 digits for normal doubles)
    int exponent;            ///< the decimal exponent of the digit after it
    unsigned char digit;     ///< the digit after it (if has_digit)
    bool has_digit;          ///< whether the shortest decimal is integral * 10 + digit
};

/// The shortest decimal in the rounding interval of a positive finite double
/// given by its bits, the closest one if there are several (to_decimal of
/// Zmij, which keeps the last digit apart: the 15 or 16 digits before it can be
/// converted without a multiplication by 10 first). Always inlined: GCC
/// otherwise calls it, and its result goes through memory.
JSON_HEDLEY_ALWAYS_INLINE shortest_decimal to_shortest(std::uint64_t bits) noexcept
{
    constexpr int extra_shift = 9;
    const auto raw_exp = static_cast<int>((bits >> 52u) & 0x7FFu);
    std::uint64_t bin_sig = bits & ((std::uint64_t{1} << 52u) - 1);
    // a power of two has a narrower interval below (except the smallest normal)
    const bool regular = bin_sig != 0 || raw_exp <= 1;
    const int bin_exp = (raw_exp == 0 ? 1 : raw_exp) - 1075;
    if (raw_exp != 0)
    {
        bin_sig |= std::uint64_t{1} << 52u;
    }
    // floor(log10(2^bin_exp)), or floor(log10(3/4 * 2^bin_exp)) for the irregular case
    const int dec_exp = ((bin_exp * 315653) - (regular ? 0 : 131072)) >> 20;
    // scaled by 10^(-dec_exp - 1): the integral part is the shorter candidate
    const int shift = bin_exp + ((-(dec_exp + 1) * 217707) >> 16) + 1 + extra_shift;
    const uint128_parts p10 = pow10(-dec_exp - 1);
    const uint128_parts p = umul192_hi128(p10.high, p10.low, bin_sig << static_cast<unsigned>(shift));
    std::uint64_t integral = p.high >> static_cast<unsigned>(extra_shift);
    const std::uint64_t fractional = (p.high << static_cast<unsigned>(64 - extra_shift)) | (p.low >> static_cast<unsigned>(extra_shift));
    std::uint64_t digit = 0;
    bool round_up = false;
    bool round_down = false;
    if (JSON_HEDLEY_LIKELY(regular))
    {
        const std::uint64_t half_ulp = (p10.high >> static_cast<unsigned>(extra_shift + 1 - shift)) + (1 - (bin_sig & 1u));
        round_up = fractional + half_ulp < fractional;
        round_down = half_ulp > fractional;
        // the last digit of the longer candidate, rounded to nearest
        digit = umul128_add_hi64(fractional, 10, (std::uint64_t{1} << 63u) + 6);
        if (fractional == (std::uint64_t{1} << 62u))
        {
            digit = 2; // 2.5 rounds to 2
        }
    }
    else
    {
        const std::uint64_t half_ulp = p10.high >> static_cast<unsigned>(extra_shift + 1 - shift);
        round_up = half_ulp > ~std::uint64_t{0} - fractional;
        round_down = (half_ulp >> 1u) > fractional;
        digit = umul128_add_hi64(fractional, 10, (std::uint64_t{1} << 63u) - 1);
        const std::uint64_t lowest = umul128_add_hi64(fractional - (half_ulp >> 1u), 10, ~std::uint64_t{0});
        digit = digit < lowest ? lowest : digit;
    }
    integral += round_up ? 1u : 0u;
    // if the shorter candidate is outside the rounding interval: one digit more
    return shortest_decimal{integral, dec_exp, static_cast<unsigned char>(digit), !round_up && !round_down};
}

/// The shortest decimal in the rounding interval of a positive finite double
/// given by its bits, as one number. The significand can end in zeros.
inline decimal to_decimal(std::uint64_t bits) noexcept
{
    const shortest_decimal d = to_shortest(bits);
    if (d.has_digit)
    {
        return decimal{(d.integral * 10) + d.digit, d.exponent};
    }
    return decimal{d.integral, d.exponent + 1};
}

}  // namespace zmij
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
