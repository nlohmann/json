//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2009 Florian Loitsch <https://florian.loitsch.com/>
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cmath>   // signbit, isfinite
#include <cstddef> // size_t
#include <cstdint> // intN_t, uintN_t
#include <cstring> // memcpy, memmove
#include <limits> // numeric_limits
#include <type_traits> // conditional

#ifdef _MSC_VER
    #include <cstdlib> // _byteswap_uint64
#endif

// SSE2 (every x86-64 CPU) and NEON (every 64-bit Arm CPU) convert the 16
// digits of a double at once
#if defined(__x86_64__) || (defined(_M_X64) && !defined(_M_ARM64EC))
    #include <emmintrin.h>
    #define JSON_DTOA_SSE2 1
    #define JSON_DTOA_NEON 0
#elif (defined(__aarch64__) || defined(_M_ARM64)) && !defined(_M_ARM64EC) && !defined(__ARM_BIG_ENDIAN)
    #include <arm_neon.h>
    #define JSON_DTOA_SSE2 0
    #define JSON_DTOA_NEON 1
#else
    #define JSON_DTOA_SSE2 0
    #define JSON_DTOA_NEON 0
#endif

#include <nlohmann/detail/conversions/zmij.hpp>
#include <nlohmann/detail/macro_scope.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/*!
@brief implements the Grisu2 algorithm for binary to decimal floating-point
conversion.

This implementation is a slightly modified version of the reference
implementation which may be obtained from
http://florian.loitsch.com/publications (bench.tar.gz).

The code is distributed under the MIT license, Copyright (c) 2009 Florian Loitsch.

For a detailed description of the algorithm see:

[1] Loitsch, "Printing Floating-Point Numbers Quickly and Accurately with
    Integers", Proceedings of the ACM SIGPLAN 2010 Conference on Programming
    Language Design and Implementation, PLDI 2010
[2] Burger, Dybvig, "Printing Floating-Point Numbers Quickly and Accurately",
    Proceedings of the ACM SIGPLAN 1996 Conference on Programming Language
    Design and Implementation, PLDI 1996
*/
namespace dtoa_impl
{

template<typename Target, typename Source>
Target reinterpret_bits(const Source source)
{
    static_assert(sizeof(Target) == sizeof(Source), "size mismatch");

    Target target;
    std::memcpy(&target, &source, sizeof(Source));
    return target;
}

struct diyfp // f * 2^e
{
    static constexpr int kPrecision = 64; // = q

    std::uint64_t f = 0;
    int e = 0;

    constexpr diyfp(std::uint64_t f_, int e_) noexcept : f(f_), e(e_) {}

    /*!
    @brief returns x - y
    @pre x.e == y.e and x.f >= y.f
    */
    static diyfp sub(const diyfp& x, const diyfp& y) noexcept
    {
        JSON_ASSERT(x.e == y.e);
        JSON_ASSERT(x.f >= y.f);

        return {x.f - y.f, x.e};
    }

    /*!
    @brief returns x * y
    @note The result is rounded. (Only the upper q bits are returned.)
    */
    static diyfp mul(const diyfp& x, const diyfp& y) noexcept
    {
        static_assert(kPrecision == 64, "internal error");

        // Computes:
        //  f = round((x.f * y.f) / 2^q)
        //  e = x.e + y.e + q

        // Emulate the 64-bit * 64-bit multiplication:
        //
        // p = u * v
        //   = (u_lo + 2^32 u_hi) (v_lo + 2^32 v_hi)
        //   = (u_lo v_lo         ) + 2^32 ((u_lo v_hi         ) + (u_hi v_lo         )) + 2^64 (u_hi v_hi         )
        //   = (p0                ) + 2^32 ((p1                ) + (p2                )) + 2^64 (p3                )
        //   = (p0_lo + 2^32 p0_hi) + 2^32 ((p1_lo + 2^32 p1_hi) + (p2_lo + 2^32 p2_hi)) + 2^64 (p3                )
        //   = (p0_lo             ) + 2^32 (p0_hi + p1_lo + p2_lo                      ) + 2^64 (p1_hi + p2_hi + p3)
        //   = (p0_lo             ) + 2^32 (Q                                          ) + 2^64 (H                 )
        //   = (p0_lo             ) + 2^32 (Q_lo + 2^32 Q_hi                           ) + 2^64 (H                 )
        //
        // (Since Q might be larger than 2^32 - 1)
        //
        //   = (p0_lo + 2^32 Q_lo) + 2^64 (Q_hi + H)
        //
        // (Q_hi + H does not overflow a 64-bit int)
        //
        //   = p_lo + 2^64 p_hi

        const std::uint64_t u_lo = x.f & 0xFFFFFFFFu;
        const std::uint64_t u_hi = x.f >> 32u;
        const std::uint64_t v_lo = y.f & 0xFFFFFFFFu;
        const std::uint64_t v_hi = y.f >> 32u;

        const std::uint64_t p0 = u_lo * v_lo;
        const std::uint64_t p1 = u_lo * v_hi;
        const std::uint64_t p2 = u_hi * v_lo;
        const std::uint64_t p3 = u_hi * v_hi;

        const std::uint64_t p0_hi = p0 >> 32u;
        const std::uint64_t p1_lo = p1 & 0xFFFFFFFFu;
        const std::uint64_t p1_hi = p1 >> 32u;
        const std::uint64_t p2_lo = p2 & 0xFFFFFFFFu;
        const std::uint64_t p2_hi = p2 >> 32u;

        std::uint64_t Q = p0_hi + p1_lo + p2_lo;

        // The full product might now be computed as
        //
        // p_hi = p3 + p2_hi + p1_hi + (Q >> 32)
        // p_lo = p0_lo + (Q << 32)
        //
        // But in this particular case here, the full p_lo is not required.
        // Effectively, we only need to add the highest bit in p_lo to p_hi (and
        // Q_hi + 1 does not overflow).

        Q += std::uint64_t{1} << (64u - 32u - 1u); // round, ties up

        const std::uint64_t h = p3 + p2_hi + p1_hi + (Q >> 32u);

        return {h, x.e + y.e + 64};
    }

    /*!
    @brief normalize x such that the significand is >= 2^(q-1)
    @pre x.f != 0
    */
    static diyfp normalize(diyfp x) noexcept
    {
        JSON_ASSERT(x.f != 0);

        while ((x.f >> 63u) == 0)
        {
            x.f <<= 1u;
            x.e--;
        }

        return x;
    }

    /*!
    @brief normalize x such that the result has the exponent E
    @pre e >= x.e and the upper e - x.e bits of x.f must be zero.
    */
    static diyfp normalize_to(const diyfp& x, const int target_exponent) noexcept
    {
        const int delta = x.e - target_exponent;

        JSON_ASSERT(delta >= 0);
        JSON_ASSERT(((x.f << delta) >> delta) == x.f);

        return {x.f << delta, target_exponent};
    }
};

struct boundaries
{
    diyfp w;
    diyfp minus;
    diyfp plus;
};

/*!
Compute the (normalized) diyfp representing the input number 'value' and its
boundaries.

@pre value must be finite and positive
*/
template<typename FloatType>
boundaries compute_boundaries(FloatType value)
{
    JSON_ASSERT(std::isfinite(value));
    JSON_ASSERT(value > 0);

    // Convert the IEEE representation into a diyfp.
    //
    // If v is denormal:
    //      value = 0.F * 2^(1 - bias) = (          F) * 2^(1 - bias - (p-1))
    // If v is normalized:
    //      value = 1.F * 2^(E - bias) = (2^(p-1) + F) * 2^(E - bias - (p-1))

    static_assert(std::numeric_limits<FloatType>::is_iec559,
                  "internal error: dtoa_short requires an IEEE-754 floating-point implementation");

    constexpr int      kPrecision = std::numeric_limits<FloatType>::digits; // = p (includes the hidden bit)
    constexpr int      kBias      = std::numeric_limits<FloatType>::max_exponent - 1 + (kPrecision - 1);
    constexpr int      kMinExp    = 1 - kBias;
    constexpr std::uint64_t kHiddenBit = std::uint64_t{1} << (kPrecision - 1); // = 2^(p-1)

    using bits_type = typename std::conditional<kPrecision == 24, std::uint32_t, std::uint64_t >::type;

    const auto bits = static_cast<std::uint64_t>(reinterpret_bits<bits_type>(value));
    const std::uint64_t E = bits >> (kPrecision - 1);
    const std::uint64_t F = bits & (kHiddenBit - 1);

    const bool is_denormal = E == 0;
    const diyfp v = is_denormal
                    ? diyfp(F, kMinExp)
                    : diyfp(F + kHiddenBit, static_cast<int>(E) - kBias);

    // Compute the boundaries m- and m+ of the floating-point value
    // v = f * 2^e.
    //
    // Determine v- and v+, the floating-point predecessor and successor of v,
    // respectively.
    //
    //      v- = v - 2^e        if f != 2^(p-1) or e == e_min                (A)
    //         = v - 2^(e-1)    if f == 2^(p-1) and e > e_min                (B)
    //
    //      v+ = v + 2^e
    //
    // Let m- = (v- + v) / 2 and m+ = (v + v+) / 2. All real numbers _strictly_
    // between m- and m+ round to v, regardless of how the input rounding
    // algorithm breaks ties.
    //
    //      ---+-------------+-------------+-------------+-------------+---  (A)
    //         v-            m-            v             m+            v+
    //
    //      -----------------+------+------+-------------+-------------+---  (B)
    //                       v-     m-     v             m+            v+

    const bool lower_boundary_is_closer = F == 0 && E > 1;
    const diyfp m_plus = diyfp((2 * v.f) + 1, v.e - 1);
    const diyfp m_minus = lower_boundary_is_closer
                          ? diyfp((4 * v.f) - 1, v.e - 2)  // (B)
                          : diyfp((2 * v.f) - 1, v.e - 1); // (A)

    // Determine the normalized w+ = m+.
    const diyfp w_plus = diyfp::normalize(m_plus);

    // Determine w- = m- such that e_(w-) = e_(w+).
    const diyfp w_minus = diyfp::normalize_to(m_minus, w_plus.e);

    return {diyfp::normalize(v), w_minus, w_plus};
}

// Given normalized diyfp w, Grisu needs to find a (normalized) cached
// power-of-ten c, such that the exponent of the product c * w = f * 2^e lies
// within a certain range [alpha, gamma] (Definition 3.2 from [1])
//
//      alpha <= e = e_c + e_w + q <= gamma
//
// or
//
//      f_c * f_w * 2^alpha <= f_c 2^(e_c) * f_w 2^(e_w) * 2^q
//                          <= f_c * f_w * 2^gamma
//
// Since c and w are normalized, i.e. 2^(q-1) <= f < 2^q, this implies
//
//      2^(q-1) * 2^(q-1) * 2^alpha <= c * w * 2^q < 2^q * 2^q * 2^gamma
//
// or
//
//      2^(q - 2 + alpha) <= c * w < 2^(q + gamma)
//
// The choice of (alpha,gamma) determines the size of the table and the form of
// the digit generation procedure. Using (alpha,gamma)=(-60,-32) works out well
// in practice:
//
// The idea is to cut the number c * w = f * 2^e into two parts, which can be
// processed independently: An integral part p1, and a fractional part p2:
//
//      f * 2^e = ( (f div 2^-e) * 2^-e + (f mod 2^-e) ) * 2^e
//              = (f div 2^-e) + (f mod 2^-e) * 2^e
//              = p1 + p2 * 2^e
//
// The conversion of p1 into decimal form requires a series of divisions and
// modulos by (a power of) 10. These operations are faster for 32-bit than for
// 64-bit integers, so p1 should ideally fit into a 32-bit integer. This can be
// achieved by choosing
//
//      -e >= 32   or   e <= -32 := gamma
//
// In order to convert the fractional part
//
//      p2 * 2^e = p2 / 2^-e = d[-1] / 10^1 + d[-2] / 10^2 + ...
//
// into decimal form, the fraction is repeatedly multiplied by 10 and the digits
// d[-i] are extracted in order:
//
//      (10 * p2) div 2^-e = d[-1]
//      (10 * p2) mod 2^-e = d[-2] / 10^1 + ...
//
// The multiplication by 10 must not overflow. It is sufficient to choose
//
//      10 * p2 < 16 * p2 = 2^4 * p2 <= 2^64.
//
// Since p2 = f mod 2^-e < 2^-e,
//
//      -e <= 60   or   e >= -60 := alpha

constexpr int kAlpha = -60;
constexpr int kGamma = -32;

struct cached_power // c = f * 2^e ~= 10^k
{
    std::uint64_t f;
    int e;
    int k;
};

/*!
For a normalized diyfp w = f * 2^e, this function returns a (normalized) cached
power-of-ten c = f_c * 2^e_c, such that the exponent of the product w * c
satisfies (Definition 3.2 from [1])

     alpha <= e_c + e + q <= gamma.
*/
inline cached_power get_cached_power_for_binary_exponent(int e)
{
    // Now
    //
    //      alpha <= e_c + e + q <= gamma                                    (1)
    //      ==> f_c * 2^alpha <= c * 2^e * 2^q
    //
    // and since the c's are normalized, 2^(q-1) <= f_c,
    //
    //      ==> 2^(q - 1 + alpha) <= c * 2^(e + q)
    //      ==> 2^(alpha - e - 1) <= c
    //
    // If c were an exact power of ten, i.e. c = 10^k, one may determine k as
    //
    //      k = ceil( log_10( 2^(alpha - e - 1) ) )
    //        = ceil( (alpha - e - 1) * log_10(2) )
    //
    // From the paper:
    // "In theory the result of the procedure could be wrong since c is rounded,
    //  and the computation itself is approximated [...]. In practice, however,
    //  this simple function is sufficient."
    //
    // For IEEE double precision floating-point numbers converted into
    // normalized diyfp's w = f * 2^e, with q = 64,
    //
    //      e >= -1022      (min IEEE exponent)
    //           -52        (p - 1)
    //           -52        (p - 1, possibly normalize denormal IEEE numbers)
    //           -11        (normalize the diyfp)
    //         = -1137
    //
    // and
    //
    //      e <= +1023      (max IEEE exponent)
    //           -52        (p - 1)
    //           -11        (normalize the diyfp)
    //         = 960
    //
    // This binary exponent range [-1137,960] results in a decimal exponent
    // range [-307,324]. One does not need to store a cached power for each
    // k in this range. For each such k it suffices to find a cached power
    // such that the exponent of the product lies in [alpha,gamma].
    // This implies that the difference of the decimal exponents of adjacent
    // table entries must be less than or equal to
    //
    //      floor( (gamma - alpha) * log_10(2) ) = 8.
    //
    // (A smaller distance gamma-alpha would require a larger table.)

    // NB:
    // Actually, this function returns c, such that -60 <= e_c + e + 64 <= -34.

    constexpr int kCachedPowersMinDecExp = -300;
    constexpr int kCachedPowersDecStep = 8;

    static constexpr std::array<cached_power, 79> kCachedPowers =
    {
        {
            { 0xAB70FE17C79AC6CA, -1060, -300 },
            { 0xFF77B1FCBEBCDC4F, -1034, -292 },
            { 0xBE5691EF416BD60C, -1007, -284 },
            { 0x8DD01FAD907FFC3C,  -980, -276 },
            { 0xD3515C2831559A83,  -954, -268 },
            { 0x9D71AC8FADA6C9B5,  -927, -260 },
            { 0xEA9C227723EE8BCB,  -901, -252 },
            { 0xAECC49914078536D,  -874, -244 },
            { 0x823C12795DB6CE57,  -847, -236 },
            { 0xC21094364DFB5637,  -821, -228 },
            { 0x9096EA6F3848984F,  -794, -220 },
            { 0xD77485CB25823AC7,  -768, -212 },
            { 0xA086CFCD97BF97F4,  -741, -204 },
            { 0xEF340A98172AACE5,  -715, -196 },
            { 0xB23867FB2A35B28E,  -688, -188 },
            { 0x84C8D4DFD2C63F3B,  -661, -180 },
            { 0xC5DD44271AD3CDBA,  -635, -172 },
            { 0x936B9FCEBB25C996,  -608, -164 },
            { 0xDBAC6C247D62A584,  -582, -156 },
            { 0xA3AB66580D5FDAF6,  -555, -148 },
            { 0xF3E2F893DEC3F126,  -529, -140 },
            { 0xB5B5ADA8AAFF80B8,  -502, -132 },
            { 0x87625F056C7C4A8B,  -475, -124 },
            { 0xC9BCFF6034C13053,  -449, -116 },
            { 0x964E858C91BA2655,  -422, -108 },
            { 0xDFF9772470297EBD,  -396, -100 },
            { 0xA6DFBD9FB8E5B88F,  -369,  -92 },
            { 0xF8A95FCF88747D94,  -343,  -84 },
            { 0xB94470938FA89BCF,  -316,  -76 },
            { 0x8A08F0F8BF0F156B,  -289,  -68 },
            { 0xCDB02555653131B6,  -263,  -60 },
            { 0x993FE2C6D07B7FAC,  -236,  -52 },
            { 0xE45C10C42A2B3B06,  -210,  -44 },
            { 0xAA242499697392D3,  -183,  -36 },
            { 0xFD87B5F28300CA0E,  -157,  -28 },
            { 0xBCE5086492111AEB,  -130,  -20 },
            { 0x8CBCCC096F5088CC,  -103,  -12 },
            { 0xD1B71758E219652C,   -77,   -4 },
            { 0x9C40000000000000,   -50,    4 },
            { 0xE8D4A51000000000,   -24,   12 },
            { 0xAD78EBC5AC620000,     3,   20 },
            { 0x813F3978F8940984,    30,   28 },
            { 0xC097CE7BC90715B3,    56,   36 },
            { 0x8F7E32CE7BEA5C70,    83,   44 },
            { 0xD5D238A4ABE98068,   109,   52 },
            { 0x9F4F2726179A2245,   136,   60 },
            { 0xED63A231D4C4FB27,   162,   68 },
            { 0xB0DE65388CC8ADA8,   189,   76 },
            { 0x83C7088E1AAB65DB,   216,   84 },
            { 0xC45D1DF942711D9A,   242,   92 },
            { 0x924D692CA61BE758,   269,  100 },
            { 0xDA01EE641A708DEA,   295,  108 },
            { 0xA26DA3999AEF774A,   322,  116 },
            { 0xF209787BB47D6B85,   348,  124 },
            { 0xB454E4A179DD1877,   375,  132 },
            { 0x865B86925B9BC5C2,   402,  140 },
            { 0xC83553C5C8965D3D,   428,  148 },
            { 0x952AB45CFA97A0B3,   455,  156 },
            { 0xDE469FBD99A05FE3,   481,  164 },
            { 0xA59BC234DB398C25,   508,  172 },
            { 0xF6C69A72A3989F5C,   534,  180 },
            { 0xB7DCBF5354E9BECE,   561,  188 },
            { 0x88FCF317F22241E2,   588,  196 },
            { 0xCC20CE9BD35C78A5,   614,  204 },
            { 0x98165AF37B2153DF,   641,  212 },
            { 0xE2A0B5DC971F303A,   667,  220 },
            { 0xA8D9D1535CE3B396,   694,  228 },
            { 0xFB9B7CD9A4A7443C,   720,  236 },
            { 0xBB764C4CA7A44410,   747,  244 },
            { 0x8BAB8EEFB6409C1A,   774,  252 },
            { 0xD01FEF10A657842C,   800,  260 },
            { 0x9B10A4E5E9913129,   827,  268 },
            { 0xE7109BFBA19C0C9D,   853,  276 },
            { 0xAC2820D9623BF429,   880,  284 },
            { 0x80444B5E7AA7CF85,   907,  292 },
            { 0xBF21E44003ACDD2D,   933,  300 },
            { 0x8E679C2F5E44FF8F,   960,  308 },
            { 0xD433179D9C8CB841,   986,  316 },
            { 0x9E19DB92B4E31BA9,  1013,  324 },
        }
    };

    // This computation gives exactly the same results for k as
    //      k = ceil((kAlpha - e - 1) * 0.30102999566398114)
    // for |e| <= 1500, but doesn't require floating-point operations.
    // NB: log_10(2) ~= 78913 / 2^18
    JSON_ASSERT(e >= -1500);
    JSON_ASSERT(e <=  1500);
    const int f = kAlpha - e - 1;
    const int k = ((f * 78913) / (1 << 18)) + static_cast<int>(f > 0);

    const int index = (-kCachedPowersMinDecExp + k + (kCachedPowersDecStep - 1)) / kCachedPowersDecStep;
    JSON_ASSERT(index >= 0);
    JSON_ASSERT(static_cast<std::size_t>(index) < kCachedPowers.size());

    const cached_power cached = kCachedPowers[static_cast<std::size_t>(index)];
    JSON_ASSERT(kAlpha <= cached.e + e + 64);
    JSON_ASSERT(kGamma >= cached.e + e + 64);

    return cached;
}

/*!
For n != 0, returns k, such that pow10 := 10^(k-1) <= n < 10^k.
For n == 0, returns 1 and sets pow10 := 1.
*/
inline int find_largest_pow10(const std::uint32_t n, std::uint32_t& pow10)
{
    // LCOV_EXCL_START
    if (n >= 1000000000)
    {
        pow10 = 1000000000;
        return 10;
    }
    // LCOV_EXCL_STOP
    if (n >= 100000000)
    {
        pow10 = 100000000;
        return  9;
    }
    if (n >= 10000000)
    {
        pow10 = 10000000;
        return  8;
    }
    if (n >= 1000000)
    {
        pow10 = 1000000;
        return  7;
    }
    if (n >= 100000)
    {
        pow10 = 100000;
        return  6;
    }
    if (n >= 10000)
    {
        pow10 = 10000;
        return  5;
    }
    if (n >= 1000)
    {
        pow10 = 1000;
        return  4;
    }
    if (n >= 100)
    {
        pow10 = 100;
        return  3;
    }
    if (n >= 10)
    {
        pow10 = 10;
        return  2;
    }

    pow10 = 1;
    return 1;
}

inline void grisu2_round(char* buf, int len, std::uint64_t dist, std::uint64_t delta,
                         std::uint64_t rest, std::uint64_t ten_k)
{
    JSON_ASSERT(len >= 1);
    JSON_ASSERT(dist <= delta);
    JSON_ASSERT(rest <= delta);
    JSON_ASSERT(ten_k > 0);

    //               <--------------------------- delta ---->
    //                                  <---- dist --------->
    // --------------[------------------+-------------------]--------------
    //               M-                 w                   M+
    //
    //                                  ten_k
    //                                <------>
    //                                       <---- rest ---->
    // --------------[------------------+----+--------------]--------------
    //                                  w    V
    //                                       = buf * 10^k
    //
    // ten_k represents a unit-in-the-last-place in the decimal representation
    // stored in buf.
    // Decrement buf by ten_k while this takes buf closer to w.

    // The tests are written in this order to avoid overflow in unsigned
    // integer arithmetic.

    while (rest < dist
            && delta - rest >= ten_k
            && (rest + ten_k < dist || dist - rest > rest + ten_k - dist))
    {
        JSON_ASSERT(buf[len - 1] != '0');
        buf[len - 1]--;
        rest += ten_k;
    }
}

/*!
Generates V = buffer * 10^decimal_exponent, such that M- <= V <= M+.
M- and M+ must be normalized and share the same exponent -60 <= e <= -32.
*/
inline void grisu2_digit_gen(char* buffer, int& length, int& decimal_exponent,
                             diyfp M_minus, diyfp w, diyfp M_plus)
{
    static_assert(kAlpha >= -60, "internal error");
    static_assert(kGamma <= -32, "internal error");

    // Generates the digits (and the exponent) of a decimal floating-point
    // number V = buffer * 10^decimal_exponent in the range [M-, M+]. The diyfp's
    // w, M- and M+ share the same exponent e, which satisfies alpha <= e <= gamma.
    //
    //               <--------------------------- delta ---->
    //                                  <---- dist --------->
    // --------------[------------------+-------------------]--------------
    //               M-                 w                   M+
    //
    // Grisu2 generates the digits of M+ from left to right and stops as soon as
    // V is in [M-,M+].

    JSON_ASSERT(M_plus.e >= kAlpha);
    JSON_ASSERT(M_plus.e <= kGamma);

    std::uint64_t delta = diyfp::sub(M_plus, M_minus).f; // (significand of (M+ - M-), implicit exponent is e)
    std::uint64_t dist  = diyfp::sub(M_plus, w      ).f; // (significand of (M+ - w ), implicit exponent is e)

    // Split M+ = f * 2^e into two parts p1 and p2 (note: e < 0):
    //
    //      M+ = f * 2^e
    //         = ((f div 2^-e) * 2^-e + (f mod 2^-e)) * 2^e
    //         = ((p1        ) * 2^-e + (p2        )) * 2^e
    //         = p1 + p2 * 2^e

    const diyfp one(std::uint64_t{1} << -M_plus.e, M_plus.e);

    auto p1 = static_cast<std::uint32_t>(M_plus.f >> -one.e); // p1 = f div 2^-e (Since -e >= 32, p1 fits into a 32-bit int.)
    std::uint64_t p2 = M_plus.f & (one.f - 1);                    // p2 = f mod 2^-e

    // 1)
    //
    // Generate the digits of the integral part p1 = d[n-1]...d[1]d[0]

    JSON_ASSERT(p1 > 0);

    std::uint32_t pow10{};
    const int k = find_largest_pow10(p1, pow10);

    //      10^(k-1) <= p1 < 10^k, pow10 = 10^(k-1)
    //
    //      p1 = (p1 div 10^(k-1)) * 10^(k-1) + (p1 mod 10^(k-1))
    //         = (d[k-1]         ) * 10^(k-1) + (p1 mod 10^(k-1))
    //
    //      M+ = p1                                             + p2 * 2^e
    //         = d[k-1] * 10^(k-1) + (p1 mod 10^(k-1))          + p2 * 2^e
    //         = d[k-1] * 10^(k-1) + ((p1 mod 10^(k-1)) * 2^-e + p2) * 2^e
    //         = d[k-1] * 10^(k-1) + (                         rest) * 2^e
    //
    // Now generate the digits d[n] of p1 from left to right (n = k-1,...,0)
    //
    //      p1 = d[k-1]...d[n] * 10^n + d[n-1]...d[0]
    //
    // but stop as soon as
    //
    //      rest * 2^e = (d[n-1]...d[0] * 2^-e + p2) * 2^e <= delta * 2^e

    int n = k;
    while (n > 0)
    {
        // Invariants:
        //      M+ = buffer * 10^n + (p1 + p2 * 2^e)    (buffer = 0 for n = k)
        //      pow10 = 10^(n-1) <= p1 < 10^n
        //
        const std::uint32_t d = p1 / pow10;  // d = p1 div 10^(n-1)
        const std::uint32_t r = p1 % pow10;  // r = p1 mod 10^(n-1)
        //
        //      M+ = buffer * 10^n + (d * 10^(n-1) + r) + p2 * 2^e
        //         = (buffer * 10 + d) * 10^(n-1) + (r + p2 * 2^e)
        //
        JSON_ASSERT(d <= 9);
        buffer[length++] = static_cast<char>('0' + d); // buffer := buffer * 10 + d
        //
        //      M+ = buffer * 10^(n-1) + (r + p2 * 2^e)
        //
        p1 = r;
        n--;
        //
        //      M+ = buffer * 10^n + (p1 + p2 * 2^e)
        //      pow10 = 10^n
        //

        // Now check if enough digits have been generated.
        // Compute
        //
        //      p1 + p2 * 2^e = (p1 * 2^-e + p2) * 2^e = rest * 2^e
        //
        // Note:
        // Since rest and delta share the same exponent e, it suffices to
        // compare the significands.
        const std::uint64_t rest = (std::uint64_t{p1} << -one.e) + p2;
        if (rest <= delta)
        {
            // V = buffer * 10^n, with M- <= V <= M+.

            decimal_exponent += n;

            // We may now just stop. But instead, it looks as if the buffer
            // could be decremented to bring V closer to w.
            //
            // pow10 = 10^n is now 1 ulp in the decimal representation V.
            // The rounding procedure works with diyfp's with an implicit
            // exponent of e.
            //
            //      10^n = (10^n * 2^-e) * 2^e = ulp * 2^e
            //
            const std::uint64_t ten_n = std::uint64_t{pow10} << -one.e;
            grisu2_round(buffer, length, dist, delta, rest, ten_n);

            return;
        }

        pow10 /= 10;
        //
        //      pow10 = 10^(n-1) <= p1 < 10^n
        // Invariants restored.
    }

    // 2)
    //
    // The digits of the integral part have been generated:
    //
    //      M+ = d[k-1]...d[1]d[0] + p2 * 2^e
    //         = buffer            + p2 * 2^e
    //
    // Now generate the digits of the fractional part p2 * 2^e.
    //
    // Note:
    // No decimal point is generated: the exponent is adjusted instead.
    //
    // p2 actually represents the fraction
    //
    //      p2 * 2^e
    //          = p2 / 2^-e
    //          = d[-1] / 10^1 + d[-2] / 10^2 + ...
    //
    // Now generate the digits d[-m] of p1 from left to right (m = 1,2,...)
    //
    //      p2 * 2^e = d[-1]d[-2]...d[-m] * 10^-m
    //                      + 10^-m * (d[-m-1] / 10^1 + d[-m-2] / 10^2 + ...)
    //
    // using
    //
    //      10^m * p2 = ((10^m * p2) div 2^-e) * 2^-e + ((10^m * p2) mod 2^-e)
    //                = (                   d) * 2^-e + (                   r)
    //
    // or
    //      10^m * p2 * 2^e = d + r * 2^e
    //
    // i.e.
    //
    //      M+ = buffer + p2 * 2^e
    //         = buffer + 10^-m * (d + r * 2^e)
    //         = (buffer * 10^m + d) * 10^-m + 10^-m * r * 2^e
    //
    // and stop as soon as 10^-m * r * 2^e <= delta * 2^e

    JSON_ASSERT(p2 > delta);

    int m = 0;
    for (;;)
    {
        // Invariant:
        //      M+ = buffer * 10^-m + 10^-m * (d[-m-1] / 10 + d[-m-2] / 10^2 + ...) * 2^e
        //         = buffer * 10^-m + 10^-m * (p2                                 ) * 2^e
        //         = buffer * 10^-m + 10^-m * (1/10 * (10 * p2)                   ) * 2^e
        //         = buffer * 10^-m + 10^-m * (1/10 * ((10*p2 div 2^-e) * 2^-e + (10*p2 mod 2^-e)) * 2^e
        //
        JSON_ASSERT(p2 <= (std::numeric_limits<std::uint64_t>::max)() / 10);
        p2 *= 10;
        const std::uint64_t d = p2 >> -one.e;     // d = (10 * p2) div 2^-e
        const std::uint64_t r = p2 & (one.f - 1); // r = (10 * p2) mod 2^-e
        //
        //      M+ = buffer * 10^-m + 10^-m * (1/10 * (d * 2^-e + r) * 2^e
        //         = buffer * 10^-m + 10^-m * (1/10 * (d + r * 2^e))
        //         = (buffer * 10 + d) * 10^(-m-1) + 10^(-m-1) * r * 2^e
        //
        JSON_ASSERT(d <= 9);
        buffer[length++] = static_cast<char>('0' + d); // buffer := buffer * 10 + d
        //
        //      M+ = buffer * 10^(-m-1) + 10^(-m-1) * r * 2^e
        //
        p2 = r;
        m++;
        //
        //      M+ = buffer * 10^-m + 10^-m * p2 * 2^e
        // Invariant restored.

        // Check if enough digits have been generated.
        //
        //      10^-m * p2 * 2^e <= delta * 2^e
        //              p2 * 2^e <= 10^m * delta * 2^e
        //                    p2 <= 10^m * delta
        delta *= 10;
        dist  *= 10;
        if (p2 <= delta)
        {
            break;
        }
    }

    // V = buffer * 10^-m, with M- <= V <= M+.

    decimal_exponent -= m;

    // 1 ulp in the decimal representation is now 10^-m.
    // Since delta and dist are now scaled by 10^m, we need to do the
    // same with ulp in order to keep the units in sync.
    //
    //      10^m * 10^-m = 1 = 2^-e * 2^e = ten_m * 2^e
    //
    const std::uint64_t ten_m = one.f;
    grisu2_round(buffer, length, dist, delta, p2, ten_m);

    // By construction this algorithm generates the shortest possible decimal
    // number (Loitsch, Theorem 6.2) which rounds back to w.
    // For an input number of precision p, at least
    //
    //      N = 1 + ceil(p * log_10(2))
    //
    // decimal digits are sufficient to identify all binary floating-point
    // numbers (Matula, "In-and-Out conversions").
    // This implies that the algorithm does not produce more than N decimal
    // digits.
    //
    //      N = 17 for p = 53 (IEEE double precision)
    //      N = 9  for p = 24 (IEEE single precision)
}

/*!
v = buf * 10^decimal_exponent
len is the length of the buffer (number of decimal digits)
The buffer must be large enough, i.e. >= max_digits10.
*/
JSON_HEDLEY_NON_NULL(1)
inline void grisu2(char* buf, int& len, int& decimal_exponent,
                   diyfp m_minus, diyfp v, diyfp m_plus)
{
    JSON_ASSERT(m_plus.e == m_minus.e);
    JSON_ASSERT(m_plus.e == v.e);

    //  --------(-----------------------+-----------------------)--------    (A)
    //          m-                      v                       m+
    //
    //  --------------------(-----------+-----------------------)--------    (B)
    //                      m-          v                       m+
    //
    // First scale v (and m- and m+) such that the exponent is in the range
    // [alpha, gamma].

    const cached_power cached = get_cached_power_for_binary_exponent(m_plus.e);

    const diyfp c_minus_k(cached.f, cached.e); // = c ~= 10^-k

    // The exponent of the products is = v.e + c_minus_k.e + q and is in the range [alpha,gamma]
    const diyfp w       = diyfp::mul(v,       c_minus_k);
    const diyfp w_minus = diyfp::mul(m_minus, c_minus_k);
    const diyfp w_plus  = diyfp::mul(m_plus,  c_minus_k);

    //  ----(---+---)---------------(---+---)---------------(---+---)----
    //          w-                      w                       w+
    //          = c*m-                  = c*v                   = c*m+
    //
    // diyfp::mul rounds its result and c_minus_k is approximated too. w, w- and
    // w+ are now off by a small amount.
    // In fact:
    //
    //      w - v * 10^k < 1 ulp
    //
    // To account for this inaccuracy, add resp. subtract 1 ulp.
    //
    //  --------+---[---------------(---+---)---------------]---+--------
    //          w-  M-                  w                   M+  w+
    //
    // Now any number in [M-, M+] (bounds included) will round to w when input,
    // regardless of how the input rounding algorithm breaks ties.
    //
    // And digit_gen generates the shortest possible such number in [M-, M+].
    // Note that this does not mean that Grisu2 always generates the shortest
    // possible number in the interval (m-, m+).
    const diyfp M_minus(w_minus.f + 1, w_minus.e);
    const diyfp M_plus (w_plus.f  - 1, w_plus.e );

    decimal_exponent = -cached.k; // = -(-k) = k

    grisu2_digit_gen(buf, len, decimal_exponent, M_minus, w, M_plus);
}

/*!
v = buf * 10^decimal_exponent
len is the length of the buffer (number of decimal digits)
The buffer must be large enough, i.e. >= max_digits10.
*/
template<typename FloatType>
JSON_HEDLEY_NON_NULL(1)
void grisu2(char* buf, int& len, int& decimal_exponent, FloatType value)
{
    static_assert(diyfp::kPrecision >= std::numeric_limits<FloatType>::digits + 3,
                  "internal error: not enough precision");

    JSON_ASSERT(std::isfinite(value));
    JSON_ASSERT(value > 0);

    // If the neighbors (and boundaries) of 'value' are always computed for double-precision
    // numbers, all float's can be recovered using strtod (and strtof). However, the resulting
    // decimal representations are not exactly "short".
    //
    // The documentation for 'std::to_chars' (https://en.cppreference.com/w/cpp/utility/to_chars)
    // says "value is converted to a string as if by std::sprintf in the default ("C") locale"
    // and since sprintf promotes floats to doubles, I think this is exactly what 'std::to_chars'
    // does.
    // On the other hand, the documentation for 'std::to_chars' requires that "parsing the
    // representation using the corresponding std::from_chars function recovers value exactly". That
    // indicates that single precision floating-point numbers should be recovered using
    // 'std::strtof'.
    //
    // NB: If the neighbors are computed for single-precision numbers, there is a single float
    //     (7.0385307e-26f) which can't be recovered using strtod. The resulting double precision
    //     value is off by 1 ulp.
#if 0 // NOLINT(readability-avoid-unconditional-preprocessor-if)
    const boundaries w = compute_boundaries(static_cast<double>(value));
#else
    const boundaries w = compute_boundaries(value);
#endif

    grisu2(buf, len, decimal_exponent, w.minus, w.w, w.plus);
}

/*!
@brief the shortest digits of a positive finite float (other than double): Grisu2
*/
template<typename FloatType>
JSON_HEDLEY_NON_NULL(1)
void shortest_digits(char* buf, int& len, int& decimal_exponent, FloatType value)
{
    grisu2(buf, len, decimal_exponent, value);
}

/*!
@brief the shortest digits of a positive finite double: the conversion of
Zmij (see zmij.hpp), which always finds the shortest digits that read back as
the same value (Grisu2 does not for about one double in a thousand), and the
closest of them if there are several

v = buf * 10^decimal_exponent, as for grisu2()
*/
JSON_HEDLEY_NON_NULL(1)
inline void shortest_digits(char* buf, int& len, int& decimal_exponent, double value)
{
    static_assert(std::numeric_limits<double>::is_iec559 && std::numeric_limits<double>::digits == 53,
                  "internal error: the conversion of Zmij needs IEEE 754 binary64 doubles");
    JSON_ASSERT(std::isfinite(value));
    JSON_ASSERT(value > 0);

    std::uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    zmij::decimal d = zmij::to_decimal(bits);
    // without trailing zeros (up to 16): 8, 4, 2, 1 at a time
    while (d.significand % 100000000 == 0)
    {
        d.significand /= 100000000;
        d.exponent += 8;
    }
    if (d.significand % 10000 == 0)
    {
        d.significand /= 10000;
        d.exponent += 4;
    }
    if (d.significand % 100 == 0)
    {
        d.significand /= 100;
        d.exponent += 2;
    }
    if (d.significand % 10 == 0)
    {
        d.significand /= 10;
        d.exponent += 1;
    }
    // at most 17 digits, written from the back two at a time
    static constexpr const char* pairs =
        "00010203040506070809101112131415161718192021222324252627282930313233343536373839"
        "40414243444546474849505152535455565758596061626364656667686970717273747576777879"
        "8081828384858687888990919293949596979899";
    std::array<char, 20> digits{};
    std::size_t n = digits.size();
    while (d.significand >= 100)
    {
        const std::uint64_t two_digits = d.significand % 100; // a variable: GCC calls a cast of the remainder useless where std::uint64_t is std::size_t
        const auto i = static_cast<std::size_t>(two_digits) * 2;
        d.significand /= 100;
        n -= 2;
        digits[n] = pairs[i];
        digits[n + 1] = pairs[i + 1];
    }
    if (d.significand >= 10)
    {
        const auto i = static_cast<std::size_t>(d.significand) * 2;
        n -= 2;
        digits[n] = pairs[i];
        digits[n + 1] = pairs[i + 1];
    }
    else
    {
        digits[--n] = static_cast<char>('0' + d.significand);
    }
    len = static_cast<int>(digits.size() - n);
    std::memcpy(buf, digits.data() + n, static_cast<std::size_t>(len));
    decimal_exponent = d.exponent;
}

/*!
@brief appends a decimal representation of e to buf
@return a pointer to the element following the exponent.
@pre -1000 < e < 1000
*/
JSON_HEDLEY_NON_NULL(1)
JSON_HEDLEY_RETURNS_NON_NULL
inline char* append_exponent(char* buf, int e)
{
    JSON_ASSERT(e > -1000);
    JSON_ASSERT(e <  1000);

    if (e < 0)
    {
        e = -e;
        *buf++ = '-';
    }
    else
    {
        *buf++ = '+';
    }

    auto k = static_cast<std::uint32_t>(e);
    if (k < 10)
    {
        // Always print at least two digits in the exponent.
        // This is for compatibility with printf("%g").
        *buf++ = '0';
        *buf++ = static_cast<char>('0' + k);
    }
    else if (k < 100)
    {
        *buf++ = static_cast<char>('0' + (k / 10));
        k %= 10;
        *buf++ = static_cast<char>('0' + k);
    }
    else
    {
        *buf++ = static_cast<char>('0' + (k / 100));
        k %= 100;
        *buf++ = static_cast<char>('0' + (k / 10));
        k %= 10;
        *buf++ = static_cast<char>('0' + k);
    }

    return buf;
}

/*!
@brief prettify v = buf * 10^decimal_exponent

If v is in the range [10^min_exp, 10^max_exp) it will be printed in fixed-point
notation. Otherwise it will be printed in exponential notation.

@pre min_exp < 0
@pre max_exp > 0
*/
JSON_HEDLEY_NON_NULL(1)
JSON_HEDLEY_RETURNS_NON_NULL
inline char* format_buffer(char* buf, int len, int decimal_exponent,
                           int min_exp, int max_exp)
{
    JSON_ASSERT(min_exp < 0);
    JSON_ASSERT(max_exp > 0);

    const int k = len;
    const int n = len + decimal_exponent;

    // v = buf * 10^(n-k)
    // k is the length of the buffer (number of decimal digits)
    // n is the position of the decimal point relative to the start of the buffer.

    if (k <= n && n <= max_exp)
    {
        // digits[000]
        // len <= max_exp + 2

        std::memset(buf + k, '0', static_cast<size_t>(n) - static_cast<size_t>(k));
        // Make it look like a floating-point number (#362, #378)
        buf[n + 0] = '.';
        buf[n + 1] = '0';
        return buf + (static_cast<size_t>(n) + 2);
    }

    if (0 < n && n <= max_exp)
    {
        // dig.its
        // len <= max_digits10 + 1

        JSON_ASSERT(k > n);

        std::memmove(buf + (static_cast<size_t>(n) + 1), buf + n, static_cast<size_t>(k) - static_cast<size_t>(n));
        buf[n] = '.';
        return buf + (static_cast<size_t>(k) + 1U);
    }

    if (min_exp < n && n <= 0)
    {
        // 0.[000]digits
        // len <= 2 + (-min_exp - 1) + max_digits10

        std::memmove(buf + (2 + static_cast<size_t>(-n)), buf, static_cast<size_t>(k));
        buf[0] = '0';
        buf[1] = '.';
        std::memset(buf + 2, '0', static_cast<size_t>(-n));
        return buf + (2U + static_cast<size_t>(-n) + static_cast<size_t>(k));
    }

    if (k == 1)
    {
        // dE+123
        // len <= 1 + 5

        buf += 1;
    }
    else
    {
        // d.igitsE+123
        // len <= max_digits10 + 1 + 5

        std::memmove(buf + 2, buf + 1, static_cast<size_t>(k) - 1);
        buf[1] = '.';
        buf += 1 + static_cast<size_t>(k);
    }

    *buf++ = 'e';
    return append_exponent(buf, n - 1);
}

/// eight decimal digits (a value below 10^8) as bytes 0..9, the first digit
/// in the most significant byte: three steps that divide all lanes at once
/// by a multiplication (the conversion of Xiang JunBo, as in Zmij)
inline std::uint64_t eight_digit_bytes(std::uint64_t abcdefgh) noexcept
{
    const std::uint64_t abcd_efgh = abcdefgh + (((std::uint64_t{1} << 32u) - 10000u) * ((abcdefgh * (((std::uint64_t{1} << 40u) / 10000u) + 1u)) >> 40u));
    const std::uint64_t ab_cd_ef_gh = abcd_efgh + (((std::uint64_t{1} << 16u) - 100u) * (((abcd_efgh * (((std::uint64_t{1} << 19u) / 100u) + 1u)) >> 19u) & 0x7F0000007Fu));
    return ab_cd_ef_gh + (((std::uint64_t{1} << 8u) - 10u) * (((ab_cd_ef_gh * (((std::uint64_t{1} << 10u) / 10u) + 1u)) >> 10u) & 0x000F000F000F000Fu));
}

/// store the bytes of v, the most significant one first (one byte swap and
/// one store where the byte order is known: compilers do not reliably merge
/// the byte stores once this is inlined)
inline void store_msb_first(char* p, std::uint64_t v) noexcept
{
#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    v = __builtin_bswap64(v);
    std::memcpy(p, &v, sizeof(v));
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    std::memcpy(p, &v, sizeof(v));
#elif defined(_MSC_VER) // (little-endian on all its targets)
    v = _byteswap_uint64(v);
    std::memcpy(p, &v, sizeof(v));
#else
    for (unsigned i = 0; i < 8; ++i)
    {
        p[i] = static_cast<char>(v >> (56u - (8u * i)));
    }
#endif
}

/*!
@brief digits * 10^exp for a double, in the layout of format_buffer()

The layout is that of format_buffer() with min_exp -4 and max_exp 15 (the
digits10 of double). The digits are converted eight at a time and placed
with fixed-size moves instead of per-digit loops and moves of the buffer.

@param[in] digits  the digits (not 0, at most 17 digits; trailing zeros allowed)
@param[in] exp     the decimal exponent of the last digit
@return a pointer past the text; up to 41 bytes at @a first are written
        (some beyond the returned end)
*/
JSON_HEDLEY_NON_NULL(1)
JSON_HEDLEY_RETURNS_NON_NULL
inline char* write_decimal(char* first, std::uint64_t digits, int exp) noexcept
{
    JSON_ASSERT(digits != 0 && digits < 100000000000000000u);
    const std::uint64_t upper = digits / 100000000u;
    const std::uint64_t b0 = upper / 100000000u; // (one digit: it is its own byte)
    const std::uint64_t b1 = eight_digit_bytes(upper % 100000000u);
    const std::uint64_t b2 = eight_digit_bytes(digits % 100000000u);
    // leading and trailing zero digits: zero bytes, counted without division
    int leading = 16;
    int zeros = 16;
    if (b0 != 0)
    {
        leading = count_leading_zeros(b0) / 8;
    }
    else if (b1 != 0)
    {
        leading = 8 + (count_leading_zeros(b1) / 8);
    }
    else
    {
        leading += count_leading_zeros(b2) / 8;
    }
    if (b2 != 0)
    {
        zeros = count_trailing_zeros(b2) / 8;
    }
    else if (b1 != 0)
    {
        zeros = 8 + (count_trailing_zeros(b1) / 8);
    }
    // (else: 16, b0 is the one digit that is not 0)
    // the digits as text at text + leading, then '0's, so that fixed-size
    // moves need not check how many digits there are
    std::array<char, 64> text; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
    store_msb_first(text.data(), b0 + 0x3030303030303030u);
    store_msb_first(text.data() + 8, b1 + 0x3030303030303030u);
    store_msb_first(text.data() + 16, b2 + 0x3030303030303030u);
    std::memset(text.data() + 24, '0', 40);
    const int k = 24 - leading - zeros; // significant digits
    const int n = k + exp + zeros;      // position of the decimal point after the first digit
    const char* const s0 = text.data() + leading;

    if (-4 < n && n <= 15)
    {
        // "0.[000]digits" (n <= 0) is the digits after 1 - n leading '0's
        // with the point after the first; "digits[000].0" (n >= k) and
        // "dig.its" put the point after n characters
        const int pad = n <= 0 ? 1 - n : 0;
        const char* const s = s0 - pad;
        const int len = k + pad;
        const int point = n + pad;
        std::memcpy(first, s, 16);
        std::memcpy(first + point + 1, s + point, 24);
        first[point] = '.';
        return first + (point >= len ? point + 2 : len + 1);
    }

    // d.igitse+XX, with at least two exponent digits (as append_exponent())
    std::memcpy(first, s0, 16);
    std::memcpy(first + 2, s0 + 1, 16);
    first[1] = '.';
    char* const end = first + (k == 1 ? 1 : k + 1);
    const int e = n - 1;
    const auto ea = static_cast<unsigned>(e < 0 ? -e : e);
    const bool three = ea >= 100;
    end[0] = 'e';
    end[1] = e < 0 ? '-' : '+';
    end[2] = static_cast<char>('0' + (three ? ea / 100 : (ea / 10) % 10));
    end[3] = static_cast<char>('0' + (three ? (ea / 10) % 10 : ea % 10));
    end[4] = static_cast<char>('0' + (ea % 10));
    return end + (three ? 5 : 4);
}

/*!
@brief the shortest decimal of a positive double (Zmij), as write_decimal()
writes it

For a normal double, the shorter candidate has 15 or 16 digits: they are
converted at once (two halves of eight digits) and followed by the digit
after them, if there is one, without the multiplication and division by 10
that counting the digits of one number would take. The fixed layouts move
the digits after the point by one byte.

@return a pointer past the text; up to 41 bytes at @a first are written
        (some beyond the returned end)
*/
JSON_HEDLEY_NON_NULL(1)
JSON_HEDLEY_RETURNS_NON_NULL
inline char* write_shortest(char* first, const zmij::shortest_decimal d) noexcept
{
    const std::uint64_t sig = d.integral;
    if (JSON_HEDLEY_UNLIKELY(sig < 100000000000000u || sig >= 10000000000000000u))
    {
        // (subnormals)
        return d.has_digit ? write_decimal(first, (sig * 10) + d.digit, d.exponent) : write_decimal(first, sig, d.exponent + 1);
    }
    const bool sixteen = sig >= 1000000000000000u; // (else 15 digits)
    const int last = d.has_digit ? d.digit : 0;
    const std::uint64_t upper = sig / 100000000u;
#if JSON_DTOA_SSE2
    // NOLINTBEGIN(portability-simd-intrinsics)
    // the two halves in the 64-bit lanes, each as abcd * 2^32 + efgh, then as
    // bytes (as eight_digit_bytes(), one lane each)
    const __m128i x = _mm_set_epi64x(static_cast<long long>(sig - (upper * 100000000u)), static_cast<long long>(upper));
    const __m128i abcd = _mm_srli_epi64(_mm_mul_epu32(x, _mm_set1_epi64x(109951163)), 40); // 2^40 / 10000 + 1
    const __m128i abcd_efgh = _mm_add_epi64(x, _mm_mul_epu32(abcd, _mm_set1_epi64x(4294957296))); // 2^32 - 10000
    // 32-bit lanes in the order of the text: abcd, efgh of both halves
    const __m128i fours = _mm_shuffle_epi32(abcd_efgh, _MM_SHUFFLE(2, 3, 0, 1));
    const __m128i ab = _mm_srli_epi16(_mm_mulhi_epu16(fours, _mm_set1_epi32(5243)), 3);
    const __m128i ab_cd = _mm_or_si128(_mm_slli_epi32(_mm_sub_epi16(fours, _mm_mullo_epi16(ab, _mm_set1_epi32(100))), 16), ab);
    // 16-bit lanes ab (< 100) -> bytes a, b: 256 * ab - 2559 * (ab / 10)
    const __m128i bytes = _mm_sub_epi16(_mm_slli_epi16(ab_cd, 8), _mm_mullo_epi16(_mm_set1_epi16(2559), _mm_mulhi_epu16(ab_cd, _mm_set1_epi16(6554))));
    // the last digit that is not 0 (sig is not 0)
    const auto nonzero = static_cast<std::uint64_t>(_mm_movemask_epi8(_mm_cmpgt_epi8(bytes, _mm_setzero_si128())));
    const int digits = 63 - count_leading_zeros(nonzero) + (sixteen ? 1 : 0); // without trailing zeros
    const __m128i chars = _mm_add_epi8(bytes, _mm_set1_epi8('0'));
    // the 16 characters from the first digit
    const __m128i s = sixteen ? chars : _mm_or_si128(_mm_srli_si128(chars, 1), _mm_slli_si128(_mm_cvtsi32_si128('0' + last), 15));
    const char s16 = static_cast<char>(sixteen ? '0' + last : '0'); // the 17th
    const auto store_16 = [&s](char* p) noexcept
    {
        std::memcpy(p, &s, 16);
    };
    const char first_digit = static_cast<char>(_mm_cvtsi128_si32(s));
    // NOLINTEND(portability-simd-intrinsics)
#elif JSON_DTOA_NEON
    // as with SSE2: the halves in 32-bit lanes, then abcd, efgh of both
    const uint32x2_t halves = vcreate_u32(upper | ((sig - (upper * 100000000u)) << 32u));
    const uint32x2_t abcd = vmovn_u64(vshrq_n_u64(vmull_n_u32(halves, static_cast<std::uint32_t>(((std::uint64_t{1} << 40u) / 10000u) + 1u)), 40));
    const uint32x2_t efgh = vmls_n_u32(halves, abcd, 10000u);
    const uint32x4_t fours = vcombine_u32(vzip1_u32(abcd, efgh), vzip2_u32(abcd, efgh));
    const uint32x4_t ab = vshrq_n_u32(vmulq_n_u32(fours, 5243u), 19);
    const uint16x8_t ab_cd = vreinterpretq_u16_u32(vorrq_u32(ab, vshlq_n_u32(vmlsq_n_u32(fours, ab, 100u), 16)));
    const uint16x8_t tens = vshrq_n_u16(vmulq_n_u16(ab_cd, 103u), 10);
    const uint8x16_t bytes = vreinterpretq_u8_u16(vorrq_u16(tens, vshlq_n_u16(vmlsq_n_u16(ab_cd, tens, 10u), 8)));
    // the last digit that is not 0 (sig is not 0): a nibble per byte
    const std::uint64_t nonzero = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(vtstq_u8(bytes, bytes)), 4)), 0);
    const int digits = ((63 - count_leading_zeros(nonzero)) / 4) + (sixteen ? 1 : 0); // without trailing zeros
    const uint8x16_t chars = vaddq_u8(bytes, vdupq_n_u8('0'));
    // the 16 characters from the first digit
    const uint8x16_t s = sixteen ? chars : vextq_u8(chars, vdupq_n_u8(static_cast<std::uint8_t>('0' + last)), 1);
    const char s16 = static_cast<char>(sixteen ? '0' + last : '0'); // the 17th
    const auto store_16 = [&s](char* p) noexcept
    {
        vst1q_u8(reinterpret_cast<std::uint8_t*>(p), s); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    };
    const auto first_digit = static_cast<char>(vgetq_lane_u8(s, 0));
#else
    const std::uint64_t hi = eight_digit_bytes(upper);
    const std::uint64_t lo = eight_digit_bytes(sig - (upper * 100000000u));
    // trailing zero digits: zero bytes (sig is not 0)
    const int zeros = lo != 0 ? count_trailing_zeros(lo) / 8 : 8 + (count_trailing_zeros(hi) / 8);
    const int digits = 15 - zeros + (sixteen ? 1 : 0); // without trailing zeros
    // the 16 characters from the first digit
    const std::uint64_t s_hi = (sixteen ? hi : (hi << 8u) | (lo >> 56u)) + 0x3030303030303030u;
    const std::uint64_t s_lo = (sixteen ? lo : (lo << 8u) | static_cast<std::uint64_t>(last)) + 0x3030303030303030u;
    const char s16 = static_cast<char>(sixteen ? '0' + last : '0'); // the 17th
    const auto store_16 = [s_hi, s_lo](char* p) noexcept
    {
        store_msb_first(p, s_hi);
        store_msb_first(p + 8, s_lo);
    };
    const auto first_digit = static_cast<char>(s_hi >> 56u);
#endif
    const int len = d.has_digit ? 16 + (sixteen ? 1 : 0) : digits; // significant digits
    const int n = 16 + (sixteen ? 1 : 0) + d.exponent;           // digits before the point

    if (JSON_HEDLEY_LIKELY(n >= 1 && n <= 15))
    {
        // "dig.its" and "digits[000].0": the digits after the point move by
        // one byte ('0's follow the digits)
#if JSON_DTOA_SSE2
        // NOLINTBEGIN(portability-simd-intrinsics)
        // (in the register: reading the digits back from memory right after
        // storing them waits until the stores are done)
        const __m128i at = _mm_set1_epi8(static_cast<char>(n));
        const __m128i index = _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
        const __m128i before = _mm_cmpgt_epi8(at, index);
        const __m128i after = _mm_cmpgt_epi8(index, at);
        const __m128i text = _mm_or_si128(_mm_or_si128(_mm_and_si128(s, before), _mm_and_si128(_mm_slli_si128(s, 1), after)),
                                          _mm_andnot_si128(_mm_or_si128(before, after), _mm_set1_epi8('.')));
        std::memcpy(first, &text, 16);
        first[16] = static_cast<char>(_mm_extract_epi16(s, 7) >> 8);
        first[17] = s16;
        // NOLINTEND(portability-simd-intrinsics)
#elif JSON_DTOA_NEON
        const uint8x16_t index = vcombine_u8(vcreate_u8(0x0706050403020100u), vcreate_u8(0x0F0E0D0C0B0A0908u));
        const uint8x16_t at = vdupq_n_u8(static_cast<std::uint8_t>(n));
        const uint8x16_t after_point = vbslq_u8(vcgtq_u8(index, at), vextq_u8(vdupq_n_u8(0), s, 15), vdupq_n_u8('.'));
        vst1q_u8(reinterpret_cast<std::uint8_t*>(first), vbslq_u8(vcltq_u8(index, at), s, after_point)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        first[16] = static_cast<char>(vgetq_lane_u8(s, 15));
        first[17] = s16;
#else
        store_16(first);
        first[16] = s16;
        std::uint64_t after_point[2]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
        std::memcpy(after_point, first + n, 16);
        std::memcpy(first + n + 1, after_point, 16);
        first[n] = '.';
#endif
        return first + (n >= len ? n + 2 : len + 1);
    }
    if (n <= 0 && n > -4)
    {
        // "0.[000]digits"
        std::memset(first, '0', 8);
        first[1] = '.';
        store_16(first + 2 - n);
        first[18 - n] = s16;
        return first + 2 - n + len;
    }
    // d.igitse+XX, with at least two exponent digits (as append_exponent())
    store_16(first + 1);
    first[17] = s16;
    first[0] = first_digit;
    first[1] = '.';
    char* const end = first + (len == 1 ? 1 : len + 1);
    const int e = n - 1;
    const auto ea = static_cast<unsigned>(e < 0 ? -e : e);
    const bool three = ea >= 100;
    end[0] = 'e';
    end[1] = e < 0 ? '-' : '+';
    end[2] = static_cast<char>('0' + (three ? ea / 100 : (ea / 10) % 10));
    end[3] = static_cast<char>('0' + (three ? (ea / 10) % 10 : ea % 10));
    end[4] = static_cast<char>('0' + (ea % 10));
    return end + (three ? 5 : 4);
}

/// the powers of ten up to 10^16
inline const std::array<std::uint64_t, 17>& powers_of_ten_16() noexcept
{
    static const std::array<std::uint64_t, 17> powers =
    {
        {
            1u, 10u, 100u, 1000u, 10000u, 100000u, 1000000u, 10000000u, 100000000u, 1000000000u, 10000000000u,
            100000000000u, 1000000000000u, 10000000000000u, 100000000000000u, 1000000000000000u, 10000000000000000u
        }
    };
    return powers;
}

/*!
@brief digits * 10^exp, as write_decimal() writes it, for the digits of a
double that need no conversion (count digits, at most 15, the first not 0;
trailing zeros allowed): extended to 16 digits and written by write_shortest()

@return a pointer past the text; up to 41 bytes at @a first are written
        (some beyond the returned end)
*/
JSON_HEDLEY_NON_NULL(1)
JSON_HEDLEY_RETURNS_NON_NULL
inline char* write_short_decimal(char* first, std::uint64_t digits, int count, int exp) noexcept
{
    JSON_ASSERT(digits >= powers_of_ten_16()[static_cast<std::size_t>(count - 1)] && count <= 15);
    const int scale = 16 - count;
    return write_shortest(first, zmij::shortest_decimal{digits * powers_of_ten_16()[static_cast<std::size_t>(scale)], exp - scale - 1, 0, false});
}

/// as write_short_decimal(), counting the digits (not 0, less than 10^15)
JSON_HEDLEY_NON_NULL(1)
JSON_HEDLEY_RETURNS_NON_NULL
inline char* write_short_decimal(char* first, std::uint64_t digits, int exp) noexcept
{
    JSON_ASSERT(digits != 0 && digits < 1000000000000000u);
    // floor(log10(2^bits)) + 1 digits, or one less
    const int log2_bound = ((64 - count_leading_zeros(digits)) * 1233) >> 12;
    const int count = log2_bound + (digits >= powers_of_ten_16()[static_cast<std::size_t>(log2_bound)] ? 1 : 0);
    return write_short_decimal(first, digits, count, exp);
}

/// a positive finite float (other than double): Grisu2 and format_buffer()
template<typename FloatType>
JSON_HEDLEY_NON_NULL(1, 2)
JSON_HEDLEY_RETURNS_NON_NULL
char* write_positive(char* first, const char* last, FloatType value)
{
    JSON_ASSERT(last - first >= std::numeric_limits<FloatType>::max_digits10);

    // Compute v = buffer * 10^decimal_exponent.
    // The decimal digits are stored in the buffer, which needs to be interpreted
    // as an unsigned decimal integer.
    // len is the length of the buffer, i.e., the number of decimal digits.
    int len = 0;
    int decimal_exponent = 0;
    shortest_digits(first, len, decimal_exponent, value);

    JSON_ASSERT(len <= std::numeric_limits<FloatType>::max_digits10);

    // Format the buffer like printf("%.*g", prec, value)
    constexpr int kMinExp = -4;
    // Use digits10 here to increase compatibility with version 2.
    constexpr int kMaxExp = std::numeric_limits<FloatType>::digits10;

    JSON_ASSERT(last - first >= kMaxExp + 2);
    JSON_ASSERT(last - first >= 2 + (-kMinExp - 1) + std::numeric_limits<FloatType>::max_digits10);
    JSON_ASSERT(last - first >= std::numeric_limits<FloatType>::max_digits10 + 6);

    return format_buffer(first, len, decimal_exponent, kMinExp, kMaxExp);
}

/// a positive finite double: the shortest digits (Zmij), laid out by
/// write_shortest() (through a local buffer if [first, last) is shorter than
/// the 41 bytes it may write)
JSON_HEDLEY_NON_NULL(1, 2)
JSON_HEDLEY_RETURNS_NON_NULL
inline char* write_positive(char* first, const char* last, double value)
{
    static_assert(std::numeric_limits<double>::is_iec559 && std::numeric_limits<double>::digits == 53,
                  "internal error: the conversion of Zmij needs IEEE 754 binary64 doubles");
    std::uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    const zmij::shortest_decimal d = zmij::to_shortest(bits);
    if (JSON_HEDLEY_LIKELY(last - first >= 41))
    {
        return write_shortest(first, d);
    }
    std::array<char, 64> buf; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
    const auto len = static_cast<std::size_t>(write_shortest(buf.data(), d) - buf.data());
    JSON_ASSERT(static_cast<std::size_t>(last - first) >= len);
    std::memcpy(first, buf.data(), len);
    return first + len;
}

}  // namespace dtoa_impl

/*!
@brief generates a decimal representation of the floating-point number value in [first, last).

The format of the resulting decimal representation is similar to printf's %g
format. Returns an iterator pointing past-the-end of the decimal representation.

@note The input number must be finite, i.e. NaN's and Inf's are not supported.
@note The buffer must be large enough.
@note The result is NOT null-terminated.
*/
template<typename FloatType>
JSON_HEDLEY_NON_NULL(1, 2)
JSON_HEDLEY_RETURNS_NON_NULL
char* to_chars(char* first, const char* last, FloatType value)
{
    JSON_ASSERT(std::isfinite(value));

    // Use signbit(value) instead of (value < 0) since signbit works for -0.
    if (std::signbit(value))
    {
        value = -value;
        *first++ = '-';
    }

#ifdef __GNUC__
    JSON_HEDLEY_DIAGNOSTIC_PUSH
    JSON_HEDLEY_PRAGMA(GCC diagnostic ignored "-Wfloat-equal")
#endif
    if (value == 0) // +-0
    {
        *first++ = '0';
        // Make it look like a floating-point number (#362, #378)
        *first++ = '.';
        *first++ = '0';
        return first;
    }
#ifdef __GNUC__
    JSON_HEDLEY_DIAGNOSTIC_POP
#endif

    return dtoa_impl::write_positive(first, last, value);
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
