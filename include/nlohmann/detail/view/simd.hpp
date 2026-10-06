//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-FileCopyrightText: 2018-2025 The simdjson authors <https://github.com/simdjson/simdjson>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <atomic> // atomic
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint64_t

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>

// Vector code for long runs of string bytes. NEON (AArch64) and SSE2 (x86-64)
// belong to the baseline instruction sets and are used by default. The vector
// UTF-8 check needs NEON or SSSE3. SSSE3 is not part of x86-64, and the code
// must not depend on the flags of a translation unit (two translation units
// with different flags would have different definitions of the same inline
// functions): the check is compiled for SSSE3 with a function attribute and
// used where the CPU has SSSE3 (all x86-64 CPUs since about 2011), else the
// portable check. JSON_VIEW_USE_SSSE3 skips the CPU check (for code compiled
// for SSSE3 anyway); JSON_VIEW_NO_SIMD selects the portable code.
#if !defined(JSON_VIEW_NO_SIMD) && defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__)) && NLOHMANN_VIEW_LITTLE_ENDIAN
    #include <arm_neon.h>
    #define NLOHMANN_VIEW_NEON 1
#else
    #define NLOHMANN_VIEW_NEON 0
#endif
#if !defined(JSON_VIEW_NO_SIMD) && !NLOHMANN_VIEW_NEON && (defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2))
    #include <emmintrin.h>
    #define NLOHMANN_VIEW_SSE2 1
#else
    #define NLOHMANN_VIEW_SSE2 0
#endif
#if NLOHMANN_VIEW_SSE2 && defined(JSON_VIEW_USE_SSSE3)
    #include <tmmintrin.h>
    #define NLOHMANN_VIEW_SSSE3 1 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#else
    #define NLOHMANN_VIEW_SSSE3 0 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#endif
#if NLOHMANN_VIEW_SSE2 && !NLOHMANN_VIEW_SSSE3 && ((defined(__clang__) && __clang_major__ >= 4) || (defined(__GNUC__) && !defined(__clang__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9))))
    // (GCC before 4.9 has no SSSE3 intrinsics without -mssse3)
    #include <cpuid.h>
    #include <tmmintrin.h>
    #define NLOHMANN_VIEW_SSSE3_DISPATCH 1 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
    #define NLOHMANN_VIEW_SSSE3_TARGET __attribute__((target("ssse3")))
#elif NLOHMANN_VIEW_SSE2 && !NLOHMANN_VIEW_SSSE3 && defined(_MSC_VER)
    // (MSVC compiles intrinsics of any instruction set)
    #include <intrin.h>
    #include <tmmintrin.h>
    #define NLOHMANN_VIEW_SSSE3_DISPATCH 1 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
    #define NLOHMANN_VIEW_SSSE3_TARGET
#else
    #define NLOHMANN_VIEW_SSSE3_DISPATCH 0 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
    #define NLOHMANN_VIEW_SSSE3_TARGET
#endif
#define NLOHMANN_VIEW_VECTOR (NLOHMANN_VIEW_NEON || NLOHMANN_VIEW_SSE2)
#define NLOHMANN_VIEW_VECTOR_UTF8 (NLOHMANN_VIEW_NEON || NLOHMANN_VIEW_SSSE3 || NLOHMANN_VIEW_SSSE3_DISPATCH)

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

#if NLOHMANN_VIEW_VECTOR
/*!
@brief the first byte of a string run that is a quote, a backslash, a control
character, or not ASCII, 16 bytes per step

Stops at such a byte, or where fewer than 16 bytes are left (the caller tells
the two apart). A signed compare with 0x20 finds control characters and
non-ASCII bytes at once.
*/
NLOHMANN_VIEW_ALWAYS_INLINE const unsigned char* vector_plain_run(const unsigned char* p, const unsigned char* e) noexcept
{
    while (e - p >= 16)
    {
#if NLOHMANN_VIEW_NEON
        const uint8x16_t in = vld1q_u8(p);
        const uint8x16_t special = vorrq_u8(vorrq_u8(vceqq_u8(in, vdupq_n_u8('"')), vceqq_u8(in, vdupq_n_u8('\\'))),
                                            vcltq_s8(vreinterpretq_s8_u8(in), vdupq_n_s8(0x20)));
        // one nibble per byte (the usual NEON replacement of x86's movemask, see
        // D. Kutenin, "Porting x86 vector bitmask optimizations to Arm NEON", 2022)
        const std::uint64_t bits = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(special), 4)), 0);
        if (bits != 0)
        {
            return p + (count_trailing_zeros(bits) >> 2u);
        }
#else
        const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(p)));
        const __m128i special = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(in, _mm_set1_epi8('"')), _mm_cmpeq_epi8(in, _mm_set1_epi8('\\'))),
                                             _mm_cmplt_epi8(in, _mm_set1_epi8(0x20)));
        const auto bits = static_cast<std::uint64_t>(static_cast<unsigned>(_mm_movemask_epi8(special)));
        if (bits != 0)
        {
            return p + count_trailing_zeros(bits);
        }
#endif
        p += 16;
    }
    return p;
}
#endif

#if NLOHMANN_VIEW_SSSE3_DISPATCH
/// whether the CPU has SSSE3 (CPUID leaf 1, ECX bit 9)
inline bool cpu_ssse3() noexcept
{
#if defined(_MSC_VER) && !defined(__clang__)
    std::array<int, 4> regs {{}};
    __cpuid(regs.data(), 1);
    return (static_cast<unsigned>(regs[2]) & (1u << 9u)) != 0;
#else
    unsigned eax = 0;
    unsigned ebx = 0;
    unsigned ecx = 0;
    unsigned edx = 0;
    return __get_cpuid(1, &eax, &ebx, &ecx, &edx) != 0 && (ecx & (1u << 9u)) != 0;
#endif
}

/// whether the CPU has SSSE3, asked once: the answer is kept in an atomic
/// that is initialized at compile time, so that neither a guard of a local
/// static nor a global constructor is needed (threads that ask at the same
/// time all store the same answer)
NLOHMANN_VIEW_ALWAYS_INLINE bool cpu_has_ssse3() noexcept
{
    static std::atomic<int> known{0}; // 0: not asked yet, 1: no, 2: yes
    int state = known.load(std::memory_order_relaxed);
    if (NLOHMANN_VIEW_UNLIKELY(state == 0))
    {
        state = cpu_ssse3() ? 2 : 1;
        known.store(state, std::memory_order_relaxed);
    }
    return state == 2;
}
#endif

#if NLOHMANN_VIEW_VECTOR_UTF8
/// Tables of the UTF-8 check of J. Keiser and D. Lemire, "Validating UTF-8 In
/// Less Than One Instruction Per Byte" (2021), as in simdjson ("lookup4"): each
/// maps a nibble (high and low nibble of the previous byte, high nibble of the
/// current byte) to the errors it allows; a byte pair is ill-formed if all
/// three have an error bit in common.
template<typename Dummy = void>
struct utf8_lookup4
{
    static constexpr std::uint8_t too_short = 1u << 0u, too_long = 1u << 1u, overlong_3 = 1u << 2u, too_large = 1u << 3u;
    static constexpr std::uint8_t surrogate = 1u << 4u, overlong_2 = 1u << 5u, too_large_1000 = 1u << 6u, overlong_4 = 1u << 6u;
    static constexpr std::uint8_t two_conts = 1u << 7u, carry = too_short | too_long | two_conts;
    static const std::array<std::uint8_t, 16> byte_1_high;
    static const std::array<std::uint8_t, 16> byte_1_low;
    static const std::array<std::uint8_t, 16> byte_2_high;
};

template<typename Dummy>
const std::array<std::uint8_t, 16> utf8_lookup4<Dummy>::byte_1_high =
{
    {
        too_long, too_long, too_long, too_long, too_long, too_long, too_long, too_long,
        two_conts, two_conts, two_conts, two_conts,
        too_short | overlong_2, too_short, too_short | overlong_3 | surrogate, too_short | too_large | too_large_1000 | overlong_4
    }
};

template<typename Dummy>
const std::array<std::uint8_t, 16> utf8_lookup4<Dummy>::byte_1_low =
{
    {
        carry | overlong_3 | overlong_2 | overlong_4, carry | overlong_2, carry, carry,
        carry | too_large, carry | too_large | too_large_1000, carry | too_large | too_large_1000, carry | too_large | too_large_1000,
        carry | too_large | too_large_1000, carry | too_large | too_large_1000, carry | too_large | too_large_1000, carry | too_large | too_large_1000,
        carry | too_large | too_large_1000, carry | too_large | too_large_1000 | surrogate, carry | too_large | too_large_1000, carry | too_large | too_large_1000
    }
};

template<typename Dummy>
const std::array<std::uint8_t, 16> utf8_lookup4<Dummy>::byte_2_high =
{
    {
        too_short, too_short, too_short, too_short, too_short, too_short, too_short, too_short,
        static_cast<std::uint8_t>(too_long | overlong_2 | two_conts | overlong_3 | too_large_1000 | overlong_4),
        static_cast<std::uint8_t>(too_long | overlong_2 | two_conts | overlong_3 | too_large),
        static_cast<std::uint8_t>(too_long | overlong_2 | two_conts | surrogate | too_large),
        static_cast<std::uint8_t>(too_long | overlong_2 | two_conts | surrogate | too_large),
        too_short, too_short, too_short, too_short
    }
};

/// the end of scan_string_vector from block, where the vector loop stopped
/// (ill-formed UTF-8, or fewer than 16 bytes left): one byte or sequence at a
/// time, from the start of a sequence that crosses into the block
inline const unsigned char* scan_string_finish(const unsigned char* p, const unsigned char* block, const unsigned char* e, const std::uint8_t* plain) noexcept
{
    for (int i = 1; i <= 3 && block - i >= p; ++i)
    {
        const unsigned char c = block[-i];
        if (c < 0x80)
        {
            break;
        }
        if (c >= 0xC0)
        {
            const int len = 2 + static_cast<int>(c >= 0xE0) + static_cast<int>(c >= 0xF0);
            if (len > i)
            {
                block -= i;
            }
            break;
        }
    }
    for (p = block; p != e;)
    {
        if (*p < 0x80)
        {
            if (plain[*p] == 0)
            {
                return p;
            }
            ++p;
            continue;
        }
        const std::size_t n = validate_one_utf8(p, static_cast<std::size_t>(e - p));
        if (n == 0)
        {
            return p;
        }
        p += n;
    }
    return p;
}

/*!
@brief the rest of a string from p (a character boundary), 16 bytes per step

The first quote, backslash, or control character is found with vector
compares, and the UTF-8 check covers the bytes up to it. Returns where the
string scan stops, like scan_string_run: before ill-formed UTF-8 and for the
last bytes of the input, the bytes are checked one sequence at a time. Out of
line, so that no constants of the check occupy registers in the parse loop.
On x86-64, it is compiled for SSSE3 (see cpu_has_ssse3()).
*/
NLOHMANN_VIEW_SSSE3_TARGET NLOHMANN_VIEW_NOINLINE inline const unsigned char* scan_string_vector(const unsigned char* p, const unsigned char* e, const std::uint8_t* plain) noexcept
{
    using lookup = utf8_lookup4<>;
    const unsigned char* block = p;
#if NLOHMANN_VIEW_NEON
    const uint8x16_t t1h = vld1q_u8(lookup::byte_1_high.data());
    const uint8x16_t t1l = vld1q_u8(lookup::byte_1_low.data());
    const uint8x16_t t2h = vld1q_u8(lookup::byte_2_high.data());
    uint8x16_t prev = vdupq_n_u8(0);
    while (e - block >= 16)
    {
        const uint8x16_t in = vld1q_u8(block);
        const uint8x16_t special = vorrq_u8(vorrq_u8(vceqq_u8(in, vdupq_n_u8('"')), vceqq_u8(in, vdupq_n_u8('\\'))), vcltq_u8(in, vdupq_n_u8(0x20)));
        const uint8x16_t prev1 = vextq_u8(prev, in, 15);
        const uint8x16_t sc = vandq_u8(vandq_u8(vqtbl1q_u8(t1h, vshrq_n_u8(prev1, 4)), vqtbl1q_u8(t1l, vandq_u8(prev1, vdupq_n_u8(0x0F)))), vqtbl1q_u8(t2h, vshrq_n_u8(in, 4)));
        const uint8x16_t must23 = vorrq_u8(vqsubq_u8(vextq_u8(prev, in, 14), vdupq_n_u8(0xE0 - 0x80)), vqsubq_u8(vextq_u8(prev, in, 13), vdupq_n_u8(0xF0 - 0x80)));
        const uint8x16_t err = veorq_u8(vandq_u8(must23, vdupq_n_u8(0x80)), sc);
        const std::uint64_t special_bits = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(special), 4)), 0);
        const std::uint64_t err_bits = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(vtstq_u8(err, err)), 4)), 0);
        if (special_bits != 0)
        {
            // errors up to the special byte count (an incomplete sequence
            // before a quote shows at the quote); the bytes after it do not
            const unsigned k = static_cast<unsigned>(count_trailing_zeros(special_bits)) >> 2u;
            const std::uint64_t upto = k == 15 ? ~std::uint64_t{0} :
                                       (std::uint64_t{1} << (4u * (k + 1u))) - 1u;
            if ((err_bits & upto) == 0)
            {
                return block + k;
            }
            break;
        }
        if (err_bits != 0)
        {
            break;
        }
        prev = in;
        block += 16;
    }
#else
    // the same with SSSE3 (pshufb for the table lookups; nibbles from 16-bit
    // shifts, as there are no byte shifts)
    const __m128i t1h = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_1_high.data())));
    const __m128i t1l = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_1_low.data())));
    const __m128i t2h = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_2_high.data())));
    const __m128i nibble = _mm_set1_epi8(0x0F);
    const __m128i zero = _mm_setzero_si128();
    __m128i prev = zero;
    while (e - block >= 16)
    {
        const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(block)));
        const __m128i special = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(in, _mm_set1_epi8('"')), _mm_cmpeq_epi8(in, _mm_set1_epi8('\\'))),
                                             _mm_cmpeq_epi8(_mm_subs_epu8(in, _mm_set1_epi8(0x1F)), zero)); // in < 0x20
        const __m128i prev1 = _mm_alignr_epi8(in, prev, 15);
        const __m128i sc = _mm_and_si128(_mm_and_si128(_mm_shuffle_epi8(t1h, _mm_and_si128(_mm_srli_epi16(prev1, 4), nibble)),
                                         _mm_shuffle_epi8(t1l, _mm_and_si128(prev1, nibble))),
                                         _mm_shuffle_epi8(t2h, _mm_and_si128(_mm_srli_epi16(in, 4), nibble)));
        const __m128i must23 = _mm_or_si128(_mm_subs_epu8(_mm_alignr_epi8(in, prev, 14), _mm_set1_epi8(0xE0 - 0x80)),
                                            _mm_subs_epu8(_mm_alignr_epi8(in, prev, 13), _mm_set1_epi8(0xF0 - 0x80)));
        const __m128i err = _mm_xor_si128(_mm_and_si128(must23, _mm_set1_epi8(static_cast<char>(-128))), sc);
        const auto special_bits = static_cast<unsigned>(_mm_movemask_epi8(special));
        const auto err_bits = ~static_cast<unsigned>(_mm_movemask_epi8(_mm_cmpeq_epi8(err, zero))) & 0xFFFFu;
        if (special_bits != 0)
        {
            const unsigned k = static_cast<unsigned>(count_trailing_zeros(static_cast<std::uint64_t>(special_bits)));
            if ((err_bits & ((2u << k) - 1u)) == 0)
            {
                return block + k;
            }
            break;
        }
        if (err_bits != 0)
        {
            break;
        }
        prev = in;
        block += 16;
    }
#endif
    return scan_string_finish(p, block, e, plain);
}
#endif

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
