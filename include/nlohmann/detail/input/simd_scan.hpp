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

#include <nlohmann/detail/bit_ops.hpp>
#include <nlohmann/detail/macro_scope.hpp>

// Vector code for runs of string bytes, used by the lexer for contiguous input
// (see string_bulk_run()). NEON (AArch64) and SSE2 (x86-64) belong to the
// baseline instruction sets and are used by default. The vector UTF-8 check
// needs NEON or SSSE3. SSSE3 is not part of x86-64, and the code must not
// depend on the flags of a translation unit (two translation units with
// different flags would have different definitions of the same inline
// functions): the check is compiled for SSSE3 with a function attribute and
// used where the CPU has SSSE3 (all x86-64 CPUs since about 2011), else the
// portable check. Code compiled for SSSE3 anyway (-mssse3 or more) skips the
// CPU check. JSON_NO_SIMD selects the portable code everywhere.
// NLOHMANN_JSON_NO_TARGET_ATTRIBUTE (for compilers that ignore the target
// attribute and then reject the SSSE3 intrinsics) keeps the check portable
// without disabling the SSE2 code.
//
// The vector UTF-8 check (utf8_lookup4) is adapted from simdjson
// (https://github.com/simdjson/simdjson, Daniel Lemire, Geoff Langdale, John
// Keiser, and contributors, available under the Apache 2.0 and MIT licenses;
// used here under the MIT license): the "lookup4" algorithm and tables of
// J. Keiser and D. Lemire, "Validating UTF-8 In Less Than One Instruction Per
// Byte" (2021).
#if !defined(JSON_NO_SIMD) && defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__)) && defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #include <arm_neon.h>
    #define JSON_SCAN_NEON 1
#else
    #define JSON_SCAN_NEON 0
#endif
// (x86 only: other targets can define __SSE2__ as well, e.g., WebAssembly with -msse2, but have no <cpuid.h>)
#if !defined(JSON_NO_SIMD) && !JSON_SCAN_NEON && (defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)) && !defined(_M_ARM64EC) && (defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2))
    #include <emmintrin.h>
    #define JSON_SCAN_SSE2 1
#else
    #define JSON_SCAN_SSE2 0
#endif
#if JSON_SCAN_SSE2 && defined(__SSSE3__)
    #include <tmmintrin.h>
    #define JSON_SCAN_SSSE3 1 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#else
    #define JSON_SCAN_SSSE3 0 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#endif
#if JSON_SCAN_SSE2 && !JSON_SCAN_SSSE3 && !defined(NLOHMANN_JSON_NO_TARGET_ATTRIBUTE) && ((defined(__clang__) && __clang_major__ >= 4) || (defined(__GNUC__) && !defined(__clang__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)) && !defined(__cpp_modules)))
    // (GCC before 4.9 has no SSSE3 intrinsics without -mssse3; GCC with C++20
    // modules drops the target attribute from functions it reads from a module
    // interface and then rejects the intrinsics: "needs isa option -mssse3")
    // <cpuid.h> of GCC before 11 has no include guard, and json.hpp and
    // json_view.hpp both include it
    #ifndef NLOHMANN_JSON_CPUID_INCLUDED
        #define NLOHMANN_JSON_CPUID_INCLUDED
        #include <cpuid.h>
    #endif
    #include <tmmintrin.h>
    #define JSON_SCAN_SSSE3_DISPATCH 1 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
    #define JSON_SCAN_SSSE3_TARGET __attribute__((target("ssse3")))
#elif JSON_SCAN_SSE2 && !JSON_SCAN_SSSE3 && defined(_MSC_VER)
    // (MSVC compiles intrinsics of any instruction set)
    #include <intrin.h>
    #include <tmmintrin.h>
    #define JSON_SCAN_SSSE3_DISPATCH 1 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
    #define JSON_SCAN_SSSE3_TARGET
#else
    #define JSON_SCAN_SSSE3_DISPATCH 0 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
    #define JSON_SCAN_SSSE3_TARGET
#endif
// The UTF-8 check of string runs (vector_utf8_run) also has a 32-byte variant
// for CPUs with AVX2 (most x86-64 CPUs since about 2015), compiled with a
// function attribute and chosen at run time inside the out-of-line 16-byte
// check, whatever the flags of the translation unit: the CPU check adds no code
// to the lexer's string loop, and every translation unit has the same
// definitions. Not with MSVC (not measured), and not with GCC for Windows,
// which does not align the stack for spilled AVX registers (GCC bug 54412).
#if JSON_SCAN_SSE2 && !defined(NLOHMANN_JSON_NO_TARGET_ATTRIBUTE) && !(defined(_WIN32) && !defined(__clang__)) && ((defined(__clang__) && __clang_major__ >= 4) || (defined(__GNUC__) && !defined(__clang__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)) && !defined(__cpp_modules)))
    #ifndef NLOHMANN_JSON_CPUID_INCLUDED
        #define NLOHMANN_JSON_CPUID_INCLUDED
        #include <cpuid.h>
    #endif
    #include <immintrin.h>
    #define JSON_SCAN_AVX2_DISPATCH 1 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
    #define JSON_SCAN_AVX2_TARGET __attribute__((target("avx2")))
#else
    #define JSON_SCAN_AVX2_DISPATCH 0 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#endif
#define JSON_SCAN_VECTOR (JSON_SCAN_NEON || JSON_SCAN_SSE2)
#define JSON_SCAN_VECTOR_UTF8 (JSON_SCAN_NEON || JSON_SCAN_SSSE3 || JSON_SCAN_SSSE3_DISPATCH)

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

#if JSON_SCAN_VECTOR
/*!
@brief the first byte of a string run that is a quote, a backslash, a control
character, or not ASCII, 16 bytes per step

Stops at such a byte, or where fewer than 16 bytes are left (the caller tells
the two apart). One signed compare finds the quote, the control characters and
the non-ASCII bytes at once: flipping bit 1 maps 0x00-0x1F onto itself and the
quote (0x22) onto 0x20, keeps 0x80-0xFF negative, and maps every other byte to
33 or more, so these are exactly the bytes with (int8_t)(c ^ 2) < 33 (see
D. Lemire, "Detect control characters, quotes and backslashes efficiently
using SWAR", 2025). The backslash needs its own compare.
*/
JSON_HEDLEY_ALWAYS_INLINE const unsigned char* vector_plain_run(const unsigned char* p, const unsigned char* e) noexcept
{
    while (e - p >= 16)
    {
#if JSON_SCAN_NEON
        const uint8x16_t in = vld1q_u8(p);
        const uint8x16_t special = vorrq_u8(vceqq_u8(in, vdupq_n_u8('\\')),
                                            vcltq_s8(vreinterpretq_s8_u8(veorq_u8(in, vdupq_n_u8(2))), vdupq_n_s8(33)));
        // one nibble per byte (the usual NEON replacement of x86's movemask, see
        // D. Kutenin, "Porting x86 vector bitmask optimizations to Arm NEON", 2022)
        const std::uint64_t bits = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(special), 4)), 0);
        if (bits != 0)
        {
            return p + (count_trailing_zeros(bits) >> 2u);
        }
#else
        const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(p))); // NOLINT(bugprone-casting-through-void)
        const __m128i special = _mm_or_si128(_mm_cmpeq_epi8(in, _mm_set1_epi8('\\')),
                                             _mm_cmplt_epi8(_mm_xor_si128(in, _mm_set1_epi8(2)), _mm_set1_epi8(33)));
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

#if JSON_SCAN_VECTOR
/// vector_plain_run() for runs that are already longer than a few words:
/// inline with SSE2, out of line with NEON, where a larger string loop slows
/// down the rest of the lexer
#if JSON_SCAN_NEON
    JSON_HEDLEY_NEVER_INLINE inline
#else
    JSON_HEDLEY_ALWAYS_INLINE
#endif
const unsigned char* vector_plain_run_long(const unsigned char* p, const unsigned char* e) noexcept
{
    return vector_plain_run(p, e);
}
#endif

#if JSON_SCAN_SSSE3_DISPATCH
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
JSON_HEDLEY_ALWAYS_INLINE bool cpu_has_ssse3() noexcept
{
    static std::atomic<int> known{0}; // 0: not asked yet, 1: no, 2: yes
    int state = known.load(std::memory_order_relaxed);
    if (JSON_HEDLEY_UNLIKELY(state == 0))
    {
        state = cpu_ssse3() ? 2 : 1;
        known.store(state, std::memory_order_relaxed);
    }
    return state == 2;
}
#endif

/// whether the CPU has AVX2 (CPUID leaf 7, EBX bit 5) and the OS saves the
/// YMM registers (CPUID leaf 1, ECX bits 27 and 28; XCR0 bits 1 and 2); false
/// where the library has no AVX2 code
inline bool cpu_avx2() noexcept
{
#if JSON_SCAN_AVX2_DISPATCH
    unsigned eax = 0;
    unsigned ebx = 0;
    unsigned ecx = 0;
    unsigned edx = 0;
    if (__get_cpuid_max(0, nullptr) < 7 || __get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0 || (ecx & (3u << 27u)) != (3u << 27u))
    {
        return false;
    }
    unsigned xcr0 = 0; // NOLINT(misc-const-correctness): written by the assembly
    unsigned xcr0_high = 0; // NOLINT(misc-const-correctness)
    __asm__ __volatile__("xgetbv" : "=a"(xcr0), "=d"(xcr0_high) : "c"(0)); // NOLINT(hicpp-no-assembler)
    if ((xcr0 & 6u) != 6u)
    {
        return false;
    }
    __cpuid_count(7, 0, eax, ebx, ecx, edx);
    return (ebx & (1u << 5u)) != 0;
#else
    return false;
#endif
}

/// the answer of cpu_avx2(), asked once (0: not asked yet, 1: no, 2: yes; see
/// cpu_has_ssse3()); the tests store 1 to check the 16-byte code on CPUs with
/// AVX2, and 0 to ask again
inline std::atomic<int>& cpu_avx2_state() noexcept
{
    static std::atomic<int> known{0};
    return known;
}

/// whether the CPU has AVX2
JSON_HEDLEY_ALWAYS_INLINE bool cpu_has_avx2() noexcept
{
    int state = cpu_avx2_state().load(std::memory_order_relaxed);
    if (JSON_HEDLEY_UNLIKELY(state == 0))
    {
        state = cpu_avx2() ? 2 : 1;
        cpu_avx2_state().store(state, std::memory_order_relaxed);
    }
    return state == 2;
}

#if JSON_SCAN_VECTOR_UTF8
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

#if JSON_SCAN_AVX2_DISPATCH
/// the errors of the UTF-8 check in 16 bytes @a in after @a prev (see
/// vector_utf8_run()), for the 32-byte functions
JSON_SCAN_AVX2_TARGET JSON_HEDLEY_ALWAYS_INLINE __m128i utf8_errors_avx2_16(const __m128i in, const __m128i prev, const __m128i t1h, const __m128i t1l, const __m128i t2h) noexcept
{
    const __m128i nibble = _mm_set1_epi8(0x0F);
    const __m128i prev1 = _mm_alignr_epi8(in, prev, 15);
    const __m128i sc = _mm_and_si128(_mm_and_si128(_mm_shuffle_epi8(t1h, _mm_and_si128(_mm_srli_epi16(prev1, 4), nibble)),
                                     _mm_shuffle_epi8(t1l, _mm_and_si128(prev1, nibble))),
                                     _mm_shuffle_epi8(t2h, _mm_and_si128(_mm_srli_epi16(in, 4), nibble)));
    const __m128i must23 = _mm_or_si128(_mm_subs_epu8(_mm_alignr_epi8(in, prev, 14), _mm_set1_epi8(0xE0 - 0x80)),
                                        _mm_subs_epu8(_mm_alignr_epi8(in, prev, 13), _mm_set1_epi8(0xF0 - 0x80)));
    return _mm_xor_si128(_mm_and_si128(must23, _mm_set1_epi8(static_cast<char>(-128))), sc);
}

/// the errors of the UTF-8 check in 32 bytes @a in after @a prev: as with 16
/// bytes, but the byte shifts work within each 16-byte lane, so the bytes
/// before each lane are put together first
JSON_SCAN_AVX2_TARGET JSON_HEDLEY_ALWAYS_INLINE __m256i utf8_errors_avx2_32(const __m256i in, const __m256i prev, const __m256i t1h, const __m256i t1l, const __m256i t2h) noexcept
{
    const __m256i nibble = _mm256_set1_epi8(0x0F);
    const __m256i before = _mm256_permute2x128_si256(prev, in, 0x21); // the upper half of prev, the lower half of in
    const __m256i prev1 = _mm256_alignr_epi8(in, before, 15);
    const __m256i sc = _mm256_and_si256(_mm256_and_si256(_mm256_shuffle_epi8(t1h, _mm256_and_si256(_mm256_srli_epi16(prev1, 4), nibble)),
                                        _mm256_shuffle_epi8(t1l, _mm256_and_si256(prev1, nibble))),
                                        _mm256_shuffle_epi8(t2h, _mm256_and_si256(_mm256_srli_epi16(in, 4), nibble)));
    const __m256i must23 = _mm256_or_si256(_mm256_subs_epu8(_mm256_alignr_epi8(in, before, 14), _mm256_set1_epi8(0xE0 - 0x80)),
                                           _mm256_subs_epu8(_mm256_alignr_epi8(in, before, 13), _mm256_set1_epi8(0xF0 - 0x80)));
    return _mm256_xor_si256(_mm256_and_si256(must23, _mm256_set1_epi8(static_cast<char>(-128))), sc);
}

/// the quotes, backslashes, and control characters in 16 bytes (see vector_utf8_run())
JSON_SCAN_AVX2_TARGET JSON_HEDLEY_ALWAYS_INLINE __m128i string_specials_avx2_16(const __m128i in) noexcept
{
    return _mm_or_si128(_mm_cmpeq_epi8(in, _mm_set1_epi8('\\')),
                        _mm_cmpeq_epi8(_mm_subs_epu8(_mm_xor_si128(in, _mm_set1_epi8(2)), _mm_set1_epi8(32)), _mm_setzero_si128()));
}

/// vector_utf8_run() with AVX2: 32 bytes per step, then one 16-byte step
JSON_SCAN_AVX2_TARGET JSON_HEDLEY_NEVER_INLINE inline bool vector_utf8_run_avx2(const unsigned char* p, const unsigned char* e, const unsigned char*& block_out) noexcept
{
    using lookup = utf8_lookup4<>;
    const unsigned char* block = p;
    const __m128i t1h_16 = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_1_high.data()))); // NOLINT(bugprone-casting-through-void)
    const __m128i t1l_16 = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_1_low.data()))); // NOLINT(bugprone-casting-through-void)
    const __m128i t2h_16 = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_2_high.data()))); // NOLINT(bugprone-casting-through-void)
    const __m256i t1h = _mm256_broadcastsi128_si256(t1h_16);
    const __m256i t1l = _mm256_broadcastsi128_si256(t1l_16);
    const __m256i t2h = _mm256_broadcastsi128_si256(t2h_16);
    const __m256i zero = _mm256_setzero_si256();
    __m256i prev = zero;
    while (e - block >= 32)
    {
        const __m256i in = _mm256_loadu_si256(static_cast<const __m256i*>(static_cast<const void*>(block))); // NOLINT(bugprone-casting-through-void)
        const __m256i special = _mm256_or_si256(_mm256_cmpeq_epi8(in, _mm256_set1_epi8('\\')),
                                                _mm256_cmpeq_epi8(_mm256_subs_epu8(_mm256_xor_si256(in, _mm256_set1_epi8(2)), _mm256_set1_epi8(32)), zero));
        const __m256i err = utf8_errors_avx2_32(in, prev, t1h, t1l, t2h);
        const auto special_bits = static_cast<unsigned>(_mm256_movemask_epi8(special));
        const auto err_bits = ~static_cast<unsigned>(_mm256_movemask_epi8(_mm256_cmpeq_epi8(err, zero)));
        if (special_bits != 0)
        {
            // errors up to the special byte count (see vector_utf8_run()); for
            // k = 31, 2u << k is 0 and the mask has all bits set
            const auto k = static_cast<unsigned>(count_trailing_zeros(static_cast<std::uint64_t>(special_bits)));
            if ((err_bits & ((2u << k) - 1u)) == 0)
            {
                block_out = block + k;
                return true;
            }
            block_out = block;
            return false;
        }
        if (err_bits != 0)
        {
            block_out = block;
            return false;
        }
        prev = in;
        block += 32;
    }
    if (e - block >= 16)
    {
        const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(block))); // NOLINT(bugprone-casting-through-void)
        const __m128i err = utf8_errors_avx2_16(in, _mm256_extracti128_si256(prev, 1), t1h_16, t1l_16, t2h_16);
        const auto special_bits = static_cast<unsigned>(_mm_movemask_epi8(string_specials_avx2_16(in)));
        const auto err_bits = ~static_cast<unsigned>(_mm_movemask_epi8(_mm_cmpeq_epi8(err, _mm_setzero_si128()))) & 0xFFFFu;
        if (special_bits != 0)
        {
            const auto k = static_cast<unsigned>(count_trailing_zeros(static_cast<std::uint64_t>(special_bits)));
            if ((err_bits & ((2u << k) - 1u)) == 0)
            {
                block_out = block + k;
                return true;
            }
        }
        else if (err_bits == 0)
        {
            block += 16;
        }
    }
    block_out = block;
    return false;
}

#endif

/*!
@brief the run of plain string bytes and well-formed UTF-8 at p (a character
       boundary), 16 bytes per step

The first quote, backslash, or control character is found with vector
compares, and the UTF-8 check of J. Keiser and D. Lemire covers the bytes up
to it. Returns true with @a block at that byte; returns false with @a block at
the start of the 16 bytes where the check found ill-formed UTF-8 or where
fewer than 16 bytes are left, for the caller to finish one sequence at a time.
Out of line, so that no constants of the check occupy registers in the
caller's loop. On x86-64, it is compiled for SSSE3 (see cpu_has_ssse3()), and
hands runs of 32 bytes or more to vector_utf8_run_avx2() where the CPU has AVX2.
*/
JSON_SCAN_SSSE3_TARGET JSON_HEDLEY_NEVER_INLINE inline bool vector_utf8_run(const unsigned char* p, const unsigned char* e, const unsigned char*& block_out) noexcept
{
#if JSON_SCAN_AVX2_DISPATCH
    if (e - p >= 32 && cpu_has_avx2())
    {
        return vector_utf8_run_avx2(p, e, block_out);
    }
#endif
    using lookup = utf8_lookup4<>;
    const unsigned char* block = p;
#if JSON_SCAN_NEON
    const uint8x16_t t1h = vld1q_u8(lookup::byte_1_high.data());
    const uint8x16_t t1l = vld1q_u8(lookup::byte_1_low.data());
    const uint8x16_t t2h = vld1q_u8(lookup::byte_2_high.data());
    uint8x16_t prev = vdupq_n_u8(0);
    while (e - block >= 16)
    {
        const uint8x16_t in = vld1q_u8(block);
        // the quote and the control characters: (c ^ 2) < 33 (see vector_plain_run())
        const uint8x16_t special = vorrq_u8(vceqq_u8(in, vdupq_n_u8('\\')), vcltq_u8(veorq_u8(in, vdupq_n_u8(2)), vdupq_n_u8(33)));
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
                block_out = block + k;
                return true;
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
    const __m128i t1h = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_1_high.data()))); // NOLINT(bugprone-casting-through-void)
    const __m128i t1l = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_1_low.data()))); // NOLINT(bugprone-casting-through-void)
    const __m128i t2h = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_2_high.data()))); // NOLINT(bugprone-casting-through-void)
    const __m128i nibble = _mm_set1_epi8(0x0F);
    const __m128i zero = _mm_setzero_si128();
    __m128i prev = zero;
    while (e - block >= 16)
    {
        const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(block))); // NOLINT(bugprone-casting-through-void)
        // the quote and the control characters: (c ^ 2) < 33, that is,
        // (c ^ 2) - 32 saturates to 0 (see vector_plain_run())
        const __m128i special = _mm_or_si128(_mm_cmpeq_epi8(in, _mm_set1_epi8('\\')),
                                             _mm_cmpeq_epi8(_mm_subs_epu8(_mm_xor_si128(in, _mm_set1_epi8(2)), _mm_set1_epi8(32)), zero));
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
            const auto k = static_cast<unsigned>(count_trailing_zeros(static_cast<std::uint64_t>(special_bits)));
            if ((err_bits & ((2u << k) - 1u)) == 0)
            {
                block_out = block + k;
                return true;
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
    block_out = block;
    return false;
}

/*!
@brief skip 16-byte blocks of well-formed UTF-8 at p (a character boundary)

Like vector_utf8_run, but quotes, backslashes, and control characters are
ordinary characters. Returns the start of the first block in which the check
found an error (which may belong to a sequence begun in the block before) or
where fewer than 16 bytes are left; a sequence may be cut at that point, so the
caller resumes at its start, one sequence at a time.
*/
JSON_SCAN_SSSE3_TARGET JSON_HEDLEY_NEVER_INLINE inline const unsigned char* vector_utf8_valid_blocks(const unsigned char* block, const unsigned char* e) noexcept
{
    using lookup = utf8_lookup4<>;
#if JSON_SCAN_NEON
    const uint8x16_t t1h = vld1q_u8(lookup::byte_1_high.data());
    const uint8x16_t t1l = vld1q_u8(lookup::byte_1_low.data());
    const uint8x16_t t2h = vld1q_u8(lookup::byte_2_high.data());
    uint8x16_t prev = vdupq_n_u8(0);
    while (e - block >= 16)
    {
        const uint8x16_t in = vld1q_u8(block);
        if (vmaxvq_u8(vorrq_u8(in, prev)) < 0x80)
        {
            // ASCII here, and no sequence from the block before to finish
            prev = in;
            block += 16;
            continue;
        }
        const uint8x16_t prev1 = vextq_u8(prev, in, 15);
        const uint8x16_t sc = vandq_u8(vandq_u8(vqtbl1q_u8(t1h, vshrq_n_u8(prev1, 4)), vqtbl1q_u8(t1l, vandq_u8(prev1, vdupq_n_u8(0x0F)))), vqtbl1q_u8(t2h, vshrq_n_u8(in, 4)));
        const uint8x16_t must23 = vorrq_u8(vqsubq_u8(vextq_u8(prev, in, 14), vdupq_n_u8(0xE0 - 0x80)), vqsubq_u8(vextq_u8(prev, in, 13), vdupq_n_u8(0xF0 - 0x80)));
        const uint8x16_t err = veorq_u8(vandq_u8(must23, vdupq_n_u8(0x80)), sc);
        if (vmaxvq_u8(err) != 0)
        {
            break;
        }
        prev = in;
        block += 16;
    }
#else
    const __m128i t1h = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_1_high.data()))); // NOLINT(bugprone-casting-through-void)
    const __m128i t1l = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_1_low.data()))); // NOLINT(bugprone-casting-through-void)
    const __m128i t2h = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_2_high.data()))); // NOLINT(bugprone-casting-through-void)
    const __m128i nibble = _mm_set1_epi8(0x0F);
    const __m128i zero = _mm_setzero_si128();
    __m128i prev = zero;
    while (e - block >= 16)
    {
        const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(block))); // NOLINT(bugprone-casting-through-void)
        if (_mm_movemask_epi8(_mm_or_si128(in, prev)) == 0)
        {
            prev = in;
            block += 16;
            continue;
        }
        const __m128i prev1 = _mm_alignr_epi8(in, prev, 15);
        const __m128i sc = _mm_and_si128(_mm_and_si128(_mm_shuffle_epi8(t1h, _mm_and_si128(_mm_srli_epi16(prev1, 4), nibble)),
                                         _mm_shuffle_epi8(t1l, _mm_and_si128(prev1, nibble))),
                                         _mm_shuffle_epi8(t2h, _mm_and_si128(_mm_srli_epi16(in, 4), nibble)));
        const __m128i must23 = _mm_or_si128(_mm_subs_epu8(_mm_alignr_epi8(in, prev, 14), _mm_set1_epi8(0xE0 - 0x80)),
                                            _mm_subs_epu8(_mm_alignr_epi8(in, prev, 13), _mm_set1_epi8(0xF0 - 0x80)));
        const __m128i err = _mm_xor_si128(_mm_and_si128(must23, _mm_set1_epi8(static_cast<char>(-128))), sc);
        if (_mm_movemask_epi8(_mm_cmpeq_epi8(err, zero)) != 0xFFFF)
        {
            break;
        }
        prev = in;
        block += 16;
    }
#endif
    return block;
}
#endif

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
