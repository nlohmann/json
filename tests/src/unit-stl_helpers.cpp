//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <limits>
#include <type_traits>

// The detail helpers that stand in for standard library functions of newer
// standards: each uses the standard function where the library has it and a
// C++11 implementation otherwise, so this file is also built with
// JSON_HAS_CPP_17, JSON_HAS_CPP_20, and JSON_HAS_CPP_23 to test both.

namespace
{
struct with_constexpr_member
{
    static constexpr std::size_t lower = 64; // no out-of-line definition
};
} // namespace

TEST_CASE("detail::clamp")
{
    using nlohmann::detail::clamp;

    SECTION("integers")
    {
        CHECK(clamp(5, 1, 10) == 5);
        CHECK(clamp(0, 1, 10) == 1);
        CHECK(clamp(11, 1, 10) == 10);
        CHECK(clamp(1, 1, 10) == 1);
        CHECK(clamp(10, 1, 10) == 10);
        CHECK(clamp(7, 7, 7) == 7);
        CHECK(clamp(-5, -3, 3) == -3);
        CHECK(clamp(std::size_t{0}, std::size_t{64}, std::size_t{0x10000}) == 64);
        CHECK(clamp(std::size_t{0x20000}, std::size_t{64}, std::size_t{0x10000}) == 0x10000);
    }

    SECTION("floating-point numbers")
    {
        CHECK(clamp(0.5, 0.0, 1.0) == 0.5);
        CHECK(clamp(-0.5, 0.0, 1.0) == 0.0);
        CHECK(clamp(1.5, 0.0, 1.0) == 1.0);
        CHECK(clamp(-std::numeric_limits<double>::infinity(), 0.0, 1.0) == 0.0);
    }

    SECTION("by value: a static constexpr member needs no definition")
    {
        CHECK(clamp(std::size_t{1}, with_constexpr_member::lower, std::size_t{100}) == 64);
    }

    SECTION("constexpr and noexcept")
    {
        static_assert(clamp(3, 1, 2) == 2, "clamp must be constexpr");
        static_assert(noexcept(clamp(3, 1, 2)), "clamp must be noexcept");
    }
}

TEST_CASE("detail::bit_cast")
{
    using nlohmann::detail::bit_cast;

    CHECK(bit_cast<std::uint64_t>(1.0) == 0x3FF0000000000000u);
    CHECK(bit_cast<std::uint64_t>(-2.0) == 0xC000000000000000u);
    CHECK(bit_cast<std::uint32_t>(1.0f) == 0x3F800000u);
    CHECK(bit_cast<double>(std::uint64_t{0x4009000000000000u}) == 3.125);
    CHECK(bit_cast<float>(std::uint32_t{0xC0490000u}) == -3.140625f);
    CHECK(bit_cast<std::int8_t>(std::uint8_t{0xFF}) == -1);

    // to and from byte arrays
    const auto bytes = bit_cast<std::array<std::uint8_t, 4>>(std::uint32_t{0x01020304u});
    // qualified: with a std::array argument, ADL would also find std::bit_cast in C++20
    CHECK(nlohmann::detail::bit_cast<std::uint32_t>(bytes) == 0x01020304u);

    static_assert(noexcept(bit_cast<std::uint64_t>(1.0)), "bit_cast must be noexcept");
}

TEST_CASE("detail::byteswap")
{
    using nlohmann::detail::byteswap;

    CHECK(byteswap(std::uint16_t{0x0102u}) == 0x0201u);
    CHECK(byteswap(std::uint16_t{0xFF00u}) == 0x00FFu);
    CHECK(byteswap(std::uint32_t{0x01020304u}) == 0x04030201u);
    CHECK(byteswap(std::uint32_t{0xFF000080u}) == 0x800000FFu);
    CHECK(byteswap(std::uint64_t{0x0102030405060708u}) == 0x0807060504030201u);
    CHECK(byteswap(std::uint64_t{0xFF00000000000080u}) == 0x80000000000000FFu);

    // an involution
    for (std::uint64_t x :
            {
                std::uint64_t{0}, std::uint64_t{1}, std::uint64_t{0x123456789ABCDEF0u}, (std::numeric_limits<std::uint64_t>::max)()
            })
    {
        CHECK(byteswap(byteswap(x)) == x);
        CHECK(byteswap(byteswap(static_cast<std::uint32_t>(x))) == static_cast<std::uint32_t>(x));
        CHECK(byteswap(byteswap(static_cast<std::uint16_t>(x))) == static_cast<std::uint16_t>(x));
    }

    static_assert(std::is_same < decltype(byteswap(std::uint16_t{})), std::uint16_t >::value, "byteswap keeps the type");
    static_assert(std::is_same < decltype(byteswap(std::uint32_t{})), std::uint32_t >::value, "byteswap keeps the type");
    static_assert(std::is_same < decltype(byteswap(std::uint64_t{})), std::uint64_t >::value, "byteswap keeps the type");
}

TEST_CASE("detail::count_leading_zeros and count_trailing_zeros")
{
    using nlohmann::detail::count_leading_zeros;
    using nlohmann::detail::count_trailing_zeros;

    // a single bit, and that bit with all lower (resp. higher) bits set: both
    // halves of the 32-bit fallbacks
    for (int k = 0; k < 64; ++k)
    {
        const std::uint64_t bit = std::uint64_t{1} << k;
        CAPTURE(k)
        CHECK(count_leading_zeros(bit) == 63 - k);
        CHECK(count_leading_zeros(bit | (bit - 1)) == 63 - k);
        CHECK(count_trailing_zeros(bit) == k);
        CHECK(count_trailing_zeros(bit | ~(bit | (bit - 1))) == k);
    }
}
