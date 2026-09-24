//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#if JSON_TEST_USING_MULTIPLE_HEADERS
    #include <nlohmann/detail/meta/type_traits.hpp>
#else
    #include <nlohmann/json.hpp>
#endif

TEST_CASE("type traits")
{
    SECTION("is_c_string")
    {
        using nlohmann::detail::is_c_string;
        using nlohmann::detail::is_c_string_uncvref;

        SECTION("char *")
        {
            CHECK(is_c_string<char*>::value);
            CHECK(is_c_string<const char*>::value);
            CHECK(is_c_string<char* const>::value);
            CHECK(is_c_string<const char* const>::value);

            CHECK_FALSE(is_c_string<char*&>::value);
            CHECK_FALSE(is_c_string<const char*&>::value);
            CHECK_FALSE(is_c_string<char* const&>::value);
            CHECK_FALSE(is_c_string<const char* const&>::value);

            CHECK(is_c_string_uncvref<char*&>::value);
            CHECK(is_c_string_uncvref<const char*&>::value);
            CHECK(is_c_string_uncvref<char* const&>::value);
            CHECK(is_c_string_uncvref<const char* const&>::value);
        }

        SECTION("char[]")
        {
            // NOLINTBEGIN(hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)
            CHECK(is_c_string<char[]>::value);
            CHECK(is_c_string<const char[]>::value);

            CHECK_FALSE(is_c_string<char(&)[]>::value);
            CHECK_FALSE(is_c_string<const char(&)[]>::value);

            CHECK(is_c_string_uncvref<char(&)[]>::value);
            CHECK(is_c_string_uncvref<const char(&)[]>::value);
            // NOLINTEND(hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)
        }
    }

    SECTION("char_traits")
    {
        SECTION("to_int_type does not sign-extend")
        {
            using unsigned_traits = nlohmann::detail::char_traits<unsigned char>;
            using signed_traits = nlohmann::detail::char_traits<signed char>;

            CHECK(unsigned_traits::to_int_type(static_cast<unsigned char>(0x7F)) == 0x7F);
            CHECK(unsigned_traits::to_int_type(static_cast<unsigned char>(0x80)) == 0x80);
            CHECK(unsigned_traits::to_int_type(static_cast<unsigned char>(0xFF)) == 0xFF);

            CHECK(signed_traits::to_int_type(static_cast<signed char>(0x7F)) == 0x7F);
            // 0x80 and 0xFF do not fit in signed char (MSVC C4309), so spell them as negative values
            CHECK(signed_traits::to_int_type(static_cast<signed char>(0x80 - 0x100)) == 0x80);
            CHECK(signed_traits::to_int_type(static_cast<signed char>(0xFF - 0x100)) == 0xFF);
        }

        SECTION("no byte value collides with eof")
        {
            using unsigned_traits = nlohmann::detail::char_traits<unsigned char>;
            using signed_traits = nlohmann::detail::char_traits<signed char>;

            for (int i = 0; i < 256; ++i)
            {
                CHECK(unsigned_traits::to_int_type(static_cast<unsigned char>(i)) != unsigned_traits::eof());
                CHECK(signed_traits::to_int_type(static_cast<signed char>(i)) != signed_traits::eof());
            }
        }
    }
}
