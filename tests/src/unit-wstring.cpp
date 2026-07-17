//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

// ICPC errors out on multibyte character sequences in source files
#ifndef __INTEL_COMPILER
namespace
{
bool wstring_is_utf16();
bool wstring_is_utf16()
{
    return (std::wstring(L"💩") == std::wstring(L"\U0001F4A9"));
}

bool u16string_is_utf16();
bool u16string_is_utf16()
{
    return (std::u16string(u"💩") == std::u16string(u"\U0001F4A9"));
}

bool u32string_is_utf32();
bool u32string_is_utf32()
{
    return (std::u32string(U"💩") == std::u32string(U"\U0001F4A9"));
}
} // namespace

TEST_CASE("wide strings")
{
    SECTION("std::wstring")
    {
        if (wstring_is_utf16())
        {
            std::wstring const w = L"[12.2,\"Ⴥaäö💤🧢\"]";
            json const j = json::parse(w);
            CHECK(j.dump() == "[12.2,\"Ⴥaäö💤🧢\"]");
        }
    }

    SECTION("invalid std::wstring")
    {
        if (wstring_is_utf16())
        {
            std::wstring const w = L"\"\xDBFF";
            json _;
            CHECK_THROWS_AS(_ = json::parse(w), json::parse_error&);

            // a lone low surrogate cannot start a pair
            CHECK_THROWS_AS(_ = json::parse(std::wstring{L'"', static_cast<wchar_t>(0xDC00), L'"'}), json::parse_error&);
            // a high surrogate followed by a non-low-surrogate unit is invalid
            CHECK_THROWS_AS(_ = json::parse(std::wstring{L'"', static_cast<wchar_t>(0xD800), L'a', L'"'}), json::parse_error&);
            // a lone low surrogate must not swallow the following unit; the
            // exact-message check lives in the u16string section below, since
            // the message here depends on sizeof(wchar_t)
            CHECK_THROWS_AS(_ = json::parse(std::wstring{L'"', static_cast<wchar_t>(0xDC00), L'a', L'"'}), json::parse_error&);
        }
    }

    SECTION("std::u16string")
    {
        if (u16string_is_utf16())
        {
            std::u16string const w = u"[12.2,\"Ⴥaäö💤🧢\"]";
            json const j = json::parse(w);
            CHECK(j.dump() == "[12.2,\"Ⴥaäö💤🧢\"]");
        }
    }

    SECTION("invalid std::u16string")
    {
        if (u16string_is_utf16())
        {
            std::u16string const w = u"\"\xDBFF";
            json _;
            CHECK_THROWS_AS(_ = json::parse(w), json::parse_error&);

            // a lone low surrogate cannot start a pair
            CHECK_THROWS_AS(_ = json::parse(std::u16string{u'"', 0xDC00, u'"'}), json::parse_error&);
            // a high surrogate followed by a non-low-surrogate unit is invalid
            CHECK_THROWS_AS(_ = json::parse(std::u16string{u'"', 0xD800, u'a', u'"'}), json::parse_error&);
            // a lone low surrogate must not swallow the following unit: pairing
            // it with any second unit would produce valid UTF-8, so the error
            // has to report an ill-formed byte at the surrogate's own position
            CHECK_THROWS_WITH_AS(_ = json::parse(std::u16string{u'"', 0xDC00, u'a', u'"'}), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"<U+0000>'", json::parse_error&);
            // a valid surrogate pair is still decoded (U+1F600)
            CHECK(json::parse(std::u16string{u'"', 0xD83D, 0xDE00, u'"'}).get<std::string>() == "\xF0\x9F\x98\x80");
        }
    }

    SECTION("std::u32string")
    {
        if (u32string_is_utf32())
        {
            std::u32string const w = U"[12.2,\"Ⴥaäö💤🧢\"]";
            json const j = json::parse(w);
            CHECK(j.dump() == "[12.2,\"Ⴥaäö💤🧢\"]");
        }
    }

    SECTION("invalid std::u32string")
    {
        if (u32string_is_utf32())
        {
            std::u32string const w = U"\"\x110000";
            json _;
            CHECK_THROWS_AS(_ = json::parse(w), json::parse_error&);
        }
    }
}
#endif
