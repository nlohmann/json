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

TEST_CASE("wide strings")
{
    SECTION("std::wstring")
    {
        // U+10C5 U+0061(a) U+00E4 U+00F6 U+1F4A4 U+1F9E2, written with \u/\U
        // escapes rather than as raw multibyte characters so this file
        // compiles on toolchains (e.g. classic ICC) that error out on
        // multibyte character sequences in source files
        std::wstring const w = L"[12.2,\"\u10C5a\u00E4\u00F6\U0001F4A4\U0001F9E2\"]";
        json const j = json::parse(w);
        CHECK(j.dump() == "[12.2,\"" "\xE1\x83\x85" "a" "\xC3\xA4" "\xC3\xB6" "\xF0\x9F\x92\xA4" "\xF0\x9F\xA7\xA2" "\"]");
    }

    SECTION("invalid std::wstring")
    {
        std::wstring const w = L"\"\xDBFF";
        json _;
        CHECK_THROWS_AS(_ = json::parse(w), json::parse_error&);

        // the exact message depends on the width of wchar_t: a 16-bit
        // wchar_t passes the lone surrogate to the UTF-8 decoder unchanged
        // (rejected as a single ill-formed byte at column 2), while a
        // 32-bit wchar_t first encodes it as an ill-formed three-byte
        // sequence (rejected one byte later, at column 3)
        const char* const error_low_surrogate = sizeof(wchar_t) == 2
                                                ? "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"<U+0000>'"
                                                : "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"\xED\xB0'";
        const char* const error_high_surrogate = sizeof(wchar_t) == 2
            ? "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"<U+0000>'"
            : "[json.exception.parse_error.101] parse error at line 1, column 3: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"\xED\xA0'";

        // a lone low surrogate cannot start a pair
        CHECK_THROWS_WITH_AS(_ = json::parse(std::wstring{L'"', static_cast<wchar_t>(0xDC00), L'"'}), error_low_surrogate, json::parse_error&);
        // a high surrogate followed by a non-low-surrogate unit is invalid
        CHECK_THROWS_WITH_AS(_ = json::parse(std::wstring{L'"', static_cast<wchar_t>(0xD800), L'a', L'"'}), error_high_surrogate, json::parse_error&);
        // ... also when the unit is above the low surrogates
        CHECK_THROWS_WITH_AS(_ = json::parse(std::wstring{L'"', static_cast<wchar_t>(0xD800), static_cast<wchar_t>(0xE000), L'"'}), error_high_surrogate, json::parse_error&);
        // a lone low surrogate must not swallow the following unit: pairing
        // it with any second unit would produce valid UTF-8, so the error
        // has to report an ill-formed byte at the surrogate's own position
        CHECK_THROWS_WITH_AS(_ = json::parse(std::wstring{L'"', static_cast<wchar_t>(0xDC00), L'a', L'"'}), error_low_surrogate, json::parse_error&);
    }

    SECTION("std::u16string")
    {
        std::u16string const w = u"[12.2,\"\u10C5a\u00E4\u00F6\U0001F4A4\U0001F9E2\"]";
        json const j = json::parse(w);
        CHECK(j.dump() == "[12.2,\"" "\xE1\x83\x85" "a" "\xC3\xA4" "\xC3\xB6" "\xF0\x9F\x92\xA4" "\xF0\x9F\xA7\xA2" "\"]");
    }

    SECTION("invalid std::u16string")
    {
        std::u16string const w = u"\"\xDBFF";
        json _;
        CHECK_THROWS_AS(_ = json::parse(w), json::parse_error&);

        // a lone low surrogate cannot start a pair
        CHECK_THROWS_WITH_AS(_ = json::parse(std::u16string{u'"', 0xDC00, u'"'}), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"<U+0000>'", json::parse_error&);
        // a high surrogate followed by a non-low-surrogate unit is invalid
        CHECK_THROWS_WITH_AS(_ = json::parse(std::u16string{u'"', 0xD800, u'a', u'"'}), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"<U+0000>'", json::parse_error&);
        // ... also when the unit is above the low surrogates
        CHECK_THROWS_WITH_AS(_ = json::parse(std::u16string{u'"', 0xD800, 0xE000, u'"'}), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"<U+0000>'", json::parse_error&);
        // a lone low surrogate must not swallow the following unit: pairing
        // it with any second unit would produce valid UTF-8, so the error
        // has to report an ill-formed byte at the surrogate's own position
        CHECK_THROWS_WITH_AS(_ = json::parse(std::u16string{u'"', 0xDC00, u'a', u'"'}), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"<U+0000>'", json::parse_error&);
        // a valid surrogate pair is still decoded (U+1F600)
        CHECK(json::parse(std::u16string{u'"', 0xD83D, 0xDE00, u'"'}).get<std::string>() == "\xF0\x9F\x98\x80");
    }

    SECTION("std::u32string")
    {
        std::u32string const w = U"[12.2,\"\u10C5a\u00E4\u00F6\U0001F4A4\U0001F9E2\"]";
        json const j = json::parse(w);
        CHECK(j.dump() == "[12.2,\"" "\xE1\x83\x85" "a" "\xC3\xA4" "\xC3\xB6" "\xF0\x9F\x92\xA4" "\xF0\x9F\xA7\xA2" "\"]");
    }

    SECTION("invalid std::u32string")
    {
        std::u32string const w = U"\"\x110000";
        json _;
        CHECK_THROWS_AS(_ = json::parse(w), json::parse_error&);

        // a code unit above U+10FFFF must not be narrowed onto the EOF
        // sentinel: 0xFFFFFFFF would otherwise end the document silently and
        // let everything following it pass the strict end-of-input check
        std::u32string const trailing{U'[', U'1', U']', static_cast<char32_t>(0xFFFFFFFF), U'x'};
        CHECK_THROWS_WITH_AS(_ = json::parse(trailing), "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: '1]\xFF'; expected end of input", json::parse_error&);
        CHECK(!json::accept(trailing));

        // the same unit inside a string is reported as an ill-formed byte
        CHECK_THROWS_WITH_AS(_ = json::parse(std::u32string{U'"', static_cast<char32_t>(0xFFFFFFFF), U'"'}), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"\xFF'", json::parse_error&);
    }
}
