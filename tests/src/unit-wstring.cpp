//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <cwchar>
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
            CHECK_THROWS_WITH_AS(_ = json::parse(std::u16string{u'"', 0xDC00, u'"'}), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"\xFF'", json::parse_error&);
            // a high surrogate followed by a non-low-surrogate unit is invalid
            CHECK_THROWS_WITH_AS(_ = json::parse(std::u16string{u'"', 0xD800, u'a', u'"'}), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"\xFF'", json::parse_error&);
            // ... also when the unit is above the low surrogates
            CHECK_THROWS_WITH_AS(_ = json::parse(std::u16string{u'"', 0xD800, 0xE000, u'"'}), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"\xFF'", json::parse_error&);
            // a lone low surrogate must not swallow the following unit: pairing
            // it with any second unit would produce valid UTF-8, so the error
            // has to report an ill-formed byte at the surrogate's own position
            CHECK_THROWS_WITH_AS(_ = json::parse(std::u16string{u'"', 0xDC00, u'a', u'"'}), "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid string: ill-formed UTF-8 byte; last read: '\"\xFF'", json::parse_error&);
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

    SECTION("malformed wide-string input outside strings (#5645)")
    {
        json _;

        // a lone low surrogate inside a literal must not be truncated to its
        // low byte and mistaken for the letter the literal expects next
        // (0xDC72 truncates to 'r', which is what "true" expects after 't')
        CHECK_THROWS_WITH_AS(_ = json::parse(std::u16string{u't', static_cast<char16_t>(0xDC72), u'u', u'e'}),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid literal; last read: 't\xFF'", json::parse_error&);

        // ... also when the lone surrogate is the last unit of the input
        CHECK_THROWS_WITH_AS(_ = json::parse(std::u16string{u'f', u'a', u'l', u's', static_cast<char16_t>(0xDD65)}),
                             "[json.exception.parse_error.101] parse error at line 1, column 5: syntax error while parsing value - invalid literal; last read: 'fals\xFF'", json::parse_error&);

        // a high surrogate followed by a unit that is not its low surrogate
        // must not silently swallow that unit
        CHECK_THROWS_WITH_AS(_ = json::parse(std::u16string{u't', static_cast<char16_t>(0xD872), u'X', u'u', u'e'}),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid literal; last read: 't\xFF'", json::parse_error&);

        // ... in particular, if the swallowed unit is the newline that ends a
        // // comment, the comment must not extend over the following line
        CHECK(json::parse(std::u16string{u'[', u'1', u' ', u'/', u'/', static_cast<char16_t>(0xD800), u'\n',
                                         u',', u'2', u' ', u'/', u'/', u'\n', u']'},
                          nullptr, true, /*ignore_comments*/true) == json::parse("[1,2]"));
        CHECK(json::accept(std::u16string{u'[', u'1', u' ', u'/', u'/', static_cast<char16_t>(0xD800), u'\n',
                                          u',', u'2', u' ', u'/', u'/', u'\n', u']'}, /*ignore_comments*/true));

        // cases 5 and 6 use a 32-bit wchar_t (Linux, macOS, the BSDs) to reach
        // the UTF-32 helper tested above via u32string; the 16-bit wchar_t of
        // Windows goes through the UTF-16 helper instead, already covered by
        // the u16string cases above
#if WCHAR_MAX > 0xFFFFu
        // a negative wchar_t must not be mistaken for
        // char_traits<char>::eof() and silently end the input, letting
        // trailing garbage pass the strict end-of-input check (only observable
        // where wint_t is signed, e.g. macOS/the BSDs; on Linux wint_t is
        // unsigned and this was already handled by #5348)
        std::wstring w = L"[1]";
        w.push_back(static_cast<wchar_t>(-1));
        w += L"garbage";
        CHECK(!json::accept(w));
        CHECK_THROWS_WITH_AS(_ = json::parse(w),
                             "[json.exception.parse_error.101] parse error at line 1, column 4: syntax error while parsing value - invalid literal; last read: '1]\xFF'; expected end of input", json::parse_error&);

        // other negative wchar_t units must not be truncated to their low
        // byte (0xFFFFFF72 truncates to 'r', as in the u16string case above)
        CHECK_THROWS_WITH_AS(_ = json::parse(std::wstring{L't', static_cast<wchar_t>(0xFFFFFF72), L'u', L'e'}),
                             "[json.exception.parse_error.101] parse error at line 1, column 2: syntax error while parsing value - invalid literal; last read: 't\xFF'", json::parse_error&);
#endif
    }
}
#endif
