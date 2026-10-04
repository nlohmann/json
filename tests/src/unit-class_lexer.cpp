//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;

#include <array> // array
#include <cfloat> // FLT_EVAL_METHOD
#include <cstdint> // uint32_t, uint64_t
#include <cstdlib> // strtod
#include <cstring> // memcpy
#include <sstream> // stringstream
#include <string> // string
#include <utility> // pair
#include <vector> // vector

namespace
{
// shortcut to scan a string literal
json::lexer::token_type scan_string(const char* s, bool ignore_comments = false);
json::lexer::token_type scan_string(const char* s, const bool ignore_comments)
{
    auto ia = nlohmann::detail::input_adapter(s);
    return nlohmann::detail::lexer<json, decltype(ia)>(std::move(ia), ignore_comments).scan(); // NOLINT(hicpp-move-const-arg,performance-move-const-arg)
}
} // namespace

std::string get_error_message(const char* s, bool ignore_comments = false); // NOLINT(misc-use-internal-linkage)
std::string get_error_message(const char* s, const bool ignore_comments)
{
    auto ia = nlohmann::detail::input_adapter(s);
    auto lexer = nlohmann::detail::lexer<json, decltype(ia)>(std::move(ia), ignore_comments); // NOLINT(hicpp-move-const-arg,performance-move-const-arg)
    lexer.scan();
    return lexer.get_error_message();
}

TEST_CASE("lexer class")
{
    SECTION("scan")
    {
        SECTION("structural characters")
        {
            CHECK((scan_string("[") == json::lexer::token_type::begin_array));
            CHECK((scan_string("]") == json::lexer::token_type::end_array));
            CHECK((scan_string("{") == json::lexer::token_type::begin_object));
            CHECK((scan_string("}") == json::lexer::token_type::end_object));
            CHECK((scan_string(",") == json::lexer::token_type::value_separator));
            CHECK((scan_string(":") == json::lexer::token_type::name_separator));
        }

        SECTION("literal names")
        {
            CHECK((scan_string("null") == json::lexer::token_type::literal_null));
            CHECK((scan_string("true") == json::lexer::token_type::literal_true));
            CHECK((scan_string("false") == json::lexer::token_type::literal_false));
        }

        SECTION("numbers")
        {
            CHECK((scan_string("0") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("1") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("2") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("3") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("4") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("5") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("6") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("7") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("8") == json::lexer::token_type::value_unsigned));
            CHECK((scan_string("9") == json::lexer::token_type::value_unsigned));

            CHECK((scan_string("-0") == json::lexer::token_type::value_integer));
            CHECK((scan_string("-1") == json::lexer::token_type::value_integer));

            CHECK((scan_string("1.1") == json::lexer::token_type::value_float));
            CHECK((scan_string("-1.1") == json::lexer::token_type::value_float));
            CHECK((scan_string("1E10") == json::lexer::token_type::value_float));
        }

        SECTION("whitespace")
        {
            // result is end_of_input, because not token is following
            CHECK((scan_string(" ") == json::lexer::token_type::end_of_input));
            CHECK((scan_string("\t") == json::lexer::token_type::end_of_input));
            CHECK((scan_string("\n") == json::lexer::token_type::end_of_input));
            CHECK((scan_string("\r") == json::lexer::token_type::end_of_input));
            CHECK((scan_string(" \t\n\r\n\t ") == json::lexer::token_type::end_of_input));
        }
    }

    SECTION("token_type_name")
    {
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::uninitialized)) == "<uninitialized>"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::literal_true)) == "true literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::literal_false)) == "false literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::literal_null)) == "null literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::value_string)) == "string literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::value_unsigned)) == "number literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::value_integer)) == "number literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::value_float)) == "number literal"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::begin_array)) == "'['"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::begin_object)) == "'{'"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::end_array)) == "']'"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::end_object)) == "'}'"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::name_separator)) == "':'"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::value_separator)) == "','"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::parse_error)) == "<parse error>"));
        CHECK((std::string(json::lexer::token_type_name(json::lexer::token_type::end_of_input)) == "end of input"));
    }

    SECTION("parse errors on first character")
    {
        for (int c = 1; c < 128; ++c)
        {
            // create string from the ASCII code
            const auto s = std::string(1, static_cast<char>(c));
            // store scan() result
            const auto res = scan_string(s.c_str());

            CAPTURE(s)

            switch (c)
            {
                // single characters that are valid tokens
                case ('['):
                case (']'):
                case ('{'):
                case ('}'):
                case (','):
                case (':'):
                case ('0'):
                case ('1'):
                case ('2'):
                case ('3'):
                case ('4'):
                case ('5'):
                case ('6'):
                case ('7'):
                case ('8'):
                case ('9'):
                {
                    CHECK((res != json::lexer::token_type::parse_error));
                    break;
                }

                // whitespace
                case (' '):
                case ('\t'):
                case ('\n'):
                case ('\r'):
                {
                    CHECK((res == json::lexer::token_type::end_of_input));
                    break;
                }

                // anything else is not expected
                default:
                {
                    CHECK((res == json::lexer::token_type::parse_error));
                    break;
                }
            }
        }
    }

    SECTION("very large string")
    {
        // strings larger than 1024 bytes yield a resize of the lexer's yytext buffer
        std::string s("\"");
        s += std::string(2048, 'x');
        s += "\"";
        CHECK((scan_string(s.c_str()) == json::lexer::token_type::value_string));
    }

    SECTION("fail on comments")
    {
        CHECK((scan_string("/", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/", false) == "invalid literal");

        CHECK((scan_string("/!", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/!", false) == "invalid literal");
        CHECK((scan_string("/*", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/*", false) == "invalid literal");
        CHECK((scan_string("/**", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/**", false) == "invalid literal");

        CHECK((scan_string("//", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("//", false) == "invalid literal");
        CHECK((scan_string("/**/", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/**/", false) == "invalid literal");
        CHECK((scan_string("/** /", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/** /", false) == "invalid literal");

        CHECK((scan_string("/***/", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/***/", false) == "invalid literal");
        CHECK((scan_string("/* true */", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/* true */", false) == "invalid literal");
        CHECK((scan_string("/*/**/", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/*/**/", false) == "invalid literal");
        CHECK((scan_string("/*/* */", false) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/*/* */", false) == "invalid literal");
    }

    SECTION("ignore comments")
    {
        CHECK((scan_string("/", true) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/", true) == "invalid comment; expecting '/' or '*' after '/'");

        CHECK((scan_string("/!", true) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/!", true) == "invalid comment; expecting '/' or '*' after '/'");
        CHECK((scan_string("/*", true) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/*", true) == "invalid comment; missing closing '*/'");
        CHECK((scan_string("/**", true) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/**", true) == "invalid comment; missing closing '*/'");

        CHECK((scan_string("//", true) == json::lexer::token_type::end_of_input));
        CHECK((scan_string("/**/", true) == json::lexer::token_type::end_of_input));
        CHECK((scan_string("/** /", true) == json::lexer::token_type::parse_error));
        CHECK(get_error_message("/** /", true) == "invalid comment; missing closing '*/'");

        CHECK((scan_string("/***/", true) == json::lexer::token_type::end_of_input));
        CHECK((scan_string("/* true */", true) == json::lexer::token_type::end_of_input));
        CHECK((scan_string("/*/**/", true) == json::lexer::token_type::end_of_input));
        CHECK((scan_string("/*/* */", true) == json::lexer::token_type::end_of_input));

        CHECK((scan_string("//\n//\n", true) == json::lexer::token_type::end_of_input));
        CHECK((scan_string("/**//**//**/", true) == json::lexer::token_type::end_of_input));
    }
}

TEST_CASE("lexer number fast path")
{
    // The contiguous fast path (used for pointer/string input) must agree with
    // the streaming byte path (used for std::istream) on token type, numeric
    // value, and round-trip text for every well-formed number, and reject the
    // same malformed numbers with the same message.
    SECTION("contiguous vs streaming parity")
    {
        const std::vector<std::string> numbers =
        {
            "0", "-0", "1", "-1", "42", "-42", "10", "100", "1234567890",
            "0.0", "-0.0", "3.14", "-3.14", "0.5", "-0.001", "123.456789",
            "1e0", "1E0", "1e10", "1e-10", "1e+10", "1.5e3", "-2.5E-4",
            "9223372036854775807",             // INT64_MAX -> unsigned
            "9223372036854775808",             // INT64_MAX + 1 -> unsigned
            "18446744073709551615",            // UINT64_MAX -> unsigned
            "18446744073709551616",            // UINT64_MAX + 1 -> float
            "-9223372036854775808",            // INT64_MIN -> integer
            "-9223372036854775809",            // INT64_MIN - 1 -> float
            "123456789012345678901234567890",  // huge -> float
            "0.30000000000000004", "2.2250738585072014e-308", "1e308",
            // high-precision / wide-exponent values that exercise the
            // std::from_chars (Eisel-Lemire) path beyond the Clinger subset
            "1.7976931348623157e308", "1.2345678901234567e-250",
            "9007199254740993", "5e-324", "1e-320"
        };

        for (const auto& n : numbers)
        {
            const std::string doc = "[" + n + "]";

            // contiguous fast path
            const json a = json::parse(doc);
            // streaming byte path
            std::stringstream ss(doc);
            const json b = json::parse(ss);

            CAPTURE(n)
            CHECK(a == b);
            CHECK(a.dump() == b.dump());
            CHECK(a[0].type() == b[0].type());
        }
    }

    SECTION("significant-digit gate for the Clinger fast path")
    {
        // Clinger's fast path needs a significand below 2^53, so it cannot
        // succeed once the mantissa has 17 or more significant digits (the
        // significand would be at least 10^16). The lexer skips the attempt
        // there. That is only allowed to save work: every value must still come
        // out bit-exactly, and both scanners must agree. In particular the gate
        // must not fire for tokens whose leading zeros merely look like extra
        // digits - "0.1234567890123456" has 16 significant digits, not 17.
        const std::vector<std::string> numbers =
        {
            "1234567890123456",                  // 16 significant digits
            "12345678901234567",                 // 17 -> attempt skipped
            "123456789012345678",                // 18 -> attempt skipped
            "0.1234567890123456",                // 16: the leading "0" is not significant
            "0.12345678901234567",               // 17
            "0.00000000000000001",               // 1, in a long token
            "0.000000000000000012345678901234",  // 14, in a long token
            "-0.0000000000000000000001",         // 1, negative
            "1.0000000000000000",                // 17: trailing zeros are significant here
            "10000000000000000",                 // 17
            "9007199254740992",                  // 2^53
            "9007199254740993",                  // 2^53 + 1
            "-65.613616999999977",               // canada.json shape
            "1.2345678901234567e-250",           // 17 with an exponent
            "1.234567890123456e-250",            // 16 with an exponent
            "1e10", "0.0", "-0.0", "0e0", "0.000123"
        };

        for (const auto& n : numbers)
        {
            CAPTURE(n)
            const std::string doc = "[" + n + "]";

            const json a = json::parse(doc);   // contiguous fast path
            std::stringstream ss(doc);
            const json b = json::parse(ss);    // streaming byte path

            CHECK(a[0].type() == b[0].type());
            CHECK(a == b);

            if (a[0].is_number_float())
            {
                const double expected = std::strtod(n.c_str(), nullptr);
                CHECK(a[0].get<double>() == expected);
                CHECK(b[0].get<double>() == expected);
            }
        }
    }

    SECTION("token type classification")
    {
        CHECK((scan_string("0") == json::lexer::token_type::value_unsigned));
        CHECK((scan_string("-1") == json::lexer::token_type::value_integer));
        CHECK((scan_string("1.5") == json::lexer::token_type::value_float));
        CHECK((scan_string("1e5") == json::lexer::token_type::value_float));
        CHECK((scan_string("18446744073709551615") == json::lexer::token_type::value_unsigned));
        CHECK((scan_string("18446744073709551616") == json::lexer::token_type::value_float));
        CHECK((scan_string("-9223372036854775808") == json::lexer::token_type::value_integer));
        CHECK((scan_string("-9223372036854775809") == json::lexer::token_type::value_float));
    }

    SECTION("malformed numbers are rejected identically")
    {
        for (const char* bad :
                {"-", "1.", "1e", "1e+", "1.2e", "01", "-01", "1..2", "1.2.3"
                })
        {
            CAPTURE(bad)
            // the contiguous fast path must decline and let the byte path report
            const std::string doc = std::string("[") + bad + "]";
            CHECK_FALSE(json::accept(doc));
            std::stringstream ss(doc);
            CHECK_FALSE(json::accept(ss));
        }
    }

#if !defined(JSON_NOEXCEPTION)
    // these sections parse invalid input, which aborts when exceptions are off
    SECTION("exhaustive grammar parity with the streaming path")
    {
        // The JSON number grammar is encoded twice: once as the scan_number()
        // state machine and once as the contiguous fast path. Enumerate every
        // short string over the number alphabet and require the two encodings to
        // agree exactly - on acceptance, on the reported error, and on the parsed
        // value - so they cannot drift apart.
        const std::string alphabet = "01.eE+-";

        // full outcome of parsing @a doc, so a mismatch in type, value, or error
        // message is caught, not just a mismatch in acceptance
        const auto outcome = [](const std::string & doc, bool streaming) -> std::string
        {
            try
            {
                if (streaming)
                {
                    std::stringstream ss(doc);
                    const json j = json::parse(ss);
                    return std::string(j[0].type_name()) + '|' + j.dump();
                }
                const json j = json::parse(doc);
                return std::string(j[0].type_name()) + '|' + j.dump();
            }
            catch (const json::parse_error& e)
            {
                return {e.what()};
            }
        };

        std::vector<std::string> mismatches;
        std::vector<std::string> tokens{""};
        for (std::size_t length = 1; length <= 4; ++length)
        {
            std::vector<std::string> next;
            next.reserve(tokens.size() * alphabet.size());
            for (const auto& prefix : tokens)
            {
                for (const char c : alphabet)
                {
                    next.push_back(prefix + c);
                }
            }
            tokens = next;

            for (const auto& token : tokens)
            {
                const std::string doc = "[" + token + "]";
                if (outcome(doc, false) != outcome(doc, true))
                {
                    mismatches.push_back(doc);
                }
            }
        }

        // 7 + 49 + 343 + 2401 tokens
        CHECK(tokens.size() == 2401);
        CAPTURE(mismatches)
        CHECK(mismatches.empty());
    }

    SECTION("error positions match the streaming path")
    {
        // Rejecting identically is not enough: the fast path must also report the
        // error at the same position as the byte path. A number directly followed
        // by a newline is the interesting case, because the byte path reaches the
        // newline (which resets the column) and then ungets it.
        // returns the parse_error message, or "" if the document parsed
        const auto contiguous_error = [](const std::string & doc) -> std::string
        {
            try
            {
                const json j = json::parse(doc);
                static_cast<void>(j);
            }
            catch (const json::parse_error& e)
            {
                return {e.what()};
            }
            return {};
        };
        const auto streaming_error = [](const std::string & doc) -> std::string
        {
            try
            {
                std::stringstream ss(doc);
                const json j = json::parse(ss);
                static_cast<void>(j);
            }
            catch (const json::parse_error& e)
            {
                return {e.what()};
            }
            return {};
        };

        for (const char* bad :
                {"[01\n]", "[00\n]", "[-01\n]", "{1\n}", "[1\n2]", "[1.2.3\n]",
                 "[1 \n2]", "[\n1\n2]", "1\n2", "[01\r\n]", "[1e\n]", "[-\n]"
                })
        {
            CAPTURE(bad)
            const std::string doc = bad;
            const std::string contiguous_what = contiguous_error(doc);

            CHECK_FALSE(contiguous_what.empty());
            CHECK(contiguous_what == streaming_error(doc));
        }

        // A number terminated by a newline must report the same position as the
        // same number terminated by anything else: scan_number() reads the
        // terminator and ungets it, so the reported column is the one reached
        // after the number's last character - not the 0 that an unget() across
        // the newline used to leave behind.
        CHECK(contiguous_error("[01\n]") == contiguous_error("[01 ]"));
        CHECK(contiguous_error("[01\n]") ==
              "[json.exception.parse_error.101] parse error at line 1, column 3: "
              "syntax error while parsing array - unexpected number literal; expected ']'");

        // the same for a multi-character token, where the column of the last
        // character (the '3' of "-2.5e3") differs from the column it starts at
        CHECK(contiguous_error("null -2.5e3\nfalse") == contiguous_error("null -2.5e3 false"));
        CHECK(contiguous_error("null -2.5e3\nfalse") ==
              "[json.exception.parse_error.101] parse error at line 1, column 11: "
              "syntax error while parsing value - unexpected number literal; expected end of input");
    }
#endif
}

TEST_CASE("lexer string fast path")
{
    // Build a byte string from explicit values: a hex escape in a string
    // literal swallows every following hex digit, which makes sequences like
    // "\xC3\xA9b" mean something other than they look like.
    const auto bytes = [](std::initializer_list<int> values)
    {
        std::string result;
        for (const int value : values)
        {
            result.push_back(static_cast<char>(value));
        }
        return result;
    };

#if !defined(JSON_NOEXCEPTION)
    // the full outcome of parsing @a doc: the parsed value, or the exact error
    // message, so a mismatch in either is caught. Only usable with exceptions
    // on: parsing invalid input aborts when they are off.
    const auto outcome = [](const std::string & doc, bool streaming) -> std::string
    {
        try
        {
            if (streaming)
            {
                std::stringstream ss(doc);
                const json j = json::parse(ss);
                return j.dump();
            }
            const json j = json::parse(doc);
            return j.dump();
        }
        // not just parse_error: if a bulk scanner ever let ill-formed UTF-8
        // through, dump() would throw type_error.316, and that has to surface
        // as a reported mismatch rather than as an uncaught exception
        catch (const json::exception& e)
        {
            return {e.what()};
        }
    };
#endif

    // once at the start of the string, once past the first 8-byte SWAR word, so
    // the bulk scanner sees each case with and without a run behind it
    const std::vector<std::size_t> offsets{0, 9};

#if !defined(JSON_NOEXCEPTION)
    SECTION("exhaustive contiguous vs streaming parity")
    {
        // ordinary ASCII, both specials, a control byte, characters that make
        // the preceding backslash a valid escape, a UTF-8 lead byte of each
        // length, a continuation byte, and a byte that is never valid
        const std::vector<std::string> alphabet =
        {
            "a", "\"", "\\", "n", "u", "0", bytes({0x01}),
            bytes({0xC3}), bytes({0xA9}), bytes({0xE4}), bytes({0xF0}),
            bytes({0x80}), bytes({0xFF})
        };

        std::vector<std::string> mismatches;
        std::vector<std::string> tokens{""};
        for (std::size_t length = 1; length <= 3; ++length)
        {
            std::vector<std::string> next;
            next.reserve(tokens.size() * alphabet.size());
            for (const auto& prefix : tokens)
            {
                for (const auto& symbol : alphabet)
                {
                    next.push_back(prefix + symbol);
                }
            }
            tokens = next;

            for (const auto& token : tokens)
            {
                for (const std::size_t offset : offsets)
                {
                    const std::string doc = "[\"" + std::string(offset, 'a') + token + "\"]";
                    if (outcome(doc, false) != outcome(doc, true))
                    {
                        mismatches.push_back(doc);
                    }
                }
            }
        }

        // 13 + 169 + 2197 tokens, each at two offsets
        CHECK(tokens.size() == 2197);
        CAPTURE(mismatches)
        CHECK(mismatches.empty());
    }

    SECTION("special bytes at every offset of the SWAR stride")
    {
        // The bulk scanner consumes 8 bytes at a time and then a tail; place
        // every kind of byte that ends a run at each offset across two words,
        // so multibyte sequences also straddle the word boundary.
        const std::vector<std::string> specials =
        {
            "\"", "\\", bytes({0x01}), bytes({0x1F}), bytes({0x7F}),
            bytes({0xC3, 0xA9}), bytes({0xE4, 0xB8, 0xAD}), bytes({0xF0, 0x9F, 0x98, 0x80}),
            bytes({0xFF}), bytes({0xC3}), bytes({0xE4, 0xB8})
        };

        std::vector<std::string> mismatches;
        for (std::size_t offset = 0; offset <= 17; ++offset)
        {
            for (const auto& special : specials)
            {
                const std::string doc = "[\"" + std::string(offset, 'a') + special + "\"]";
                if (outcome(doc, false) != outcome(doc, true))
                {
                    mismatches.push_back(doc);
                }
            }
        }
        CAPTURE(mismatches)
        CHECK(mismatches.empty());
    }
#endif

    // json::accept() never throws, so the ranges stay covered without exceptions
    SECTION("UTF-8 ranges are accepted and rejected as documented")
    {
        // The bulk validator must accept exactly what the byte-at-a-time
        // scanner accepts, so pin the boundaries of every range it recognizes.
        // aggregate, only ever brace-initialized below; default member
        // initializers would stop it being an aggregate in C++11
        struct utf8_case // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init)
        {
            std::string sequence;
            bool valid;
            const char* description;
        };
        const std::vector<utf8_case> cases =
        {
            {bytes({0xC2, 0x80}), true, "U+0080, shortest two-byte"},
            {bytes({0xDF, 0xBF}), true, "U+07FF, longest two-byte"},
            {bytes({0xC1, 0xBF}), false, "overlong two-byte"},
            {bytes({0xC2, 0x7F}), false, "two-byte with bad continuation"},
            {bytes({0xE0, 0xA0, 0x80}), true, "U+0800, shortest three-byte"},
            {bytes({0xE0, 0x9F, 0xBF}), false, "overlong three-byte"},
            {bytes({0xED, 0x9F, 0xBF}), true, "U+D7FF, just below the surrogates"},
            {bytes({0xED, 0xA0, 0x80}), false, "surrogate U+D800"},
            {bytes({0xED, 0xBF, 0xBF}), false, "surrogate U+DFFF"},
            {bytes({0xEE, 0x80, 0x80}), true, "U+E000, just above the surrogates"},
            {bytes({0xEF, 0xBF, 0xBF}), true, "U+FFFF"},
            {bytes({0xF0, 0x90, 0x80, 0x80}), true, "U+10000, shortest four-byte"},
            {bytes({0xF0, 0x8F, 0xBF, 0xBF}), false, "overlong four-byte"},
            {bytes({0xF4, 0x8F, 0xBF, 0xBF}), true, "U+10FFFF, highest code point"},
            {bytes({0xF4, 0x90, 0x80, 0x80}), false, "above U+10FFFF"},
            {bytes({0xF5, 0x80, 0x80, 0x80}), false, "lead byte out of range"},
            {bytes({0x80}), false, "bare continuation byte"},
            {bytes({0xFF}), false, "byte that never appears in UTF-8"},
            {bytes({0xC3}), false, "truncated two-byte"},
            {bytes({0xE4, 0xB8}), false, "truncated three-byte"},
            {bytes({0xF0, 0x9F, 0x98}), false, "truncated four-byte"}
        };

        for (const auto& test_case : cases)
        {
            CAPTURE(test_case.description)
            for (const std::size_t offset : offsets)
            {
                CAPTURE(offset)
                const std::string doc = "[\"" + std::string(offset, 'a') + test_case.sequence + "\"]";
                CHECK(json::accept(doc) == test_case.valid);
#if !defined(JSON_NOEXCEPTION)
                CHECK(outcome(doc, false) == outcome(doc, true));
#endif
            }
        }
    }
}

TEST_CASE("parse_float_fast declines what it cannot convert exactly")
{
    // The lexer only hands well-formed numbers to parse_float_fast, so the
    // malformed ones below can only be passed to it directly. Declining is
    // always safe: the caller then falls back to a slower, exact conversion.
    const auto fast = [](const std::string & s, double & out)
    {
        return nlohmann::detail::parse_float_fast(s.data(), s.data() + s.size(), out);
    };
    double out = 0;

#if defined(FLT_EVAL_METHOD) && FLT_EVAL_METHOD != 0
    // without true double precision, the fast path declines everything
    CHECK_FALSE(fast("1.5", out));
#else
    CHECK(fast("1.5", out));
    CHECK(out == 1.5);
    CHECK(fast("+2.5e1", out));
    CHECK(out == 25.0);
    CHECK(fast("-25E-1", out));
    CHECK(out == -2.5);
    CHECK(fast("1e", out));
    CHECK(out == 1.0);
#endif

    // not a number
    CHECK_FALSE(fast("", out));
    CHECK_FALSE(fast("-", out));
    CHECK_FALSE(fast(".", out));
    CHECK_FALSE(fast("1.2.3", out));
    CHECK_FALSE(fast("1x", out));
    CHECK_FALSE(fast("1e+", out));
    CHECK_FALSE(fast("1e1x", out));

    // numbers that are not represented exactly on the fast path
    CHECK_FALSE(fast("12345678901234567890", out));
    CHECK_FALSE(fast("1e10000", out));
    CHECK_FALSE(fast("9007199254740993", out));
    CHECK_FALSE(fast("1e23", out));
    CHECK_FALSE(fast("1e-23", out));
}

namespace
{
// arbitrary-precision unsigned integers, just enough to recompute the table of
// powers of five (little-endian 32-bit limbs)
using big_uint = std::vector<std::uint32_t>;

void big_trim(big_uint& a)
{
    while (!a.empty() && a.back() == 0)
    {
        a.pop_back();
    }
}

big_uint big_from(std::uint64_t high, std::uint64_t low)
{
    big_uint a = {static_cast<std::uint32_t>(low), static_cast<std::uint32_t>(low >> 32u),
                  static_cast<std::uint32_t>(high), static_cast<std::uint32_t>(high >> 32u)
                 };
    big_trim(a);
    return a;
}

big_uint big_mul(const big_uint& a, const big_uint& b)
{
    big_uint r(a.size() + b.size(), 0);
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        std::uint64_t carry = 0;
        for (std::size_t j = 0; j < b.size(); ++j)
        {
            const std::uint64_t t = (static_cast<std::uint64_t>(a[i]) * b[j]) + r[i + j] + carry;
            r[i + j] = static_cast<std::uint32_t>(t);
            carry = t >> 32u;
        }
        r[i + b.size()] = static_cast<std::uint32_t>(carry);
    }
    big_trim(r);
    return r;
}

big_uint big_shl(const big_uint& a, std::size_t s)
{
    big_uint r(s / 32, 0);
    std::uint32_t carry = 0;
    for (const std::uint32_t x : a)
    {
        const std::uint64_t t = static_cast<std::uint64_t>(x) << (s % 32);
        r.push_back(static_cast<std::uint32_t>(t) | carry);
        carry = static_cast<std::uint32_t>(t >> 32u);
    }
    r.push_back(carry);
    big_trim(r);
    return r;
}

// a + 1 (add) or a - 1 (!add, a > 0)
big_uint big_step(big_uint a, bool add)
{
    for (auto& x : a)
    {
        const std::uint32_t old = x;
        x = add ? x + 1 : x - 1;
        if ((add && x > old) || (!add && x < old))
        {
            break;
        }
    }
    if (add && (a.empty() || a.back() == 0))
    {
        a.push_back(1);
    }
    big_trim(a);
    return a;
}

bool big_less_equal(const big_uint& a, const big_uint& b)
{
    if (a.size() != b.size())
    {
        return a.size() < b.size();
    }
    for (std::size_t i = a.size(); i-- > 0;)
    {
        if (a[i] != b[i])
        {
            return a[i] < b[i];
        }
    }
    return true;
}

std::size_t big_bit_length(const big_uint& a)
{
    std::size_t n = a.size() * 32;
    for (std::uint32_t top = a.back(); (top & 0x80000000u) == 0; top <<= 1u)
    {
        --n;
    }
    return n;
}

std::uint64_t bits_of(double d)
{
    std::uint64_t b = 0;
    std::memcpy(&b, &d, sizeof(b));
    return b;
}

bool eisel_lemire(const std::string& s, double& out)
{
    return nlohmann::detail::parse_float_eisel_lemire(s.data(), s.data() + s.size(), out);
}

// significant digits of a token, without trailing zeros
std::size_t significant_digits(const std::string& s)
{
    std::string digits;
    for (const char c : s)
    {
        if (c == 'e' || c == 'E')
        {
            break;
        }
        if (c >= '0' && c <= '9' && !(digits.empty() && c == '0'))
        {
            digits += c;
        }
    }
    while (!digits.empty() && digits.back() == '0')
    {
        digits.pop_back();
    }
    return digits.size();
}
} // namespace

TEST_CASE("Eisel-Lemire float conversion")
{
    SECTION("the table of powers of five")
    {
        // Recompute every entry the way fast_float's table_generation.py
        // defines it, using only multiplications and comparisons: for q >= 0
        // the most significant 128 bits of 5^q; for q < 0 floor(2^b / 5^-q) + 1
        // for b = z + 127 (q >= -27), or that value for b = 2z + 128 cut to
        // its most significant 128 bits (q < -27), where z is the bit length
        // of 5^-q.
        const auto& table = nlohmann::detail::pow5_128();
        big_uint power5 = {1};
        for (std::int64_t q = 0; q <= nlohmann::detail::pow5_128_largest_power; ++q)
        {
            const auto index = static_cast<std::size_t>(2 * (q - nlohmann::detail::pow5_128_smallest_power));
            const big_uint entry = big_from(table[index], table[index + 1]);
            const std::size_t bits = big_bit_length(power5);
            if (bits <= 128)
            {
                CHECK(entry == big_shl(power5, 128 - bits));
            }
            else
            {
                // floor(5^q / 2^(bits - 128))
                CHECK(big_less_equal(big_shl(entry, bits - 128), power5));
                CHECK_FALSE(big_less_equal(big_shl(big_step(entry, true), bits - 128), power5));
            }
            power5 = big_mul(power5, {5});
        }

        power5 = {5};
        for (std::int64_t q = -1; q >= nlohmann::detail::pow5_128_smallest_power; --q)
        {
            const auto index = static_cast<std::size_t>(2 * (q - nlohmann::detail::pow5_128_smallest_power));
            const big_uint entry = big_from(table[index], table[index + 1]);
            CHECK(big_bit_length(entry) == 128);
            const std::size_t z = big_bit_length(power5);
            const big_uint two_b = big_shl({1}, q >= -27 ? z + 127 : (2 * z) + 128);
            // c = floor(2^b / p) + 1, stored as floor(c / 2^s):
            // (entry * 2^s - 1) * p <= 2^b < ((entry + 1) * 2^s - 1) * p
            const std::size_t s = q >= -27 ? 0 : z + 1;
            CHECK(big_less_equal(big_mul(big_step(big_shl(entry, s), false), power5), two_b));
            CHECK_FALSE(big_less_equal(big_mul(big_step(big_shl(big_step(entry, true), s), false), power5), two_b));
            power5 = big_mul(power5, {5});
        }
    }

    SECTION("128-bit products and leading zeros")
    {
        // whichever implementation the compiler gets (with or without a
        // 128-bit integer type or a builtin)
        std::uint64_t state = 42;
        for (int i = 0; i < 10000; ++i)
        {
            state ^= state << 13u;
            state ^= state >> 7u;
            state ^= state << 17u;
            const std::uint64_t a = state;
            const std::uint64_t b = (state * 0x9E3779B97F4A7C15u) >> (i % 64);
            const auto product = nlohmann::detail::full_multiplication(a, b);
            CHECK(big_from(product.high, product.low) == big_mul(big_from(0, a), big_from(0, b)));

            const int k = i % 64;
            const std::uint64_t x = (std::uint64_t{1} << k) | (a & ((std::uint64_t{1} << k) - 1));
            CHECK(nlohmann::detail::count_leading_zeros(x) == 63 - k);
        }
    }

    SECTION("known values")
    {
        // Generated with Python, whose float() is correctly rounded:
        //   cases = [<hard cases>, 2**53 + 2k + 1, 2**54 + 4k + 2, and exact midpoints
        //            between neighbouring doubles, also 1e-60 above and below them]
        //   print('{"%s", 0x%016xu},' % (s, struct.unpack('<Q', struct.pack('<d', float(s)))[0]))
        const std::vector<std::pair<std::string, std::uint64_t>> known =
        {
            {"0", 0x0000000000000000u},
            {"-0", 0x8000000000000000u},
            {"0.0", 0x0000000000000000u},
            {"-0.0", 0x8000000000000000u},
            {"0e5", 0x0000000000000000u},
            {"0.000e-9", 0x0000000000000000u},
            {"1", 0x3ff0000000000000u},
            {"-1", 0xbff0000000000000u},
            {"0.1", 0x3fb999999999999au},
            {"0.3", 0x3fd3333333333333u},
            {"1.5", 0x3ff8000000000000u},
            {"-2.5e-3", 0xbf647ae147ae147bu},
            {"1e23", 0x44b52d02c7e14af6u},
            {"1e22", 0x4480f0cf064dd592u},
            {"8.98846567431158e307", 0x7fe0000000000000u},
            {"2.2250738585072011e-308", 0x000fffffffffffffu},
            {"2.2250738585072012e-308", 0x0010000000000000u},
            {"2.2250738585072014e-308", 0x0010000000000000u},
            {"4.9406564584124654e-324", 0x0000000000000001u},
            {"2.4703282292062327e-324", 0x0000000000000000u},
            {"2.4703282292062328e-324", 0x0000000000000001u},
            {"1e-324", 0x0000000000000000u},
            {"3e-324", 0x0000000000000001u},
            {"1.7976931348623157e308", 0x7fefffffffffffffu},
            {"1.7976931348623158e308", 0x7fefffffffffffffu},
            {"1.7976931348623159e308", 0x7ff0000000000000u},
            {"1e308", 0x7fe1ccf385ebc8a0u},
            {"1e309", 0x7ff0000000000000u},
            {"-1e400", 0xfff0000000000000u},
            {"1e-400", 0x0000000000000000u},
            {"9007199254740991", 0x433fffffffffffffu},
            {"9007199254740992", 0x4340000000000000u},
            {"9007199254740993", 0x4340000000000000u},
            {"9007199254740995", 0x4340000000000002u},
            {"18014398509481986", 0x4350000000000000u},
            {"18014398509481990", 0x4350000000000002u},
            {"7.2057594037927933e16", 0x4370000000000000u},
            {"123456789012345678901234567890", 0x45f8ee90ff6c373eu},
            {"1.000000000000000111", 0x3ff0000000000000u},
            {"1.0000000000000001110223", 0x3ff0000000000000u},
            {"1.00000000000000011102230246251565404236316680908203125", 0x3ff0000000000000u},
            {"1.00000000000000011102230246251565404236316680908203126", 0x3ff0000000000001u},
            {"0.00000000000000000000000000000000000000000000000000000000000001", 0x3310747ddddf22a8u},
            {"100000000000000000000000000000000000000000000", 0x4911efc659cf7d4cu},
            {"1234567890123456789", 0x43b12210f47de981u},
            {"12345678901234567890", 0x43e56a95319d63e1u},
            {"1234567890123456789.5", 0x43b12210f47de981u},
            {"0.1234567890123456789012345", 0x3fbf9add3746f65fu},
            {"4.4501477170144023e-308", 0x001fffffffffffffu},
            {"2.4406961166466664e-309", 0x0001c14ae5310a48u},
            {"5e-324", 0x0000000000000001u},
            {"1.0e-307", 0x0031fa182c40c60du},
            {"179769313486231570814527423731704356798070567525844996598917476803157260780028538760589558632766878171540458953514382464234321326889464182768467546703537516986049910576551282076245490090389328944075868508455133942304583236903222948165808559332123348274797826204144723168738177180919299881250404026184124858368", 0x7fefffffffffffffu},
            {"4.9e-324", 0x0000000000000001u},
            {"9007199254740993", 0x4340000000000000u},
            {"18014398509481986", 0x4350000000000000u},
            {"9007199254740995", 0x4340000000000002u},
            {"18014398509481990", 0x4350000000000002u},
            {"9007199254740997", 0x4340000000000002u},
            {"18014398509481994", 0x4350000000000002u},
            {"9007199254740999", 0x4340000000000004u},
            {"18014398509481998", 0x4350000000000004u},
            {"9007199254741001", 0x4340000000000004u},
            {"18014398509482002", 0x4350000000000004u},
            {"9007199254741003", 0x4340000000000006u},
            {"18014398509482006", 0x4350000000000006u},
            {"9007199254741005", 0x4340000000000006u},
            {"18014398509482010", 0x4350000000000006u},
            {"9007199254741007", 0x4340000000000008u},
            {"18014398509482014", 0x4350000000000008u},
            {"9007199254741009", 0x4340000000000008u},
            {"18014398509482018", 0x4350000000000008u},
            {"9007199254741011", 0x434000000000000au},
            {"18014398509482022", 0x435000000000000au},
            {"9007199254741013", 0x434000000000000au},
            {"18014398509482026", 0x435000000000000au},
            {"9007199254741015", 0x434000000000000cu},
            {"18014398509482030", 0x435000000000000cu},
            {"9007199254741017", 0x434000000000000cu},
            {"18014398509482034", 0x435000000000000cu},
            {"9007199254741019", 0x434000000000000eu},
            {"18014398509482038", 0x435000000000000eu},
            {"9007199254741021", 0x434000000000000eu},
            {"18014398509482042", 0x435000000000000eu},
            {"9007199254741023", 0x4340000000000010u},
            {"18014398509482046", 0x4350000000000010u},
            {"9007199254741025", 0x4340000000000010u},
            {"18014398509482050", 0x4350000000000010u},
            {"9007199254741027", 0x4340000000000012u},
            {"18014398509482054", 0x4350000000000012u},
            {"9007199254741029", 0x4340000000000012u},
            {"18014398509482058", 0x4350000000000012u},
            {"9007199254741031", 0x4340000000000014u},
            {"18014398509482062", 0x4350000000000014u},
            {"9007199254741033", 0x4340000000000014u},
            {"18014398509482066", 0x4350000000000014u},
            {"9007199254741035", 0x4340000000000016u},
            {"18014398509482070", 0x4350000000000016u},
            {"9007199254741037", 0x4340000000000016u},
            {"18014398509482074", 0x4350000000000016u},
            {"9007199254741039", 0x4340000000000018u},
            {"18014398509482078", 0x4350000000000018u},
            {"9007199254741041", 0x4340000000000018u},
            {"18014398509482082", 0x4350000000000018u},
            {"9007199254741043", 0x434000000000001au},
            {"18014398509482086", 0x435000000000001au},
            {"9007199254741045", 0x434000000000001au},
            {"18014398509482090", 0x435000000000001au},
            {"9007199254741047", 0x434000000000001cu},
            {"18014398509482094", 0x435000000000001cu},
            {"9007199254741049", 0x434000000000001cu},
            {"18014398509482098", 0x435000000000001cu},
            {"9007199254741051", 0x434000000000001eu},
            {"18014398509482102", 0x435000000000001eu},
            {"9007199254741053", 0x434000000000001eu},
            {"18014398509482106", 0x435000000000001eu},
            {"9007199254741055", 0x4340000000000020u},
            {"18014398509482110", 0x4350000000000020u},
            {"9007199254741057", 0x4340000000000020u},
            {"18014398509482114", 0x4350000000000020u},
            {"9007199254741059", 0x4340000000000022u},
            {"18014398509482118", 0x4350000000000022u},
            {"9007199254741061", 0x4340000000000022u},
            {"18014398509482122", 0x4350000000000022u},
            {"9007199254741063", 0x4340000000000024u},
            {"18014398509482126", 0x4350000000000024u},
            {"9007199254741065", 0x4340000000000024u},
            {"18014398509482130", 0x4350000000000024u},
            {"9007199254741067", 0x4340000000000026u},
            {"18014398509482134", 0x4350000000000026u},
            {"9007199254741069", 0x4340000000000026u},
            {"18014398509482138", 0x4350000000000026u},
            {"9007199254741071", 0x4340000000000028u},
            {"18014398509482142", 0x4350000000000028u},
            {"0.00000000000000000142055942108419951085063380808124102279024543292671443374397544090470546507276594638824462890625", 0x3c3a3466f662d406u},
            {"0.000000000000000001420559421084199510850633808081241022790245432926714433743975440904705465072765946388244628906251", 0x3c3a3466f662d407u},
            {"0.00000000000000000142055942108419951085063380808124102279024543292671443374397444090470546507276594638824462890625", 0x3c3a3466f662d406u},
            {"8656.5250079159513916238211095333099365234375", 0x40c0e84333759a94u},
            {"8656.52500791595139162382110953330993652343751", 0x40c0e84333759a94u},
            {"8656.525007915951391623821109533309936523437499999999999999999", 0x40c0e84333759a93u},
            {"13.07696731650454946560557800694368779659271240234375", 0x402a276842967ef0u},
            {"13.076967316504549465605578006943687796592712402343751", 0x402a276842967ef0u},
            {"13.07696731650454946560557800694368779659271240234374999999999", 0x402a276842967eefu},
            {"74708253715391928", 0x437096ac2cc7ee5cu},
            {"747082537153919281", 0x43a4bc5737f9e9f2u},
            {"74708253715391927.99999999999999999999999999999999999999999999", 0x437096ac2cc7ee5bu},
            {"1809802988.27203977108001708984375", 0x41daf7d9bb11691au},
            {"1809802988.272039771080017089843751", 0x41daf7d9bb11691au},
            {"1809802988.272039771080017089843749999999999999999999999999999", 0x41daf7d9bb116919u},
            {"51.390809684186766759239617385901510715484619140625", 0x4049b2060d3e4568u},
            {"51.3908096841867667592396173859015107154846191406251", 0x4049b2060d3e4569u},
            {"51.39080968418676675923961738590151071548461914062499999999999", 0x4049b2060d3e4568u},
            {"9999807412.59738445281982421875", 0x4202a0479da4c772u},
            {"9999807412.597384452819824218751", 0x4202a0479da4c772u},
            {"9999807412.597384452819824218749999999999999999999999999999999", 0x4202a0479da4c771u},
            {"0.00000000023260971767101600534534272272645127367651785021962496102787554264068603515625", 0x3deff83a135dec10u},
            {"0.000000000232609717671016005345342722726451273676517850219624961027875542640686035156251", 0x3deff83a135dec11u},
            {"0.00000000023260971767101600534534272272645127367651785021962496102787544264068603515625", 0x3deff83a135dec10u},
            {"0.000000000497610482021202508216234789619066523902457532813059515319764614105224609375", 0x3e01190730d1ec48u},
            {"0.0000000004976104820212025082162347896190665239024575328130595153197646141052246093751", 0x3e01190730d1ec48u},
            {"0.000000000497610482021202508216234789619066523902457532813059515319764514105224609375", 0x3e01190730d1ec47u},
            {"0.0000000000291336422596533830691676779231223432149733287843673679162748157978057861328125", 0x3dc004321559736eu},
            {"0.00000000002913364225965338306916767792312234321497332878436736791627481579780578613281251", 0x3dc004321559736fu},
            {"0.0000000000291336422596533830691676779231223432149733287843673679162748057978057861328125", 0x3dc004321559736eu},
            {"0.000000000000000039237155154865396441907405399546892080260012902422940561653064150959835387766361236572265625", 0x3c869e61cfa3b8a4u},
            {"0.0000000000000000392371551548653964419074053995468920802600129024229405616530641509598353877663612365722656251", 0x3c869e61cfa3b8a5u},
            {"0.000000000000000039237155154865396441907405399546892080260012902422940561653054150959835387766361236572265625", 0x3c869e61cfa3b8a4u},
            {"0.00000000000000006496592863767266414092845207857846208631635335985395063307379359685000963509082794189453125", 0x3c92b9a3b219ee84u},
            {"0.000000000000000064965928637672664140928452078578462086316353359853950633073793596850009635090827941894531251", 0x3c92b9a3b219ee85u},
            {"0.00000000000000006496592863767266414092845207857846208631635335985395063307378359685000963509082794189453125", 0x3c92b9a3b219ee84u},
            {"0.0000000000448169607439179753541822628688597626549217078917308754171244800090789794921875", 0x3dc8a36d2e8094dau},
            {"0.00000000004481696074391797535418226286885976265492170789173087541712448000907897949218751", 0x3dc8a36d2e8094dau},
            {"0.0000000000448169607439179753541822628688597626549217078917308754171244700090789794921875", 0x3dc8a36d2e8094d9u},
            {"1800873890234250.875", 0x4319978a820cfe2cu},
            {"1800873890234250.8751", 0x4319978a820cfe2cu},
            {"1800873890234250.874999999999999999999999999999999999999999999", 0x4319978a820cfe2bu},
            {"0.000023941132739153309216405436654628857695570331998169422149658203125", 0x3ef91aa61d42e0e0u},
            {"0.0000239411327391533092164054366546288576955703319981694221496582031251", 0x3ef91aa61d42e0e1u},
            {"0.000023941132739153309216405436654628857695570331998169422149658193125", 0x3ef91aa61d42e0e0u},
            {"8339818978785937.5", 0x433da1056bb8ba92u},
            {"8339818978785937.51", 0x433da1056bb8ba92u},
            {"8339818978785937.499999999999999999999999999999999999999999999", 0x433da1056bb8ba91u},
            {"283649145986385328", 0x438f7dcb29dae42eu},
            {"2836491459863853281", 0x43c3ae9efa28ce9cu},
            {"283649145986385327.9999999999999999999999999999999999999999999", 0x438f7dcb29dae42du},
            {"0.0000000000000000004203729478287971874304476341685497759528753070014375965192388040492232903488911688327789306640625", 0x3c1f049ed78cb8a2u},
            {"0.00000000000000000042037294782879718743044763416854977595287530700143759651923880404922329034889116883277893066406251", 0x3c1f049ed78cb8a3u},
            {"0.0000000000000000004203729478287971874304476341685497759528753070014375965192387040492232903488911688327789306640625", 0x3c1f049ed78cb8a2u},
            {"340031.78635183119331486523151397705078125", 0x4114c0ff25396a18u},
            {"340031.786351831193314865231513977050781251", 0x4114c0ff25396a19u},
            {"340031.7863518311933148652315139770507812499999999999999999999", 0x4114c0ff25396a18u},
            {"0.0000000004543709717853330820053712055931242029538363880192264332436025142669677734375", 0x3dff3960f070bf76u},
            {"0.00000000045437097178533308200537120559312420295383638801922643324360251426696777343751", 0x3dff3960f070bf76u},
            {"0.0000000004543709717853330820053712055931242029538363880192264332436024142669677734375", 0x3dff3960f070bf75u},
            {"0.0000000000007937958898451257082591244100968761704503924570008877026339177973568439483642578125", 0x3d6bede0b40e37c2u},
            {"0.00000000000079379588984512570825912441009687617045039245700088770263391779735684394836425781251", 0x3d6bede0b40e37c3u},
            {"0.0000000000007937958898451257082591244100968761704503924570008877026339176973568439483642578125", 0x3d6bede0b40e37c2u},
            {"0.00000000000000068304843500200357021582520000166071595321259251644419041582523277611471712589263916015625", 0x3cc89c02848f8654u},
            {"0.000000000000000683048435002003570215825200001660715953212592516444190415825232776114717125892639160156251", 0x3cc89c02848f8655u},
            {"0.00000000000000068304843500200357021582520000166071595321259251644419041582513277611471712589263916015625", 0x3cc89c02848f8654u},
            {"0.00000000147705080029041786940146712084494760863773166192913777194917201995849609375", 0x3e1960235bc34d06u},
            {"0.000000001477050800290417869401467120844947608637731661929137771949172019958496093751", 0x3e1960235bc34d06u},
            {"0.00000000147705080029041786940146712084494760863773166192913777194917101995849609375", 0x3e1960235bc34d05u},
            {"2164972979236447104", 0x43be0b87743fb524u},
            {"21649729792364471041", 0x43f2c734a8a7d136u},
            {"2164972979236447103.999999999999999999999999999999999999999999", 0x43be0b87743fb523u},
            {"13124633159586767", 0x4347506464a469e8u},
            {"131246331595867671", 0x437d247d7dcd8461u},
            {"13124633159586766.99999999999999999999999999999999999999999999", 0x4347506464a469e7u},
            {"0.000000000000027605165650764659887597286048864477738779108113853499872902830247767269611358642578125", 0x3d1f14a5b417cb08u},
            {"0.0000000000000276051656507646598875972860488644777387791081138534998729028302477672696113586425781251", 0x3d1f14a5b417cb09u},
            {"0.000000000000027605165650764659887597286048864477738779108113853499872902820247767269611358642578125", 0x3d1f14a5b417cb08u},
            {"0.01727792833395616796388072344825559412129223346710205078125", 0x3f91b14e248c42c8u},
            {"0.017277928333956167963880723448255594121292233467102050781251", 0x3f91b14e248c42c9u},
            {"0.01727792833395616796388072344825559412129223346710205078124999", 0x3f91b14e248c42c8u},
            {"0.00000000000003096211381890547702500862566064822950373937142376501441276559489779174327850341796875", 0x3d216e1c61130b22u},
            {"0.000000000000030962113818905477025008625660648229503739371423765014412765594897791743278503417968751", 0x3d216e1c61130b22u},
            {"0.00000000000003096211381890547702500862566064822950373937142376501441276558489779174327850341796875", 0x3d216e1c61130b21u},
            {"0.0000000000000683414954481284270259359974108983284531919182025472281338807079009711742401123046875", 0x3d333c86137e5170u},
            {"0.00000000000006834149544812842702593599741089832845319191820254722813388070790097117424011230468751", 0x3d333c86137e5170u},
            {"0.0000000000000683414954481284270259359974108983284531919182025472281338806979009711742401123046875", 0x3d333c86137e516fu},
            {"3237539054990129.75", 0x4327010c9aa36664u},
            {"3237539054990129.751", 0x4327010c9aa36664u},
            {"3237539054990129.749999999999999999999999999999999999999999999", 0x4327010c9aa36663u},
            {"0.0000000000000105429301486355911969397173440055240907798901443814809653076736140064895153045654296875", 0x3d07bd95dfb8a1eeu},
            {"0.00000000000001054293014863559119693971734400552409077989014438148096530767361400648951530456542968751", 0x3d07bd95dfb8a1eeu},
            {"0.0000000000000105429301486355911969397173440055240907798901443814809653076636140064895153045654296875", 0x3d07bd95dfb8a1edu},
            {"9460.2061893763575426419265568256378173828125", 0x40c27a1a6469da1eu},
            {"9460.20618937635754264192655682563781738281251", 0x40c27a1a6469da1fu},
            {"9460.206189376357542641926556825637817382812499999999999999999", 0x40c27a1a6469da1eu},
            {"465000373656610.53125", 0x42fa6ea56179c228u},
            {"465000373656610.531251", 0x42fa6ea56179c229u},
            {"465000373656610.5312499999999999999999999999999999999999999999", 0x42fa6ea56179c228u},
            {"0.000000000107709773707743713401260815383950956818093214195641849073581397533416748046875", 0x3ddd9b66c974bb14u},
            {"0.0000000001077097737077437134012608153839509568180932141956418490735813975334167480468751", 0x3ddd9b66c974bb14u},
            {"0.000000000107709773707743713401260815383950956818093214195641849073581297533416748046875", 0x3ddd9b66c974bb13u},
            {"0.012083347821554271152300064073870089487172663211822509765625", 0x3f88bf277dc215f4u},
            {"0.0120833478215542711523000640738700894871726632118225097656251", 0x3f88bf277dc215f5u},
            {"0.01208334782155427115230006407387008948717266321182250976562499", 0x3f88bf277dc215f4u},
            {"2309804058391724800", 0x43c0070946d098e2u},
            {"23098040583917248001", 0x43f408cb9884bf1au},
            {"2309804058391724799.999999999999999999999999999999999999999999", 0x43c0070946d098e1u},
            {"0.000000000078286047058220682019445698291671103911937290575906445155851542949676513671875", 0x3dd584e40ca80638u},
            {"0.0000000000782860470582206820194456982916711039119372905759064451558515429496765136718751", 0x3dd584e40ca80638u},
            {"0.000000000078286047058220682019445698291671103911937290575906445155851532949676513671875", 0x3dd584e40ca80637u},
            {"2940024994425.709228515625", 0x4285643929d3cdacu},
            {"2940024994425.7092285156251", 0x4285643929d3cdadu},
            {"2940024994425.709228515624999999999999999999999999999999999999", 0x4285643929d3cdacu},
            {"9503358.427352792583405971527099609375", 0x4162204fcdacdfc4u},
            {"9503358.4273527925834059715270996093751", 0x4162204fcdacdfc4u},
            {"9503358.427352792583405971527099609374999999999999999999999999", 0x4162204fcdacdfc3u},
            {"0.00005589147834433423614399101542193903924271580763161182403564453125", 0x3f0d4da092aa5d6au},
            {"0.000055891478344334236143991015421939039242715807631611824035644531251", 0x3f0d4da092aa5d6bu},
            {"0.00005589147834433423614399101542193903924271580763161182403564452125", 0x3f0d4da092aa5d6au},
            {"0.0000000164797038506435664295103900420409737126448135313694365322589874267578125", 0x3e51b1e8107bd640u},
            {"0.00000001647970385064356642951039004204097371264481353136943653225898742675781251", 0x3e51b1e8107bd641u},
            {"0.0000000164797038506435664295103900420409737126448135313694365322589774267578125", 0x3e51b1e8107bd640u},
            {"73055.7873927834807545877993106842041015625", 0x40f1d5fc99292ce2u},
            {"73055.78739278348075458779931068420410156251", 0x40f1d5fc99292ce3u},
            {"73055.78739278348075458779931068420410156249999999999999999999", 0x40f1d5fc99292ce2u},
            {"0.00000000002558172364455232122427880575336067736115508441940846751094795763492584228515625", 0x3dbc209d7509115au},
            {"0.000000000025581723644552321224278805753360677361155084419408467510947957634925842285156251", 0x3dbc209d7509115bu},
            {"0.00000000002558172364455232122427880575336067736115508441940846751094794763492584228515625", 0x3dbc209d7509115au},
            {"0.000000000854497507560657937804791333430312443020238077906469698064029216766357421875", 0x3e0d5c3d540cc0d2u},
            {"0.0000000008544975075606579378047913334303124430202380779064696980640292167663574218751", 0x3e0d5c3d540cc0d2u},
            {"0.000000000854497507560657937804791333430312443020238077906469698064029116766357421875", 0x3e0d5c3d540cc0d1u},
            {"26671499731071461376", 0x43f722433b19970eu},
            {"266714997310714613761", 0x442cead409dffcd2u},
            {"26671499731071461375.99999999999999999999999999999999999999999", 0x43f722433b19970eu},
            {"0.0000000002725195963972150049060368088050545186395989816219298518262803554534912109375", 0x3df2ba37271cf5f2u},
            {"0.00000000027251959639721500490603680880505451863959898162192985182628035545349121093751", 0x3df2ba37271cf5f2u},
            {"0.0000000002725195963972150049060368088050545186395989816219298518262802554534912109375", 0x3df2ba37271cf5f1u},
            {"0.0000000000377224663702246439557904325637937886957218314165629635681398212909698486328125", 0x3dc4bcf7157af68eu},
            {"0.00000000003772246637022464395579043256379378869572183141656296356813982129096984863281251", 0x3dc4bcf7157af68fu},
            {"0.0000000000377224663702246439557904325637937886957218314165629635681398112909698486328125", 0x3dc4bcf7157af68eu},
            {"0.00000000000000009977342762593364154535842258994910996905560208471673566688053824691451154649257659912109375", 0x3c9cc1fac312e2a6u},
            {"0.000000000000000099773427625933641545358422589949109969055602084716735666880538246914511546492576599121093751", 0x3c9cc1fac312e2a6u},
            {"0.00000000000000009977342762593364154535842258994910996905560208471673566688052824691451154649257659912109375", 0x3c9cc1fac312e2a5u},
            {"0.0000000003146248171139977444431948290159907662133509376189977047033607959747314453125", 0x3df59ef03588a228u},
            {"0.00000000031462481711399774444319482901599076621335093761899770470336079597473144531251", 0x3df59ef03588a229u},
            {"0.0000000003146248171139977444431948290159907662133509376189977047033606959747314453125", 0x3df59ef03588a228u},
            {"488899209263030304", 0x439b23acf64c5e80u},
            {"4888992092630303041", 0x43d0f64c19efbb10u},
            {"488899209263030303.9999999999999999999999999999999999999999999", 0x439b23acf64c5e80u},
            {"1.88357157350592807620870416940306313335895538330078125", 0x3ffe231bf23e21acu},
            {"1.883571573505928076208704169403063133358955383300781251", 0x3ffe231bf23e21adu},
            {"1.883571573505928076208704169403063133358955383300781249999999", 0x3ffe231bf23e21acu},
            {"0.0000000216458400594294836451424756990254139044083103726734407246112823486328125", 0x3e573df694e72fb8u},
            {"0.00000002164584005942948364514247569902541390440831037267344072461128234863281251", 0x3e573df694e72fb9u},
            {"0.0000000216458400594294836451424756990254139044083103726734407246112723486328125", 0x3e573df694e72fb8u},
            {"5107.79271041116453488939441740512847900390625", 0x40b3f3caef11cb26u},
            {"5107.792710411164534889394417405128479003906251", 0x40b3f3caef11cb27u},
            {"5107.792710411164534889394417405128479003906249999999999999999", 0x40b3f3caef11cb26u},
            {"734059.8035226609208621084690093994140625", 0x412666d79b67527cu},
            {"734059.80352266092086210846900939941406251", 0x412666d79b67527du},
            {"734059.8035226609208621084690093994140624999999999999999999999", 0x412666d79b67527cu},
            {"61431562016722684", 0x436b47f5c40021e0u},
            {"614315620167226841", 0x43a10cf99a80152cu},
            {"61431562016722683.99999999999999999999999999999999999999999999", 0x436b47f5c40021dfu},
            {"2.0060840449445034305853141631814651191234588623046875", 0x40000c75cab08326u},
            {"2.00608404494450343058531416318146511912345886230468751", 0x40000c75cab08326u},
            {"2.006084044944503430585314163181465119123458862304687499999999", 0x40000c75cab08325u},
            {"0.0000001760623599453036952716420489480075861621344301966018974781036376953125", 0x3e87a174e55262cau},
            {"0.00000017606235994530369527164204894800758616213443019660189747810363769531251", 0x3e87a174e55262cbu},
            {"0.0000001760623599453036952716420489480075861621344301966018974781035376953125", 0x3e87a174e55262cau},
            {"0.833085849636964581588216560703585855662822723388671875", 0x3feaa8a3a7de6fb6u},
            {"0.8330858496369645815882165607035858556628227233886718751", 0x3feaa8a3a7de6fb6u},
            {"0.8330858496369645815882165607035858556628227233886718749999999", 0x3feaa8a3a7de6fb5u},
            {"45031428.4182307310402393341064453125", 0x418579002358895au},
            {"45031428.41823073104023933410644531251", 0x418579002358895bu},
            {"45031428.41823073104023933410644531249999999999999999999999999", 0x418579002358895au},
            {"5003361733758455296", 0x43d15be0bf39dd24u},
            {"50033617337584552961", 0x4405b2d8ef08546cu},
            {"5003361733758455295.999999999999999999999999999999999999999999", 0x43d15be0bf39dd23u},
        };

        for (const auto& c : known)
        {
            CAPTURE(c.first)
            double out = 0;
            if (eisel_lemire(c.first, out))
            {
                CHECK(bits_of(out) == c.second);
            }
            else
            {
                // only tokens with more than 19 significant digits are left to
                // strtod: those whose value lies too close to a tie
                CHECK(significant_digits(c.first) > 19);
            }
        }
    }

    SECTION("round trip")
    {
        // every double written by to_chars and read back, also with trailing
        // digits that make the token longer than 19 digits
        std::uint64_t state = 5295;
        std::size_t declined = 0;
        for (int i = 0; i < 200000; ++i)
        {
            state ^= state << 13u;
            state ^= state >> 7u;
            state ^= state << 17u;
            std::uint64_t b = state;
            if ((b & 0x7FF0000000000000u) == 0x7FF0000000000000u)
            {
                continue; // infinity or NaN
            }
            if (i % 4 == 0)
            {
                b &= 0x800FFFFFFFFFFFFFu; // subnormals
            }
            double d = 0;
            std::memcpy(&d, &b, sizeof(d));

            std::array<char, 64> buffer{};
            const char* end = nlohmann::detail::to_chars(buffer.data(), buffer.data() + buffer.size(), d);
            const std::string token(buffer.data(), static_cast<std::size_t>(end - buffer.data()));
            CAPTURE(token)
            double out = 0;
            REQUIRE(eisel_lemire(token, out));
            CHECK(bits_of(out) == b);

            // insert digits before the exponent: the value moves by far less
            // than the distance to the rounding boundary, so it must not change
            std::string longer = token;
            const std::size_t e = longer.find('e');
            const std::size_t dot = longer.find('.');
            const std::string extra = dot == std::string::npos ? ".000000000000000000001" : "000000000000000000001";
            longer.insert(e == std::string::npos ? longer.size() : e, extra);
            CAPTURE(longer)
            if (eisel_lemire(longer, out))
            {
                CHECK(bits_of(out) == b);
            }
            else
            {
                // w and w + 1 round differently: only when the value is very
                // close to a rounding boundary
                ++declined;
            }
        }
        CHECK(declined < 1000); // 107 of the 200,000
    }

    SECTION("used by the lexer")
    {
        // 17 significant digits: beyond Clinger's fast path
        CHECK(bits_of(json::parse("-65.613616999999977").get<double>()) == bits_of(-65.613616999999977));
        CHECK(bits_of(json::parse("2.2250738585072011e-308").get<double>()) == 0x000FFFFFFFFFFFFFu);
        CHECK(bits_of(json::parse("4.9406564584124654e-324").get<double>()) == 1u);
        json _;
        CHECK_THROWS_WITH_AS(_ = json::parse("1.7976931348623159e308"),
                             "[json.exception.out_of_range.406] number overflow parsing '1.7976931348623159e308'", json::out_of_range&);
    }
}
