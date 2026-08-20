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

#include <sstream> // stringstream
#include <string> // string
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

            CAPTURE(n);
            CHECK(a == b);
            CHECK(a.dump() == b.dump());
            CHECK(a[0].type() == b[0].type());
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
            CAPTURE(bad);
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
        const auto outcome = [](const std::string & doc, bool streaming)
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
                return std::string(e.what());
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
        CAPTURE(mismatches);
        CHECK(mismatches.empty());
    }

    SECTION("error positions match the streaming path")
    {
        // Rejecting identically is not enough: the fast path must also report the
        // error at the same position as the byte path. A number directly followed
        // by a newline is the interesting case, because the byte path reaches the
        // newline (which resets the column) and then ungets it.
        // returns the parse_error message, or "" if the document parsed
        const auto contiguous_error = [](const std::string & doc)
        {
            try
            {
                const json j = json::parse(doc);
                static_cast<void>(j);
            }
            catch (const json::parse_error& e)
            {
                return std::string(e.what());
            }
            return std::string();
        };
        const auto streaming_error = [](const std::string & doc)
        {
            try
            {
                std::stringstream ss(doc);
                const json j = json::parse(ss);
                static_cast<void>(j);
            }
            catch (const json::parse_error& e)
            {
                return std::string(e.what());
            }
            return std::string();
        };

        for (const char* bad :
                {"[01\n]", "[00\n]", "[-01\n]", "{1\n}", "[1\n2]", "[1.2.3\n]",
                 "[1 \n2]", "[\n1\n2]", "1\n2", "[01\r\n]", "[1e\n]", "[-\n]"
                })
        {
            CAPTURE(bad);
            const std::string doc = bad;
            const std::string contiguous_what = contiguous_error(doc);

            CHECK_FALSE(contiguous_what.empty());
            CHECK(contiguous_what == streaming_error(doc));
        }

        // the column must be the one the offending token actually starts at,
        // not the 0 that an unget() across the newline used to leave behind
        CHECK(contiguous_error("[01\n]") ==
              "[json.exception.parse_error.101] parse error at line 1, column 3: "
              "syntax error while parsing array - unexpected number literal; expected ']'");
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
    const auto outcome = [](const std::string & doc, bool streaming)
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
            return std::string(e.what());
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
        CAPTURE(mismatches);
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
        CAPTURE(mismatches);
        CHECK(mismatches.empty());
    }
#endif

    // json::accept() never throws, so the ranges stay covered without exceptions
    SECTION("UTF-8 ranges are accepted and rejected as documented")
    {
        // The bulk validator must accept exactly what the byte-at-a-time
        // scanner accepts, so pin the boundaries of every range it recognizes.
        struct utf8_case
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
            CAPTURE(test_case.description);
            for (const std::size_t offset : offsets)
            {
                CAPTURE(offset);
                const std::string doc = "[\"" + std::string(offset, 'a') + test_case.sequence + "\"]";
                CHECK(json::accept(doc) == test_case.valid);
#if !defined(JSON_NOEXCEPTION)
                CHECK(outcome(doc, false) == outcome(doc, true));
#endif
            }
        }
    }
}
