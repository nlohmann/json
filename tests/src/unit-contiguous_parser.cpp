//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// parse() and accept() read text in one block of memory with
// detail::contiguous_parser, and everything else (here: std::list iterators)
// with the lexer's byte path. These tests check that the two agree on every
// input: the same value, with the same number types and float bits, or the
// same exception with the same message.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;
using nlohmann::ordered_json;

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <list>
#include <map>
#include <random>
#include <string>
#include <type_traits>
#include <vector>

namespace
{

/// the value with its number types and float bits; below 100 levels, the
/// library's dump() (whose recursion is bounded) describes the rest
template<typename Json>
std::string describe_value(const Json& j, int depth = 0)
{
    std::string out;
    if (depth >= 100)
    {
        out = j.dump();
        return out;
    }
    switch (j.type())
    {
        case Json::value_t::number_float:
        {
            const double d = j.template get<double>();
            std::uint64_t bits = 0;
            std::memcpy(&bits, &d, sizeof(bits));
            out += "f" + std::to_string(bits);
            break;
        }
        case Json::value_t::number_integer:
            out += "i" + j.dump();
            break;
        case Json::value_t::number_unsigned:
            out += "u" + j.dump();
            break;
        case Json::value_t::array:
            out += "[";
            for (const auto& e : j)
            {
                out += describe_value(e, depth + 1) + ",";
            }
            out += "]";
            break;
        case Json::value_t::object:
            out += "{";
            for (auto it = j.begin(); it != j.end(); ++it)
            {
                out += Json(it.key()).dump() + ":" + describe_value(it.value(), depth + 1) + ",";
            }
            out += "}";
            break;
        case Json::value_t::null:
        case Json::value_t::boolean:
        case Json::value_t::string:
        case Json::value_t::binary:
        case Json::value_t::discarded:
        default:
            out += j.dump();
            break;
    }
    return out;
}

#if !defined(JSON_NOEXCEPTION)
template<typename Json, typename Parse>
std::string outcome(Parse parse)
{
    try
    {
        return describe_value(parse());
    }
    catch (const typename Json::exception& e)
    {
        return std::string("exception: ") + e.what();
    }
}
#endif

/// every SAX event with its values, the text of float tokens, and the parse
/// error with its position, token and message; returns false after
/// @a stop_after events (to stop the parse)
class event_log : public nlohmann::json_sax<json>
{
  public:
    explicit event_log(std::size_t stop_after_ = static_cast<std::size_t>(-1), bool continue_after_error_ = false)
        : stop_after(stop_after_), continue_after_error(continue_after_error_)
    {}

    bool null() override
    {
        return add("null");
    }
    bool boolean(bool val) override
    {
        return add(val ? "true" : "false");
    }
    bool number_integer(number_integer_t val) override
    {
        return add("i" + std::to_string(val));
    }
    bool number_unsigned(number_unsigned_t val) override
    {
        return add("u" + std::to_string(val));
    }
    bool number_float(number_float_t val, const string_t& s) override
    {
        std::uint64_t bits = 0;
        std::memcpy(&bits, &val, sizeof(bits));
        return add("f" + std::to_string(bits) + " " + s);
    }
    bool string(string_t& val) override
    {
        return add("s" + val);
    }
    bool binary(binary_t& /*val*/) override
    {
        return add("binary");
    }
    bool start_object(std::size_t elements) override
    {
        return add("{" + std::to_string(elements));
    }
    bool key(string_t& val) override
    {
        return add("k" + val);
    }
    bool end_object() override
    {
        return add("}");
    }
    bool start_array(std::size_t elements) override
    {
        return add("[" + std::to_string(elements));
    }
    bool end_array() override
    {
        return add("]");
    }
    bool parse_error(std::size_t position, const std::string& last_token, const nlohmann::detail::exception& ex) override
    {
        events.push_back("error " + std::to_string(position) + " " + last_token + " " + ex.what());
        return continue_after_error;
    }

    const std::vector<std::string>& log() const noexcept
    {
        return events;
    }

  private:
    bool add(const std::string& event)
    {
        events.push_back(event);
        return events.size() != stop_after;
    }

    std::vector<std::string> events {}; // NOLINT(readability-redundant-member-init)
    std::size_t stop_after;
    bool continue_after_error;
};

/// sax_parse() of the contiguous path against the byte path, also with a
/// handler that stops the parse
void check_same_events(const std::string& text, const std::list<char>& bytes)
{
    for (const std::size_t stop_after :
            {
                static_cast<std::size_t>(-1), std::size_t{1}, std::size_t{3}
            })
    {
        CAPTURE(stop_after)
        event_log contiguous(stop_after);
        event_log byte_path(stop_after);
        const bool r1 = json::sax_parse(text, &contiguous);
        const bool r2 = json::sax_parse(bytes.begin(), bytes.end(), &byte_path);
        CHECK(r1 == r2);
        CHECK(contiguous.log() == byte_path.log());
    }
    // a handler that asks to go on after an error (the default parser then
    // reports what follows, e.g., the missing end of the input)
    event_log contiguous(static_cast<std::size_t>(-1), true);
    event_log byte_path(static_cast<std::size_t>(-1), true);
    const bool r1 = json::sax_parse(text, &contiguous);
    const bool r2 = json::sax_parse(bytes.begin(), bytes.end(), &byte_path);
    CHECK(r1 == r2);
    CHECK(contiguous.log() == byte_path.log());
}

/// the contiguous path (a std::string) against the byte path (std::list iterators)
template<typename Json>
void check_same(const std::string& text)
{
    CAPTURE(text)
    const std::list<char> bytes(text.begin(), text.end());

#if !defined(JSON_NOEXCEPTION)
    // with exceptions: the value, or the same exception for both
    const std::string contiguous = outcome<Json>([&]
    {
        return Json::parse(text);
    });
    const std::string byte_path = outcome<Json>([&]
    {
        return Json::parse(bytes.begin(), bytes.end());
    });
    CHECK(contiguous == byte_path);
#endif

    // without exceptions: the value, or discarded for both
    const Json c = Json::parse(text, nullptr, false);
    const Json b = Json::parse(bytes.begin(), bytes.end(), nullptr, false);
    CHECK(c.is_discarded() == b.is_discarded());

    CHECK(Json::accept(text) == Json::accept(bytes.begin(), bytes.end()));
    if (std::is_same<Json, json>::value)
    {
        check_same_events(text, bytes);
    }
    // a pointer range without a terminating NUL
    std::vector<char> exact(text.begin(), text.end());
    if (!exact.empty())
    {
        CHECK(Json::accept(exact.data(), exact.data() + exact.size()) == Json::accept(bytes.begin(), bytes.end()));
    }
}

void check_both(const std::string& text)
{
    check_same<json>(text);
    check_same<ordered_json>(text);
}

/// a random JSON text, mostly valid, with the corner cases of the parser
class generator
{
  public:
    explicit generator(std::uint32_t seed) : rng(seed) {}

    std::string document(int depth)
    {
        std::string out;
        value(out, depth);
        return out;
    }

  private:
    std::uint32_t pick(std::uint32_t n)
    {
        return static_cast<std::uint32_t>(rng() % n);
    }

    void whitespace(std::string& out)
    {
        static const char* const choices[] = {"", "", "", " ", "\n", "\n        ", "\t", "\r\n  ", "\n                  ", "  "}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        out += choices[pick(10)];
    }

    void number(std::string& out)
    {
        static const char* const choices[] = // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        {
            "0", "-0", "1", "-1", "42", "123456789012345678", "-123456789012345678", "1234567890123456789",
            "-1234567890123456789", "9223372036854775807", "-9223372036854775808", "-9223372036854775809",
            "18446744073709551615", "18446744073709551616", "123456789012345678901234567890", "0.0", "-0.0",
            "1.5", "-65.613616999999977", "1e10", "1E+10", "1e-10", "2.2250738585072014e-308", "4.9e-324",
            "1e-400", "1.7976931348623157e308", "1e308", "1e309", "-1e309", "123.456e-789", "0.1e1",
            "12345678901234567890.5", "1.00000000000000011102230246251565404236316680908203125",
            "9007199254740993", "0.30000000000000004", "1e22", "1e23", "100000000000000000000000",
            "00", "01", "-", "1.", ".5", "1e", "1e+", "--1", "+1", "1.5e3.2", "0x10", "1_000"
        };
        out += choices[pick(sizeof(choices) / sizeof(choices[0]))];
    }

    void string(std::string& out)
    {
        static const char* const pieces[] = // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        {
            "a", "key", "a longer piece of plain ASCII text for the vector paths", "\\n", "\\t", "\\\"",
            "\\\\", "\\/", "\\b", "\\f", "\\r", "\\u0000", "\\u00e4", "\\u20AC", "\\uD83D\\uDE00",
            "\\uD83D", "\\uDE00", "\\uD83Dx", "\\u12", "\\x", "\xC3\xA4", "\xE2\x82\xAC", "\xF0\x9F\x98\x80",
            "\xC0\xAF", "\xED\xA0\x80", "\xF4\x90\x80\x80", "\x80", "\xFF", "\x01", "\x1F", "\x7F", "\t"
        };
        out += '"';
        const auto n = pick(6);
        for (std::uint32_t i = 0; i < n; ++i)
        {
            // mostly well-formed pieces
            out += pieces[pick(5) == 0 ? pick(sizeof(pieces) / sizeof(pieces[0])) : pick(20)];
        }
        out += '"';
    }

    void value(std::string& out, int depth)
    {
        const auto kind = depth > 0 ? pick(9) : 3 + pick(6);
        switch (kind)
        {
            case 0:
            case 1:
            {
                out += '[';
                whitespace(out);
                const auto n = pick(6);
                for (std::uint32_t i = 0; i < n; ++i)
                {
                    if (i != 0)
                    {
                        out += ',';
                        whitespace(out);
                    }
                    value(out, depth - 1);
                    whitespace(out);
                }
                out += ']';
                break;
            }
            case 2:
            {
                out += '{';
                whitespace(out);
                const auto n = pick(6);
                for (std::uint32_t i = 0; i < n; ++i)
                {
                    if (i != 0)
                    {
                        out += ',';
                        whitespace(out);
                    }
                    // a few duplicate keys
                    if (pick(4) == 0)
                    {
                        out += "\"dup\"";
                    }
                    else
                    {
                        string(out);
                    }
                    whitespace(out);
                    out += pick(2) == 0 ? ":" : ": ";
                    whitespace(out);
                    value(out, depth - 1);
                    whitespace(out);
                }
                out += '}';
                break;
            }
            case 3:
            case 4:
                number(out);
                break;
            case 5:
            case 6:
                string(out);
                break;
            case 7:
                out += pick(2) == 0 ? "true" : "false";
                break;
            default:
                out += "null";
                break;
        }
    }

    std::mt19937 rng;
};

} // namespace

TEST_CASE("contiguous parser")
{
    SECTION("fixed inputs")
    {
        const char* const inputs[] = // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        {
            "", " ", "\n", "null", "true", "false", "nul", "tru", "fals", "nullx", "[]", "{}", "[", "{", "]", "}",
            "[1,]", "[,1]", R"({"a":1,})", R"({"a" 1})", R"({"a":})", "{1:2}", "[1 2]", R"("")", R"("abc)", R"("\")",
            "\xEF\xBB\xBF[1]", "\xEF\xBB[1]", "\xEF[1]", "\xEF\xBB\xBF", " [1] ", "[1]x", "[1] [2]", "1 2",
            R"({"a":1,"a":2})", R"({"b":1,"a":2,"b":3})", R"(["\u0000"])", "[1e400]", "[-1e400]",
            R"({"a": [1, 2, {"b": null}], "c": "d"})", "[true,false,null]", "[[[[[]]]]]",
        };
        for (const char* input : inputs)
        {
            check_both(input);
        }

        // NUL bytes: by default the end of the input (between values), else an error
        check_both(std::string("[1]\0garbage", 11));
        check_both(std::string("[1,\0]", 5));
        check_both(std::string("\"a\0b\"", 5));
        check_both(std::string("\0", 1));
        check_both(std::string("1\0", 2));
    }

    SECTION("deep nesting")
    {
        // across the 64-level words of the nesting stack
        const std::vector<std::size_t> depths = {63, 64, 65, 127, 128, 129, 200, 1000, 10000};
        for (const std::size_t depth : depths)
        {
            check_both(std::string(depth, '[') + std::string(depth, ']'));
            std::string objects;
            for (std::size_t i = 0; i < depth; ++i)
            {
                objects += (i % 2 == 0) ? "{\"k\":" : "[";
            }
            objects += "1";
            for (std::size_t i = depth; i-- > 0;)
            {
                objects += (i % 2 == 0) ? "}" : "]";
            }
            check_both(objects);
            // unbalanced
            check_both(std::string(depth, '[') + std::string(depth - 1, ']'));
            check_both(std::string(depth, '[') + std::string(depth + 1, ']'));
        }
        // a value after a container that closes a 64-level word
        std::string mixed = std::string(64, '[') + "1" + std::string(63, ']') + ",{\"a\":2}]";
        check_both(mixed);
        mixed = "{\"x\":" + std::string(64, '[') + std::string(64, ']') + ",\"y\":[1]}";
        check_both(mixed);
    }

    SECTION("generated documents and their mutations")
    {
        generator gen(20261105u);
        std::mt19937 rng(42u); // NOLINT(cert-msc32-c,cert-msc51-cpp,bugprone-random-generator-seed): reproducible
        const char alphabet[] = "{}[]:,\"\\ \t\n\r0123456789-+.eEtrufalsn/u\x80\xbf\xc3\xe2\xed\xf0\xff"; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        for (int round = 0; round < 1500; ++round)
        {
            const std::string text = gen.document(1 + (round % 5));
            check_both(text);
            // every truncation of short documents, and a few mutations
            if (text.size() < 60)
            {
                for (std::size_t n = 0; n < text.size(); ++n)
                {
                    check_same<json>(text.substr(0, n));
                }
            }
            for (int m = 0; m < 3 && !text.empty(); ++m)
            {
                std::string mutated = text;
                const std::size_t pos = rng() % mutated.size();
                switch (rng() % 3)
                {
                    case 0:
                        mutated[pos] = alphabet[rng() % (sizeof(alphabet) - 1)];
                        break;
                    case 1:
                        mutated.insert(pos, 1, alphabet[rng() % (sizeof(alphabet) - 1)]);
                        break;
                    default:
                        mutated.erase(pos, 1);
                        break;
                }
                check_same<json>(mutated);
            }
        }
    }

    SECTION("narrow number types")
    {
        // integers that do not fit become floats, floats are converted to float
        using narrow_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int32_t, std::uint32_t, float>;
        const std::vector<std::string> inputs =
        {
            "[2147483647, 2147483648, -2147483648, -2147483649, 4294967295, 4294967296, 18446744073709551615]",
            "[1.5, 3.4028234663852886e38, 3.4028235677973366e38, 1e39, -1e39, 1e-46, 0.1, 16777217]",
            "[-0, 0.0, 123456789012345678901234567890, -9223372036854775809]", "1e39", "4294967296", "-2147483649"
        };
        for (const auto& input : inputs)
        {
            check_same<narrow_json>(input);
        }
        generator gen(17u);
        for (int round = 0; round < 200; ++round)
        {
            check_same<narrow_json>(gen.document(1 + (round % 4)));
        }
    }

    SECTION("number corner cases at the end of the input")
    {
        // the number ends at the end of the block (no closing bracket after it)
        for (const char* number :
                {"0", "-0", "1", "12345678", "123456789", "1234567890123456789", "18446744073709551616",
                 "1.5", "1e5", "1e", "1.", "-", "1.5e-3", "123456789012345678901234567890e-10"
                })
        {
            check_both(number);
            check_both(std::string("[") + number + "]");
            check_both(std::string("{\"n\":") + number + "}");
        }
    }

    SECTION("accept() of floats near the largest value")
    {
        // accept() skips digits without their value and computes it only for
        // a float whose exponent may reach the largest value
        for (const char* number :
                {"17976931348623158e292", "17976931348623159e292", "1797693134862315.8e293", "1797693134862315.9e293",
                 "0.17976931348623158e309", "0.17976931348623159e309", "-17976931348623159e292", "9999999999999999999e289"
                })
        {
            check_both(number);
            check_both(std::string("[") + number + "]");
        }
        CHECK(json::accept("17976931348623158e292"));
        CHECK_FALSE(json::accept("17976931348623159e292"));
        CHECK(json::accept("[1797693134862315.8e293]"));
        CHECK_FALSE(json::accept("[1797693134862315.9e293]"));
        CHECK(json::accept("0.17976931348623158e309"));
        CHECK_FALSE(json::accept("0.17976931348623159e309"));
        CHECK_FALSE(json::accept("-17976931348623159e292"));

        using narrow_json = nlohmann::basic_json<std::map, std::vector, std::string, bool, std::int32_t, std::uint32_t, float>;
        check_same<narrow_json>("34028235e31");
        check_same<narrow_json>("34028236e31");
        CHECK(narrow_json::accept("34028235e31"));
        CHECK_FALSE(narrow_json::accept("34028236e31"));
    }

    SECTION("callbacks, comments and trailing commas take the default parser")
    {
        // (the results are those of the options; the contiguous parser does not support them)
        CHECK(json::parse("[1,]", nullptr, true, false, true) == json({1}));
        CHECK(json::parse("[1/*c*/]", nullptr, true, true) == json({1}));
        CHECK(json::accept("[1,]", false, true));
        CHECK(json::accept("// c\n[1]", true));
        int calls = 0;
        const json j = json::parse("[1,2]", [&calls](int /*depth*/, json::parse_event_t /*event*/, json& /*parsed*/) noexcept
        {
            ++calls;
            return true;
        });
        CHECK(j == json({1, 2}));
        CHECK(calls == 4);
    }
}
