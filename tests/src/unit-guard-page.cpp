//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// The fast paths for contiguous input (bulk string scanning, SWAR searches,
// UTF-8 prefix validation, the 8-digit number loop, the 8-byte indentation
// skip, the BSON/BON8 bulk string readers) load several bytes at a time. This
// test places every input directly in front of (or directly behind) an
// inaccessible page, so reading even one byte outside the input crashes, with
// or without sanitizers. ASan alone misses over-reads into the slack of the
// same heap allocation.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
    #define JSON_TEST_GUARD_PAGE_WINDOWS
    #ifndef NOMINMAX
        #define NOMINMAX
    #endif
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#elif defined(__unix__) || defined(__APPLE__)
    #define JSON_TEST_GUARD_PAGE_POSIX
    #include <sys/mman.h>
    #include <unistd.h>
#endif

#if defined(JSON_TEST_GUARD_PAGE_WINDOWS) || defined(JSON_TEST_GUARD_PAGE_POSIX)

namespace
{
// Three pages: an inaccessible one, a readable one, an inaccessible one. An
// input is copied either to the end of the middle page (any read past its last
// byte faults) or to its start (any read before its first byte faults).
class guarded_buffer
{
  public:
    guarded_buffer()
        : page(page_size())
    {
#if defined(JSON_TEST_GUARD_PAGE_WINDOWS)
        void* const p = VirtualAlloc(nullptr, 3 * page, MEM_RESERVE | MEM_COMMIT, PAGE_NOACCESS);
        REQUIRE(p != nullptr);
        base = static_cast<unsigned char*>(p);
        DWORD old_protect = 0;
        REQUIRE(VirtualProtect(base + page, page, PAGE_READWRITE, &old_protect) != 0);
#else
        void* const p = mmap(nullptr, 3 * page, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
        REQUIRE(p != MAP_FAILED);
        base = static_cast<unsigned char*>(p);
        REQUIRE(mprotect(base + page, page, PROT_READ | PROT_WRITE) == 0);
#endif
    }

    ~guarded_buffer()
    {
#if defined(JSON_TEST_GUARD_PAGE_WINDOWS)
        VirtualFree(base, 0, MEM_RELEASE);
#else
        munmap(base, 3 * page);
#endif
    }

    guarded_buffer(const guarded_buffer&) = delete;
    guarded_buffer& operator=(const guarded_buffer&) = delete;
    guarded_buffer(guarded_buffer&&) = delete;
    guarded_buffer& operator=(guarded_buffer&&) = delete;

    // copies @a input so its last byte is the last readable byte
    const std::uint8_t* at_end(const std::string& input)
    {
        REQUIRE(input.size() <= page);
        unsigned char* const first = base + (2 * page) - input.size();
        std::transform(input.begin(), input.end(), first, [](const char c)
        {
            return static_cast<unsigned char>(c);
        });
        return first;
    }

    // copies @a input so its first byte is the first readable byte
    const std::uint8_t* at_start(const std::string& input)
    {
        REQUIRE(input.size() <= page);
        unsigned char* const first = base + page;
        std::transform(input.begin(), input.end(), first, [](const char c)
        {
            return static_cast<unsigned char>(c);
        });
        return first;
    }

  private:
    static std::size_t page_size()
    {
#if defined(JSON_TEST_GUARD_PAGE_WINDOWS)
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        return static_cast<std::size_t>(info.dwPageSize);
#else
        return static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
#endif
    }

    std::size_t page = 0;
    unsigned char* base = nullptr;
};

// the serialization of the result of @a f, or the exception message; @a f
// takes the allow_exceptions flag, which is false without exceptions, where
// an error yields a discarded value instead
template<typename F>
std::string outcome(F f)
{
#if defined(JSON_NOEXCEPTION)
    return "value: " + f(false).dump(-1, ' ', false, json::error_handler_t::keep);
#else
    try
    {
        return "value: " + f(true).dump(-1, ' ', false, json::error_handler_t::keep);
    }
    catch (const json::exception& e)
    {
        return std::string("error: ") + e.what();
    }
#endif
}

// a SAX handler that only counts events, so sax_parse runs without a DOM
struct counting_sax : nlohmann::json_sax<json>
{
    std::size_t events = 0;
    std::string error{}; // NOLINT(readability-redundant-member-init)

    bool null() override
    {
        return count();
    }
    bool boolean(bool /*val*/) override
    {
        return count();
    }
    bool number_integer(number_integer_t /*val*/) override
    {
        return count();
    }
    bool number_unsigned(number_unsigned_t /*val*/) override
    {
        return count();
    }
    bool number_float(number_float_t /*val*/, const string_t& /*s*/) override
    {
        return count();
    }
    bool string(string_t& /*val*/) override
    {
        return count();
    }
    bool binary(binary_t& /*val*/) override
    {
        return count();
    }
    bool start_object(std::size_t /*elements*/) override
    {
        return count();
    }
    bool key(string_t& /*val*/) override
    {
        return count();
    }
    bool end_object() override
    {
        return count();
    }
    bool start_array(std::size_t /*elements*/) override
    {
        return count();
    }
    bool end_array() override
    {
        return count();
    }
    bool parse_error(std::size_t position, const std::string& /*last_token*/, const nlohmann::detail::exception& ex) override
    {
        error = std::to_string(position) + " " + ex.what();
        return false;
    }

  private:
    bool count()
    {
        ++events;
        return true;
    }
};

// all prefixes of each seed, so the input ends at every byte of it
std::vector<std::string> all_prefixes(const std::vector<std::string>& seeds)
{
    std::vector<std::string> result;
    for (const auto& seed : seeds)
    {
        for (std::size_t n = 0; n <= seed.size(); ++n)
        {
            result.push_back(seed.substr(0, n));
        }
    }
    return result;
}

std::vector<std::string> json_seeds()
{
    std::vector<std::string> seeds =
    {
        // string runs: ASCII, escapes, \u escapes, surrogate pairs
        "\"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ\"",
        R"("ab\ncd\"ef\\gh\u00e4ij\uD83D\uDE00kl\u12")",
        // 2-, 3- and 4-byte UTF-8 sequences, then invalid UTF-8
        std::string("\"\xC3\xA4\xE2\x82\xAC\xF0\x9F\x98\x80\xC3\xA4\xE2\x82\xAC\xF0\x9F\x98\x80") + "abcdefgh\"",
        "\"abcdefgh\xC3\x28 \xED\xA0\x80 \xF4\x90\x80\x80 \xF8 \xC0\xAF\"",
        std::string("\"abcdefg\x01") + "abcdefgh\"",
        // numbers, so the 8-digit loop runs up to the end
        "12345678",
        "1234567890123456",
        "12345678901234567890123",
        "-0.000000001234567890123456789",
        "3.14159265358979323846264338327950288e+100",
        "-1.2345678901234567e-12",
        "1E-5",
        "[1.5,2e10,-3E-5,0.000000001,123456789012345678]",
        // literals
        "[true,false,null]",
        // comments (only parsed with ignore_comments)
        "/* comment */ [1, // line comment\n 2] /**/",
        // a pretty-printed document
        json::parse(R"({"a": [1, 2.5, "three", {"b": null, "c": [true, false]}], "d": {"e": {"f": {"g": "h"}}}})").dump(4),
        json::parse(R"({"a": [1, 2.5, "three", {"b": null, "c": [true, false]}], "d": {"e": {"f": {"g": "h"}}}})").dump(8, '\t'),
    };

    // indentation runs of every length, with and without a closing bracket
    for (std::size_t n = 0; n <= 20; ++n)
    {
        seeds.push_back("[\n" + std::string(n, ' ') + "1,\n" + std::string(n, ' ') + "2\n]");
    }

    return all_prefixes(seeds);
}

// a value whose binary serializations contain long strings and keys, numbers
// of every width, and nested containers
json binary_document()
{
    json j;
    j["a key that is longer than eight bytes"] = "a string value that is longer than eight bytes";
    j["\xC3\xA4\xE2\x82\xAC\xF0\x9F\x98\x80"] = "\xF0\x9F\x98\x80\xE2\x82\xAC\xC3\xA4 utf-8 0123456789";
    j["numbers"] = {0, 1, -1, 255, -256, 65536, -2147483649LL, 4294967296ULL, 1.5, -2.25e100};
    j["nested"] = {{"x", {{"y", {true, false, nullptr}}}}};
    j["s"] = "";
    return j;
}

// readers for check_binary(), callable with a container or an iterator range
// followed by the allow_exceptions flag
#define JSON_TEST_GUARD_PAGE_READER(name, from)                                     \
    struct name                                                                     \
    {                                                                               \
        template<typename... Args>                                                  \
        json operator()(bool allow_exceptions, Args&& ... args) const               \
        {                                                                           \
            return json::from(std::forward<Args>(args)..., true, allow_exceptions); \
        }                                                                           \
    };
JSON_TEST_GUARD_PAGE_READER(read_bson, from_bson)
JSON_TEST_GUARD_PAGE_READER(read_bon8, from_bon8)
JSON_TEST_GUARD_PAGE_READER(read_cbor, from_cbor)
JSON_TEST_GUARD_PAGE_READER(read_msgpack, from_msgpack)
JSON_TEST_GUARD_PAGE_READER(read_ubjson, from_ubjson)
JSON_TEST_GUARD_PAGE_READER(read_bjdata, from_bjdata)
#undef JSON_TEST_GUARD_PAGE_READER

// @a bytes as characters (explicitly converted: the iterator-range constructor
// would convert implicitly, which -fsanitize=integer reports)
std::string as_chars(const std::vector<std::uint8_t>& bytes)
{
    std::string result;
    result.reserve(bytes.size());
    for (const std::uint8_t b : bytes)
    {
        result.push_back(static_cast<char>(b));
    }
    return result;
}

// reads every prefix of @a bytes at both ends of the guarded page and from a
// std::string, which must give the same outcome
template<typename Reader>
void check_binary(guarded_buffer& guard, const std::vector<std::uint8_t>& bytes, Reader parse)
{
    for (const auto& input : all_prefixes({as_chars(bytes)}))
    {
        CAPTURE(input)
        const std::string expected = outcome([&](bool allow)
        {
            return parse(allow, input);
        });
        for (int placement = 0; placement < 2; ++placement)
        {
            const std::uint8_t* const first = placement == 0 ? guard.at_end(input) : guard.at_start(input);
            CHECK(outcome([&](bool allow)
            {
                return parse(allow, first, first + input.size());
            }) == expected);
        }
    }
}

// parse_float_native() at both ends of the guarded page, compared bit for bit
// with converting the same token from a std::string
template<typename FloatType>
std::uint64_t float_bits(FloatType value)
{
    static_assert(sizeof(FloatType) <= sizeof(std::uint64_t), "unsupported floating-point width");
    std::uint64_t bits = 0;
    std::memcpy(&bits, &value, sizeof(value));
    return bits;
}

template<typename FloatType>
void check_float_native(guarded_buffer& guard, const std::string& token)
{
    const auto decimal_point = token.find('.');
    const auto exponent = token.find_first_of("eE");
    const auto mantissa_end = exponent == std::string::npos ? token.size() : exponent;
    const auto expected = nlohmann::detail::parse_float_native<FloatType>(token.data(), token.data() + token.size(), decimal_point, mantissa_end);
    for (int placement = 0; placement < 2; ++placement)
    {
        const char* const first = reinterpret_cast<const char*>(placement == 0 ? guard.at_end(token) : guard.at_start(token));
        const auto value = nlohmann::detail::parse_float_native<FloatType>(first, first + token.size(), decimal_point, mantissa_end);
        CHECK(float_bits(value) == float_bits(expected));
    }
}
} // namespace

TEST_CASE("guard page")
{
    guarded_buffer guard;

    SECTION("string scanning")
    {
        // fills that drive each function to a different stop
        const std::vector<std::string> fills =
        {
            std::string(64, 'a'),
            std::string(64, '"'),
            std::string(64, '\\'),
            std::string(64, '\x01'),
            std::string(64, '\x7F'),
            std::string(64, '\xFF'),
        };
        std::vector<std::string> patterns = fills;
        {
            std::string utf8;
            while (utf8.size() < 64)
            {
                utf8 += "\xC3\xA4\xE2\x82\xAC\xF0\x9F\x98\x80" "ab";
            }
            patterns.push_back(utf8);
        }
        {
            std::string bytes;
            for (unsigned int i = 0; i < 64; ++i)
            {
                bytes.push_back(static_cast<char>((i * 37u) & 0xFFu));
            }
            patterns.push_back(bytes);
        }

        for (const auto& pattern : patterns)
        {
            for (std::size_t n = 0; n <= 64; ++n)
            {
                const std::string input = pattern.substr(0, n);
                for (int placement = 0; placement < 2; ++placement)
                {
                    const unsigned char* const p = placement == 0 ? guard.at_end(input) : guard.at_start(input);

                    CHECK(nlohmann::detail::find_string_special(p, n) <= n);
                    CHECK(nlohmann::detail::find_ascii_copyable_run(p, n) <= n);
                    CHECK(nlohmann::detail::valid_utf8_prefix(p, n) <= n);
                    CHECK(nlohmann::detail::valid_utf8_string(p, n) == (nlohmann::detail::valid_utf8_prefix(p, n) == n));
#if defined(JSON_USE_SIMDUTF) && defined(JSON_HAS_CPP_17)
                    CHECK(nlohmann::detail::find_string_delimiter(p, n) <= n);
#endif
                    CHECK(nlohmann::detail::string_bulk_run(p, n) <= n);
                    CHECK(nlohmann::detail::scalar_string_bulk_run(p, n) <= n);
                    for (std::size_t i = 0; i < n; ++i)
                    {
                        CHECK(nlohmann::detail::validate_one_utf8(p + i, n - i) <= n - i);
                    }
                }
            }
        }
    }

    SECTION("float conversion")
    {
        // the lexer converts floats from its token buffer, so the JSON section
        // below never places a float token at the page boundary; this calls the
        // conversion directly: the 8-digit loops of parse_float_significand()
        // and digit_comparison() read up to the end of the token
        const std::vector<std::string> tokens = all_prefixes(
        {
            "1234567812345678123456781234567812345678",
            "-1.2345678901234567890123456789e-123",
            "0.00000000000000000000000000000000000001",
            "98765432.10987654",
            "123456789012345678901234567890e-30",
            // halfway between 1 and the next double, then just above it
            "1.00000000000000011102230246251565404236316680908203125",
            "1.000000000000000111022302462515654042363166809082031250000000001",
        });
        for (const auto& token : tokens)
        {
            // only complete number tokens: the conversion expects validated input
            if (!token.empty() && json::accept(token))
            {
                CAPTURE(token)
                check_float_native<double>(guard, token);
                check_float_native<float>(guard, token);
            }
        }
    }

    SECTION("JSON")
    {
        for (const auto& input : json_seeds())
        {
            CAPTURE(input)
            const std::string expected = outcome([&](bool allow)
            {
                return json::parse(input, nullptr, allow);
            });
            const std::string expected_comments = outcome([&](bool allow)
            {
                return json::parse(input, nullptr, allow, true);
            });
            const bool expected_accept = json::accept(input);
            counting_sax expected_sax;
            const bool expected_sax_result = json::sax_parse(input, &expected_sax);

            for (int placement = 0; placement < 2; ++placement)
            {
                const std::uint8_t* const first = placement == 0 ? guard.at_end(input) : guard.at_start(input);
                const std::uint8_t* const last = first + input.size();

                CHECK(outcome([&](bool allow)
                {
                    return json::parse(first, last, nullptr, allow);
                }) == expected);
                CHECK(outcome([&](bool allow)
                {
                    return json::parse(first, last, nullptr, allow, true);
                }) == expected_comments);
                CHECK(json::accept(first, last) == expected_accept);

                counting_sax sax;
                CHECK(json::sax_parse(first, last, &sax) == expected_sax_result);
                CHECK(sax.events == expected_sax.events);
                CHECK(sax.error == expected_sax.error);
            }
        }
    }

    SECTION("binary formats")
    {
        // every prefix ends inside a value, e.g., inside a BSON key or BON8
        // string without its terminator
        const json j = binary_document();
        check_binary(guard, json::to_bson(j), read_bson());
        check_binary(guard, json::to_bon8(j), read_bon8());
        check_binary(guard, json::to_cbor(j), read_cbor());
        check_binary(guard, json::to_msgpack(j), read_msgpack());
        check_binary(guard, json::to_ubjson(j), read_ubjson());
        check_binary(guard, json::to_bjdata(j), read_bjdata());
    }
}

#endif
