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

#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <vector>

// Parsing from a FILE* locks the file once and reads it with the unlocked
// stdio functions (see JSON_DISABLE_UNLOCKED_FILE_IO). These tests pin that
// this is not observable: the results are the same, the file is unlocked
// again when parsing ends - also with an exception - and the same thread can
// keep using the file while it is locked, e.g., from a SAX callback.

namespace
{
// a file name of its own for every run: the test runs for several C++
// standards and configurations at the same time, in the same directory
std::string temp_file_name()
{
    std::random_device rd;
    return "unit-file_input-" + std::to_string(rd()) + ".tmp";
}

using file_ptr = std::unique_ptr<std::FILE, int (*)(std::FILE*)>;

// write @a content to the file @a name and open it for reading
file_ptr open_with(const char* name, const std::string& content)
{
    {
        std::ofstream file(name, std::ios::binary);
        file << content;
    }
    return {std::fopen(name, "rb"), &std::fclose};
}

// The stdio lock is recursive, so whether parsing released it can only be
// seen from another thread: ftrylockfile() fails there while this thread
// holds the lock. ftrylockfile() is POSIX; elsewhere, the check is skipped.
#if defined(__GLIBC__) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
void check_unlocked(std::FILE* f)
{
    int result = -1;
    std::thread other([f, &result]
    {
        result = ftrylockfile(f);
        if (result == 0)
        {
            funlockfile(f);
        }
    });
    other.join();
    CHECK(result == 0);
}
#else
void check_unlocked(std::FILE* /*f*/) {}
#endif

// SAX consumer that also reads the position of the file it is parsing, which
// takes the file's lock again on the same thread
class position_reading_sax : public nlohmann::json_sax<json>
{
  public:
    explicit position_reading_sax(std::FILE* f) : m_file(f) {}
    position_reading_sax(const position_reading_sax&) = delete;
    position_reading_sax(position_reading_sax&&) = delete;
    position_reading_sax& operator=(const position_reading_sax&) = delete;
    position_reading_sax& operator=(position_reading_sax&&) = delete;
    ~position_reading_sax() override = default;

    bool null() override
    {
        return record();
    }
    bool boolean(bool /*val*/) override
    {
        return record();
    }
    bool number_integer(number_integer_t /*val*/) override
    {
        return record();
    }
    bool number_unsigned(number_unsigned_t /*val*/) override
    {
        return record();
    }
    bool number_float(number_float_t /*val*/, const string_t& /*s*/) override
    {
        return record();
    }
    bool string(string_t& /*val*/) override
    {
        return record();
    }
    bool binary(binary_t& /*val*/) override
    {
        return record();
    }
    bool start_object(std::size_t /*elements*/) override
    {
        return record();
    }
    bool key(string_t& /*val*/) override
    {
        return record();
    }
    bool end_object() override
    {
        return record();
    }
    bool start_array(std::size_t /*elements*/) override
    {
        return record();
    }
    bool end_array() override
    {
        return record();
    }
    bool parse_error(std::size_t /*position*/, const std::string& /*last_token*/, const nlohmann::detail::exception& /*ex*/) override
    {
        return false;
    }

    const std::vector<long>& positions() const
    {
        return m_positions;
    }

  private:
    bool record()
    {
        m_positions.push_back(std::ftell(m_file));
        return true;
    }

    std::FILE* m_file;
    std::vector<long> m_positions{}; // NOLINT(readability-redundant-member-init)
};
}  // namespace

TEST_CASE("parsing from a FILE*")
{
    const std::string temp_name = temp_file_name();
    const char* const name = temp_name.c_str();
    const std::string input = "{\"a\": [1, -2.5, \"three\", true, null], \"b\": {\"c\": \"caf\xc3\xa9\"}}";

    SECTION("values are the same as when parsing from a string")
    {
        const file_ptr f = open_with(name, input);
        REQUIRE(f != nullptr);
        CHECK(json::parse(f.get()) == json::parse(input));
        // the whole input was consumed
        std::array<char, 8> rest{};
        CHECK(std::fgets(rest.data(), static_cast<int>(rest.size()), f.get()) == nullptr);
        check_unlocked(f.get());
    }

#if !defined(JSON_NOEXCEPTION)
    SECTION("the file is unlocked after a parse error")
    {
        const file_ptr f = open_with(name, "[1, 2, x]");
        REQUIRE(f != nullptr);
        json _;
        CHECK_THROWS_WITH_AS(_ = json::parse(f.get()),
                             "[json.exception.parse_error.101] parse error at line 1, column 8: syntax error while parsing value - invalid literal; last read: '2, x'",
                             json::parse_error&);
        check_unlocked(f.get());

        // the file is still usable: the rest of the input is there
        std::array<char, 8> rest{};
        CHECK(std::fgets(rest.data(), static_cast<int>(rest.size()), f.get()) != nullptr);
        CHECK(std::string(rest.data()) == "]");
    }

#endif // !defined(JSON_NOEXCEPTION)

    SECTION("the file can be parsed again and read with stdio afterwards")
    {
        const file_ptr f = open_with(name, "[1] [2] tail");
        REQUIRE(f != nullptr);

        // sax_parse with strict == false stops after the first value; an array
        // ends with its closing bracket, so the space after it is not read
        json j;
        nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type> sax1(j);
        CHECK(json::sax_parse(f.get(), &sax1, json::input_format_t::json, false));
        CHECK(j == json({1}));
        check_unlocked(f.get());

        json k;
        nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type> sax2(k);
        CHECK(json::sax_parse(f.get(), &sax2, json::input_format_t::json, false));
        CHECK(k == json({2}));
        check_unlocked(f.get());

        std::array<char, 8> rest{};
        CHECK(std::fgets(rest.data(), static_cast<int>(rest.size()), f.get()) != nullptr);
        CHECK(std::string(rest.data()) == " tail");
    }

    SECTION("the same thread can use the file while it is parsed")
    {
        const file_ptr f = open_with(name, "[10, 20, 30]");
        REQUIRE(f != nullptr);
        position_reading_sax sax(f.get());
        CHECK(json::sax_parse(f.get(), &sax));
        // start_array, three numbers, end_array
        CHECK(sax.positions().size() == 5);
        CHECK(sax.positions().front() == 1);
        check_unlocked(f.get());
    }

    SECTION("binary formats read from a FILE*")
    {
        const json j = {{"string", std::string(300, 'x')}, {"array", {1, 2, 3}}, {"number", 1.5}};
        const std::vector<std::uint8_t> cbor = json::to_cbor(j);
        const file_ptr f = open_with(name, std::string(reinterpret_cast<const char*>(cbor.data()), cbor.size()));
        REQUIRE(f != nullptr);
        CHECK(json::from_cbor(f.get()) == j);
        check_unlocked(f.get());
    }

    static_cast<void>(std::remove(name));
}
