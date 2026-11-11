//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// The budget for the elements of the UBJSON containers of a valueless type
// ('Z', 'T', 'F') of a whole input: 1048576 plus
// JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE for every byte read (see
// docs/mkdocs/docs/api/macros/json_ubjson_valueless_elements_per_byte.md).
//
// The file is built several times, with the macro defined to other values (see
// tests/CMakeLists.txt), and every boundary below is computed from the macro.
// What it can test depends on the value: with a rate of at most 10000 the
// budget can be reached with the few bytes of a test, so the tests exceed it
// at the exact byte; with a rate of 131072 or more the budget cannot be reached
// by an input of any size (see the macro's page: 2^20 / 8 = 131072 elements per
// byte is what the shortest header of a container of the largest size allows), and
// the tests check that nothing is refused, in particular that the limit does
// not wrap around for a rate near the largest integer. The input is read with
// a SAX handler that counts the values, because a DOM of a million values is
// what makes such a test slow under Valgrind.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <cstddef> // size_t
#include <cstdio> // FILE, tmpfile, fwrite, fseek, fclose
#include <cstdint> // uint8_t, uint32_t
#include <list>
#include <sstream>
#include <vector>

#include "ubjson_valueless.hpp"
using utils::ValuelessEventCounter;
using utils::valueless_arrays;

#ifndef JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE
    #error "this test needs the macro: compile it with JSON_TEST_KEEP_MACROS (see tests/CMakeLists.txt)"
#endif

namespace
{
/// the base of the budget and the limit of a single container: both 2^20
constexpr std::uint32_t budget_base = 1048576;

#if JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE <= 10000 || JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE >= 131072
/// what version 3.12.0 wrote for a table of @a rows (at most 32767) rows of
/// @a width nulls with to_ubjson(table, true, true): `[$[#I` and the count of
/// the rows (7 bytes), then a row as `$Z#` and its count (`U` and 1 byte up to
/// 255, `I` and 2 bytes up to 32767, `l` and 4 bytes above): 5, 6 or 8 bytes
std::vector<std::uint8_t> rows_3_12_0(const std::uint32_t rows, const std::uint32_t width)
{
    std::vector<std::uint8_t> v = {'[', '$', '[', '#', 'I', static_cast<std::uint8_t>(rows >> 8), static_cast<std::uint8_t>(rows)};
    for (std::uint32_t row = 0; row < rows; ++row)
    {
        v.push_back('$');
        v.push_back('Z');
        v.push_back('#');
        if (width <= 255)
        {
            v.push_back('U');
        }
        else if (width <= 32767)
        {
            v.push_back('I');
            v.push_back(static_cast<std::uint8_t>(width >> 8));
        }
        else
        {
            v.push_back('l');
            v.push_back(static_cast<std::uint8_t>(width >> 24));
            v.push_back(static_cast<std::uint8_t>(width >> 16));
            v.push_back(static_cast<std::uint8_t>(width >> 8));
        }
        v.push_back(static_cast<std::uint8_t>(width));
    }
    return v;
}
#endif
} // namespace

// the macro must not be a character or bool: every character type is refused
static_assert(nlohmann::detail::valueless_elements_rate_is_char_or_bool<bool>::value, "bool is refused");
static_assert(nlohmann::detail::valueless_elements_rate_is_char_or_bool<char>::value, "char is refused");
static_assert(nlohmann::detail::valueless_elements_rate_is_char_or_bool<signed char>::value, "signed char is refused");
static_assert(nlohmann::detail::valueless_elements_rate_is_char_or_bool<unsigned char>::value, "unsigned char is refused");
static_assert(nlohmann::detail::valueless_elements_rate_is_char_or_bool<wchar_t>::value, "wchar_t is refused");
static_assert(nlohmann::detail::valueless_elements_rate_is_char_or_bool<char16_t>::value, "char16_t is refused");
static_assert(nlohmann::detail::valueless_elements_rate_is_char_or_bool<char32_t>::value, "char32_t is refused");
#if defined(__cpp_char8_t)
    static_assert(nlohmann::detail::valueless_elements_rate_is_char_or_bool<char8_t>::value, "char8_t is refused");
#endif
static_assert(!nlohmann::detail::valueless_elements_rate_is_char_or_bool<int>::value, "int is accepted");
static_assert(!nlohmann::detail::valueless_elements_rate_is_char_or_bool<unsigned long long>::value, "unsigned long long is accepted");

TEST_CASE("UBJSON the limit of a single container does not depend on the macro")
{
#if !defined(JSON_NOEXCEPTION)
    json _;

    SECTION("a container of more than 1048576 elements is refused")
    {
        // the first check of every container; its message differs from that of
        // the budget, so that it is clear which limit was exceeded
        for (const char marker :
                {'Z', 'T', 'F'
                })
        {
            const auto input = valueless_arrays(marker, {budget_base + 1});
            CHECK_THROWS_WITH_AS(_ = json::from_ubjson(input), "[json.exception.out_of_range.408] syntax error while parsing UBJSON size: excessive array size", json::out_of_range&);
        }
    }
#endif

    SECTION("a container of 1048576 elements is accepted at the start of an input")
    {
        // whatever the rate: the base is the per-container limit. The handler
        // ends the parse at the first value, so that the million values are
        // not read
        const std::vector<std::uint8_t> single = {'[', '$', 'Z', '#', 'l', 0x00, 0x10, 0x00, 0x00};
        ValuelessEventCounter sax;
        sax.stop_after = 1;
        CHECK(!json::sax_parse(single, &sax, json::input_format_t::ubjson));
        CHECK(sax.error_id == 0);
        CHECK(sax.values == 1);
    }
}

#if JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE <= 10000

namespace
{
/// the rate of the build; at most 10000 here, which the boundaries rely on
constexpr std::uint32_t rate = JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE;

/// elements of the first of two containers; the second one is then refused at
/// its header, which is read at byte 1 + 9 + 9 = 19
constexpr std::uint32_t first_count = 524288;

/// the largest count the second container may have at byte 19: base plus rate
/// for each of the 19 bytes, less what the first one used. For a rate of at
/// most 27594, the largest that keeps this within the limit of one container
constexpr std::uint32_t second_allowed = budget_base - first_count + (19 * rate);
} // namespace

TEST_CASE("UBJSON the valueless elements of a whole input are bounded")
{
    // The per-container limit alone let nine bytes (`[$Z#l` and a count of
    // 1048576) announce a million values, and every further nine bytes another
    // million. The elements of all containers of type 'Z', 'T' or 'F' in one
    // input are added up: they may not exceed 1048576 plus
    // JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE for every byte read when the
    // container's header has been read.
#if !defined(JSON_NOEXCEPTION)
    json _;
    const char* const budget_message = "[json.exception.out_of_range.408] syntax error while parsing UBJSON size: excessive number of elements without payload";
#endif

    SECTION("the input of the original report is rejected")
    {
        // the second array is the first one that is refused, by one element
#if !defined(JSON_NOEXCEPTION)
        CHECK_THROWS_WITH_AS(_ = json::from_ubjson(valueless_arrays('Z', {first_count, second_allowed + 1})), budget_message, json::out_of_range&);
#endif

        // and is accepted with one element less
        ValuelessEventCounter sax;
        CHECK(json::sax_parse(valueless_arrays('Z', {first_count, second_allowed}), &sax, json::input_format_t::ubjson));
        CHECK(sax.values == first_count + second_allowed);
    }

    SECTION("every input adapter applies the budget")
    {
        const auto input = valueless_arrays('Z', {first_count, second_allowed + 1});

        // stream; not strict, which does not matter
        std::stringstream stream;
        stream.write(reinterpret_cast<const char*>(input.data()), static_cast<std::streamsize>(input.size()));
        ValuelessEventCounter from_stream;
        CHECK(!json::sax_parse(stream, &from_stream, json::input_format_t::ubjson, false));
        CHECK(from_stream.error_id == 408);

        // a container that is not contiguous; the counts of arrays of
        // different types are added up
        std::vector<std::uint8_t> mixed = {'['};
        utils::append_valueless_array(mixed, 'T', first_count);
        utils::append_valueless_array(mixed, 'F', second_allowed + 1);
        mixed.push_back(']');
        const std::list<std::uint8_t> as_list(mixed.begin(), mixed.end());
        ValuelessEventCounter from_list;
        CHECK(!json::sax_parse(as_list.begin(), as_list.end(), &from_list, json::input_format_t::ubjson));
        CHECK(from_list.error_id == 408);
        CHECK(from_list.values == first_count);

        // FILE*
        FILE* const file = std::tmpfile(); // NOLINT(cppcoreguidelines-owning-memory)
        REQUIRE(file != nullptr);
        CHECK(std::fwrite(input.data(), 1, input.size(), file) == input.size());
        CHECK(std::fseek(file, 0, SEEK_SET) == 0);
        ValuelessEventCounter from_file;
        CHECK(!json::sax_parse(file, &from_file, json::input_format_t::ubjson));
        CHECK(from_file.error_id == 408);
        std::fclose(file); // NOLINT(cert-err33-c,cppcoreguidelines-owning-memory)
    }

    SECTION("the limit is exact and the bytes read raise it")
    {
        // [ [$Z#l first_count] [$U#l payload + payload bytes] [$Z#l count] ]:
        // chars_read is 1 + 9 + (9 + payload) + 9 = 28 + payload when the last
        // header has been read, so the last array may hold
        // rate * (28 + payload) values on top of the base less the
        // first_count of the first array. The payload is as large as the
        // limit of one container allows, but at most 4096
        constexpr std::uint32_t payload_limit = (524288 / rate) - 40;
        constexpr std::uint32_t payload = payload_limit < 4096 ? payload_limit : 4096;
        constexpr std::uint32_t last_allowed = budget_base - first_count + (rate * (28 + payload));
        static_assert(last_allowed < budget_base, "the count must be accepted by the limit of one container");

        for (const std::uint32_t count :
                {
                    last_allowed, last_allowed + 1
                })
        {
            CAPTURE(count)
            std::vector<std::uint8_t> input = {'['};
            utils::append_valueless_array(input, 'Z', first_count);
            input.insert(input.end(), {'[', '$', 'U', '#', 'l',
                                       static_cast<std::uint8_t>(payload >> 24), static_cast<std::uint8_t>(payload >> 16),
                                       static_cast<std::uint8_t>(payload >> 8), static_cast<std::uint8_t>(payload)
                                      });
            input.insert(input.end(), payload, 0x01);
            utils::append_valueless_array(input, 'Z', count);
            input.push_back(']');
            ValuelessEventCounter sax;
            const bool accepted = count == last_allowed;
            CHECK(json::sax_parse(input, &sax, json::input_format_t::ubjson) == accepted);
            CHECK(sax.error_id == (accepted ? 0 : 408));
            CHECK(sax.values == first_count + payload + (accepted ? count : 0u));
        }
    }

    SECTION("a table written by 3.12.0")
    {
        // Version 3.12.0 wrote a table of rows of nulls with one `$Z#` header
        // per row (see the macro's page). A row of `width` elements has a
        // header of 6 bytes up to 32767 elements (5 up to 255), so the budget
        // grows by 6 * rate per row, and the row brings `width`. The 7 bytes
        // of the outer header are read first. Row r is accepted while
        //     r * width <= 1048576 + rate * (7 + 6 * r),
        // which is r <= (1048576 + 7 * rate) / (width - 6 * rate) for a width
        // above 6 * rate, and always true otherwise.
        constexpr std::uint32_t width = 1000;
        constexpr std::uint32_t rows = 1200;
        constexpr std::uint32_t credit = 6 * rate;
        constexpr std::uint32_t accepted_rows = width > credit ? (budget_base + (7 * rate)) / (width - credit) : rows;
        constexpr std::uint32_t read_rows = accepted_rows < rows ? accepted_rows : rows;

        ValuelessEventCounter sax;
        CHECK(json::sax_parse(rows_3_12_0(rows, width), &sax, json::input_format_t::ubjson) == (accepted_rows >= rows));
        CHECK(sax.error_id == (accepted_rows >= rows ? 0 : 408));
        CHECK(sax.values == static_cast<std::size_t>(read_rows) * width);
    }
}

#elif JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE >= 131072

TEST_CASE("UBJSON a rate that cannot be reached switches the budget off")
{
    // The rate is so large (2^20 / 8 = 131072 elements per byte or more)
    // that no input can exceed the budget: the shortest header of a container
    // of the largest size is 8 bytes (`$Z#l` and a count of 4 bytes, in an
    // array of arrays). The limit is base + rate * bytes read, which wraps
    // around for a rate near the largest integer in 64 and in 32
    // bits already at the first byte, unless it saturates: a wrapped limit
    // would refuse the second container below (at byte 19 or at byte 10, where
    // a limit of 2^20 + 10 * rate wraps for a 32-bit rate of 0x7FFFFFFF).
#if !defined(JSON_NOEXCEPTION)
    json _;
#endif

    SECTION("containers of the largest size are accepted one after the other")
    {
        // the first container is accepted by the base alone, the second one is
        // not: it needs the rate. The handler ends the parse at its first
        // value, so that the second million values are not read
        const auto input = valueless_arrays('Z', {budget_base, budget_base});
        ValuelessEventCounter sax;
        sax.stop_after = static_cast<std::size_t>(budget_base) + 1;
        CHECK(!json::sax_parse(input, &sax, json::input_format_t::ubjson));
        CHECK(sax.error_id == 0);
        CHECK(sax.values == static_cast<std::size_t>(budget_base) + 1);
    }

    SECTION("the limit of a single container still applies")
    {
        const auto input = valueless_arrays('T', {budget_base, budget_base + 1});
        ValuelessEventCounter sax;
        CHECK(!json::sax_parse(input, &sax, json::input_format_t::ubjson));
        CHECK(sax.error_id == 408);
        CHECK(sax.values == budget_base);
#if !defined(JSON_NOEXCEPTION)
        CHECK_THROWS_WITH_AS(_ = json::from_ubjson(valueless_arrays('F', {budget_base + 1})), "[json.exception.out_of_range.408] syntax error while parsing UBJSON size: excessive array size", json::out_of_range&);
#endif
    }

    SECTION("a table written by 3.12.0 is read completely")
    {
        // 1200 rows of 1000 values are refused after 1074 rows at the default
        // rate and are accepted with every rate of 167 and more
        ValuelessEventCounter sax;
        CHECK(json::sax_parse(rows_3_12_0(1200, 1000), &sax, json::input_format_t::ubjson));
        CHECK(sax.error_id == 0);
        CHECK(sax.values == 1200u * 1000u);
    }
}

// (rates from 10001 to 131071 can be reached, but not with the few bytes of a
// test: there is nothing to test for them here)
#endif
