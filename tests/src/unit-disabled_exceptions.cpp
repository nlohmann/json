//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

// disable -Wnoexcept as exceptions are switched off for this test suite
DOCTEST_GCC_SUPPRESS_WARNING_PUSH
DOCTEST_GCC_SUPPRESS_WARNING("-Wnoexcept")

#include <nlohmann/json.hpp>
using json = nlohmann::json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

/////////////////////////////////////////////////////////////////////
// for #2824
/////////////////////////////////////////////////////////////////////

class sax_no_exception : public nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type>
{
  public:
    explicit sax_no_exception(json& j) : nlohmann::detail::json_sax_dom_parser<json, nlohmann::detail::string_input_adapter_type>(j, false) {}

    static bool parse_error(std::size_t /*position*/, const std::string& /*last_token*/, const json::exception& ex)
    {
        error_string = new std::string(ex.what()); // NOLINT(cppcoreguidelines-owning-memory)
        return false;
    }

    static std::string* error_string;
};

std::string* sax_no_exception::error_string = nullptr;

TEST_CASE("Tests with disabled exceptions")
{
    SECTION("issue #2824 - encoding of json::exception::what()")
    {
        json j;
        sax_no_exception sax(j);

        CHECK (!json::sax_parse("xyz", &sax));
        CHECK(*sax_no_exception::error_string == "[json.exception.parse_error.101] parse error at line 1, column 1: syntax error while parsing value - invalid literal; last read: 'x'");
        delete sax_no_exception::error_string; // NOLINT(cppcoreguidelines-owning-memory)
    }

    SECTION("issue #5672 - value(json_pointer, default) must not abort for array tokens that are not a valid index")
    {
        const json j = {1, 2, 3};

        // a syntactically valid index that is out of range for this array
        CHECK(j.value("/7"_json_pointer, 42) == 42);
        // a reference token that is not a number at all
        CHECK(j.value("/1a"_json_pointer, 42) == 42);
        // the empty reference token (JSON pointer "/")
        CHECK(j.value("/"_json_pointer, 42) == 42);
        // an index whose magnitude does not fit into size_type
        CHECK(j.value("/99999999999999999999999"_json_pointer, 42) == 42);
        CHECK(j.value("/18446744073709551615"_json_pointer, 42) == 42);
    }

    SECTION("growing an ordered_json object")
    {
        auto j = nlohmann::ordered_json::object();
        for (int i = 0; i < 100; ++i)
        {
            j[std::to_string(i)] = {{"nested", i}};
        }

        CHECK(j.size() == 100);
        int i = 0;
        for (const auto& element : j.items())
        {
            CHECK(element.key() == std::to_string(i));
            CHECK(element.value()["nested"] == i);
            ++i;
        }
    }
}

DOCTEST_GCC_SUPPRESS_WARNING_POP
