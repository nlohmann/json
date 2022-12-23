/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.2
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2019 Niels Lohmann <http://nlohmann.me>.

Permission is hereby  granted, free of charge, to any  person obtaining a copy
of this software and associated  documentation files (the "Software"), to deal
in the Software  without restriction, including without  limitation the rights
to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <iostream>
#include <string>

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

//prototype to make -Wmissing-prototypes happy
std::ostream& operator<<(std::ostream& out, const nlohmann::position_t& p);

//test json parser with detailed line / col information as metadata

struct token_start_stop
{
    nlohmann::position_t start{};
    nlohmann::position_t stop{};
};

std::ostream& operator<<(std::ostream& out, const nlohmann::position_t& p)
{
    out << p.chars_read_total << '(' << p.lines_read << ':' << p.chars_read_current_line << ')';
    return out;
}

using json_with_token_start_stop =
    nlohmann::basic_json <
    std::map,
    std::vector,
    std::string,
    bool,
    std::int64_t,
    std::uint64_t,
    double,
    std::allocator,
    nlohmann::adl_serializer,
    std::vector<std::uint8_t>,
    token_start_stop >;

//adapted from detail::json_sax_dom_parser
class sax_with_token_start_stop_metadata
{
  public:
    using json = json_with_token_start_stop;
    using number_integer_t = typename json::number_integer_t;
    using number_unsigned_t = typename json::number_unsigned_t;
    using number_float_t = typename json::number_float_t;
    using string_t = typename json::string_t;
    using binary_t = typename json::binary_t;

    /*!
    @param[in,out] r  reference to a JSON value that is manipulated while
                       parsing
    @param[in] allow_exceptions_  whether parse errors yield exceptions
    */
    explicit sax_with_token_start_stop_metadata(json& r, const bool allow_exceptions_ = true)
        : root(r)
        , ref_stack{}
        , object_element{nullptr}
        , errored{false}
        , allow_exceptions(allow_exceptions_)
        , start_stop{}
    {}

    void next_token_start(const nlohmann::position_t& p)
    {
        start_stop.start = p;
    }

    void next_token_end(const nlohmann::position_t& p)
    {
        start_stop.stop = p;
    }

    bool null()
    {
        handle_value(nullptr);
        return true;
    }

    bool boolean(bool val)
    {
        handle_value(val);
        return true;
    }

    bool number_integer(number_integer_t val)
    {
        handle_value(val);
        return true;
    }

    bool number_unsigned(number_unsigned_t val)
    {
        handle_value(val);
        return true;
    }

    bool number_float(number_float_t val, const string_t& /*unused*/)
    {
        handle_value(val);
        return true;
    }

    bool string(string_t& val)
    {
        handle_value(val);
        return true;
    }

    bool binary(binary_t& val)
    {
        handle_value(std::move(val));
        return true;
    }

    bool start_object(std::size_t len)
    {
        ref_stack.push_back(handle_value(json::value_t::object));
        ref_stack.back()->start = start_stop.start;

        if (len != static_cast<std::size_t>(-1) && len > ref_stack.back()->max_size())
        {
            throw nlohmann::detail::out_of_range::create(408, nlohmann::detail::concat("excessive object size: ", std::to_string(len)), ref_stack.back());
        }

        return true;
    }

    bool key(string_t& val)
    {
        assert(!ref_stack.empty());
        assert(ref_stack.back()->is_object());

        // add null at given key and store the reference for later
        object_element = &(*ref_stack.back())[val];
        return true;
    }

    bool end_object()
    {
        assert(!ref_stack.empty());
        assert(ref_stack.back()->is_object());

        ref_stack.back()->stop = start_stop.stop;
        ref_stack.pop_back();
        return true;
    }

    bool start_array(std::size_t len)
    {
        ref_stack.push_back(handle_value(json::value_t::array));
        ref_stack.back()->start = start_stop.start;

        if (len != static_cast<std::size_t>(-1) && len > ref_stack.back()->max_size())
        {
            throw nlohmann::detail::out_of_range::create(408, nlohmann::detail::concat("excessive array size: ", std::to_string(len)), ref_stack.back());
        }

        return true;
    }

    bool end_array()
    {
        assert(!ref_stack.empty());
        assert(ref_stack.back()->is_array());

        ref_stack.back()->stop = start_stop.stop;
        ref_stack.pop_back();
        return true;
    }

    template<class Exception>
    bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/, const Exception& ex)
    {
        errored = true;
        static_cast<void>(ex);
        if (allow_exceptions)
        {
            throw ex;
        }
        return false;
    }

    constexpr bool is_errored() const
    {
        return errored;
    }

  private:
    /*!
    @invariant If the ref stack is empty, then the passed value will be the new
               root.
    @invariant If the ref stack contains a value, then it is an array or an
               object to which we can add elements
    */
    template<typename Value>
    json*
    handle_value(Value&& v)
    {
        if (ref_stack.empty())
        {
            root = json(std::forward<Value>(v));
            root.start = start_stop.start;
            root.stop = start_stop.stop;
            return &root;
        }

        assert(ref_stack.back()->is_array() || ref_stack.back()->is_object());

        if (ref_stack.back()->is_array())
        {
            auto& array_element = ref_stack.back()->emplace_back(std::forward<Value>(v));
            array_element.start = start_stop.start;
            array_element.stop = start_stop.stop;
            return &array_element;
        }

        assert(ref_stack.back()->is_object());
        assert(object_element);
        *object_element = json(std::forward<Value>(v));
        object_element->start = start_stop.start;
        object_element->stop = start_stop.stop;
        return object_element;
    }

    /// the parsed JSON value
    json& root;
    /// stack to model hierarchy of values
    std::vector<json*> ref_stack{};
    /// helper to hold the reference for the next object element
    json* object_element = nullptr;
    /// whether a syntax error occurred
    bool errored = false;
    /// whether to throw exceptions in case of errors
    const bool allow_exceptions = true;
    /// start / stop information for the current token
    token_start_stop start_stop{};
};

TEST_CASE("parse-json-with-position-info")
{
    const std::string str =
        /*line 0*/ R"({)"
        "\n"
        /*line 1*/ R"(  "array" : [)"
        "\n"
        /*line 2*/ R"(    14294967296,)"
        "\n"
        /*line 3*/ R"(    -1,)"
        "\n"
        /*line 4*/ R"(    true,)"
        "\n"
        /*line 5*/ R"(    4.2,)"
        "\n"
        /*line 6*/ R"(    null,)"
        "\n"
        /*line 7*/ R"(    "str")"
        "\n"
        /*line 8*/ R"(  ])"
        "\n"
        /*line 9*/ R"(})";
    json_with_token_start_stop j;
    sax_with_token_start_stop_metadata sax{j};
    CHECK(nlohmann::json::sax_parse(str, &sax, nlohmann::json::input_format_t::json));
    CHECK(j.start.lines_read == 0);
    CHECK(j.start.chars_read_current_line == 0);

    CHECK(j["array"].start.lines_read == 1);
    CHECK(j["array"].start.chars_read_current_line == 12);

    CHECK(j["array"][0].start.lines_read == 2);
    CHECK(j["array"][0].start.chars_read_current_line == 4);
    CHECK(j["array"][0].stop.lines_read == 2);
    CHECK(j["array"][0].stop.chars_read_current_line == 15);

    CHECK(j["array"][1].start.lines_read == 3);
    CHECK(j["array"][1].start.chars_read_current_line == 4);
    CHECK(j["array"][1].stop.lines_read == 3);
    CHECK(j["array"][1].stop.chars_read_current_line == 6);

    CHECK(j["array"][2].start.lines_read == 4);
    CHECK(j["array"][2].start.chars_read_current_line == 4);
    CHECK(j["array"][2].stop.lines_read == 4);
    CHECK(j["array"][2].stop.chars_read_current_line == 8);

    CHECK(j["array"][3].start.lines_read == 5);
    CHECK(j["array"][3].start.chars_read_current_line == 4);
    CHECK(j["array"][3].stop.lines_read == 5);
    CHECK(j["array"][3].stop.chars_read_current_line == 7);

    CHECK(j["array"][4].start.lines_read == 6);  //starts directly after last value....
    CHECK(j["array"][4].start.chars_read_current_line == 4);
    CHECK(j["array"][4].stop.lines_read == 6);
    CHECK(j["array"][4].stop.chars_read_current_line == 8);

    CHECK(j["array"][5].start.lines_read == 7);
    CHECK(j["array"][5].start.chars_read_current_line == 4);
    CHECK(j["array"][5].stop.lines_read == 7);
    CHECK(j["array"][5].stop.chars_read_current_line == 9);

    CHECK(j["array"].stop.lines_read == 8);
    CHECK(j["array"].stop.chars_read_current_line == 3);

    CHECK(j.stop.lines_read == 9);
    CHECK(j.stop.chars_read_current_line == 1);
}
