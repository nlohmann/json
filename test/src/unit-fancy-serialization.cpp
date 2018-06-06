/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.1.2
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2018 Evan Driscoll <evaned@gmail.com>

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

#include "catch.hpp"
#include <iostream>

#include <nlohmann/json.hpp>

using nlohmann::json;
using nlohmann::json_pointer;
using nlohmann::fancy_dump;
using nlohmann::print_style;
using nlohmann::print_stylizer;

// Chops off the first line (if empty, but if it *isn't* empty you're
// probably using this wrong), measures the leading indent on the
// *next* line, then chops that amount off of all subsequent lines.
std::string dedent(const char* str)
{
    std::stringstream out;
    std::stringstream ss(str);
    std::string line;
    bool first = true;
    int indent = -1;

    while (getline(ss, line))
    {
        if (first && line.empty())
        {
            first = false;
            continue;
        }
        if (indent == -1)
        {
            indent = line.find_first_not_of(' ');
            assert(indent != std::string::npos);
        }
        out << line.c_str() + indent << "\n";
    }

    std::string ans = out.str();
    if (ans[ans.size() - 1] == '\n' and str[strlen(str) - 1] != '\n')
    {
        ans.resize(ans.size() - 1);
    }

    return ans;
}

std::string fancy_to_string(json j, print_style style = print_style())
{
    std::stringstream ss;
    fancy_dump(ss, j, style);
    return ss.str();
}

std::string fancy_to_string(json j, print_stylizer stylizer)
{
    std::stringstream ss;
    fancy_dump(ss, j, stylizer);
    return ss.str();
}

TEST_CASE("serialization")
{
    SECTION("primitives")
    {
        SECTION("null")
        {
            auto str = fancy_to_string({});
            CHECK(str == "null");
        }

        SECTION("true")
        {
            auto str = fancy_to_string(true);
            CHECK(str == "true");
        }

        SECTION("false")
        {
            auto str = fancy_to_string(false);
            CHECK(str == "false");
        }

        SECTION("integer")
        {
            auto str = fancy_to_string(10);
            CHECK(str == "10");
        }

        SECTION("floating point")
        {
            auto str = fancy_to_string(7.5);
            CHECK(str == "7.5");
        }
    }

    SECTION("strings")
    {
        SECTION("long strings usually print")
        {
            auto str = fancy_to_string(
                           "The quick brown fox jumps over the lazy brown dog");
            CHECK(str ==
                  "\"The quick brown fox jumps over the lazy brown dog\"");
        }

        SECTION("long strings can be shortened")
        {
            print_style style;
            style.strings_maximum_length = 10;

            auto str = fancy_to_string(
                           "The quick brown fox jumps over the lazy brown dog",
                           style);
            CHECK(str == "\"The qu...g\"");
        }

        SECTION("requesting extremely short strings limits what is included")
        {
            const char* const quick = "The quick brown fox jumps over the lazy brown dog";

            std::pair<unsigned, const char*> tests[] =
            {
                {5, "\"T...g\""},
                {4, "\"T...\""},
                {3, "\"...\""},
                {2, "\"..\""},
                {1, "\".\""},
            };

            for (auto test : tests)
            {
                print_style style;
                style.strings_maximum_length = test.first;
                auto str = fancy_to_string(quick, style);
                CHECK(str == test.second);
            }
        }

        SECTION("But you cannot ask for a length of zero; that means unlimited")
        {
            print_style style;
            style.strings_maximum_length = 0;

            auto str = fancy_to_string(
                           "The quick brown fox jumps over the lazy brown dog",
                           style);
            CHECK(str ==
                  "\"The quick brown fox jumps over the lazy brown dog\"");
        }

        SECTION("\"Limiting\" to something long doesn't do anything")
        {
            print_style style;
            style.strings_maximum_length = 100;

            auto str = fancy_to_string(
                           "The quick brown fox jumps over the lazy brown dog",
                           style);
            CHECK(str ==
                  "\"The quick brown fox jumps over the lazy brown dog\"");
        }

        // TODO: Handle escape sequences. Figure out what we want the
        // behavior to be, first. :-)
    }

    SECTION("maximum depth")
    {
        SECTION("recursing past the maximum depth with a list elides the subobjects")
        {
            print_style style;
            style.depth_limit = 1;

            auto str_flat = fancy_to_string({1, {1}}, style);
            CHECK(str_flat == "[1,[...]]");

            style = print_style::preset_multiline;
            style.depth_limit = 1;
            auto str_lines = fancy_to_string({1, {1}}, style);
            CHECK(str_lines == dedent(R"(
                  [
                      1,
                      [...]
                  ])"));
        }

        SECTION("recursing past the maximum depth with an object elides the subobjects")
        {
            print_style style;
            style.depth_limit = 1;

            auto str_flat = fancy_to_string({1, {{"one", 1}}}, style);
            CHECK(str_flat == "[1,{...}]");

            style = print_style::preset_multiline;
            style.depth_limit = 1;
            auto str_lines = fancy_to_string({1, {{"one", 1}}}, style);
            CHECK(str_lines == dedent(R"(
                  [
                      1,
                      {...}
                  ])"));
        }
    }

    SECTION("changing styles")
    {
        SECTION("can style objects of a key differently")
        {
            print_stylizer stylizer;
            stylizer.get_default_style() = print_style::preset_multiline;
            stylizer.register_key_matcher_style("one line");

            auto str = fancy_to_string(
            {
                {
                    "one line", {1, 2}
                },
                {
                    "two lines", {1, 2}
                }
            },
            stylizer);

            CHECK(str == dedent(R"(
                {
                    "one line": [1,2],
                    "two lines": [
                        1,
                        2
                    ]
                })"));
        }

        SECTION("changes propagate (unless overridden)")
        {
            print_stylizer stylizer;
            stylizer.get_default_style() = print_style::preset_multiline;
            stylizer.register_key_matcher_style("one line");

            auto str = fancy_to_string(
            {
                {
                    "one line", {{"still one line", {1, 2}}}
                },
            },
            stylizer);

            CHECK(str == dedent(R"(
                {
                    "one line": {"still one line":[1,2]}
                })"));
        }

        SECTION("example of more sophisticated context matcher")
        {
            print_stylizer stylizer;
            stylizer.get_default_style() = print_style::preset_multiline;

            stylizer.register_style(
                [] (const json_pointer<json>& context)
            {
                // Matches if context[-2] is "each elem on one line"
                return (context.cend() - context.cbegin() >= 2)
                       && (*(context.cend() - 2) == "each elem on one line");
            }
            ).space_after_comma = true;

            auto str = fancy_to_string(
            {
                {
                    "each elem on one line", {
                        {1, 2, 3, 4, 5},
                        {1, 2, 3, 4, 5}
                    },
                },
                {
                    "fully multiline", {
                        {1, 2, 3},
                    }
                }
            },
            stylizer);

            CHECK(str == dedent(R"(
                {
                    "each elem on one line": [
                        [1, 2, 3, 4, 5],
                        [1, 2, 3, 4, 5]
                    ],
                    "fully multiline": [
                        [
                            1,
                            2,
                            3
                        ]
                    ]
                })"));
        }

        SECTION("example of more sophisticated json matcher")
        {
            print_stylizer stylizer;
            stylizer.get_default_style() = print_style::preset_multiline;

            stylizer.register_style(
                [] (const json & j)
            {
                return j.type() == json::value_t::array;
            }
            ) = print_style::preset_one_line;

            auto str = fancy_to_string(
            {
                {
                    "an array", {1, 2, 3}
                },
                {
                    "an object", {{"key", "val"}}
                }
            },
            stylizer);

            CHECK(str == dedent(R"(
                {
                    "an array": [1, 2, 3],
                    "an object": {
                        "key": "val"
                    }
                })"));
        }
    }

    SECTION("Spaces after commas are controllable separately from multiline")
    {
        SECTION("commas")
        {
            print_style style;
            style.space_after_comma = true;
            auto str = fancy_to_string({1, 2, 3}, style);
            CHECK(str == "[1, 2, 3]");
        }

        SECTION("colons")
        {
            print_style style;
            style.space_after_colon = true;
            auto str = fancy_to_string({{"one", 1}}, style);
            CHECK(str == "{\"one\": 1}");
        }

        SECTION("multiline can have no space")
        {
            print_style style = print_style::preset_multiline;
            style.space_after_colon = false;
            auto str = fancy_to_string({{"one", 1}}, style);
            CHECK(str == dedent(R"(
                {
                    "one":1
                })"));

        }
    }

    SECTION("given width")
    {
        print_style style = print_style::preset_multiline;
        auto str = fancy_to_string({"foo", 1, 2, 3, false, {{"one", 1}}}, style);
        CHECK(str == dedent(R"(
              [
                  "foo",
                  1,
                  2,
                  3,
                  false,
                  {
                      "one": 1
                  }
              ])"));
    }

    SECTION("given fill")
    {
        print_style style = print_style::preset_multiline;
        style.indent_step = 1;
        style.indent_char = '\t';

        auto str = fancy_to_string({"foo", 1, 2, 3, false, {{"one", 1}}}, style);
        CHECK(str ==
              "[\n"
              "\t\"foo\",\n"
              "\t1,\n"
              "\t2,\n"
              "\t3,\n"
              "\tfalse,\n"
              "\t{\n"
              "\t\t\"one\": 1\n"
              "\t}\n"
              "]"
             );
    }

    SECTION("indent_char is honored for deep indents in lists")
    {
        print_style style = print_style::preset_multiline;
        style.indent_step = 300;
        style.indent_char = 'X';

        auto str = fancy_to_string({1, {1}}, style);

        std::string indent(300, 'X');
        CHECK(str ==
              "[\n" +
              indent + "1,\n" +
              indent + "[\n" +
              indent + indent + "1\n" +
              indent + "]\n" +
              "]");
    }

    SECTION("indent_char is honored for deep indents in objects")
    {
        print_style style = print_style::preset_multiline;
        style.indent_step = 300;
        style.indent_char = 'X';

        auto str = fancy_to_string({{"key", {{"key", 1}}}}, style);

        std::string indent(300, 'X');
        CHECK(str ==
              "{\n" +
              indent + "\"key\": {\n" +
              indent + indent + "\"key\": 1\n" +
              indent + "}\n" +
              "}");
    }
}
