/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.5
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2022 Niels Lohmann <http://nlohmann.me>.

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

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;

TEST_CASE("const_iterator class")
{
    SECTION("construction")
    {
        SECTION("constructor")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it(&j);
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                json::const_iterator it(&j);
            }

            SECTION("array")
            {
                json j(json::value_t::array);
                json::const_iterator it(&j);
            }
        }

        SECTION("copy assignment")
        {
            json j(json::value_t::null);
            json::const_iterator it(&j);
            json::const_iterator it2(&j);
            it2 = it;
        }

        SECTION("copy constructor from non-const iterator")
        {
            SECTION("create from uninitialized iterator")
            {
                const json::iterator it {};
                json::const_iterator cit(it);
            }

            SECTION("create from initialized iterator")
            {
                json j;
                const json::iterator it = j.begin();
                json::const_iterator cit(it);
            }
        }
    }

    SECTION("initialization")
    {
        SECTION("set_begin")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it(&j);
                it.set_begin();
                CHECK((it == j.cbegin()));
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                json::const_iterator it(&j);
                it.set_begin();
                CHECK((it == j.cbegin()));
            }

            SECTION("array")
            {
                json j(json::value_t::array);
                json::const_iterator it(&j);
                it.set_begin();
                CHECK((it == j.cbegin()));
            }
        }

        SECTION("set_end")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it(&j);
                it.set_end();
                CHECK((it == j.cend()));
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                json::const_iterator it(&j);
                it.set_end();
                CHECK((it == j.cend()));
            }

            SECTION("array")
            {
                json j(json::value_t::array);
                json::const_iterator it(&j);
                it.set_end();
                CHECK((it == j.cend()));
            }
        }
    }

    SECTION("element access")
    {
        SECTION("operator*")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it = j.cbegin();
                CHECK_THROWS_WITH_AS(*it, "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }

            SECTION("number")
            {
                json j(17);
                json::const_iterator it = j.cbegin();
                CHECK(*it == json(17));
                it = j.cend();
                CHECK_THROWS_WITH_AS(*it, "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::const_iterator it = j.cbegin();
                CHECK(*it == json("bar"));
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::const_iterator it = j.cbegin();
                CHECK(*it == json(1));
            }
        }

        SECTION("operator->")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it = j.cbegin();
                CHECK_THROWS_WITH_AS(std::string(it->type_name()), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }

            SECTION("number")
            {
                json j(17);
                json::const_iterator it = j.cbegin();
                CHECK(std::string(it->type_name()) == "number");
                it = j.cend();
                CHECK_THROWS_WITH_AS(std::string(it->type_name()), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::const_iterator it = j.cbegin();
                CHECK(std::string(it->type_name()) == "string");
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::const_iterator it = j.cbegin();
                CHECK(std::string(it->type_name()) == "number");
            }
        }
    }

    SECTION("increment/decrement")
    {
        SECTION("post-increment")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                it++;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("number")
            {
                json j(17);
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.primitive_iterator.m_it == 0));
                it++;
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                it++;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->begin()));
                it++;
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->end()));
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.array_iterator == it.m_object->m_value.array->begin()));
                it++;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
                it++;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
                it++;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
                it++;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator == it.m_object->m_value.array->end()));
            }
        }

        SECTION("pre-increment")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                ++it;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("number")
            {
                json j(17);
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.primitive_iterator.m_it == 0));
                ++it;
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                ++it;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->begin()));
                ++it;
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->end()));
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.array_iterator == it.m_object->m_value.array->begin()));
                ++it;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
                ++it;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
                ++it;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
                ++it;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator == it.m_object->m_value.array->end()));
            }
        }

        SECTION("post-decrement")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it = j.cend();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
            }

            SECTION("number")
            {
                json j(17);
                json::const_iterator it = j.cend();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                it--;
                CHECK((it.m_it.primitive_iterator.m_it == 0));
                it--;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::const_iterator it = j.cend();
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->end()));
                it--;
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->begin()));
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::const_iterator it = j.cend();
                CHECK((it.m_it.array_iterator == it.m_object->m_value.array->end()));
                it--;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
                it--;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
                it--;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
                it--;
                CHECK((it.m_it.array_iterator == it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
            }
        }

        SECTION("pre-decrement")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::const_iterator it = j.cend();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
            }

            SECTION("number")
            {
                json j(17);
                json::const_iterator it = j.cend();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                --it;
                CHECK((it.m_it.primitive_iterator.m_it == 0));
                --it;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::const_iterator it = j.cend();
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->end()));
                --it;
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->begin()));
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::const_iterator it = j.cend();
                CHECK((it.m_it.array_iterator == it.m_object->m_value.array->end()));
                --it;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
                --it;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
                --it;
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
                --it;
                CHECK((it.m_it.array_iterator == it.m_object->m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_value.array->end()));
            }
        }
    }
}
