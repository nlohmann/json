//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.2
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

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
                json const j(json::value_t::null);
                json::const_iterator const it(&j);
            }

            SECTION("object")
            {
                json const j(json::value_t::object);
                json::const_iterator const it(&j);
            }

            SECTION("array")
            {
                json const j(json::value_t::array);
                json::const_iterator const it(&j);
            }
        }

        SECTION("copy assignment")
        {
            json const j(json::value_t::null);
            json::const_iterator const it(&j);
            json::const_iterator it2(&j);
            it2 = it;
        }

        SECTION("copy constructor from non-const iterator")
        {
            SECTION("create from uninitialized iterator")
            {
                const json::iterator it {};
                json::const_iterator const cit(it);
            }

            SECTION("create from initialized iterator")
            {
                json j;
                const json::iterator it = j.begin();
                json::const_iterator const cit(it);
            }
        }
    }

    SECTION("initialization")
    {
        SECTION("set_begin")
        {
            SECTION("null")
            {
                json const j(json::value_t::null);
                json::const_iterator it(&j);
                it.set_begin();
                CHECK((it == j.cbegin()));
            }

            SECTION("object")
            {
                json const j(json::value_t::object);
                json::const_iterator it(&j);
                it.set_begin();
                CHECK((it == j.cbegin()));
            }

            SECTION("array")
            {
                json const j(json::value_t::array);
                json::const_iterator it(&j);
                it.set_begin();
                CHECK((it == j.cbegin()));
            }
        }

        SECTION("set_end")
        {
            SECTION("null")
            {
                json const j(json::value_t::null);
                json::const_iterator it(&j);
                it.set_end();
                CHECK((it == j.cend()));
            }

            SECTION("object")
            {
                json const j(json::value_t::object);
                json::const_iterator it(&j);
                it.set_end();
                CHECK((it == j.cend()));
            }

            SECTION("array")
            {
                json const j(json::value_t::array);
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
                json const j(json::value_t::null);
                json::const_iterator const it = j.cbegin();
                CHECK_THROWS_WITH_AS(*it, "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }

            SECTION("number")
            {
                json const j(17);
                json::const_iterator it = j.cbegin();
                CHECK(*it == json(17));
                it = j.cend();
                CHECK_THROWS_WITH_AS(*it, "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }

            SECTION("object")
            {
                json const j({{"foo", "bar"}});
                json::const_iterator const it = j.cbegin();
                CHECK(*it == json("bar"));
            }

            SECTION("array")
            {
                json const j({1, 2, 3, 4});
                json::const_iterator const it = j.cbegin();
                CHECK(*it == json(1));
            }
        }

        SECTION("operator->")
        {
            SECTION("null")
            {
                json const j(json::value_t::null);
                json::const_iterator const it = j.cbegin();
                CHECK_THROWS_WITH_AS(std::string(it->type_name()), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }

            SECTION("number")
            {
                json const j(17);
                json::const_iterator it = j.cbegin();
                CHECK(std::string(it->type_name()) == "number");
                it = j.cend();
                CHECK_THROWS_WITH_AS(std::string(it->type_name()), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }

            SECTION("object")
            {
                json const j({{"foo", "bar"}});
                json::const_iterator const it = j.cbegin();
                CHECK(std::string(it->type_name()) == "string");
            }

            SECTION("array")
            {
                json const j({1, 2, 3, 4});
                json::const_iterator const it = j.cbegin();
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
                json const j(json::value_t::null);
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                it++;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("number")
            {
                json const j(17);
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.primitive_iterator.m_it == 0));
                it++;
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                it++;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("object")
            {
                json const j({{"foo", "bar"}});
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->begin()));
                it++;
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->end()));
            }

            SECTION("array")
            {
                json const j({1, 2, 3, 4});
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
                json const j(json::value_t::null);
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                ++it;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("number")
            {
                json const j(17);
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.primitive_iterator.m_it == 0));
                ++it;
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                ++it;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("object")
            {
                json const j({{"foo", "bar"}});
                json::const_iterator it = j.cbegin();
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->begin()));
                ++it;
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->end()));
            }

            SECTION("array")
            {
                json const j({1, 2, 3, 4});
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
                json const j(json::value_t::null);
                json::const_iterator const it = j.cend();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
            }

            SECTION("number")
            {
                json const j(17);
                json::const_iterator it = j.cend();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                it--;
                CHECK((it.m_it.primitive_iterator.m_it == 0));
                it--;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("object")
            {
                json const j({{"foo", "bar"}});
                json::const_iterator it = j.cend();
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->end()));
                it--;
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->begin()));
            }

            SECTION("array")
            {
                json const j({1, 2, 3, 4});
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
                json const j(json::value_t::null);
                json::const_iterator const it = j.cend();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
            }

            SECTION("number")
            {
                json const j(17);
                json::const_iterator it = j.cend();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                --it;
                CHECK((it.m_it.primitive_iterator.m_it == 0));
                --it;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("object")
            {
                json const j({{"foo", "bar"}});
                json::const_iterator it = j.cend();
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->end()));
                --it;
                CHECK((it.m_it.object_iterator == it.m_object->m_value.object->begin()));
            }

            SECTION("array")
            {
                json const j({1, 2, 3, 4});
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
