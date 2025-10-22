//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;

template<typename Iter>
using can_post_increment_temporary = decltype((std::declval<Iter>()++)++);

template<typename Iter>
using can_post_decrement_temporary = decltype((std::declval<Iter>()--)--);

TEST_CASE("iterator class")
{
    SECTION("construction")
    {
        SECTION("constructor")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator const it(&j);
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                json::iterator const it(&j);
            }

            SECTION("array")
            {
                json j(json::value_t::array);
                json::iterator const it(&j);
            }
        }

        SECTION("copy assignment")
        {
            json j(json::value_t::null);
            json::iterator const it(&j);
            json::iterator it2(&j);
            it2 = it;
        }
    }

    SECTION("initialization")
    {
        SECTION("set_begin")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator it(&j);
                it.set_begin();
                CHECK((it == j.begin()));
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                json::iterator it(&j);
                it.set_begin();
                CHECK((it == j.begin()));
            }

            SECTION("array")
            {
                json j(json::value_t::array);
                json::iterator it(&j);
                it.set_begin();
                CHECK((it == j.begin()));
            }
        }

        SECTION("set_end")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator it(&j);
                it.set_end();
                CHECK((it == j.end()));
            }

            SECTION("object")
            {
                json j(json::value_t::object);
                json::iterator it(&j);
                it.set_end();
                CHECK((it == j.end()));
            }

            SECTION("array")
            {
                json j(json::value_t::array);
                json::iterator it(&j);
                it.set_end();
                CHECK((it == j.end()));
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
                json::iterator const it = j.begin();
                CHECK_THROWS_WITH_AS(*it, "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }

            SECTION("number")
            {
                json j(17);
                json::iterator it = j.begin();
                CHECK(*it == json(17));
                it = j.end();
                CHECK_THROWS_WITH_AS(*it, "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::iterator const it = j.begin();
                CHECK(*it == json("bar"));
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::iterator const it = j.begin();
                CHECK(*it == json(1));
            }
        }

        SECTION("operator->")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator const it = j.begin();
                CHECK_THROWS_WITH_AS(std::string(it->type_name()), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }

            SECTION("number")
            {
                json j(17);
                json::iterator it = j.begin();
                CHECK(std::string(it->type_name()) == "number");
                it = j.end();
                CHECK_THROWS_WITH_AS(std::string(it->type_name()), "[json.exception.invalid_iterator.214] cannot get value", json::invalid_iterator&);
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::iterator const it = j.begin();
                CHECK(std::string(it->type_name()) == "string");
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::iterator const it = j.begin();
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
                json::iterator it = j.begin();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                it++;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("number")
            {
                json j(17);
                json::iterator it = j.begin();
                CHECK((it.m_it.primitive_iterator.m_it == 0));
                it++;
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                it++;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::iterator it = j.begin();
                CHECK((it.m_it.object_iterator == it.m_object->m_data.m_value.object->begin()));
                it++;
                CHECK((it.m_it.object_iterator == it.m_object->m_data.m_value.object->end()));
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::iterator it = j.begin();
                CHECK((it.m_it.array_iterator == it.m_object->m_data.m_value.array->begin()));
                it++;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
                it++;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
                it++;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
                it++;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator == it.m_object->m_data.m_value.array->end()));
            }
        }

        SECTION("pre-increment")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator it = j.begin();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                ++it;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("number")
            {
                json j(17);
                json::iterator it = j.begin();
                CHECK((it.m_it.primitive_iterator.m_it == 0));
                ++it;
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                ++it;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::iterator it = j.begin();
                CHECK((it.m_it.object_iterator == it.m_object->m_data.m_value.object->begin()));
                ++it;
                CHECK((it.m_it.object_iterator == it.m_object->m_data.m_value.object->end()));
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::iterator it = j.begin();
                CHECK((it.m_it.array_iterator == it.m_object->m_data.m_value.array->begin()));
                ++it;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
                ++it;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
                ++it;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
                ++it;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator == it.m_object->m_data.m_value.array->end()));
            }
        }

        SECTION("post-decrement")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator const it = j.end();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
            }

            SECTION("number")
            {
                json j(17);
                json::iterator it = j.end();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                it--;
                CHECK((it.m_it.primitive_iterator.m_it == 0));
                it--;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::iterator it = j.end();
                CHECK((it.m_it.object_iterator == it.m_object->m_data.m_value.object->end()));
                it--;
                CHECK((it.m_it.object_iterator == it.m_object->m_data.m_value.object->begin()));
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::iterator it = j.end();
                CHECK((it.m_it.array_iterator == it.m_object->m_data.m_value.array->end()));
                it--;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
                it--;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
                it--;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
                it--;
                CHECK((it.m_it.array_iterator == it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
            }
        }

        SECTION("pre-decrement")
        {
            SECTION("null")
            {
                json j(json::value_t::null);
                json::iterator const it = j.end();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
            }

            SECTION("number")
            {
                json j(17);
                json::iterator it = j.end();
                CHECK((it.m_it.primitive_iterator.m_it == 1));
                --it;
                CHECK((it.m_it.primitive_iterator.m_it == 0));
                --it;
                CHECK((it.m_it.primitive_iterator.m_it != 0 && it.m_it.primitive_iterator.m_it != 1));
            }

            SECTION("object")
            {
                json j({{"foo", "bar"}});
                json::iterator it = j.end();
                CHECK((it.m_it.object_iterator == it.m_object->m_data.m_value.object->end()));
                --it;
                CHECK((it.m_it.object_iterator == it.m_object->m_data.m_value.object->begin()));
            }

            SECTION("array")
            {
                json j({1, 2, 3, 4});
                json::iterator it = j.end();
                CHECK((it.m_it.array_iterator == it.m_object->m_data.m_value.array->end()));
                --it;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
                --it;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
                --it;
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
                --it;
                CHECK((it.m_it.array_iterator == it.m_object->m_data.m_value.array->begin()));
                CHECK((it.m_it.array_iterator != it.m_object->m_data.m_value.array->end()));
            }
        }
    }
    SECTION("equality-preserving")
    {
        SECTION("post-increment")
        {
            SECTION("primitive_iterator_t")
            {
                using Iter = nlohmann::detail::primitive_iterator_t;
                CHECK(std::is_same < decltype(std::declval<Iter&>()++), Iter >::value);
            }
            SECTION("iter_impl")
            {
                using Iter = nlohmann::detail::iter_impl<json>;
                CHECK(std::is_same < decltype(std::declval<Iter&>()++), Iter >::value);
            }
            SECTION("json_reverse_iterator")
            {
                using Base = nlohmann::detail::iter_impl<json>;
                using Iter = nlohmann::detail::json_reverse_iterator<Base>;
                CHECK(std::is_same < decltype(std::declval<Iter&>()++), Iter >::value);
            }
        }
        SECTION("post-decrement")
        {
            SECTION("primitive_iterator_t")
            {
                using Iter = nlohmann::detail::primitive_iterator_t;
                CHECK(std::is_same < decltype(std::declval<Iter&>()--), Iter >::value);
            }
            SECTION("iter_impl")
            {
                using Iter = nlohmann::detail::iter_impl<json>;
                CHECK(std::is_same < decltype(std::declval<Iter&>()--), Iter >::value );
            }
            SECTION("json_reverse_iterator")
            {
                using Base = nlohmann::detail::iter_impl<json>;
                using Iter = nlohmann::detail::json_reverse_iterator<Base>;
                CHECK(std::is_same < decltype(std::declval<Iter&>()--), Iter >::value );
            }
        }
    }
    // prevent "accidental mutation of a temporary object"
    SECTION("cert-dcl21-cpp")
    {
        using nlohmann::detail::is_detected;
        SECTION("post-increment")
        {
            SECTION("primitive_iterator_t")
            {
                using Iter = nlohmann::detail::primitive_iterator_t;
                CHECK_FALSE(is_detected<can_post_increment_temporary, Iter&>::value);
            }
            SECTION("iter_impl")
            {
                using Iter = nlohmann::detail::iter_impl<json>;
                CHECK_FALSE(is_detected<can_post_increment_temporary, Iter&>::value);
            }
            SECTION("json_reverse_iterator")
            {
                using Base = nlohmann::detail::iter_impl<json>;
                using Iter = nlohmann::detail::json_reverse_iterator<Base>;
                CHECK_FALSE(is_detected<can_post_increment_temporary, Iter&>::value);
            }
        }
        SECTION("post-decrement")
        {
            SECTION("primitive_iterator_t")
            {
                using Iter = nlohmann::detail::primitive_iterator_t;
                CHECK_FALSE(is_detected<can_post_decrement_temporary, Iter&>::value);
            }
            SECTION("iter_impl")
            {
                using Iter = nlohmann::detail::iter_impl<json>;
                CHECK_FALSE(is_detected<can_post_decrement_temporary, Iter&>::value);
            }
            SECTION("json_reverse_iterator")
            {
                using Base = nlohmann::detail::iter_impl<json>;
                using Iter = nlohmann::detail::json_reverse_iterator<Base>;
                CHECK_FALSE(is_detected<can_post_decrement_temporary, Iter&>::value);
            }

        }
    }
}
