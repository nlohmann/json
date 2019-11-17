/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.7.3
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

#include "doctest_compatibility.h"

#define private public
#include <nlohmann/json.hpp>
using nlohmann::json;
#undef private

namespace
{
// special test case to check if memory is leaked if constructor throws
template<class T>
struct bad_allocator : std::allocator<T>
{
    template<class... Args>
    void construct(T*, Args&& ...)
    {
        throw std::bad_alloc();
    }
};
}

TEST_CASE("bad_alloc")
{
    SECTION("bad_alloc")
    {
        // create JSON type using the throwing allocator
        using bad_json = nlohmann::basic_json<std::map,
              std::vector,
              std::string,
              bool,
              std::int64_t,
              std::uint64_t,
              double,
              bad_allocator>;

        // creating an object should throw
        CHECK_THROWS_AS(bad_json(bad_json::value_t::object), std::bad_alloc&);
    }
}

namespace
{
bool next_construct_fails = false;
bool next_destroy_fails = false;
bool next_deallocate_fails = false;

template<class T>
struct my_allocator : std::allocator<T>
{
    using std::allocator<T>::allocator;

    template<class... Args>
    void construct(T* p, Args&& ... args)
    {
        if (next_construct_fails)
        {
            next_construct_fails = false;
            throw std::bad_alloc();
        }
        else
        {
            ::new (reinterpret_cast<void*>(p)) T(std::forward<Args>(args)...);
        }
    }

    void deallocate(T* p, std::size_t n)
    {
        if (next_deallocate_fails)
        {
            next_deallocate_fails = false;
            throw std::bad_alloc();
        }
        else
        {
            std::allocator<T>::deallocate(p, n);
        }
    }

    void destroy(T* p)
    {
        if (next_destroy_fails)
        {
            next_destroy_fails = false;
            throw std::bad_alloc();
        }
        else
        {
            p->~T();
        }
    }

    template <class U>
    struct rebind
    {
        using other = my_allocator<U>;
    };
};

// allows deletion of raw pointer, usually hold by json_value
template<class T>
void my_allocator_clean_up(T* p)
{
    assert(p != nullptr);
    my_allocator<T> alloc;
    alloc.destroy(p);
    alloc.deallocate(p, 1);
}
}

TEST_CASE("controlled bad_alloc")
{
    // create JSON type using the throwing allocator
    using my_json = nlohmann::basic_json<std::map,
          std::vector,
          std::string,
          bool,
          std::int64_t,
          std::uint64_t,
          double,
          my_allocator>;

    SECTION("class json_value")
    {
        SECTION("json_value(value_t)")
        {
            SECTION("object")
            {
                next_construct_fails = false;
                auto t = my_json::value_t::object;
                CHECK_NOTHROW(my_allocator_clean_up(my_json::json_value(t).object));
                next_construct_fails = true;
                CHECK_THROWS_AS(my_json::json_value(t), std::bad_alloc&);
                next_construct_fails = false;
            }
            SECTION("array")
            {
                next_construct_fails = false;
                auto t = my_json::value_t::array;
                CHECK_NOTHROW(my_allocator_clean_up(my_json::json_value(t).array));
                next_construct_fails = true;
                CHECK_THROWS_AS(my_json::json_value(t), std::bad_alloc&);
                next_construct_fails = false;
            }
            SECTION("string")
            {
                next_construct_fails = false;
                auto t = my_json::value_t::string;
                CHECK_NOTHROW(my_allocator_clean_up(my_json::json_value(t).string));
                next_construct_fails = true;
                CHECK_THROWS_AS(my_json::json_value(t), std::bad_alloc&);
                next_construct_fails = false;
            }
        }

        SECTION("json_value(const string_t&)")
        {
            next_construct_fails = false;
            my_json::string_t v("foo");
            CHECK_NOTHROW(my_allocator_clean_up(my_json::json_value(v).string));
            next_construct_fails = true;
            CHECK_THROWS_AS(my_json::json_value(v), std::bad_alloc&);
            next_construct_fails = false;
        }
    }

    SECTION("class basic_json")
    {
        SECTION("basic_json(const CompatibleObjectType&)")
        {
            next_construct_fails = false;
            std::map<std::string, std::string> v {{"foo", "bar"}};
            CHECK_NOTHROW(my_json(v));
            next_construct_fails = true;
            CHECK_THROWS_AS(my_json(v), std::bad_alloc&);
            next_construct_fails = false;
        }

        SECTION("basic_json(const CompatibleArrayType&)")
        {
            next_construct_fails = false;
            std::vector<std::string> v {"foo", "bar", "baz"};
            CHECK_NOTHROW(my_json(v));
            next_construct_fails = true;
            CHECK_THROWS_AS(my_json(v), std::bad_alloc&);
            next_construct_fails = false;
        }

        SECTION("basic_json(const typename string_t::value_type*)")
        {
            next_construct_fails = false;
            CHECK_NOTHROW(my_json("foo"));
            next_construct_fails = true;
            CHECK_THROWS_AS(my_json("foo"), std::bad_alloc&);
            next_construct_fails = false;
        }

        SECTION("basic_json(const typename string_t::value_type*)")
        {
            next_construct_fails = false;
            std::string s("foo");
            CHECK_NOTHROW(my_json(s));
            next_construct_fails = true;
            CHECK_THROWS_AS(my_json(s), std::bad_alloc&);
            next_construct_fails = false;
        }
    }
}
