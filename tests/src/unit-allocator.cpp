//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#define JSON_TESTS_PRIVATE
#include <nlohmann/json.hpp>
using nlohmann::json;

namespace
{
// special test case to check if memory is leaked if constructor throws
template<class T>
struct bad_allocator : std::allocator<T>
{
    using std::allocator<T>::allocator;

    bad_allocator() = default;
    template<class U> bad_allocator(const bad_allocator<U>& /*unused*/) { }

    template<class... Args>
    [[noreturn]] void construct(T* /*unused*/, Args&& ... /*unused*/) // NOLINT(cppcoreguidelines-missing-std-forward)
    {
        throw std::bad_alloc();
    }

    template <class U>
    struct rebind
    {
        using other = bad_allocator<U>;
    };
};
} // namespace

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

        ::new (reinterpret_cast<void*>(p)) T(std::forward<Args>(args)...);
    }

    void deallocate(T* p, std::size_t n)
    {
        if (next_deallocate_fails)
        {
            next_deallocate_fails = false;
            throw std::bad_alloc();
        }

        std::allocator<T>::deallocate(p, n);
    }

    void destroy(T* p)
    {
        if (next_destroy_fails)
        {
            next_destroy_fails = false;
            throw std::bad_alloc();
        }

        static_cast<void>(p); // fix MSVC's C4100 warning
        p->~T();
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
} // namespace

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
            const my_json::string_t v("foo");
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
            const std::map<std::string, std::string> v {{"foo", "bar"}};
            CHECK_NOTHROW(my_json(v));
            next_construct_fails = true;
            CHECK_THROWS_AS(my_json(v), std::bad_alloc&);
            next_construct_fails = false;
        }

        SECTION("basic_json(const CompatibleArrayType&)")
        {
            next_construct_fails = false;
            const std::vector<std::string> v {"foo", "bar", "baz"};
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
            const std::string s("foo");
            CHECK_NOTHROW(my_json(s));
            next_construct_fails = true;
            CHECK_THROWS_AS(my_json(s), std::bad_alloc&);
            next_construct_fails = false;
        }

        SECTION("basic_json(const basic_json&) of a deeply nested value (#5387)")
        {
            // Copying a value nested deeper than the descent bound builds the
            // copy from the top down: every value whose own copy has not been
            // made yet stays a null value until it is. Failing an allocation
            // part-way through is what proves such a half-built copy can still
            // be destroyed.
            //
            // Which path the failure lands in depends on the build: the first
            // allocation of a copy belongs to the outermost level, so here it
            // is the descending one. Built with JSON_NO_THREAD_LOCAL - as the
            // ci_test_no_thread_local target builds the whole suite - no
            // descent is made at all and the very same failure lands in the
            // iterative path instead, part-way through its worklist.
            const auto check_deep_copy = [](bool objects)
            {
                CAPTURE(objects);

                next_construct_fails = false;

                // deeper than the 128 levels the copy constructor descends into
                const std::size_t depth = 300;

                my_json j = 1;
                for (std::size_t i = 0; i < depth; ++i)
                {
                    if (objects)
                    {
                        my_json wrapper = my_json::object();
                        wrapper["a"] = std::move(j);
                        j = std::move(wrapper);
                    }
                    else
                    {
                        j = my_json::array({std::move(j)});
                    }
                }

                // NOLINTNEXTLINE(performance-unnecessary-copy-initialization): the copy is what is tested
                CHECK_NOTHROW(my_json(j));

                next_construct_fails = true;
                // NOLINTNEXTLINE(performance-unnecessary-copy-initialization): the copy is what is tested
                CHECK_THROWS_AS(my_json(j), std::bad_alloc&);
                next_construct_fails = false;
            };

            check_deep_copy(false);
            check_deep_copy(true);
        }
    }
}

namespace
{
template<class T>
struct allocator_no_forward : std::allocator<T>
{
    allocator_no_forward() = default;
    template <class U>
    allocator_no_forward(allocator_no_forward<U> /*unused*/) {}

    template <class U>
    struct rebind
    {
        using other =  allocator_no_forward<U>;
    };

    template <class... Args>
    void construct(T* p, const Args& ... args) noexcept(noexcept(::new (static_cast<void*>(p)) T(args...)))
    {
        // force copy even if move is available
        ::new (static_cast<void*>(p)) T(args...);
    }
};
} // namespace

TEST_CASE("bad my_allocator::construct")
{
    SECTION("my_allocator::construct doesn't forward")
    {
        using bad_alloc_json = nlohmann::basic_json<std::map,
              std::vector,
              std::string,
              bool,
              std::int64_t,
              std::uint64_t,
              double,
              allocator_no_forward>;

        bad_alloc_json j;
        j["test"] = bad_alloc_json::array_t();
        j["test"].push_back("should not leak");
    }
}
