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

TEST_CASE("get_allocator")
{
    const auto alloc = nlohmann::json::get_allocator();
    CHECK(alloc == std::allocator<nlohmann::json>());
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
                CAPTURE(objects)

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
// counts every allocation made on behalf of a basic_json value (of its own
// object_t/array_t/string_t/binary_t or of its own type), and can be told to
// fail one of them: the n-th call to allocate() throws std::bad_alloc instead
// of allocating, whichever type it is allocating for
std::size_t alloc_call_count = 0;
long fail_at_alloc_call = -1; // -1: never fail

template<class T>
struct nth_alloc_fails_allocator : std::allocator<T>
{
    using std::allocator<T>::allocator;

    T* allocate(std::size_t n)
    {
        const auto index = alloc_call_count++;
        if (fail_at_alloc_call >= 0 && index == static_cast<std::size_t>(fail_at_alloc_call))
        {
            throw std::bad_alloc();
        }
        return std::allocator<T>::allocate(n);
    }

    template <class U>
    struct rebind
    {
        using other = nth_alloc_fails_allocator<U>;
    };
};

// builds a value nested more than 128 levels deep - the bound the copy
// constructor descends into before it continues without the call stack - and
// checks that a copy survives any single allocation of it failing: every
// attempt either throws std::bad_alloc, without crashing or leaving the
// source altered, or completes the copy
template<class BasicJsonType>
void check_deep_copy_survives_failing_allocation(bool nest_objects)
{
    CAPTURE(nest_objects)

    fail_at_alloc_call = -1;

    // [[[ ... [1] ... ]]], or the same nesting with objects, 130 levels deep
    BasicJsonType src = 1;
    for (std::size_t i = 0; i < 130; ++i)
    {
        if (nest_objects)
        {
            BasicJsonType wrapper = BasicJsonType::object();
            wrapper["a"] = std::move(src);
            src = std::move(wrapper);
        }
        else
        {
            src = BasicJsonType::array({std::move(src)});
        }
    }

    const std::string original_dump = src.dump();

    // first measure how many allocations an unhindered copy takes
    alloc_call_count = 0;
    {
        // NOLINTNEXTLINE(performance-unnecessary-copy-initialization): the copy is what is measured
        const BasicJsonType measure(src);
    }
    const std::size_t total_allocations = alloc_call_count;
    REQUIRE(total_allocations > 0);
    REQUIRE(src.dump() == original_dump);

    // let the 0th, 1st, 2nd, ... allocation of the copy fail in turn; every
    // such copy must throw std::bad_alloc rather than crash, and the source
    // must come out exactly as it went in
    for (std::size_t n = 0; n < total_allocations; ++n)
    {
        CAPTURE(n)
        alloc_call_count = 0;
        fail_at_alloc_call = static_cast<long>(n);

        CHECK_THROWS_AS(BasicJsonType(src), std::bad_alloc&);

        fail_at_alloc_call = -1;
        CHECK(src.dump() == original_dump);
    }

    // once no allocation is made to fail, the copy itself must succeed
    fail_at_alloc_call = -1;
    const BasicJsonType copy(src);
    CHECK(copy.dump() == original_dump);
    CHECK(src.dump() == original_dump);
}
} // namespace

TEST_CASE("copy of a deeply nested value survives a failing allocation (#5640)")
{
    // With iterator debugging (MSVC STL debug builds, also used by clang-cl),
    // containers allocate a debug proxy through the allocator inside their
    // noexcept move constructors, so failing that allocation terminates the
    // program instead of throwing std::bad_alloc. Nothing to check there.
#if !(defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL > 0)
    SECTION("std::map-backed object_t")
    {
        using bad_alloc_json = nlohmann::basic_json<std::map,
              std::vector,
              std::string,
              bool,
              std::int64_t,
              std::uint64_t,
              double,
              nth_alloc_fails_allocator>;

        check_deep_copy_survives_failing_allocation<bad_alloc_json>(false);
        check_deep_copy_survives_failing_allocation<bad_alloc_json>(true);
    }

    SECTION("ordered_map-backed object_t")
    {
        using bad_alloc_ordered_json = nlohmann::basic_json<nlohmann::ordered_map,
              std::vector,
              std::string,
              bool,
              std::int64_t,
              std::uint64_t,
              double,
              nth_alloc_fails_allocator>;

        check_deep_copy_survives_failing_allocation<bad_alloc_ordered_json>(false);
        check_deep_copy_survives_failing_allocation<bad_alloc_ordered_json>(true);
    }
#endif
}

namespace
{
// counts the allocations of pairs with a non-const first member: the object
// types store std::pair<const Key, T>, so only the scratch space of the
// iterative deep copy allocates std::pair<Key, T>
std::size_t scratch_pair_allocations = 0;

template<class T>
struct is_scratch_pair : std::false_type {};

template<class K, class V>
struct is_scratch_pair<std::pair<K, V>> : std::integral_constant < bool, !std::is_const<K>::value > {};

template<class T>
struct scratch_counting_allocator : std::allocator<T>
{
    using std::allocator<T>::allocator;

    T* allocate(std::size_t n)
    {
        if (is_scratch_pair<T>::value)
        {
            ++scratch_pair_allocations;
        }
        return std::allocator<T>::allocate(n);
    }

#ifdef __cpp_lib_allocate_at_least
    // std::allocator<T>::allocate_at_least would bypass the counting, and
    // libc++'s containers prefer it over allocate from C++23 on
    auto allocate_at_least(std::size_t n)
    {
        if (is_scratch_pair<T>::value)
        {
            ++scratch_pair_allocations;
        }
        return std::allocator<T>::allocate_at_least(n);
    }
#endif

    template <class U>
    struct rebind
    {
        using other = scratch_counting_allocator<U>;
    };
};
} // namespace

TEST_CASE("deep copy uses the provided allocator")
{
    using counting_json = nlohmann::basic_json<std::map,
          std::vector,
          std::string,
          bool,
          std::int64_t,
          std::uint64_t,
          double,
          scratch_counting_allocator>;

    // deeper than the 128 levels the copy constructor descends into, so the
    // innermost objects are copied by the iterative deep copy
    counting_json j = 1;
    for (std::size_t i = 0; i < 300; ++i)
    {
        counting_json wrapper = counting_json::object();
        wrapper["a"] = std::move(j);
        j = std::move(wrapper);
    }

    scratch_pair_allocations = 0;
    // NOLINTNEXTLINE(performance-unnecessary-copy-initialization): the copy is what is tested
    const counting_json copy(j);
    CHECK(scratch_pair_allocations > 0);
    CHECK(copy == j);
}

namespace
{
// the number of constructions countdown_allocator lets happen, including the
// one that fails; 0 means none ever fails
std::size_t constructions_until_failure = 0;

template<class T>
struct countdown_allocator : std::allocator<T>
{
    using std::allocator<T>::allocator;

    template<class U, class... Args>
    void construct(U* p, Args&& ... args)
    {
        if (constructions_until_failure != 0)
        {
            --constructions_until_failure;
            if (constructions_until_failure == 0)
            {
                throw std::bad_alloc();
            }
        }

        ::new (static_cast<void*>(p)) U(std::forward<Args>(args)...);
    }

    template <class U>
    struct rebind
    {
        using other = countdown_allocator<U>;
    };
};
} // namespace

TEST_CASE("converting a deeply nested value from another specialization fails cleanly (#5650)")
{
    using countdown_json = nlohmann::basic_json<std::map,
          std::vector,
          std::string,
          bool,
          std::int64_t,
          std::uint64_t,
          double,
          countdown_allocator>;

    // deeper than the 128 levels the converting constructor descends into, so
    // that failures land on both sides of the bound - or, built with
    // JSON_NO_THREAD_LOCAL, all in the iterative conversion
    json j = {1, "two", {{"three", 3}}};
    for (std::size_t i = 0; i < 150; ++i)
    {
        j = json{{"a", json::array({j, "sibling"})}};
    }

    // Fail every construction in turn. Each failure has to reach the caller,
    // and everything built until then has to be destroyed cleanly.
    std::size_t failures = 0;
    for (std::size_t n = 1;; ++n)
    {
        constructions_until_failure = n;
        try
        {
            const countdown_json converted = j;
            constructions_until_failure = 0;
            CHECK(converted.dump() == j.dump());
            break;
        }
        catch (const std::bad_alloc&)
        {
            ++failures;
        }
    }
    CHECK(failures > 0);
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
