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

#include <functional>
#include <limits>
#include <valarray>
#if JSON_HAS_RANGES
    #include <ranges>
#endif

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
        using bad_json = nlohmann::json::with_allocator_t<bad_allocator>;

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
    using my_json = nlohmann::json::with_allocator_t<my_allocator>;

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
        using bad_alloc_json = nlohmann::json::with_allocator_t<nth_alloc_fails_allocator>;

        check_deep_copy_survives_failing_allocation<bad_alloc_json>(false);
        check_deep_copy_survives_failing_allocation<bad_alloc_json>(true);
    }

    SECTION("ordered_map-backed object_t")
    {
        using bad_alloc_ordered_json = nlohmann::ordered_json::with_allocator_t<nth_alloc_fails_allocator>;

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
    using counting_json = nlohmann::json::with_allocator_t<scratch_counting_allocator>;

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
    // MSVC 2015's debug STL constructs the containers' debug proxies through
    // the allocator in noexcept constructors, so a failing construction crashes
    // the program there instead of throwing std::bad_alloc. Nothing to check.
#if !(defined(_MSC_VER) && _MSC_VER < 1910 && defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL > 0)
    using countdown_json = nlohmann::json::with_allocator_t<countdown_allocator>;

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
#endif
}

namespace
{
template<class T>
struct allocator_no_forward : std::allocator<T>
{
    allocator_no_forward() = default;
    template <class U>
    allocator_no_forward(const allocator_no_forward<U>& /*unused*/) {}

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
        using bad_alloc_json = nlohmann::json::with_allocator_t<allocator_no_forward>;

        bad_alloc_json j;
        j["test"] = bad_alloc_json::array_t();
        j["test"].push_back("should not leak");
    }
}

namespace
{
std::size_t counting_allocator_allocations = 0;
std::size_t counting_allocator_deallocations = 0;

template<class T>
struct counting_allocator : std::allocator<T>
{
    using std::allocator<T>::allocator;

    T* allocate(std::size_t n)
    {
        ++counting_allocator_allocations;
        return std::allocator<T>::allocate(n);
    }

    void deallocate(T* p, std::size_t n)
    {
        ++counting_allocator_deallocations;
        std::allocator<T>::deallocate(p, n);
    }

    template <class U>
    struct rebind
    {
        using other = counting_allocator<U>;
    };
};
} // namespace

TEST_CASE("destructor performs no allocation, only deallocation")
{
    // see https://github.com/nlohmann/json/issues/4842 and
    // https://github.com/nlohmann/json/issues/5135: destroying nested
    // arrays/objects used to allocate a temporary stack (first with
    // std::allocator, later - after #4842 - with the provided allocator).
    // Since that stack could itself throw bad_alloc from inside the
    // noexcept destructor (#5135), destroy() no longer allocates anything:
    // it only ever frees what is already there.
    using counting_json = nlohmann::json::with_allocator_t<counting_allocator>;

    SECTION("array")
    {
        auto* j = new counting_json({1, {2, {3, 4}}, 5}); // NOLINT(cppcoreguidelines-owning-memory)
        const auto allocations_before = counting_allocator_allocations;
        const auto deallocations_before = counting_allocator_deallocations;
        delete j; // NOLINT(cppcoreguidelines-owning-memory)
        CHECK(counting_allocator_allocations == allocations_before);
        CHECK(counting_allocator_deallocations > deallocations_before);
    }

    SECTION("object")
    {
        auto* j = new counting_json({{"a", {{"b", {1, 2}}}}, {"c", 3}}); // NOLINT(cppcoreguidelines-owning-memory)
        const auto allocations_before = counting_allocator_allocations;
        const auto deallocations_before = counting_allocator_deallocations;
        delete j; // NOLINT(cppcoreguidelines-owning-memory)
        CHECK(counting_allocator_allocations == allocations_before);
        CHECK(counting_allocator_deallocations > deallocations_before);
    }

    SECTION("mixed tree of empty/non-empty arrays and objects")
    {
        auto* j = new counting_json( // NOLINT(cppcoreguidelines-owning-memory)
        {
            {"empty_obj", counting_json::object()},
            {"empty_arr", counting_json::array()},
            {"nested", {{"a", counting_json::array({1, 2, counting_json::object()})}, {"b", 3}}},
            {"tail", counting_json::array({counting_json::array({1}), 2, counting_json::array({3})})}
        });
        const auto allocations_before = counting_allocator_allocations;
        const auto deallocations_before = counting_allocator_deallocations;
        delete j; // NOLINT(cppcoreguidelines-owning-memory)
        CHECK(counting_allocator_allocations == allocations_before);
        CHECK(counting_allocator_deallocations > deallocations_before);
    }
}

// the no-exceptions CI job skips every CHECK_THROWS_AS, which would leave
// next_construct_fails set for the next allocation outside a check
#if !defined(JSON_NOEXCEPTION)
TEST_CASE("a failed allocation leaves the value unchanged")
{
    // create JSON type using the throwing allocator
    using my_json = nlohmann::json::with_allocator_t<my_allocator>;

    // Each of these creates a string, array, object, or binary value. The
    // value must be created before the type is changed: otherwise, a failed
    // creation left a value of the new type without anything behind it (an
    // assertion in its destructor, a null pointer everywhere else) or, when
    // an old value was destroyed first, with a pointer to that destroyed one.

    SECTION("creating a binary value")
    {
        const std::vector<std::uint8_t> bytes = {1, 2, 3};
        my_json _;

        next_construct_fails = true;
        CHECK_THROWS_AS(_ = my_json::binary(bytes), std::bad_alloc&);
        next_construct_fails = true;
        CHECK_THROWS_AS(_ = my_json::binary(bytes, 42), std::bad_alloc&);
        next_construct_fails = true;
        CHECK_THROWS_AS(_ = my_json::binary(std::vector<std::uint8_t>(bytes)), std::bad_alloc&);
        next_construct_fails = true;
        CHECK_THROWS_AS(_ = my_json::binary(std::vector<std::uint8_t>(bytes), 42), std::bad_alloc&);
        next_construct_fails = false;
    }

    SECTION("turning a null value into an array or object")
    {
        my_json j;

        next_construct_fails = true;
        CHECK_THROWS_AS(j[0], std::bad_alloc&);
        CHECK(j.is_null());

        next_construct_fails = true;
        CHECK_THROWS_AS(j["key"], std::bad_alloc&);
        CHECK(j.is_null());

#ifdef JSON_HAS_CPP_17
        next_construct_fails = true;
        CHECK_THROWS_AS(j[std::string_view("key")], std::bad_alloc&);
        CHECK(j.is_null());
#endif

        next_construct_fails = true;
        CHECK_THROWS_AS(j.push_back(my_json(1)), std::bad_alloc&);
        CHECK(j.is_null());

        const my_json one = 1;
        next_construct_fails = true;
        CHECK_THROWS_AS(j.push_back(one), std::bad_alloc&);
        CHECK(j.is_null());

        next_construct_fails = true;
        CHECK_THROWS_AS(j.push_back(my_json::object_t::value_type("key", 1)), std::bad_alloc&);
        CHECK(j.is_null());

        next_construct_fails = true;
        CHECK_THROWS_AS(j.emplace_back(1), std::bad_alloc&);
        CHECK(j.is_null());

        next_construct_fails = true;
        CHECK_THROWS_AS(j.emplace("key", 1), std::bad_alloc&);
        CHECK(j.is_null());

        const my_json object = {{"key", 1}};
        next_construct_fails = true;
        CHECK_THROWS_AS(j.update(object), std::bad_alloc&);
        CHECK(j.is_null());

        next_construct_fails = false;
    }

    // With iterator debugging, VS 2015's containers construct a proxy with the
    // allocator in constructors that cannot report its failure, so a failing
    // allocator crashes this section there (SIGSEGV with VS 2015 Debug x86).
#if !(defined(_MSC_VER) && _MSC_VER < 1910 && defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL > 0)
    SECTION("converting into an existing value")
    {
        // to_json replaces the value it is given; the old one must survive a
        // failed creation of the new one
        my_json j = "old";

        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, std::string("new")), std::bad_alloc&);
        CHECK(j == "old");

        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, std::vector<int> {1, 2}), std::bad_alloc&);
        CHECK(j == "old");

        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, std::vector<bool> {true, false}), std::bad_alloc&);
        CHECK(j == "old");

        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, std::map<std::string, int> {{"a", 1}}), std::bad_alloc&);
        CHECK(j == "old");

        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, my_json::binary_t({1, 2})), std::bad_alloc&);
        CHECK(j == "old");

        // the overloads for lvalues of the value types, for the value types
        // themselves, and for the remaining compatible types
        const std::string string = "new";
        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, string), std::bad_alloc&);
        CHECK(j == "old");

        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, "new"), std::bad_alloc&);
        CHECK(j == "old");

        // to_json only moves a binary value that it converted from another
        // container type, which my_json's std::vector<std::uint8_t> is not
        using binary_constructor = nlohmann::detail::external_constructor<nlohmann::detail::value_t::binary>;
        next_construct_fails = true;
        CHECK_THROWS_AS(binary_constructor::construct(j, my_json::binary_t({1, 2})), std::bad_alloc&);
        CHECK(j == "old");

        my_json::array_t array = {1, 2};
        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, array), std::bad_alloc&);
        CHECK(j == "old");
        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, std::move(array)), std::bad_alloc&);
        CHECK(j == "old");

        my_json::object_t object = {{"a", 1}};
        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, object), std::bad_alloc&);
        CHECK(j == "old");
        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, std::move(object)), std::bad_alloc&);
        CHECK(j == "old");

        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, std::valarray<int> {1, 2}), std::bad_alloc&);
        CHECK(j == "old");

#if JSON_HAS_RANGES && !defined(__MINGW32__)
        const std::vector<int> numbers = {1, 2};
        next_construct_fails = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, numbers | std::views::filter([](int /*unused*/) noexcept
        {
            return true;
        })), std::bad_alloc&);
        CHECK(j == "old");
#endif

        next_construct_fails = false;
        nlohmann::to_json(j, std::vector<int> {1, 2});
        CHECK(j == my_json({1, 2}));
    }
#endif
}
#endif

// the no-exceptions CI job has no std::bad_alloc to catch; with iterator
// debugging (MSVC STL debug builds) containers allocate inside noexcept
// functions, so failing an allocation there terminates the program
#if !defined(JSON_NOEXCEPTION) && !(defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL > 0)
namespace
{
// whether every child of j names j as its parent (always true without
// JSON_DIAGNOSTICS, where no parents are stored)
template<class BasicJsonType>
bool children_name_their_parent(const BasicJsonType& j)
{
#if JSON_DIAGNOSTICS
    if (j.is_array())
    {
        for (const auto& element : *j.m_data.m_value.array)
        {
            if (element.m_parent != &j)
            {
                return false;
            }
        }
    }
    else if (j.is_object())
    {
        for (const auto& element : *j.m_data.m_value.object)
        {
            if (element.second.m_parent != &j)
            {
                return false;
            }
        }
    }
#else
    static_cast<void>(j);
#endif
    return true;
}

enum class guarantee
{
    basic, // the value stays valid and keeps its type
    strong // the value is unchanged
};

// Runs op on a fresh value make() with the 0th, 1st, 2nd, ... allocation made
// by the library failing in turn, until op completes. Every failed attempt
// must have thrown std::bad_alloc and left the value valid, with all parent
// pointers intact (copying a value asserts the invariant), and for the strong
// guarantee exactly as it was.
template<class BasicJsonType>
void check_exception_guarantee(guarantee g,
                               const std::function<BasicJsonType()>& make,
                               const std::function<void(BasicJsonType&)>& op)
{
    fail_at_alloc_call = -1;

    bool completed = false;
    std::size_t failures = 0;
    for (std::size_t n = 0; !completed; ++n)
    {
        CAPTURE(n)
        REQUIRE(n < 1000);

        BasicJsonType j = make();
        const std::string before = j.dump();
        const auto type_before = j.type();

        alloc_call_count = 0;
        fail_at_alloc_call = static_cast<long>(n);
        try
        {
            op(j);
            completed = true;
        }
        catch (const std::bad_alloc&)
        {
            ++failures;
        }
        fail_at_alloc_call = -1;

        if (!completed)
        {
            CHECK((j.type() == type_before));
            CHECK(children_name_their_parent(j));
            const BasicJsonType copy(j); // NOLINT(performance-unnecessary-copy-initialization): the copy is the point, it allocates
            CHECK(copy.dump() == j.dump());
            if (g == guarantee::strong)
            {
                CHECK(j.dump() == before);
            }
        }
    }

    // the operation allocates, so at least one attempt must have failed
    CHECK(failures > 0);
}

template<class BasicJsonType>
void check_insert_exception_guarantees()
{
    using json_t = BasicJsonType;
    using make_t = std::function<json_t()>;

    // strings of this length do not fit into the small string buffer, so
    // copying them allocates
    const json_t val = std::string(64, 'x');
    const json_t source = json_t::array({std::string(64, 'p'), std::string(64, 'q'), std::string(64, 'r')});

    for (const bool spare_capacity :
            {
                false, true
            })
    {
        CAPTURE(spare_capacity)

        // [ "aaa...", "bbb...", "ccc..." ], with a spare slot if requested
        const make_t make = [spare_capacity]()
        {
            json_t j = json_t::array({std::string(64, 'a'), std::string(64, 'b'), std::string(64, 'c')});
            if (spare_capacity)
            {
                j.push_back(std::string(64, 'd'));
                j.erase(3);
            }
            return json_t(std::move(j));
        };

        for (const bool at_end :
                {
                    false, true
                })
        {
            CAPTURE(at_end)

            SECTION("insert(pos, const basic_json&)")
            {
                check_exception_guarantee<json_t>(guarantee::strong, make, [&](json_t& j)
                {
                    j.insert(at_end ? j.end() : j.begin() + 1, val);
                });
            }

            SECTION("insert(pos, basic_json&&)")
            {
                check_exception_guarantee<json_t>(guarantee::strong, make, [&](json_t& j)
                {
                    j.insert(at_end ? j.end() : j.begin() + 1, json_t(val));
                });
            }

            SECTION("insert(pos, size_type, const basic_json&)")
            {
                check_exception_guarantee<json_t>(guarantee::basic, make, [&](json_t& j)
                {
                    j.insert(at_end ? j.end() : j.begin() + 1, 3, val);
                });
            }

            SECTION("insert(pos, const_iterator, const_iterator)")
            {
                check_exception_guarantee<json_t>(guarantee::basic, make, [&](json_t& j)
                {
                    j.insert(at_end ? j.end() : j.begin() + 1, source.begin(), source.end());
                });
            }

            SECTION("insert(pos, initializer_list_t)")
            {
                check_exception_guarantee<json_t>(guarantee::basic, make, [&](json_t& j)
                {
                    j.insert(at_end ? j.end() : j.begin() + 1, {val, val});
                });
            }
        }
    }

    SECTION("insert(const_iterator, const_iterator) for objects")
    {
        const json_t members = {{"m", std::string(64, 'm')}, {"n", std::string(64, 'n')}, {"o", std::string(64, 'o')}};

        SECTION("no member exists yet")
        {
            check_exception_guarantee<json_t>(guarantee::basic, []()
            {
                return json_t({{"a", 1}});
            }, [&](json_t& j)
            {
                j.insert(members.begin(), members.end());
            });
        }

        SECTION("some members exist already")
        {
            check_exception_guarantee<json_t>(guarantee::basic, []()
            {
                return json_t({{"a", 1}, {"n", std::string(64, 'x')}});
            }, [&](json_t& j)
            {
                j.insert(members.begin(), members.end());
            });
        }
    }
}
} // namespace

TEST_CASE("insert() provides its documented exception guarantees (#5986)")
{
    SECTION("std::map-backed object_t")
    {
        check_insert_exception_guarantees<nlohmann::json::with_allocator_t<nth_alloc_fails_allocator>>();
    }

    SECTION("ordered_map-backed object_t")
    {
        check_insert_exception_guarantees<nlohmann::ordered_json::with_allocator_t<nth_alloc_fails_allocator>>();
    }
}
#endif

#if !defined(JSON_NOEXCEPTION)
namespace
{
// the allocation numbered sweep_fail_at (counted from 1) throws; 0 never fails
std::size_t sweep_allocations = 0;
std::size_t sweep_fail_at = 0;
std::ptrdiff_t sweep_live = 0;

template<class T>
struct sweep_allocator
{
    using value_type = T;
    // GCC 4.8's std::map takes these from the allocator instead of from
    // std::allocator_traits
    using pointer = T*;
    using const_pointer = const T*;
    using reference = T&;
    using const_reference = const T&;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;

    sweep_allocator() = default;
    template<class U> sweep_allocator(const sweep_allocator<U>& /*unused*/) noexcept {}

    T* allocate(std::size_t n)
    {
        if (sweep_fail_at != 0 && ++sweep_allocations == sweep_fail_at)
        {
            throw std::bad_alloc();
        }
        ++sweep_live;
        return std::allocator<T>().allocate(n);
    }

    void deallocate(T* p, std::size_t n) noexcept
    {
        --sweep_live;
        std::allocator<T>().deallocate(p, n);
    }

    // GCC 4.8's std::map calls these on the allocator directly instead of
    // going through std::allocator_traits
    std::size_t max_size() const noexcept
    {
        return (std::numeric_limits<std::size_t>::max)() / sizeof(T);
    }

    template<class U, class... Args>
    void construct(U* p, Args&& ... args) noexcept(noexcept(::new (static_cast<void*>(p)) U(std::forward<Args>(args)...)))
    {
        ::new (static_cast<void*>(p)) U(std::forward<Args>(args)...);
    }

    // libc++ probes whether construct() is usable for const objects (when
    // checking for trivial copies); this must not be viable then
    template<class U, class... Args>
    void construct(const U* /*unused*/, const Args& ... /*unused*/) = delete;

    template<class U>
    void destroy(U* p) noexcept
    {
        static_cast<void>(p); // unused for trivially destructible types
        p->~U();
    }

    template <class U>
    struct rebind
    {
        using other = sweep_allocator<U>;
    };

    bool operator==(const sweep_allocator& /*unused*/) const noexcept
    {
        return true;
    }
    bool operator!=(const sweep_allocator& /*unused*/) const noexcept
    {
        return false;
    }
};

// run make() with the allocation numbered k failing, for k = 1, 2, ...: every
// failure must be a std::bad_alloc and must not leave anything behind, and
// the first k without a failure must yield the value made without failures
template<class BasicJsonType, class Make>
void sweep_allocations_of(const Make& make)
{
    sweep_fail_at = 0;
    const BasicJsonType expected = make();
    const std::ptrdiff_t live_before = sweep_live;

    std::size_t failures = 0;
    for (std::size_t k = 1; k < 10000; ++k)
    {
        sweep_allocations = 0;
        sweep_fail_at = k;
        try
        {
            const BasicJsonType result = make();
            sweep_fail_at = 0;
            CHECK(result == expected);
            break;
        }
        catch (const std::bad_alloc&)
        {
            sweep_fail_at = 0;
            ++failures;
        }
        CHECK(sweep_live == live_before);
    }
    sweep_fail_at = 0;
    CHECK(failures > 10);
    CHECK(sweep_live == live_before);
}
} // namespace

TEST_CASE("parse() survives a failing allocation at every point (#5985)")
{
    // strings beyond the small string buffer, nested objects and arrays
    const std::string text = R"({"a":"a long string that does not fit into the small string buffer1","b":[1,2,[3,{"k":"another string that is longer than any small string buffer"}]],"c":{"x":1,"y":{"z":[]},"w":"yet another string that does not fit into a small buffer"},"d":1,"b":[[],{}]})";

    using sweep_json = nlohmann::json::with_allocator_t<sweep_allocator>;
    using sweep_ordered_json = nlohmann::ordered_json::with_allocator_t<sweep_allocator>;

    SECTION("json")
    {
        sweep_allocations_of<sweep_json>([&]
        {
            return sweep_json::parse(text);
        });
    }

    SECTION("ordered_json")
    {
        sweep_allocations_of<sweep_ordered_json>([&]
        {
            return sweep_ordered_json::parse(text);
        });
    }

    // With iterator debugging (MSVC STL debug builds, also used by clang-cl),
    // containers allocate a debug proxy through the allocator inside their
    // noexcept default and move constructors, so failing that allocation
    // terminates the program instead of throwing std::bad_alloc. Nothing to
    // check there.
#if !(defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL > 0)
    // Clang 3.4 and 3.5 leak memory when an element constructor throws
    // inside libstdc++'s containers (a std::map copy, a std::vector
    // reallocation), without any json value involved.
#if !(defined(__clang__) && !defined(__apple_build_version__) && __clang_major__ == 3 && __clang_minor__ < 6)
    SECTION("parser callback")
    {
        const auto keep_all = [](int /*depth*/, sweep_json::parse_event_t /*event*/, sweep_json& /*parsed*/) noexcept
        {
            return true;
        };
        sweep_allocations_of<sweep_json>([&]
        {
            return sweep_json::parse(text, keep_all);
        });

        const auto drop_d = [](int /*depth*/, sweep_json::parse_event_t event, sweep_json & parsed)
        {
            return event != sweep_json::parse_event_t::key || parsed != "d";
        };
        sweep_allocations_of<sweep_json>([&]
        {
            return sweep_json::parse(text, drop_d);
        });
    }

    SECTION("sax_parse into an existing value")
    {
        // a failed parse leaves the target in a state that is safe to destroy
        using sax_t = nlohmann::detail::json_sax_dom_parser<sweep_json, nlohmann::detail::iterator_input_adapter<const char*>>;
        sweep_allocations_of<sweep_json>([&]() -> sweep_json
        {
            sweep_json value;
            sax_t sax(value, false);
            static_cast<void>(sweep_json::sax_parse(text, &sax));
            return value;
        });
    }
#endif
#endif
}
#endif
