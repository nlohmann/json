//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++20-only part of unit-allocator.cpp (creating a value from a
// std::ranges view with a failing allocator). It is kept in a separate translation unit so
// the (much larger) unit-allocator.cpp is built for C++11 only and not rebuilt for every
// C++ standard.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#ifdef JSON_HAS_CPP_20
#if JSON_HAS_RANGES
    #include <ranges>
#endif

#include <memory>
#include <new>
#include <utility>
#include <vector>

namespace
{
bool next_construct_fails_cpp20 = false;
bool next_destroy_fails_cpp20 = false;
bool next_deallocate_fails_cpp20 = false;

template<class T>
struct my_allocator_cpp20 : std::allocator<T>
{
    using std::allocator<T>::allocator;

    template<class... Args>
    void construct(T* p, Args&& ... args)
    {
        if (next_construct_fails_cpp20)
        {
            next_construct_fails_cpp20 = false;
            throw std::bad_alloc();
        }

        ::new (reinterpret_cast<void*>(p)) T(std::forward<Args>(args)...);
    }

    void deallocate(T* p, std::size_t n)
    {
        if (next_deallocate_fails_cpp20)
        {
            next_deallocate_fails_cpp20 = false;
            throw std::bad_alloc();
        }

        std::allocator<T>::deallocate(p, n);
    }

    void destroy(T* p)
    {
        if (next_destroy_fails_cpp20)
        {
            next_destroy_fails_cpp20 = false;
            throw std::bad_alloc();
        }

        static_cast<void>(p); // fix MSVC's C4100 warning
        p->~T();
    }

    template <class U>
    struct rebind
    {
        using other = my_allocator_cpp20<U>;
    };
};
} // namespace

// the no-exceptions CI job skips every CHECK_THROWS_AS, which would leave
// next_construct_fails_cpp20 set for the next allocation outside a check
#if !defined(JSON_NOEXCEPTION)
TEST_CASE("a failed allocation leaves the value unchanged (C++20)")
{
    // create JSON type using the throwing allocator
    using my_json = nlohmann::json::with_allocator_t<my_allocator_cpp20>;

    // With iterator debugging, VS 2015's containers construct a proxy with the
    // allocator in constructors that cannot report its failure, so a failing
    // allocator crashes this section there (SIGSEGV with VS 2015 Debug x86).
#if !(defined(_MSC_VER) && _MSC_VER < 1910 && defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL > 0)
    SECTION("converting into an existing value")
    {
        // to_json replaces the value it is given; the old one must survive a
        // failed creation of the new one
        my_json j = "old";

#if JSON_HAS_RANGES && !defined(__MINGW32__)
        const std::vector<int> numbers = {1, 2};
        next_construct_fails_cpp20 = true;
        CHECK_THROWS_AS(nlohmann::to_json(j, numbers | std::views::filter([](int /*unused*/)
        {
            return true;
        })), std::bad_alloc&);
        CHECK(j == "old");
#endif

        next_construct_fails_cpp20 = false;
    }
#endif
}
#endif
#endif
