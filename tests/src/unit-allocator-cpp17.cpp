//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// This file contains the C++17-only part of unit-allocator.cpp (std::string_view key
// lookup with a failing allocator). It is kept in a separate translation unit so the (much
// larger) unit-allocator.cpp is built for C++11 only and not rebuilt for every C++
// standard.

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>

#ifdef JSON_HAS_CPP_17
#include <memory>
#include <new>
#include <string_view>
#include <utility>

namespace
{
bool next_construct_fails_cpp17 = false;
bool next_destroy_fails_cpp17 = false;
bool next_deallocate_fails_cpp17 = false;

template<class T>
struct my_allocator_cpp17 : std::allocator<T>
{
    using std::allocator<T>::allocator;

    template<class... Args>
    void construct(T* p, Args&& ... args)
    {
        if (next_construct_fails_cpp17)
        {
            next_construct_fails_cpp17 = false;
            throw std::bad_alloc();
        }

        ::new (reinterpret_cast<void*>(p)) T(std::forward<Args>(args)...);
    }

    void deallocate(T* p, std::size_t n)
    {
        if (next_deallocate_fails_cpp17)
        {
            next_deallocate_fails_cpp17 = false;
            throw std::bad_alloc();
        }

        std::allocator<T>::deallocate(p, n);
    }

    void destroy(T* p)
    {
        if (next_destroy_fails_cpp17)
        {
            next_destroy_fails_cpp17 = false;
            throw std::bad_alloc();
        }

        static_cast<void>(p); // fix MSVC's C4100 warning
        p->~T();
    }

    template <class U>
    struct rebind
    {
        using other = my_allocator_cpp17<U>;
    };
};
} // namespace

// the no-exceptions CI job skips every CHECK_THROWS_AS, which would leave
// next_construct_fails_cpp17 set for the next allocation outside a check
#if !defined(JSON_NOEXCEPTION)
TEST_CASE("a failed allocation leaves the value unchanged (C++17)")
{
    // create JSON type using the throwing allocator
    using my_json = nlohmann::json::with_allocator_t<my_allocator_cpp17>;

    SECTION("turning a null value into an array or object")
    {
        my_json j;

        next_construct_fails_cpp17 = true;
        CHECK_THROWS_AS(j[std::string_view("key")], std::bad_alloc&);
        CHECK(j.is_null());

        next_construct_fails_cpp17 = false;
    }
}
#endif
#endif
