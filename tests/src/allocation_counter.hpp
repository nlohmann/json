//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // max
#include <cstddef> // size_t
#include <cstdint> // uint8_t
#include <memory> // allocator
#include <vector> // vector

#include <nlohmann/json.hpp>

namespace utils
{
/// the allocations of the values of a JSON type that uses counting_allocator
struct allocation_counts
{
    /// bytes allocated and not yet deallocated
    std::size_t current = 0;
    /// the largest value current had
    std::size_t peak = 0;
    /// number of allocations
    std::size_t allocations = 0;
};

/// the counts of all counting_allocators; the tests are single-threaded
inline allocation_counts& counts()
{
    static allocation_counts c; // NOLINT(misc-const-correctness)
    return c;
}

/// an allocator that counts the bytes and the number of allocations of a
/// JSON type, so that a test can check how much memory a parse holds at any
/// time without measuring the memory of the process
template<class T>
struct counting_allocator : std::allocator<T>
{
    using std::allocator<T>::allocator;

    counting_allocator() = default;
    template<class U> counting_allocator(const counting_allocator<U>& /*unused*/) noexcept {} // NOLINT(google-explicit-constructor,hicpp-explicit-conversions)

    template <class U>
    struct rebind
    {
        using other = counting_allocator<U>;
    };

    T* allocate(const std::size_t n)
    {
        T* const result = std::allocator<T>::allocate(n);
        allocation_counts& c = counts();
        c.current += n * sizeof(T);
        c.peak = (std::max)(c.peak, c.current);
        ++c.allocations;
        return result;
    }

    void deallocate(T* p, const std::size_t n)
    {
        counts().current -= n * sizeof(T);
        std::allocator<T>::deallocate(p, n);
    }
};

using counted_json = nlohmann::json::with_allocator_t<counting_allocator>;

/// @a count times the bytes of @a unit
inline std::vector<std::uint8_t> repeated(const std::vector<std::uint8_t>& unit, const std::size_t count)
{
    std::vector<std::uint8_t> result;
    result.reserve(unit.size() * count);
    for (std::size_t i = 0; i < count; ++i)
    {
        result.insert(result.end(), unit.begin(), unit.end());
    }
    return result;
}
} // namespace utils
