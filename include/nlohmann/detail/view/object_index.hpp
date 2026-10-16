//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t
#include <cstdint> // uint32_t, uint64_t

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>

// Hash indexes of the keys of large objects, so that a lookup does not compare thousands
// of keys (as Boost.JSON switches from a linear search to a hash table for
// large objects). An object with document_data::index_min_members members or
// more gets an open-addressing table after parsing; its node stores the
// number of the table (1-based) in `extra`. A slot holds the offset of a key
// node from its object node (0: empty). Of duplicate keys, the first is kept,
// as for the linear search.
//
// The hash is not seeded, so keys chosen to collide could make the build
// quadratic. A key therefore sits at most index_max_displacement slots away
// from its home slot; if a key would sit further away, the table is dropped
// and the object is searched linearly (like a small one). For the same
// reason, a lookup visits at most index_max_displacement + 1 slots.

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// the farthest a key may sit from its home slot (a table with at most half of
/// its slots in use gives random keys a distance of about 50 for millions of
/// members; and every member costs at most this many steps while building)
constexpr std::size_t index_max_displacement = 64;

// a table has at least 2 * len slots (len >= index_min_members), so the probe
// window of index_max_displacement + 1 slots stays far smaller than the table
// and a probe never wraps around onto its own start
static_assert(document_data::index_min_members >= 2 * index_max_displacement,
              "a table must be much larger than the probe window of a lookup");

/// hash of a key: its bytes, eight at a time (in a fixed byte order), where the
/// last word may overlap the one before (so that no loop over single bytes is
/// needed); a key of fewer than eight bytes is read as two overlapping words of
/// four or two bytes (in the native byte order: the hash is not stored, and the
/// same on both sides of a lookup)
inline std::uint64_t key_hash(const char* s, std::size_t n) noexcept
{
    std::uint64_t h = 0x9E3779B97F4A7C15u * (n + 1);
    const auto* p = reinterpret_cast<const unsigned char*>(s); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    std::uint64_t w = 0;
    if (n >= 8)
    {
        const unsigned char* const last = p + n - 8;
        while (p < last)
        {
            h = (h ^ read_eight_bytes(p)) * 0xBF58476D1CE4E5B9u;
            h ^= h >> 29u;
            p += 8;
        }
        w = read_eight_bytes(last);
    }
    else if (n >= 4)
    {
        std::uint32_t head = 0;
        std::uint32_t tail = 0;
        std::memcpy(&head, p, 4);
        std::memcpy(&tail, p + n - 4, 4);
        w = static_cast<std::uint64_t>(head) | (static_cast<std::uint64_t>(tail) << 32u);
    }
    else if (n >= 2)
    {
        std::uint16_t head = 0;
        std::uint16_t tail = 0;
        std::memcpy(&head, p, 2);
        std::memcpy(&tail, p + n - 2, 2);
        w = static_cast<std::uint64_t>(head) | (static_cast<std::uint64_t>(tail) << 16u);
    }
    else if (n == 1)
    {
        w = p[0];
    }
    // (a product only carries bits upwards, and the slot is taken from the low
    // bits: the high bits of the last word are folded down before the multiplication)
    h = (h ^ w ^ (w >> 29u)) * 0x94D049BB133111EBu;
    return h ^ (h >> 31u);
}

/// whether the n <= 16 bytes at a and b are equal, as two overlapping words
/// (the first and the last 8, 4, or 2 bytes) and without a call
NLOHMANN_VIEW_ALWAYS_INLINE bool same_short_bytes(const unsigned char* a, const unsigned char* b, std::size_t n) noexcept
{
    if (n >= 8)
    {
        std::uint64_t x0 = 0;
        std::uint64_t x1 = 0;
        std::uint64_t y0 = 0;
        std::uint64_t y1 = 0;
        std::memcpy(&x0, a, 8);
        std::memcpy(&x1, a + n - 8, 8);
        std::memcpy(&y0, b, 8);
        std::memcpy(&y1, b + n - 8, 8);
        return x0 == y0 && x1 == y1;
    }
    if (n >= 4)
    {
        std::uint32_t x0 = 0;
        std::uint32_t x1 = 0;
        std::uint32_t y0 = 0;
        std::uint32_t y1 = 0;
        std::memcpy(&x0, a, 4);
        std::memcpy(&x1, a + n - 4, 4);
        std::memcpy(&y0, b, 4);
        std::memcpy(&y1, b + n - 4, 4);
        return x0 == y0 && x1 == y1;
    }
    if (n >= 2)
    {
        std::uint16_t x0 = 0;
        std::uint16_t x1 = 0;
        std::uint16_t y0 = 0;
        std::uint16_t y1 = 0;
        std::memcpy(&x0, a, 2);
        std::memcpy(&x1, a + n - 2, 2);
        std::memcpy(&y0, b, 2);
        std::memcpy(&y1, b + n - 2, 2);
        return x0 == y0 && x1 == y1;
    }
    return n == 0 || *a == *b;
}

/// build the table of a large object
inline void build_object_index(document_data& d, node* obj)
{
    if (d.indexes.size() >= 0xFFFFu)
    {
        return; // LCOV_EXCL_LINE (the number must fit `extra`; more large objects are searched linearly)
    }
    std::size_t cap = 16;
    while (cap < 2 * static_cast<std::size_t>(obj->len))
    {
        cap *= 2;
    }
    const std::size_t start = d.index_slots.size();
    d.index_slots.resize(start + cap, 0);
    std::uint32_t* const table = d.index_slots.data() + start;
    const std::size_t mask = cap - 1;
    for (const node* k = document_data::first_child(obj), *end = document_data::child_end(obj); k != end; k = document_data::after(k + 1))
    {
        const char* const key = d.str(*k);
        std::size_t slot = conditional_static_cast<std::size_t>(key_hash(key, k->len)) & mask;
        bool duplicate = false;
        std::size_t distance = 0;
        while (table[slot] != 0)
        {
            const node* const other = obj + table[slot];
            if (d.key_equals(*other, key, k->len))
            {
                duplicate = true; // keep the first
                break;
            }
            if (distance == index_max_displacement)
            {
                // too many keys share a home region
                d.index_slots.resize(start); // no table: the object is searched linearly
                return;
            }
            ++distance;
            slot = (slot + 1) & mask;
        }
        if (!duplicate)
        {
            table[slot] = static_cast<std::uint32_t>(k - obj);
        }
    }
    d.indexes.push_back(document_data::object_index{start, static_cast<std::uint32_t>(mask)});
    obj->extra = static_cast<std::uint16_t>(d.indexes.size());
}

/// build the tables of the large objects the parser noted
inline void build_object_indexes(document_data& d)
{
    for (const std::uint32_t i : d.large_objects)
    {
        build_object_index(d, d.nodes + i);
    }
}

/// the key node of the first member with this key of an indexed object, or
/// nullptr
inline const node* find_indexed(const document_data& d, const node* obj, const char* key, std::size_t n) noexcept
{
    const document_data::object_index& ix = d.indexes[obj->extra - 1u];
    const std::uint32_t* const table = d.index_slots.data() + ix.start;
    std::size_t slot = conditional_static_cast<std::size_t>(key_hash(key, n)) & ix.mask;
    const auto* const k_bytes = reinterpret_cast<const unsigned char*>(key); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    // (the loop for longer keys comes first, as the code is laid out; it is not the more common case)
    if (NLOHMANN_VIEW_UNLIKELY(n <= 16))
    {
        // (up to 16 bytes, the bytes are compared as two words, without a call)
        for (std::size_t distance = 0; distance <= index_max_displacement; ++distance)
        {
            const std::uint32_t s = table[slot];
            if (s == 0)
            {
                return nullptr;
            }
            const node* const k = obj + s;
            if (k->len == n && same_short_bytes(reinterpret_cast<const unsigned char*>(d.str(*k)), k_bytes, n)) // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
            {
                return k;
            }
            slot = (slot + 1) & ix.mask;
        }
        return nullptr;
    }
    for (std::size_t distance = 0; distance <= index_max_displacement; ++distance)
    {
        const std::uint32_t s = table[slot];
        if (s == 0)
        {
            return nullptr;
        }
        const node* const k = obj + s;
        if (d.key_equals(*k, key, n))
        {
            return k;
        }
        slot = (slot + 1) & ix.mask;
    }
    return nullptr; // (no key sits further from its home slot)
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
