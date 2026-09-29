//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cstddef> // size_t
#include <cstdint> // uint32_t
#include <cstring> // memcpy
#include <new> // operator new, placement new
#include <string> // string
#include <vector> // vector

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// storage of a parsed document; heap-allocated (header and an initial node
/// array in one block) so that views survive moves of the owning document
struct document_data
{
    const char* src = nullptr;
    std::size_t size = 0;
    node* tape = nullptr;
    std::size_t tape_size = 0;
    std::size_t tape_cap = 0;
    node* inline_tape = nullptr; ///< node array allocated together with this header
    std::size_t inline_cap = 0;
    std::string arena{}; ///< decoded strings that contained escapes // NOLINT(readability-redundant-member-init)
    std::string owned{}; ///< owned copy of the input, if any // NOLINT(readability-redundant-member-init)

    // hash indexes of large objects (see object_index.hpp)
    static constexpr std::uint32_t index_min_members = 128;
    struct object_index
    {
        std::size_t start;  ///< first slot in index_slots
        std::uint32_t mask; ///< slot count - 1 (a power of two minus one)
    };
    std::vector<object_index> indexes{}; // NOLINT(readability-redundant-member-init)
    std::vector<std::uint32_t> index_slots{}; // NOLINT(readability-redundant-member-init)
    std::vector<std::uint32_t> large_objects{}; ///< positions of the objects to index (noted while parsing) // NOLINT(readability-redundant-member-init)
    std::array<const char*, 4> base = {{nullptr, nullptr, nullptr, nullptr}}; ///< string bases: source, arena (indexed by flags & node_flags::storage)
    bool discarded = true;

    /// one allocation for the header and room for `nodes` nodes; large
    /// documents get a separate node array instead (so it can be trimmed)
    static document_data* create(std::size_t nodes)
    {
        nodes = nodes <= 256 ? nodes : 0;
        void* mem = ::operator new (sizeof(document_data) + (nodes * sizeof(node)));
        auto* d = new (mem) document_data(); // NOLINT(cppcoreguidelines-owning-memory): owned by the returned pointer, freed by deleter
        // (aligned: sizeof is a multiple of the alignment; through void*, as GCC's -Wcast-align wants)
        d->inline_tape = static_cast<node*>(static_cast<void*>(static_cast<char*>(mem) + sizeof(document_data))); // NOLINT(bugprone-casting-through-void)
        d->inline_cap = nodes;
        d->tape = d->inline_tape;
        d->tape_cap = nodes;
        return d;
    }

    struct deleter
    {
        void operator()(document_data* d) const noexcept
        {
            d->~document_data();
            ::operator delete (d);
        }
    };

    document_data() = default;
    document_data(const document_data&) = delete;
    document_data(document_data&&) = delete;
    document_data& operator=(const document_data&) = delete;
    document_data& operator=(document_data&&) = delete;
    ~document_data()
    {
        release();
    }

    void release() noexcept
    {
        if (tape != inline_tape)
        {
            ::operator delete (tape);
        }
        tape = inline_tape;
        tape_cap = inline_cap;
    }

    /// make room for n nodes; keeps the first tape_size nodes
    void reserve(std::size_t n)
    {
        if (n <= tape_cap)
        {
            return;
        }
        node* fresh = static_cast<node*>(::operator new (n * sizeof(node)));
        if (tape_size != 0)
        {
            std::memcpy(fresh, tape, tape_size * sizeof(node));
        }
        release();
        tape = fresh;
        tape_cap = n;
    }

    const char* str(const node& n) const noexcept
    {
        return base[n.flags & node_flags::storage] + n.off;
    }

    /// the node after n's subtree (containers span `next` nodes, scalars one)
    static NLOHMANN_VIEW_ALWAYS_INLINE const node* after(const node* n) noexcept
    {
        return n + (is_container(*n) ? n->next : 1u);
    }

    /// first element (array) or first key (object) of a container
    static NLOHMANN_VIEW_ALWAYS_INLINE const node* first_child(const node* n) noexcept
    {
        return n + 1;
    }

    /// end of the elements of a container
    static NLOHMANN_VIEW_ALWAYS_INLINE const node* child_end(const node* n) noexcept
    {
        return n + n->next;
    }
};

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
