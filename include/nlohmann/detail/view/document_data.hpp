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
#include <functional> // less
#include <map> // map
#include <memory> // unique_ptr
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
    std::array<const char*, 4> base = {{nullptr, nullptr, nullptr, nullptr}}; ///< string bases: source, arena, edit arena (indexed by flags & node_flags::storage)
    bool discarded = true;

    /// The storage of edits (editable documents only; see edit_storage.hpp).
    /// Edits never move or resize the parsed index, so views stay valid: an
    /// array/object whose elements change gets node_flags::moved, and its
    /// elements then live in a separate sequence (a header node, then the
    /// entries), whose entries link to the values.
    struct edit_state
    {
        std::vector<node*> moved{};                    ///< element sequences of moved arrays/objects (header node first) // NOLINT(readability-redundant-member-init)
        std::vector<std::size_t> moved_cap{};          ///< capacity in nodes of a growable block; 0: a fixed sequence (a new value) // NOLINT(readability-redundant-member-init)
        std::vector<std::unique_ptr<node[]>> chunks{}; ///< storage of new values and blocks; never moved // NOLINT(readability-redundant-member-init,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        std::map<const node*, node*, std::less<const node*>> regions{}; ///< new arrays/objects: root -> container that uses it as its element sequence (nullptr: linked from a block) // NOLINT(readability-redundant-member-init)
        node* chunk_cur = nullptr;
        node* chunk_end = nullptr;
        std::size_t chunk_next = 64;
        std::vector<std::unique_ptr<char[]>> texts{}; ///< edit arena, the current buffer last; earlier ones stay alive for string views // NOLINT(readability-redundant-member-init,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        std::size_t text_used = 0;
        std::size_t text_cap = 0;
        std::size_t bytes = 0; ///< memory held by edits
    };
    std::unique_ptr<edit_state> edits{}; ///< created by the first edit // NOLINT(readability-redundant-member-init)

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

    /// (editable documents) first element or key, also of a moved container
    NLOHMANN_VIEW_ALWAYS_INLINE const node* first_child_edited(const node* n) const noexcept
    {
        return NLOHMANN_VIEW_LIKELY((n->flags & node_flags::moved) == 0) ? n + 1 : edits->moved[n->off] + 1;
    }

    /// (editable documents) end of the elements, also of a moved container
    NLOHMANN_VIEW_ALWAYS_INLINE const node* child_end_edited(const node* n) const noexcept
    {
        if (NLOHMANN_VIEW_LIKELY((n->flags & node_flags::moved) == 0))
        {
            return n + n->next;
        }
        const node* const h = edits->moved[n->off];
        return h + h->next;
    }

    /// (editable documents) the value at an element position: entries of
    /// moved sequences are links. The link case is out of line, so that this
    /// compiles to a predicted branch rather than a select that delays the
    /// following loads.
    static NLOHMANN_VIEW_ALWAYS_INLINE const node* deref(const node* n) noexcept
    {
        return NLOHMANN_VIEW_LIKELY(n->kind != kind_link) ? n : follow_link(n);
    }

    static NLOHMANN_VIEW_NOINLINE const node* follow_link(const node* n) noexcept
    {
        return link_target(*n);
    }
};

/// How the index is walked: views of read-only documents follow the node
/// array alone and compile without any of the edit handling; views of
/// editable documents also follow moved element sequences and links.
template<bool Editable>
struct navigation
{
    static NLOHMANN_VIEW_ALWAYS_INLINE const node* first(const document_data& /*d*/, const node* n) noexcept
    {
        return n + 1;
    }

    static NLOHMANN_VIEW_ALWAYS_INLINE const node* end(const document_data& /*d*/, const node* n) noexcept
    {
        return n + n->next;
    }

    static NLOHMANN_VIEW_ALWAYS_INLINE const node* value(const node* n) noexcept
    {
        return n;
    }
};

template<>
struct navigation<true>
{
    static NLOHMANN_VIEW_ALWAYS_INLINE const node* first(const document_data& d, const node* n) noexcept
    {
        return d.first_child_edited(n);
    }

    static NLOHMANN_VIEW_ALWAYS_INLINE const node* end(const document_data& d, const node* n) noexcept
    {
        return d.child_end_edited(n);
    }

    static NLOHMANN_VIEW_ALWAYS_INLINE const node* value(const node* n) noexcept
    {
        return document_data::deref(n);
    }
};

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
