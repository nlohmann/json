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
#include <cstdint> // uint8_t, uint32_t
#include <cstring> // memcmp, memcpy
#include <limits> // numeric_limits
#include <map> // map
#include <memory> // unique_ptr
#include <new> // bad_alloc, operator new, placement new
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
    node* nodes = nullptr; ///< the node index (see node.hpp)
    std::size_t node_count = 0;
    std::size_t node_capacity = 0;
    node* inline_nodes = nullptr; ///< node array allocated together with this header
    std::size_t inline_capacity = 0;
    std::size_t max_depth = 0; ///< deepest nesting of arrays and objects (the root container is depth 1)
    std::vector<char> arena; ///< decoded strings that contained escapes (no terminator: they are handed out with their length)
    std::size_t arena_size = 0; ///< bytes of decoded strings at base[1] (the arena, or those of a loaded image)
    std::string owned; ///< owned copy of the input, if any (a std::string, so that its NUL serves as the parser's sentinel)
    std::vector<std::uint8_t> owned_image; ///< a loaded image the document owns (the text and the decoded strings point into it)

    // hash indexes of the keys of large objects (see object_index.hpp)
    static constexpr std::uint32_t index_min_members = 128;
    struct object_index
    {
        std::size_t start;  ///< first slot in index_slots
        std::uint32_t mask; ///< slot count - 1 (a power of two minus one)
    };
    std::vector<object_index> indexes;
    std::vector<std::uint32_t> index_slots;
    std::vector<std::uint32_t> large_objects; ///< positions of the objects to index (noted while parsing)
    std::array<const char*, 4> base = {{nullptr, nullptr, nullptr, nullptr}}; ///< string bases: source, arena, edit arena, unused (indexed by flags & node_flags::storage)
    bool discarded = true;

    /// The storage of edits (editable documents only; see edit_storage.hpp).
    /// No edit moves or resizes the parsed index, and the nodes of values
    /// written by edits never move either, so a view stays valid whenever it
    /// was taken, before the first edit or between later ones: an array/object
    /// whose elements change gets node_flags::moved, and its elements then live
    /// in a separate sequence (a header node, then the entries), whose entries
    /// link to the values.
    struct edit_state
    {
        std::vector<node*> moved{};                    ///< element sequences of moved arrays/objects (header node first) // NOLINT(readability-redundant-member-init)
        std::vector<std::size_t> moved_cap{};          ///< capacity in nodes of a growable block; 0: a fixed sequence (a new value) // NOLINT(readability-redundant-member-init)
        std::vector<std::unique_ptr<node[]>> chunks{}; ///< storage of new values and blocks; never moved // NOLINT(readability-redundant-member-init,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        std::map<const node*, node*> regions{}; ///< new arrays/objects: root -> container that uses it as its element sequence (nullptr: linked from a block) // NOLINT(readability-redundant-member-init)
        node* chunk_cur = nullptr;
        node* chunk_end = nullptr;
        std::size_t chunk_next = 64;
        std::vector<std::unique_ptr<char[]>> texts{}; ///< edit arena, the current buffer last; earlier ones stay alive for string views // NOLINT(readability-redundant-member-init,cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        std::size_t text_used = 0;
        std::size_t text_cap = 0;
        std::size_t bytes = 0; ///< memory held by edits
    };
    std::unique_ptr<edit_state> edits; ///< created by the first edit

    /// One allocation for the header and room for `count` nodes, so that a
    /// small document needs one allocation instead of two. Large documents get
    /// a separate node array instead (so it can be trimmed). When a document
    /// outgrows the inline array, that array stays unused: at most 256 nodes
    /// (4 KiB), and only for documents whose estimate was too small.
    static document_data* create(std::size_t count)
    {
        count = count <= 256 ? count : 0;
        void* mem = ::operator new (sizeof(document_data) + (count * sizeof(node)));
        auto* d = new (mem) document_data(); // NOLINT(cppcoreguidelines-owning-memory): owned by the returned pointer, freed by deleter
        // (aligned: sizeof is a multiple of the alignment; through void*, as GCC's -Wcast-align wants)
        // (null without inline nodes, not a pointer past the end of the allocation)
        d->inline_nodes = count == 0 ? nullptr : static_cast<node*>(static_cast<void*>(static_cast<char*>(mem) + sizeof(document_data))); // NOLINT(bugprone-casting-through-void)
        d->inline_capacity = count;
        d->nodes = d->inline_nodes;
        d->node_capacity = count;
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

    /// user-provided so that the class-type members can be initialized in the
    /// member initialization list (-Weffc++ asks for it, and old GCC rejects a
    /// defaulted constructor whose exception specification differs from the
    /// implicit one); they cannot take default member initializers, which old
    /// Clang (3.4-3.6) rejects. The other members have default member
    /// initializers. noexcept: create() constructs into raw memory and could not
    /// release it if this threw (the std::vector and std::string default
    /// constructors do not allocate).
    document_data() noexcept
        : arena() // NOLINT(readability-redundant-member-init)
        , owned() // NOLINT(readability-redundant-member-init)
        , owned_image() // NOLINT(readability-redundant-member-init)
        , indexes() // NOLINT(readability-redundant-member-init)
        , index_slots() // NOLINT(readability-redundant-member-init)
        , large_objects() // NOLINT(readability-redundant-member-init)
        , edits() // NOLINT(readability-redundant-member-init)
    {}
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
        if (nodes != inline_nodes)
        {
            ::operator delete (nodes);
        }
        nodes = inline_nodes;
        node_capacity = inline_capacity;
    }

    /// the largest node count whose size in bytes fits a std::size_t
    static constexpr std::size_t max_nodes() noexcept
    {
        return (std::numeric_limits<std::size_t>::max)() / sizeof(node);
    }

    [[noreturn]] NLOHMANN_VIEW_NOINLINE static void throw_bad_alloc()
    {
        NLOHMANN_VIEW_THROW(std::bad_alloc());
    }

    /// make room for n nodes; keeps the first node_count nodes (throws
    /// std::bad_alloc for a count that does not fit the address space,
    /// instead of wrapping around in n * sizeof(node))
    void reserve(std::size_t n)
    {
        if (n <= node_capacity)
        {
            return;
        }
        if (NLOHMANN_VIEW_UNLIKELY(n > max_nodes()))
        {
            throw_bad_alloc();
        }
        node* fresh = static_cast<node*>(::operator new (n * sizeof(node)));
        if (node_count != 0)
        {
            std::memcpy(fresh, nodes, node_count * sizeof(node));
        }
        release();
        nodes = fresh;
        node_capacity = n;
    }

    const char* str(const node& n) const noexcept
    {
        return base[n.flags & node_flags::storage] + n.off;
    }

    /// whether the string of node k (a key) is the n bytes at key
    bool key_equals(const node& k, const char* key, std::size_t n) const noexcept
    {
        return k.len == n && (n == 0 || std::memcmp(str(k), key, n) == 0);
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
    /// whether the walk follows edits (the template argument as a runtime
    /// condition: `Editable && ...` is a constant condition for MSVC, C4127)
    static NLOHMANN_VIEW_ALWAYS_INLINE bool editable() noexcept
    {
        return false;
    }

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
    static NLOHMANN_VIEW_ALWAYS_INLINE bool editable() noexcept
    {
        return true;
    }

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
