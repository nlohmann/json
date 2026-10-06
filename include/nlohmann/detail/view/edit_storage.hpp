//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // max, min
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t
#include <cstring> // memcpy
#include <functional> // less
#include <memory> // unique_ptr
#include <utility> // move

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/errors.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>

// The storage of edits. Edits never move or resize the parsed index: every
// value keeps its node, so views stay valid. New values and element sequences
// live in chunks that never move; strings and number tokens written by edits
// live in the edit arena. An array/object whose elements change gets
// node_flags::moved: its elements then live in a separate sequence (a header
// node, then the entries), whose entries link to the values (kind_link).

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

inline document_data::edit_state& edit_state_of(document_data& d)
{
    if (!d.edits)
    {
        d.edits.reset(new document_data::edit_state()); // NOLINT(cppcoreguidelines-owning-memory): owned by the unique_ptr
    }
    return *d.edits;
}

/// k consecutive nodes that never move (new values and blocks)
inline node* alloc_nodes(document_data& d, std::size_t k)
{
    document_data::edit_state& e = edit_state_of(d);
    if (NLOHMANN_VIEW_UNLIKELY(static_cast<std::size_t>(e.chunk_end - e.chunk_cur) < k))
    {
        const std::size_t count = (std::max)(k, e.chunk_next);
        std::unique_ptr<node[]> fresh(new node[count]()); // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        e.chunks.push_back(std::move(fresh));
        e.chunk_cur = e.chunks.back().get();
        e.chunk_end = e.chunk_cur + count;
        e.chunk_next = (std::min)(e.chunk_next * 2, std::size_t{65536});
        e.bytes += count * sizeof(node);
    }
    node* const r = e.chunk_cur;
    e.chunk_cur += k;
    return r;
}

/// copy n bytes into the edit arena and return their offset; a new buffer
/// leaves the old one alive, so that string views into it remain valid
inline std::uint32_t append_text(document_data& d, const char* s, std::size_t n)
{
    document_data::edit_state& e = edit_state_of(d);
    if (NLOHMANN_VIEW_UNLIKELY(e.text_cap - e.text_used < n))
    {
        const std::size_t cap = (std::max)(e.text_cap * 2, e.text_used + n + 256);
        if (cap > 0xFFFFFFFFu)
        {
            throw_out_of_range(416, "edits of 4 GiB or more are not supported by json_document"); // LCOV_EXCL_LINE (4 GiB)
        }
        std::unique_ptr<char[]> fresh(new char[cap]); // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        if (e.text_used != 0)
        {
            std::memcpy(fresh.get(), e.texts.back().get(), e.text_used);
        }
        e.texts.push_back(std::move(fresh));
        e.text_cap = cap;
        e.bytes += cap;
        d.base[2] = e.texts.back().get();
    }
    const auto off = static_cast<std::uint32_t>(e.text_used);
    if (n != 0)
    {
        std::memcpy(e.texts.back().get() + e.text_used, s, n);
    }
    e.text_used += n;
    return off;
}

/// the capacity in nodes of the block of a moved container (0: a fixed
/// sequence, the elements of a new value)
inline std::size_t moved_capacity(const document_data& d, const node* n) noexcept
{
    return d.edits->moved_cap[n->off];
}

/// let container n take its elements from `seq` (header node first)
inline void set_moved(document_data& d, node* n, node* seq, std::size_t cap)
{
    document_data::edit_state& e = edit_state_of(d);
    if ((n->flags & node_flags::moved) != 0)
    {
        e.moved[n->off] = seq;
        e.moved_cap[n->off] = cap;
        return;
    }
    if (e.moved.size() >= 0xFFFFFFFFu)
    {
        throw_out_of_range(416, "more than 4294967295 edited arrays and objects are not supported by json_document"); // LCOV_EXCL_LINE
    }
    if (e.moved.size() == e.moved.capacity() || e.moved_cap.size() == e.moved_cap.capacity())
    {
        // both grow before either changes, so that the push_backs cannot throw
        e.moved.reserve((2 * e.moved.size()) + 16);
        e.moved_cap.reserve((2 * e.moved.size()) + 16);
    }
    e.moved.push_back(seq);
    e.moved_cap.push_back(cap);
    n->off = static_cast<std::uint32_t>(e.moved.size() - 1);
    n->flags = static_cast<std::uint8_t>(n->flags | node_flags::moved | node_flags::is_new);
}

/// Make the elements of container n a growable block with room for `extra`
/// more nodes, and return its header. The entries link to the existing
/// values, which stay where they are. A block that grows is copied (its old
/// space is not reused).
inline node* block_of(document_data& d, node* n, std::size_t extra)
{
    if ((n->flags & node_flags::moved) != 0 && moved_capacity(d, n) != 0)
    {
        node* const h = d.edits->moved[n->off];
        if (h->next + extra <= moved_capacity(d, n))
        {
            return h;
        }
        const std::size_t cap = (std::max)(2 * moved_capacity(d, n), h->next + extra);
        node* const nh = alloc_nodes(d, cap);
        std::memcpy(nh, h, h->next * sizeof(node));
        set_moved(d, n, nh, cap);
        return nh;
    }
    const bool object = n->kind == static_cast<std::uint8_t>(value_t::object);
    const std::size_t used = 1 + (static_cast<std::size_t>(n->len) * (object ? 2 : 1));
    const std::size_t cap = used + extra;
    node* const h = alloc_nodes(d, cap);
    *h = node{};
    h->kind = n->kind;
    h->len = n->len;
    h->next = static_cast<std::uint32_t>(used);
    node* o = h + 1;
    for (const node* c = d.first_child_edited(n), *e = d.child_end_edited(n); c != e;)
    {
        if (object)
        {
            *o++ = *c++; // the key
        }
        make_link(*o, document_data::deref(c));
        ++o;
        c = document_data::after(c);
    }
    set_moved(d, n, h, cap);
    return h;
}

/// The container whose elements include `target`; nullptr for the root, for
/// a value that is no longer part of the document, and for a value that is
/// only reached through a link. Values never move between allocations, so
/// the path to `target` stays inside the allocation that holds it (the parsed
/// index, or one new value), where the extent of each container (`next`)
/// still covers its original subtree.
inline node* find_parent(const document_data& d, const node* target)
{
    const std::less<const node*> lt;
    const node* lo = d.tape;
    const node* hi = d.tape + d.tape_size;
    const node* c = d.tape;
    if (lt(target, lo) || !lt(target, hi))
    {
        if (!d.edits)
        {
            return nullptr; // LCOV_EXCL_LINE (nodes outside the index exist only after edits)
        }
        auto it = d.edits->regions.upper_bound(target);
        if (it == d.edits->regions.begin())
        {
            return nullptr; // LCOV_EXCL_LINE (an array/object with elements is in the index or a new value)
        }
        --it;
        lo = it->first;
        hi = lo + lo->next;
        if (!lt(target, hi))
        {
            return nullptr; // LCOV_EXCL_LINE (a single-node value, reached through a link)
        }
        // the root of a new value is the element sequence of its owner, or a linked value
        c = it->second != nullptr ? it->second : lo;
    }
    if (target == lo)
    {
        return nullptr;
    }
    for (;;)
    {
        if (!is_container(*c))
        {
            return nullptr; // LCOV_EXCL_LINE (the value is inside c)
        }
        const bool object = c->kind == static_cast<std::uint8_t>(value_t::object);
        const node* down = nullptr;
        for (const node* p = d.first_child_edited(c), *e = d.child_end_edited(c); p != e;)
        {
            const node* const at = object ? p + 1 : p;
            const node* const v = document_data::deref(at);
            if (v == target)
            {
                return const_cast<node*>(c); // NOLINT(cppcoreguidelines-pro-type-const-cast): the nodes belong to the document
            }
            if (is_container(*v) && !lt(v, lo) && lt(v, target) && lt(target, v + v->next))
            {
                down = v;
                break;
            }
            p = document_data::after(at);
        }
        if (down == nullptr)
        {
            return nullptr;
        }
        c = down;
    }
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
