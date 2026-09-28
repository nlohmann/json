//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t
#include <cstdint> // uint16_t, uint32_t, uint64_t
#include <cstring> // memcmp, memcpy

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>
#include <nlohmann/detail/view/object_index.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// equality test for strings of one length n <= 16: two overlapping loads per
/// string (the first and the last 8, 4, or 2 bytes) replace a memcmp, and no
/// byte outside [s, s + n) is read
class short_key
{
  public:
    short_key(const unsigned char* k, std::size_t n) noexcept
        : m_n(n)
    {
        load(k, m_a, m_b);
    }

    NLOHMANN_VIEW_ALWAYS_INLINE bool matches(const unsigned char* s) const noexcept
    {
        std::uint64_t a = 0;
        std::uint64_t b = 0;
        load(s, a, b);
        return a == m_a && b == m_b;
    }

  private:
    template<typename T>
    static NLOHMANN_VIEW_ALWAYS_INLINE std::uint64_t load_word(const unsigned char* s) noexcept
    {
        T w = 0;
        std::memcpy(&w, s, sizeof(T));
        return w;
    }

    NLOHMANN_VIEW_ALWAYS_INLINE void load(const unsigned char* s, std::uint64_t& a, std::uint64_t& b) const noexcept
    {
        if (m_n >= 8)
        {
            a = load_word<std::uint64_t>(s);
            b = load_word<std::uint64_t>(s + m_n - 8);
        }
        else if (m_n >= 4)
        {
            a = load_word<std::uint32_t>(s);
            b = load_word<std::uint32_t>(s + m_n - 4);
        }
        else if (m_n >= 2)
        {
            a = load_word<std::uint16_t>(s);
            b = load_word<std::uint16_t>(s + m_n - 2);
        }
        else
        {
            a = m_n == 1 ? s[0] : 0;
            b = 0;
        }
    }

    std::size_t m_n;
    std::uint64_t m_a = 0;
    std::uint64_t m_b = 0;
};

/// the key node of the first member of an object with the given key, or
/// nullptr; most keys are rejected by their length, from the index alone
template<bool Editable>
const node* find_member(const document_data& d, const node* object, const char* key, std::size_t n) noexcept
{
    using nav = navigation<Editable>;
    if (NLOHMANN_VIEW_UNLIKELY(object->extra != 0) && (!Editable || (object->flags & node_flags::moved) == 0))
    {
        return find_indexed(d, object, key, n); // a large object (whose members have not been edited)
    }
    const node* const end = nav::end(d, object);
    const auto* const k = reinterpret_cast<const unsigned char*>(key); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    if (NLOHMANN_VIEW_LIKELY(n <= 16))
    {
        const short_key probe(k, n);
        for (const node* m = nav::first(d, object); m != end; m = document_data::after(m + 1))
        {
            if (m->len == n && probe.matches(reinterpret_cast<const unsigned char*>(d.str(*m)))) // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
            {
                return m;
            }
        }
        return nullptr;
    }
    for (const node* m = nav::first(d, object); m != end; m = document_data::after(m + 1))
    {
        if (m->len == n && std::memcmp(d.str(*m), key, n) == 0)
        {
            return m;
        }
    }
    return nullptr;
}

/// the entry of the element of an array at an index below its size (a link
/// in the moved sequences of editable documents)
template<bool Editable>
const node* element_at(const document_data& d, const node* array, std::size_t idx) noexcept
{
    const node* e = navigation<Editable>::first(d, array);
    if (Editable && (array->flags & node_flags::moved) != 0 && d.edits->moved_cap[array->off] != 0)
    {
        return e + idx; // a growable block: one link per element
    }
    for (std::size_t i = 0; i < idx; ++i)
    {
        e = document_data::after(e);
    }
    return e;
}

/// the entry of the last element of a non-empty array, or the key of the
/// last member of a non-empty object
template<bool Editable>
const node* last_child(const document_data& d, const node* container) noexcept
{
    const std::size_t value_offset = container->kind == static_cast<std::uint8_t>(value_t::object) ? 1 : 0;
    const node* const end = navigation<Editable>::end(d, container);
    const node* last = navigation<Editable>::first(d, container);
    for (const node* c = document_data::after(last + value_offset); c != end; c = document_data::after(c + value_offset))
    {
        last = c;
    }
    return last;
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
