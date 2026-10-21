//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // is_sorted, sort, stable_sort
#include <array> // array
#include <cstddef> // size_t
#include <cstdint> // int64_t, uint32_t, uint64_t
#include <functional> // equal_to
#include <string> // string
#include <utility> // move, pair, swap
#include <vector> // vector

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>
#include <nlohmann/detail/view/number.hpp>
#include <nlohmann/detail/view/string_ref.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

// Equality of views, and of views with basic_json values, with the semantics
// of basic_json's operator== applied to the values parse() would produce:
// numbers compare by value across their types, an object is compared by its
// members with duplicate keys resolved as parse() resolves them (the last
// value, at the position of the first occurrence), and in document order if
// the object type keeps an order (ordered_json), by key otherwise.

/// The members of an object as parse() keeps them: one per key, the last
/// value at the position of the first occurrence, in the order of the
/// comparison (sorted by key, or, if the object type keeps the order, the order
/// of first occurrence). The members m[0..n) are in document order; this
/// appends to out the indices of the member of each key that has its value
/// (its last one), in the order of the comparison. Most objects have unique
/// keys; small ones are sorted by insertion, which keeps equal keys in order
/// and needs no memory.
/// whether the key a is before the key b
template<typename Key>
NLOHMANN_VIEW_ALWAYS_INLINE bool key_less(const Key& a, const Key& b) noexcept
{
    return bytes_less(a.data(), a.size(), b.data(), b.size());
}

template<typename Entry>
void resolve_indices(const Entry* m, std::size_t n, bool ordered, std::vector<std::uint32_t>& out)
{
    const std::size_t start = out.size();
    out.resize(start + n);
    std::uint32_t* const order = out.data() + start;
    for (std::size_t i = 0; i < n; ++i)
    {
        order[i] = static_cast<std::uint32_t>(i);
    }
    // sorted by key; equal keys stay in document order
    if (n <= 16)
    {
        for (std::size_t i = 1; i < n; ++i)
        {
            const std::uint32_t x = order[i];
            std::size_t j = i;
            for (; j > 0 && key_less(m[x].first, m[order[j - 1]].first); --j)
            {
                order[j] = order[j - 1];
            }
            order[j] = x;
        }
    }
    else
    {
        std::stable_sort(order, order + n, [m](std::uint32_t x, std::uint32_t y)
        {
            return key_less(m[x].first, m[y].first);
        });
    }
    if (!ordered)
    {
        // the last of each run of equal keys
        std::size_t w = 0;
        for (std::size_t i = 0; i < n;)
        {
            std::size_t last = i;
            while (last + 1 < n && m[order[last + 1]].first == m[order[i]].first)
            {
                ++last;
            }
            order[w++] = order[last];
            i = last + 1;
        }
        out.resize(start + w);
        return;
    }
    // (document order) the value of the last occurrence at the first occurrence of each key
    constexpr std::uint32_t none = 0xFFFFFFFFu;
    std::vector<std::uint32_t> value_at(n, none);
    for (std::size_t i = 0; i < n;)
    {
        std::size_t last = i;
        while (last + 1 < n && m[order[last + 1]].first == m[order[i]].first)
        {
            ++last;
        }
        value_at[order[i]] = order[last]; // (stable: order[i] is the first occurrence)
        i = last + 1;
    }
    std::size_t w = 0;
    for (std::size_t i = 0; i < n; ++i)
    {
        if (value_at[i] != none)
        {
            order[w++] = value_at[i];
        }
    }
    out.resize(start + w);
}

/// whether the keys of n members are the same, in the same order
template<typename EntryA, typename EntryB>
bool same_keys(const EntryA* a, const EntryB* b, std::size_t n)
{
    for (std::size_t i = 0; i < n; ++i)
    {
        if (!(a[i].first == b[i].first))
        {
            return false;
        }
    }
    return true;
}

/// The members of an object as parse() keeps them (one per key: the last
/// value at the position of the first occurrence), sorted by key or, if the
/// object type keeps the order, in the order of first occurrence. The
/// members are given in document order, at the end of m (from the position
/// base on); most objects have unique keys, in which case they are only sorted
/// (for small objects with an insertion sort, which keeps equal keys in order
/// and needs no memory).
template<typename Side, typename StringView>
void resolve_members(std::vector<std::pair<StringView, Side>>& m, std::size_t base, bool ordered)
{
    using entry = std::pair<StringView, Side>;
    const std::size_t n = m.size() - base;
    entry* const first = m.data() + base;
    if (ordered)
    {
        // (document order) later values of a key go to its first occurrence
        std::vector<std::size_t> order(n);
        for (std::size_t i = 0; i < n; ++i)
        {
            order[i] = i;
        }
        std::stable_sort(order.begin(), order.end(), [first](std::size_t x, std::size_t y)
        {
            return key_less(first[x].first, first[y].first);
        });
        std::vector<bool> drop(n, false);
        bool any = false;
        for (std::size_t i = 0; i < n;)
        {
            std::size_t last = i;
            while (last + 1 < n && first[order[last + 1]].first == first[order[i]].first)
            {
                ++last;
            }
            if (last != i)
            {
                first[order[i]].second = first[order[last]].second;
                for (std::size_t k = i + 1; k <= last; ++k)
                {
                    drop[order[k]] = true;
                }
                any = true;
            }
            i = last + 1;
        }
        if (any)
        {
            std::size_t w = 0;
            for (std::size_t i = 0; i < n; ++i)
            {
                if (!drop[i])
                {
                    if (w != i)
                    {
                        first[w] = std::move(first[i]);
                    }
                    ++w;
                }
            }
            m.erase(m.begin() + static_cast<std::ptrdiff_t>(base + w), m.end());
        }
        return;
    }
    // sorted by key; equal keys stay in document order
    if (n <= 16)
    {
        for (std::size_t i = 1; i < n; ++i)
        {
            entry x = std::move(first[i]);
            std::size_t j = i;
            for (; j > 0 && key_less(x.first, first[j - 1].first); --j)
            {
                first[j] = std::move(first[j - 1]);
            }
            first[j] = std::move(x);
        }
    }
    else
    {
        std::stable_sort(first, first + n, [](const entry & x, const entry & y)
        {
            return key_less(x.first, y.first);
        });
    }
    // the first key of a run with the last value
    std::size_t w = 0;
    for (std::size_t i = 0; i < n;)
    {
        std::size_t last = i;
        while (last + 1 < n && first[last + 1].first == first[i].first)
        {
            ++last;
        }
        if (w != i || last != i)
        {
            first[w] = entry(first[i].first, std::move(first[last].second));
        }
        ++w;
        i = last + 1;
    }
    m.erase(m.begin() + static_cast<std::ptrdiff_t>(base + w), m.end());
}

/// room for k more entries, growing geometrically (reserve(size() + k) alone would
/// reallocate for each object nested in another)
template<typename T>
void reserve_more(std::vector<T>& v, std::size_t k)
{
    const std::size_t needed = v.size() + k;
    if (needed > v.capacity())
    {
        v.reserve((std::max)(needed, 2 * v.capacity()));
    }
}

/// one side of a comparison: a view
template<typename BasicJsonType, typename View>
class view_side
{
  public:
    using string_view_t = typename View::string_view_t;
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using nav = navigation<View::is_editable>;

    /// the position in the elements of an array
    struct cursor
    {
        const node* pos = nullptr;
    };

    view_side() noexcept
        : m_view()
    {}

    explicit view_side(const View& v) noexcept
        : m_view(v)
    {}

    /// the document and the node of the view (nullptr: a discarded view)
    const document_data& document() const noexcept
    {
        return *m_view.m_doc;
    }

    const node* value_node() const noexcept
    {
        return m_view.m_node;
    }

    static constexpr bool is_editable = View::is_editable;

    value_t type() const noexcept
    {
        return m_view.type();
    }

    std::size_t size() const noexcept
    {
        return m_view.size();
    }

    string_view_t string() const
    {
        return m_view.get_string();
    }

    bool boolean() const noexcept
    {
        return (m_view.m_node->flags & node_flags::is_true) != 0;
    }

    number_integer_t integer() const noexcept
    {
        return static_cast<number_integer_t>(static_cast<std::int64_t>(integer_bits(*m_view.m_node)));
    }

    number_unsigned_t unsigned_integer() const noexcept
    {
        return static_cast<number_unsigned_t>(integer_bits(*m_view.m_node));
    }

    number_float_t floating() const
    {
        return float_value<number_float_t>(*m_view.m_doc, *m_view.m_node);
    }

    /// the token of a float
    string_view_t float_token() const noexcept
    {
        return string_view_t(m_view.m_doc->str(*m_view.m_node), m_view.m_node->len);
    }

    /// a number, boolean, or null as a basic_json value (no allocation)
    BasicJsonType scalar() const
    {
        switch (m_view.type())
        {
            case value_t::number_integer:
                return BasicJsonType(m_view.template get<typename BasicJsonType::number_integer_t>());
            case value_t::number_unsigned:
                return BasicJsonType(m_view.template get<typename BasicJsonType::number_unsigned_t>());
            case value_t::number_float:
                return BasicJsonType(m_view.template get<typename BasicJsonType::number_float_t>());
            case value_t::boolean:
                return BasicJsonType(m_view.template get<bool>());
            case value_t::null:
            case value_t::object:
            case value_t::array:
            case value_t::string:
            case value_t::binary:
            case value_t::discarded:
            default:
                return BasicJsonType(nullptr);
        }
    }

    /// start at the first element of this array
    void open(cursor& c) const noexcept
    {
        c.pos = nav::first(*m_view.m_doc, m_view.m_node);
    }

    /// the element at c (and advance)
    view_side take(cursor& c) const noexcept
    {
        const node* const v = nav::value(c.pos);
        c.pos = document_data::after(c.pos);
        return view_side(View(m_view.m_doc, v));
    }

    /// the keys of the first n members of this object (n <= its size), in document order
    void first_keys(string_view_t* out, std::size_t n) const noexcept
    {
        const node* pos = nav::first(*m_view.m_doc, m_view.m_node);
        for (std::size_t i = 0; i < n; ++i)
        {
            out[i] = string_view_t(m_view.m_doc->str(*pos), pos->len);
            pos = document_data::after(pos + 1);
        }
    }

    /// append the members to out, in document order; whether their keys ascend
    /// (then they are unique, and in the order of the comparison of a std::map)
    bool members(std::vector<std::pair<string_view_t, view_side>>& out, bool /*ordered*/) const
    {
        const std::size_t base = out.size();
        reserve_more(out, m_view.m_node->len);
        bool sorted = true;
        const node* pos = nav::first(*m_view.m_doc, m_view.m_node);
        for (std::size_t i = m_view.m_node->len; i != 0; --i)
        {
            const string_view_t key(m_view.m_doc->str(*pos), pos->len);
            sorted = sorted && (out.size() == base || key_less(out.back().first, key));
            out.emplace_back(key, view_side(View(m_view.m_doc, nav::value(pos + 1))));
            pos = document_data::after(pos + 1);
        }
        return sorted;
    }

  private:
    View m_view;
};

/// the other side of a comparison: a basic_json value
template<typename BasicJsonType, typename StringView>
class json_side
{
  public:
    using string_view_t = StringView;
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;

    /// the position in the elements of an array
    struct cursor
    {
        typename BasicJsonType::const_iterator it{};
    };

    json_side() noexcept = default;

    explicit json_side(const BasicJsonType& j) noexcept
        : m_json(&j)
    {}

    value_t type() const noexcept
    {
        return m_json->type();
    }

    std::size_t size() const noexcept
    {
        return m_json->size();
    }

    string_view_t string() const
    {
        const auto& s = m_json->template get_ref<const typename BasicJsonType::string_t&>();
        return string_view_t(s.data(), s.size());
    }

    bool boolean() const noexcept
    {
        return *m_json->template get_ptr<const bool*>();
    }

    number_integer_t integer() const noexcept
    {
        return *m_json->template get_ptr<const number_integer_t*>();
    }

    number_unsigned_t unsigned_integer() const noexcept
    {
        return *m_json->template get_ptr<const number_unsigned_t*>();
    }

    number_float_t floating() const noexcept
    {
        return *m_json->template get_ptr<const number_float_t*>();
    }

    BasicJsonType scalar() const
    {
        return *m_json;
    }

    void open(cursor& c) const
    {
        c.it = m_json->cbegin();
    }

    json_side take(cursor& c) const
    {
        const json_side r(*c.it);
        ++c.it;
        return r;
    }

    /// the keys of the first n members of this object (n <= its size), in document order
    void first_keys(string_view_t* out, std::size_t n) const noexcept
    {
        auto it = m_json->cbegin();
        for (std::size_t i = 0; i < n; ++i, ++it)
        {
            out[i] = string_view_t(it.key().data(), it.key().size());
        }
    }

    /// append the members to out, in the order of the comparison (the keys of a
    /// basic_json are unique); true
    bool members(std::vector<std::pair<string_view_t, json_side>>& out, bool ordered) const
    {
        const std::size_t base = out.size();
        reserve_more(out, m_json->size());
        for (auto it = m_json->cbegin(); it != m_json->cend(); ++it)
        {
            out.emplace_back(string_view_t(it.key().data(), it.key().size()), json_side(it.value()));
        }
        if (!ordered)
        {
            const auto less = [](const std::pair<string_view_t, json_side>& a, const std::pair<string_view_t, json_side>& b)
            {
                return key_less(a.first, b.first);
            };
            const auto first = out.begin() + static_cast<std::ptrdiff_t>(base);
            if (!std::is_sorted(first, out.end(), less))
            {
                std::sort(first, out.end(), less);
            }
        }
        return true;
    }

  private:
    const BasicJsonType* m_json = nullptr;
};

/*!
@brief the values at two nodes, found equal by walking both documents in the
same order

Two values are equal if they have the same type, the same number token or
string, the same elements, and the same members with the same keys in the same
order: a value that matches this way is equal under the rules above whatever
the object type and duplicate keys (the last value of a key then wins on
both sides, and their order of first occurrence is the same). The walk does
not find every equal pair (numbers spelled differently, members in another
order, duplicate keys with other values), only the ones that are the same
text; it stops at the first difference and then says nothing. Containers
nested deeper than the budget are not walked.

The walk goes through the document in its order, the comparison that follows
goes through the members of an object by key. So that the walk never reaches
a difference later than the comparison would, and never costs more than it,
it enters an object only if the two orders agree (the keys ascend, or the
object type keeps the order) or if the walk is cheaper than preparing the
comparison of the object (all values are scalars).
*/
/// the containers that lockstep found different, from the outermost to the
/// innermost: the comparison that goes on from there does not walk them again
struct lockstep_path
{
    /// the nesting depth up to which lockstep walks (the recursion is bounded)
    static constexpr unsigned budget() noexcept
    {
        return 48;
    }

    /// a pair of containers that differ; for arrays, the elements where the walk stopped
    /// (the ones before are equal)
    struct entry
    {
        const node* a;
        const node* b;
        const node* element_a;
        const node* element_b;
        std::uint32_t index;
    };

    /// the number of entries that a path can hold (a container deeper than the
    /// budget of the walk is not entered)
    static constexpr std::size_t levels() noexcept
    {
        return 50;
    }

    explicit lockstep_path(entry* storage) noexcept
        : nodes(storage)
    {}

    entry* nodes; ///< levels() entries, written before they are read
    unsigned length = 0; ///< pairs recorded by the last walk
    unsigned next = 0;   ///< the pair that the comparison enters next
    const entry* resume = nullptr; ///< the entry of the pair that was just looked at, if it is in the path
};

template<bool EA, bool EB>
class lockstep
{
  public:
    lockstep(const document_data& a, const document_data& b, lockstep_path& path, bool ordered) noexcept
        : m_a(a), m_b(b), m_path(path), m_ordered(ordered)
    {}

    /// whether the values at a and b are the same (the nodes of the values,
    /// not entries of a sequence)
    bool same(const node* a, const node* b, unsigned budget) noexcept
    {
        if (a->kind != b->kind)
        {
            return false;
        }
        switch (static_cast<value_t>(a->kind))
        {
            case value_t::null:
                return true;
            case value_t::boolean:
                return ((a->flags ^ b->flags) & node_flags::is_true) == 0;
            case value_t::string:
                return a->len == b->len && bytes_equal(m_a.str(*a), m_b.str(*b), a->len);
            case value_t::number_float: // (the token, and the digit layout that the value is read with: they only differ in a damaged image)
                return a->extra == b->extra && a->len == b->len && bytes_equal(m_a.str(*a), m_b.str(*b), a->len);
            case value_t::number_integer:
            case value_t::number_unsigned:
                return integer_bits(*a) == integer_bits(*b);
            case value_t::array:
                if (budget == 0 || a->len != b->len)
                {
                    return false;
                }
                {
                    lockstep_path::entry stop{a, b, nullptr, nullptr, 0};
                    if (elements(a, b, budget - 1, stop))
                    {
                        return true;
                    }
                    record(stop, budget);
                    return false;
                }
            case value_t::object:
                if (budget == 0 || a->len != b->len)
                {
                    return false;
                }
                if (!visits_in_order(a) || !members(a, b, budget - 1))
                {
                    record(lockstep_path::entry{a, b, nullptr, nullptr, 0}, budget);
                    return false;
                }
                return true;
            case value_t::binary:    // LCOV_EXCL_LINE (not in a document)
            case value_t::discarded: // LCOV_EXCL_LINE
            default:                 // LCOV_EXCL_LINE
                return false;        // LCOV_EXCL_LINE
        }
    }

  private:
    using nav_a = navigation<EA>;
    using nav_b = navigation<EB>;

    /// note the containers a and b (at the nesting level that budget stands
    /// for) as different
    NLOHMANN_VIEW_NOINLINE void record(const lockstep_path::entry& stop, unsigned budget) const noexcept
    {
        const unsigned level = lockstep_path::budget() - budget;
        m_path.nodes[level] = stop;
        if (m_path.length == 0)
        {
            m_path.length = level + 1; // (the innermost container is the first to be left)
        }
    }

    /// Whether the comparison that follows visits the members of the object a in the
    /// order of the document: if the object type keeps the order, if the keys
    /// ascend (it sorts by key), or if all values are scalars (then the walk costs
    /// less than collecting and sorting the members, whichever member differs).
    /// Otherwise a difference could be found by the walk later than by the
    /// comparison, which is not worth the walk.
    bool visits_in_order(const node* a) const noexcept
    {
        if (m_ordered || a->len < 2)
        {
            return true;
        }
        if (!EA && a->next == 1 + (2 * static_cast<std::size_t>(a->len)))
        {
            return true; // (scalar values only)
        }
        const node* k = nav_a::first(m_a, a);
        string_ref previous(m_a.str(*k), k->len);
        for (std::uint32_t i = a->len - 1; i != 0; --i)
        {
            k = document_data::after(k + 1);
            const string_ref key(m_a.str(*k), k->len);
            if (!key_less(previous, key))
            {
                return false;
            }
            previous = key;
        }
        return true;
    }

    bool elements(const node* a, const node* b, unsigned budget, lockstep_path::entry& stop) noexcept
    {
        const node* pa = nav_a::first(m_a, a);
        const node* pb = nav_b::first(m_b, b);
        for (std::uint32_t i = a->len; i != 0; --i)
        {
            if (!same(nav_a::value(pa), nav_b::value(pb), budget))
            {
                stop.element_a = pa;
                stop.element_b = pb;
                stop.index = a->len - i;
                return false;
            }
            pa = document_data::after(pa);
            pb = document_data::after(pb);
        }
        return true;
    }

    bool members(const node* a, const node* b, unsigned budget) noexcept
    {
        const node* pa = nav_a::first(m_a, a);
        const node* pb = nav_b::first(m_b, b);
        for (std::uint32_t i = a->len; i != 0; --i)
        {
            if (pa->len != pb->len || !bytes_equal(m_a.str(*pa), m_b.str(*pb), pa->len))
            {
                return false;
            }
            if (!same(nav_a::value(pa + 1), nav_b::value(pb + 1), budget))
            {
                return false;
            }
            pa = document_data::after(pa + 1);
            pb = document_data::after(pb + 1);
        }
        return true;
    }

    const document_data& m_a;
    const document_data& m_b;
    lockstep_path& m_path;
    bool m_ordered; ///< the object type keeps the order of the members
};

/// whether two views certainly have equal values (see lockstep); if not, the
/// path says where they differ
template<typename BasicJsonType, typename ViewA, typename ViewB>
bool certainly_equal(const view_side<BasicJsonType, ViewA>& a, const view_side<BasicJsonType, ViewB>& b, lockstep_path& path, bool ordered) noexcept
{
    const node* const na = a.value_node();
    const node* const nb = b.value_node();
    if (na == nullptr || nb == nullptr)
    {
        return false;
    }
    if (na == nb)
    {
        return true; // (the same node of the same document: documents have distinct nodes)
    }
    path.resume = nullptr;
    if (path.next < path.length && path.nodes[path.next].a == na && path.nodes[path.next].b == nb)
    {
        path.resume = &path.nodes[path.next];
        ++path.next; // (the walk found these different already)
        return false;
    }
    path.length = 0;
    const bool equal = lockstep<view_side<BasicJsonType, ViewA>::is_editable, view_side<BasicJsonType, ViewB>::is_editable>(a.document(), b.document(), path, ordered).same(na, nb, lockstep_path::budget());
    path.next = path.length != 0 ? 1 : 0; // (this pair is the first in the path)
    path.resume = path.length != 0 ? &path.nodes[0] : nullptr;
    return equal;
}

/// (a view and a basic_json value: no walk)
template<typename A, typename B>
bool certainly_equal(const A& /*a*/, const B& /*b*/, lockstep_path& /*path*/, bool /*ordered*/) noexcept
{
    return false;
}

/// (arrays of two views) the elements where the walk stopped are the next pair: the ones before are equal
template<typename BasicJsonType, typename ViewA, typename ViewB>
void resume_array(const lockstep_path& path, const view_side<BasicJsonType, ViewA>& a, const view_side<BasicJsonType, ViewB>& b,
                  typename view_side<BasicJsonType, ViewA>::cursor& cursor_a, typename view_side<BasicJsonType, ViewB>::cursor& cursor_b, std::size_t& next) noexcept
{
    if (path.resume != nullptr && path.resume->element_a != nullptr && path.resume->a == a.value_node() && path.resume->b == b.value_node())
    {
        cursor_a.pos = path.resume->element_a;
        cursor_b.pos = path.resume->element_b;
        next = path.resume->index;
    }
}

template<typename A, typename B, typename CursorA, typename CursorB>
void resume_array(const lockstep_path& /*path*/, const A& /*a*/, const B& /*b*/, CursorA& /*cursor_a*/, CursorB& /*cursor_b*/, std::size_t& /*next*/) noexcept
{}

/// whether two floats are equal (the tokens of two views: equal text and digit layout is an equal value; they
/// only differ in a damaged image)
template<typename BasicJsonType, typename ViewA, typename ViewB>
bool floats_equal(const view_side<BasicJsonType, ViewA>& a, const view_side<BasicJsonType, ViewB>& b)
{
    return (a.value_node()->extra == b.value_node()->extra && a.float_token() == b.float_token()) || std::equal_to<typename BasicJsonType::number_float_t>()(a.floating(), b.floating());
}

template<typename A, typename B>
bool floats_equal(const A& a, const B& b)
{
    return std::equal_to<typename A::number_float_t>()(a.floating(), b.floating());
}

/// Whether two objects of a type that keeps the order are different because of the keys of
/// their first members, found without the preparation of the comparison: the comparison goes
/// through the members in the order of the first occurrence of their keys, so if the first
/// members have the same distinct keys and then one pair of keys differs, where neither is
/// one of the keys before it, the objects are different. (The keys that are the same as an
/// earlier key are the duplicates that the comparison drops, so those are not decided here.)
template<typename SideA, typename SideB>
bool keys_differ_early(const SideA& a, const SideB& b)
{
    using string_view_t = typename SideA::string_view_t;
    constexpr std::size_t limit = 4;
    const std::size_t n = (std::min)((std::min)(a.size(), b.size()), limit);
    string_view_t ka[limit];
    string_view_t kb[limit];
    a.first_keys(ka, n);
    b.first_keys(kb, n);
    for (std::size_t i = 0; i < n; ++i)
    {
        if (ka[i] != kb[i])
        {
            for (std::size_t k = 0; k < i; ++k)
            {
                if (ka[i] == ka[k] || kb[i] == ka[k])
                {
                    return false; // (a duplicate: not decided)
                }
            }
            return true;
        }
    }
    return false;
}

inline bool is_number(value_t t) noexcept
{
    return t == value_t::number_integer || t == value_t::number_unsigned || t == value_t::number_float;
}

/// whether two sides are equal; iterative, so that the nesting depth is
/// limited by memory only
template<typename BasicJsonType, typename A, typename B>
bool equal(const A& a0, const B& b0)
{
    using string_view_t = typename A::string_view_t;
    const bool ordered = is_ordered_map<typename BasicJsonType::object_t>::value;

    constexpr std::size_t npos = static_cast<std::size_t>(-1);
    struct frame
    {
        A array_a{};
        B array_b{};
        typename A::cursor cursor_a{};
        typename B::cursor cursor_b{};
        std::size_t base_a = 0; ///< the members of an object: from this position in members_a
        std::size_t base_b = 0;
        std::size_t index_a = npos; ///< their order in the comparison: from this position in indices (npos: as they are)
        std::size_t index_b = npos;
        std::size_t index_mark = 0; ///< the size of indices before this frame
        bool object = false;
        std::size_t next = 0;
        std::size_t count = 0;
    };
    std::vector<frame> stack;
    std::vector<std::uint32_t> indices; // the order of the members of the open objects, where it is not their order in the document
    // the members of the open objects (the ones of an object follow those of the objects around it)
    std::vector<std::pair<string_view_t, A>> members_a;
    std::vector<std::pair<string_view_t, B>> members_b;
    std::array<lockstep_path::entry, lockstep_path::levels()> path_storage; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
    lockstep_path path(path_storage.data());
    {
        // (values that differ in type or in the size of an array need no walk)
        const value_t first = a0.type();
        const value_t second = b0.type();
        if (first != second && !(is_number(first) && is_number(second)) && first != value_t::discarded && second != value_t::discarded)
        {
            return false;
        }
        if (first == value_t::array && second == value_t::array && a0.size() != b0.size())
        {
            return false;
        }
    }
    A a = a0;
    B b = b0;
    // (pairs of views that are certainly equal need no further look)
    if (certainly_equal(a, b, path, ordered))
    {
        return true;
    }
    for (;;)
    {
        const value_t ta = a.type();
        const value_t tb = b.type();
        const bool numbers = is_number(ta) && is_number(tb);
        if (ta == value_t::discarded || tb == value_t::discarded)
        {
            // basic_json decides (JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON)
            if (ta != tb || !(BasicJsonType(value_t::discarded) == BasicJsonType(value_t::discarded)))
            {
                return false;
            }
        }
        else
        {
            if (ta != tb && !numbers) // numbers of different types can be equal
            {
                return false;
            }
            if (ta == value_t::string)
            {
                if (a.string() != b.string())
                {
                    return false;
                }
            }
            else if (ta == value_t::array || ta == value_t::object)
            {
                if (a.size() != b.size() && ta == value_t::array)
                {
                    return false;
                }
                if (ordered && ta == value_t::object && keys_differ_early(a, b))
                {
                    return false;
                }
                stack.emplace_back();
                frame& f = stack.back();
                f.object = ta == value_t::object;
                if (f.object)
                {
                    f.base_a = members_a.size();
                    f.base_b = members_b.size();
                    f.index_mark = indices.size();
                    const bool sorted_a = a.members(members_a, ordered);
                    const bool sorted_b = b.members(members_b, ordered);
                    const std::size_t size_a = members_a.size() - f.base_a;
                    const std::size_t size_b = members_b.size() - f.base_b;
                    std::size_t count_a = size_a;
                    std::size_t count_b = size_b;
                    if (!sorted_a && !sorted_b && size_a == size_b && same_keys(members_a.data() + f.base_a, members_b.data() + f.base_b, size_a))
                    {
                        // the same keys in the same order: one order of the comparison for both
                        f.index_a = indices.size();
                        f.index_b = f.index_a;
                        resolve_indices(members_a.data() + f.base_a, size_a, ordered, indices);
                        count_a = indices.size() - f.index_a;
                        count_b = count_a;
                    }
                    else
                    {
                        if (!sorted_a)
                        {
                            resolve_members(members_a, f.base_a, ordered);
                            count_a = members_a.size() - f.base_a;
                        }
                        if (!sorted_b)
                        {
                            resolve_members(members_b, f.base_b, ordered);
                            count_b = members_b.size() - f.base_b;
                        }
                    }
                    f.count = count_a;
                    if (count_a != count_b)
                    {
                        return false;
                    }
                }
                else
                {
                    f.array_a = a;
                    f.array_b = b;
                    a.open(f.cursor_a);
                    b.open(f.cursor_b);
                    f.count = a.size();
                    resume_array(path, a, b, f.cursor_a, f.cursor_b, f.next);
                }
            }
            else if (ta == value_t::boolean)
            {
                if (a.boolean() != b.boolean())
                {
                    return false;
                }
            }
            else if (numbers && ta == tb)
            {
                // numbers of one type: as basic_json compares them
                if (ta == value_t::number_integer ? a.integer() != b.integer()
                        : ta == value_t::number_unsigned ? a.unsigned_integer() != b.unsigned_integer()
                        : !floats_equal(a, b))
                {
                    return false;
                }
            }
            else if (numbers && !(a.scalar() == b.scalar())) // numbers of different types
            {
                return false;
            }
            // (null equals null)
        }

        // the next pair of values that is not certainly equal
        for (;;)
        {
            if (stack.empty())
            {
                return true;
            }
            frame& f = stack.back();
            if (f.next == f.count)
            {
                if (f.object)
                {
                    members_a.erase(members_a.begin() + static_cast<std::ptrdiff_t>(f.base_a), members_a.end());
                    members_b.erase(members_b.begin() + static_cast<std::ptrdiff_t>(f.base_b), members_b.end());
                    indices.resize(f.index_mark);
                }
                stack.pop_back(); // (f dangles now, and is bound again after continue)
                continue;
            }
            if (f.object)
            {
                const auto& member_a = members_a[f.base_a + (f.index_a == npos ? f.next : indices[f.index_a + f.next])];
                const auto& member_b = members_b[f.base_b + (f.index_b == npos ? f.next : indices[f.index_b + f.next])];
                if (!(member_a.first == member_b.first))
                {
                    return false;
                }
                a = member_a.second;
                b = member_b.second;
            }
            else
            {
                a = f.array_a.take(f.cursor_a);
                b = f.array_b.take(f.cursor_b);
            }
            ++f.next;
            if (!certainly_equal(a, b, path, ordered))
            {
                break;
            }
        }
    }
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
