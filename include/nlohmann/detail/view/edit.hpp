//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cmath> // isinf, isnan
#include <cstddef> // size_t
#include <cstdint> // int64_t, uint8_t, uint32_t, uint64_t
#include <cstring> // memcmp, memmove
#include <limits> // numeric_limits
#include <string> // string, to_string
#include <type_traits> // decay, enable_if, integral_constant, is_arithmetic, is_convertible, is_floating_point, is_same, is_signed
#include <utility> // forward

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/edit_storage.hpp>
#include <nlohmann/detail/view/errors.hpp>
#include <nlohmann/detail/view/lookup.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN

template<typename BasicJsonType, bool Editable>
class basic_json_view;

namespace detail
{
namespace view
{

/// the index of the first true condition (the number of conditions if none is)
template<bool... Conditions>
struct first_true : std::integral_constant<int, 0> {};

template<bool... Conditions>
struct first_true<false, Conditions...> : std::integral_constant < int, 1 + first_true<Conditions...>::value > {};

/// Checks a string the way basic_json's serializer does when it writes it
/// (type_error.316 with the same message), so that an editable document
/// only holds valid UTF-8: the error is at the first byte that no
/// well-formed sequence can continue with (Unicode, Table 3-7).
inline void check_utf8(const char* s, std::size_t n)
{
    const auto* const p = reinterpret_cast<const unsigned char*>(s); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto hex = [](unsigned char c)
    {
        constexpr const char* digits = "0123456789ABCDEF";
        return std::string{digits[c >> 4u], digits[c & 0xFu]};
    };
    for (std::size_t i = 0; i < n;)
    {
        const unsigned char c = p[i];
        if (c < 0x80)
        {
            ++i;
            continue;
        }
        std::size_t len = 0;
        unsigned char lo = 0x80;
        unsigned char hi = 0xBF;
        if (c >= 0xC2 && c <= 0xDF)
        {
            len = 2;
        }
        else if (c >= 0xE0 && c <= 0xEF)
        {
            len = 3;
            lo = c == 0xE0 ? 0xA0 : 0x80;
            hi = c == 0xED ? 0x9F : 0xBF;
        }
        else if (c >= 0xF0 && c <= 0xF4)
        {
            len = 4;
            lo = c == 0xF0 ? 0x90 : 0x80;
            hi = c == 0xF4 ? 0x8F : 0xBF;
        }
        else
        {
            throw_type_error(316, concat("invalid UTF-8 byte at index ", std::to_string(i), ": 0x", hex(c)));
        }
        for (std::size_t k = 1; k < len; ++k)
        {
            if (i + k == n)
            {
                throw_type_error(316, concat("incomplete UTF-8 string; last byte: 0x", hex(p[n - 1])));
            }
            const unsigned char b = p[i + k];
            if (b < (k == 1 ? lo : 0x80) || b > (k == 1 ? hi : 0xBF))
            {
                throw_type_error(316, concat("invalid UTF-8 byte at index ", std::to_string(i + k), ": 0x", hex(b)));
            }
        }
        i += len;
    }
}

/*!
@brief the edits of an editable basic_json_document

Values are accepted as views (of any document), BasicJsonType values, and
everything BasicJsonType can be constructed from. The source text is never
written: new values go to storage owned by the document (see
edit_storage.hpp).
*/
template<typename BasicJsonType, typename View>
class editor
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using string_view_t = typename View::string_view_t;
    using nav = navigation<true>;

  public:
    explicit editor(document_data& d) noexcept
        : m_doc(d)
    {}

    /// replace a value; returns its view
    template<typename V>
    View set(const View& target, V&& value)
    {
        node* const slot = own(target);
        const encoded e = encode(std::forward<V>(value));
        assign(slot, e, nullptr, false);
        return View(&m_doc, slot);
    }

    /// set a member (appended if missing; a null value becomes an object);
    /// returns a view of the member value
    template<typename V>
    View set(const View& object, string_view_t key, V&& value)
    {
        node* const o = own(object);
        if (o->kind != static_cast<std::uint8_t>(value_t::object) && o->kind != static_cast<std::uint8_t>(value_t::null))
        {
            throw_type_error(305, "cannot use operator[] with a string argument with ", object.type_name());
        }
        check_utf8(key.data(), key.size());
        const encoded e = encode(std::forward<V>(value));
        if (o->kind == static_cast<std::uint8_t>(value_t::null))
        {
            become_empty(o, value_t::object);
        }
        // an existing member: assign it (and drop later duplicates, so that
        // lookups, iteration, and materialize() agree)
        node* slot = nullptr;
        bool duplicates = false;
        for (const node* k = nav::first(m_doc, o), *end = nav::end(m_doc, o); k != end; k = document_data::after(k + 1))
        {
            if (key_equals(*k, key))
            {
                if (slot != nullptr)
                {
                    duplicates = true;
                    break;
                }
                slot = const_cast<node*>(nav::value(k + 1)); // NOLINT(cppcoreguidelines-pro-type-const-cast): the nodes belong to this document
            }
        }
        if (slot != nullptr)
        {
            if (duplicates)
            {
                erase_members(o, key, true);
            }
            assign(slot, e, o, true);
            return View(&m_doc, slot);
        }
        const node k = string_node(key.data(), key.size());
        slot = new_slot(e);
        node* const h = block_of(m_doc, o, 2);
        h[h->next] = k;
        make_link(h[h->next + 1], slot);
        h->next += 2;
        ++h->len;
        ++o->len;
        return View(&m_doc, slot);
    }

    /// assign an existing array element; returns a view of it
    template<typename V>
    View set(const View& array, std::size_t idx, V&& value)
    {
        node* const a = own(array);
        if (a->kind != static_cast<std::uint8_t>(value_t::array))
        {
            throw_type_error(305, "cannot use operator[] with a numeric argument with ", array.type_name());
        }
        check_index(idx, a->len);
        const encoded e = encode(std::forward<V>(value));
        node* const slot = const_cast<node*>(nav::value(element_at<true>(m_doc, a, idx))); // NOLINT(cppcoreguidelines-pro-type-const-cast)
        assign(slot, e, a, true);
        return View(&m_doc, slot);
    }

    /// append to an array (a null value becomes an array); returns a view of
    /// the new element
    template<typename V>
    View push_back(const View& array, V&& value)
    {
        node* const a = own(array);
        if (a->kind != static_cast<std::uint8_t>(value_t::array) && a->kind != static_cast<std::uint8_t>(value_t::null))
        {
            throw_type_error(308, "cannot use push_back() with ", array.type_name());
        }
        const encoded e = encode(std::forward<V>(value));
        if (a->kind == static_cast<std::uint8_t>(value_t::null))
        {
            become_empty(a, value_t::array);
        }
        node* const slot = new_slot(e);
        node* const h = block_of(m_doc, a, 1);
        make_link(h[h->next], slot);
        ++h->next;
        ++h->len;
        ++a->len;
        return View(&m_doc, slot);
    }

    /// insert into an array before position idx (idx <= size()); returns a
    /// view of the new element
    template<typename V>
    View insert(const View& array, std::size_t idx, V&& value)
    {
        node* const a = own(array);
        if (a->kind != static_cast<std::uint8_t>(value_t::array))
        {
            throw_type_error(309, "cannot use insert() with ", array.type_name());
        }
        check_index(idx, a->len + 1);
        const encoded e = encode(std::forward<V>(value));
        node* const slot = new_slot(e);
        node* const h = block_of(m_doc, a, 1);
        std::memmove(h + 2 + idx, h + 1 + idx, (h->next - 1 - idx) * sizeof(node));
        make_link(h[1 + idx], slot);
        ++h->next;
        ++h->len;
        ++a->len;
        return View(&m_doc, slot);
    }

    /// remove all members with this key; returns their number
    std::size_t erase(const View& object, string_view_t key)
    {
        node* const o = own(object);
        if (o->kind != static_cast<std::uint8_t>(value_t::object))
        {
            throw_type_error(307, "cannot use erase() with ", object.type_name());
        }
        for (const node* k = nav::first(m_doc, o), *end = nav::end(m_doc, o); k != end; k = document_data::after(k + 1))
        {
            if (key_equals(*k, key))
            {
                return erase_members(o, key, false);
            }
        }
        return 0;
    }

    /// remove an array element
    void erase(const View& array, std::size_t idx)
    {
        node* const a = own(array);
        if (a->kind != static_cast<std::uint8_t>(value_t::array))
        {
            throw_type_error(307, "cannot use erase() with ", array.type_name());
        }
        check_index(idx, a->len);
        node* const h = block_of(m_doc, a, 0);
        std::memmove(h + 1 + idx, h + 2 + idx, (h->next - 2 - idx) * sizeof(node));
        --h->next;
        --h->len;
        --a->len;
    }

  private:
    /// an encoded value: a scalar node, or the root of a new array/object
    struct encoded
    {
        node scalar{};
        node* region = nullptr;
    };

    /// the node of a view of this document
    node* own(const View& v)
    {
        if (NLOHMANN_VIEW_UNLIKELY(v.m_doc != &m_doc || v.m_node == nullptr))
        {
            throw_invalid_iterator(202, "view does not belong to this document");
        }
        edit_state_of(m_doc);
        return const_cast<node*>(v.m_node); // NOLINT(cppcoreguidelines-pro-type-const-cast): the nodes belong to this document
    }

    static void check_index(std::size_t idx, std::size_t limit)
    {
        if (idx >= limit)
        {
            throw_out_of_range(401, concat("array index ", std::to_string(idx), " is out of range"));
        }
    }

    bool key_equals(const node& k, string_view_t key) const noexcept
    {
        return k.len == key.size() && (key.size() == 0 || std::memcmp(m_doc.str(k), key.data(), key.size()) == 0);
    }

    /// remove the members with this key (all, or all but the first) from an object
    std::size_t erase_members(node* o, string_view_t key, bool keep_first)
    {
        node* const h = block_of(m_doc, o, 0);
        node* w = h + 1;
        std::size_t erased = 0;
        bool kept = false;
        for (node* r = h + 1, *end = h + h->next; r != end; r += 2)
        {
            const bool match = key_equals(*r, key);
            if (match && (kept || !keep_first))
            {
                ++erased;
                continue;
            }
            kept = kept || match;
            if (w != r)
            {
                w[0] = r[0];
                w[1] = r[1];
            }
            w += 2;
        }
        h->next = static_cast<std::uint32_t>(w - h);
        h->len -= static_cast<std::uint32_t>(erased);
        o->len -= static_cast<std::uint32_t>(erased);
        return erased;
    }

    /// turn a null into an empty array/object in place
    static void become_empty(node* n, value_t k) noexcept
    {
        *n = node{};
        n->kind = static_cast<std::uint8_t>(k);
        n->flags = node_flags::is_new;
        n->next = 1;
    }

    /// Replace the value at slot; `parent` is the container whose elements
    /// include slot (if known).
    void assign(node* slot, const encoded& e, node* parent, bool parent_known)
    {
        if (e.region == nullptr)
        {
            if (is_container(*slot) && slot->next > 1 && slot != m_doc.tape)
            {
                // The slot spans its old elements in the enclosing sequence, but
                // a scalar is one node: the enclosing container first switches to
                // links (then the extent of the slot no longer matters).
                node* const p = parent_known ? parent : find_parent(m_doc, slot);
                if (p != nullptr && ((p->flags & node_flags::moved) == 0 || moved_capacity(m_doc, p) == 0))
                {
                    block_of(m_doc, p, 0);
                }
            }
            *slot = e.scalar;
            return;
        }
        // an array/object: the slot keeps its extent (so that the enclosing
        // sequence still steps over it), and the elements come from the new
        // sequence
        const node* const r = e.region;
        const std::uint32_t extent = is_container(*slot) ? slot->next : 1;
        const bool was_moved = (slot->flags & node_flags::moved) != 0;
        slot->kind = r->kind;
        slot->extra = 0;
        slot->len = r->len;
        slot->next = extent;
        slot->flags = was_moved ? static_cast<std::uint8_t>(node_flags::moved | node_flags::is_new) : std::uint8_t{0};
        set_moved(m_doc, slot, e.region, 0);
        edit_state_of(m_doc).regions[e.region] = slot;
    }

    /// a node for a new element (links point to it; it never moves)
    node* new_slot(const encoded& e)
    {
        if (e.region != nullptr)
        {
            return e.region;
        }
        node* const s = alloc_nodes(m_doc, 1);
        *s = e.scalar;
        return s;
    }

    //////////////
    // encoding //
    //////////////

    template<int N>
    using encode_tag = std::integral_constant<int, N>;

    template<typename T>
    struct is_view : std::false_type {};

    template<typename J, bool E>
    struct is_view<basic_json_view<J, E>> : std::true_type {};

    template<typename V>
    encoded encode(V&& v)
    {
        using D = typename std::decay<V>::type;
        return encode_impl(std::forward<V>(v), encode_tag<first_true<is_view<D>::value,
                           std::is_same<D, BasicJsonType>::value,
                           std::is_same<D, std::nullptr_t>::value,
                           std::is_same<D, bool>::value,
                           std::is_arithmetic<D>::value,
                           std::is_convertible<const D&, string_view_t>::value>::value> {});
    }

    /// a view of any document (copied; nothing is shared with it)
    template<typename J, bool E>
    encoded encode_impl(const basic_json_view<J, E>& v, encode_tag<0> /*view*/)
    {
        if (NLOHMANN_VIEW_UNLIKELY(v.m_node == nullptr))
        {
            throw_type_error(302, "type must be a value, but is ", "discarded");
        }
        encoded r;
        if (!is_container(*v.m_node))
        {
            r.scalar = copy_scalar(*v.m_doc, *v.m_node);
            return r;
        }
        r.region = alloc_nodes(m_doc, count_nodes<E>(*v.m_doc, v.m_node));
        fill_nodes<E>(*v.m_doc, v.m_node, r.region);
        edit_state_of(m_doc).regions.emplace(r.region, nullptr);
        return r;
    }

    encoded encode_impl(const BasicJsonType& j, encode_tag<1> /*json*/)
    {
        encoded r;
        if (!j.is_structured())
        {
            r.scalar = json_scalar(j);
            return r;
        }
        r.region = alloc_nodes(m_doc, count_nodes(j));
        fill_nodes(j, r.region);
        edit_state_of(m_doc).regions.emplace(r.region, nullptr);
        return r;
    }

    encoded encode_impl(std::nullptr_t /*unused*/, encode_tag<2> /*null*/)
    {
        encoded r;
        r.scalar = plain_node(value_t::null);
        return r;
    }

    encoded encode_impl(bool b, encode_tag<3> /*boolean*/)
    {
        encoded r;
        r.scalar = plain_node(value_t::boolean);
        r.scalar.flags = static_cast<std::uint8_t>(r.scalar.flags | (b ? node_flags::is_true : 0));
        return r;
    }

    template<typename T>
    encoded encode_impl(T x, encode_tag<4> /*number*/)
    {
        encoded r;
        r.scalar = number_node(x, std::integral_constant<int, first_true<std::is_floating_point<T>::value, std::is_signed<T>::value>::value> {});
        return r;
    }

    template<typename T>
    encoded encode_impl(const T& s, encode_tag<5> /*string*/)
    {
        const string_view_t sv(s);
        check_utf8(sv.data(), sv.size());
        encoded r;
        r.scalar = string_node(sv.data(), sv.size());
        return r;
    }

    template<typename T>
    encoded encode_impl(T&& x, encode_tag<6> /*other*/)
    {
        return encode_impl(BasicJsonType(std::forward<T>(x)), encode_tag<1> {});
    }

    static node plain_node(value_t k) noexcept
    {
        node n{};
        n.kind = static_cast<std::uint8_t>(k);
        n.flags = node_flags::is_new;
        return n;
    }

    template<typename T>
    node number_node(T x, std::integral_constant<int, 0> /*floating-point*/)
    {
        return float_node(static_cast<number_float_t>(x));
    }

    template<typename T>
    node number_node(T x, std::integral_constant<int, 1> /*signed*/)
    {
        return integer_node(static_cast<std::uint64_t>(static_cast<std::int64_t>(x)), value_t::number_integer);
    }

    template<typename T>
    node number_node(T x, std::integral_constant<int, 2> /*unsigned*/)
    {
        return integer_node(static_cast<std::uint64_t>(x), value_t::number_unsigned);
    }

    /// an integer with its canonical token in the edit arena
    node integer_node(std::uint64_t bits, value_t k)
    {
        const bool negative = k == value_t::number_integer && static_cast<std::int64_t>(bits) < 0;
        std::uint64_t magnitude = negative ? 0 - bits : bits;
        std::array<char, 24> buf{};
        char* p = buf.data() + buf.size();
        do
        {
            *--p = static_cast<char>('0' + (magnitude % 10));
            magnitude /= 10;
        }
        while (magnitude != 0);
        if (negative)
        {
            *--p = '-';
        }
        const auto len = static_cast<std::size_t>(buf.data() + buf.size() - p);
        node n = plain_node(k);
        n.flags = static_cast<std::uint8_t>(n.flags | node_flags::edited);
        n.off = append_text(m_doc, p, len);
        // number_length() adds one for the sign of number_integer nodes
        n.extra = static_cast<std::uint16_t>(k == value_t::number_integer ? len - 1 : len);
        set_integer_bits(n, bits);
        return n;
    }

    /// a float with its shortest round-trip token (as basic_json::dump()
    /// writes it), or nan, inf, -inf, in the edit arena
    node float_node(number_float_t x)
    {
        string_t text;
        if (std::isnan(x))
        {
            text = "nan";
        }
        else if (std::isinf(x))
        {
            text = x > 0 ? "inf" : "-inf";
        }
        else
        {
            text = BasicJsonType(x).dump();
        }
        node n = plain_node(value_t::number_float);
        n.flags = static_cast<std::uint8_t>(n.flags | node_flags::edited);
        n.extra = 0xFFFFu; // (the digit layout is not recorded)
        n.off = append_text(m_doc, text.data(), text.size());
        n.len = static_cast<std::uint32_t>(text.size());
        return n;
    }

    /// a string (or key) in the edit arena
    node string_node(const char* s, std::size_t len)
    {
        if (NLOHMANN_VIEW_UNLIKELY(len >= 0xFFFFFFFFu))
        {
            throw_out_of_range(416, "strings of 4 GiB or more are not supported by json_document"); // LCOV_EXCL_LINE
        }
        node n = plain_node(value_t::string);
        n.flags = static_cast<std::uint8_t>(n.flags | node_flags::edited);
        n.off = append_text(m_doc, s, len);
        n.len = static_cast<std::uint32_t>(len);
        return n;
    }

    /// a scalar of a view (of any document) as a node of this document
    node copy_scalar(const document_data& from, const node& n)
    {
        if (&from == &m_doc)
        {
            return n; // the same storage
        }
        switch (static_cast<value_t>(n.kind))
        {
            case value_t::string:
                return string_node(from.str(n), n.len);
            case value_t::number_integer:
            case value_t::number_unsigned:
                return integer_node(integer_bits(n), static_cast<value_t>(n.kind));
            case value_t::number_float:
            {
                node r = plain_node(value_t::number_float);
                r.flags = static_cast<std::uint8_t>(r.flags | node_flags::edited);
                r.off = append_text(m_doc, from.str(n), n.len);
                r.len = n.len;
                r.extra = n.extra;
                return r;
            }
            case value_t::boolean:
            {
                node r = plain_node(value_t::boolean);
                r.flags = static_cast<std::uint8_t>(r.flags | (n.flags & node_flags::is_true));
                return r;
            }
            case value_t::null:
            case value_t::object:
            case value_t::array:
            case value_t::binary:
            case value_t::discarded:
            default:
                return plain_node(value_t::null);
        }
    }

    node json_scalar(const BasicJsonType& j)
    {
        switch (j.type())
        {
            case value_t::null:
                return plain_node(value_t::null);
            case value_t::boolean:
            {
                node r = plain_node(value_t::boolean);
                r.flags = static_cast<std::uint8_t>(r.flags | (j.template get<bool>() ? node_flags::is_true : 0));
                return r;
            }
            case value_t::number_integer:
                return integer_node(static_cast<std::uint64_t>(static_cast<std::int64_t>(j.template get<number_integer_t>())), value_t::number_integer);
            case value_t::number_unsigned:
                return integer_node(static_cast<std::uint64_t>(j.template get<number_unsigned_t>()), value_t::number_unsigned);
            case value_t::number_float:
                return float_node(j.template get<number_float_t>());
            case value_t::string:
            {
                const auto& s = j.template get_ref<const string_t&>();
                check_utf8(s.data(), s.size());
                return string_node(s.data(), s.size());
            }
            case value_t::binary:
                throw_type_error(319, "cannot store a binary value in a json_document", "");
            case value_t::discarded:
            case value_t::object:
            case value_t::array:
            default:
                throw_type_error(302, "type must be a value, but is ", "discarded");
        }
    }

    /// number of nodes of a subtree (containers, keys, scalars)
    template<bool E>
    static std::size_t count_nodes(const document_data& d, const node* n)
    {
        if (!is_container(*n))
        {
            return 1;
        }
        const bool object = n->kind == static_cast<std::uint8_t>(value_t::object);
        std::size_t r = 1;
        for (const node* c = navigation<E>::first(d, n), *end = navigation<E>::end(d, n); c != end;)
        {
            const node* const v = object ? c + 1 : c;
            r += (object ? 1 : 0) + count_nodes<E>(d, navigation<E>::value(v));
            c = document_data::after(v);
        }
        return r;
    }

    /// copy a subtree (of any document) as a contiguous sequence; returns its end
    template<bool E>
    node* fill_nodes(const document_data& d, const node* n, node* out)
    {
        if (!is_container(*n))
        {
            *out = copy_scalar(d, *n);
            return out + 1;
        }
        node* const self = out++;
        *self = plain_node(static_cast<value_t>(n->kind));
        self->len = n->len;
        const bool object = n->kind == static_cast<std::uint8_t>(value_t::object);
        for (const node* c = navigation<E>::first(d, n), *end = navigation<E>::end(d, n); c != end;)
        {
            if (object)
            {
                *out++ = copy_scalar(d, *c);
                ++c;
            }
            out = fill_nodes<E>(d, navigation<E>::value(c), out);
            c = document_data::after(c);
        }
        self->next = static_cast<std::uint32_t>(out - self);
        return out;
    }

    static std::size_t count_nodes(const BasicJsonType& j)
    {
        std::size_t r = 1;
        if (j.is_object())
        {
            for (const auto& member : j.items())
            {
                r += 1 + count_nodes(member.value());
            }
        }
        else if (j.is_array())
        {
            for (const auto& e : j)
            {
                r += count_nodes(e);
            }
        }
        return r;
    }

    node* fill_nodes(const BasicJsonType& j, node* out)
    {
        if (!j.is_structured())
        {
            *out = json_scalar(j);
            return out + 1;
        }
        node* const self = out++;
        *self = plain_node(j.type());
        self->len = static_cast<std::uint32_t>(j.size());
        if (j.is_object())
        {
            for (const auto& member : j.items())
            {
                check_utf8(member.key().data(), member.key().size());
                *out++ = string_node(member.key().data(), member.key().size());
                out = fill_nodes(member.value(), out);
            }
        }
        else
        {
            for (const auto& e : j)
            {
                out = fill_nodes(e, out);
            }
        }
        self->next = static_cast<std::uint32_t>(out - self);
        return out;
    }

    document_data& m_doc;
};

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
