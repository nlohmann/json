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
#include <cstdint> // int64_t, uint8_t, uint16_t, uint32_t, uint64_t
#include <cstring> // memcmp, memcpy
#include <limits> // numeric_limits
#include <string> // string
#include <vector> // vector

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/errors.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>
#include <nlohmann/detail/view/number.hpp>
#include <nlohmann/detail/view/object_index.hpp>
#include <nlohmann/detail/view/scan.hpp>

// Images: a document stored so that loading it needs no parsing.
//
// Layout (little-endian): a 64-byte header, the nodes, the text (the source,
// followed by the number tokens written by edits), a NUL, the decoded strings
// (followed by the strings written by edits), a NUL. The idea is that of
// zero-copy formats such as FlatBuffers (https://github.com/google/flatbuffers)
// and YaFF (https://github.com/yandex/yaff); no code is taken from them.
// check_image follows the idea of FlatBuffers' Verifier (bounds and
// structure) and also checks what the parser guarantees about strings and
// numbers, so that reading and serializing a checked image is safe and yields
// valid JSON.

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// how load() checks an image
enum class image_check
{
    /// everything the parser guarantees: structure and bounds, strings (valid
    /// UTF-8; source strings without quotes, backslashes, and control
    /// characters), and numbers (well-formed, matching the stored values)
    full,
    /// structure and bounds only: reading and serializing are safe, but a
    /// crafted image can yield invalid UTF-8, strings that serialize to
    /// invalid JSON, or numbers that differ from their text
    bounds,
    /// none: for images from a trusted source only (a damaged image is
    /// undefined behavior)
    none,
};

struct image_header
{
    std::array<char, 4> magic;              ///< "NJVI"
    std::uint32_t version;                  ///< 1
    std::uint64_t node_count;
    std::uint64_t text_size;
    std::uint64_t arena_size;
    std::array<std::uint64_t, 4> reserved;  ///< zero (for later versions)
};
static_assert(sizeof(image_header) == 64, "the image header must be 64 bytes");

constexpr std::uint32_t image_version = 1;

/// the largest node count and text or string size of an image (as for parsed
/// documents, offsets and counts must fit 32 bits)
constexpr std::uint64_t image_limit = 0xFFFFFFF0u;

/// Copy the current structure of an edited document into nodes in document
/// order, as the parser would have written them. Text written by edits is
/// appended to text_tail (number tokens) and arena_tail (strings); floats that
/// are not finite become null, as dump() writes them.
inline void compact_nodes(const document_data& d, std::size_t arena_size, std::vector<node>& out, std::string& text_tail, std::string& arena_tail)
{
    struct frame
    {
        const node* cur;
        const node* end;
        std::size_t index; ///< the container's node in out
        std::uint32_t count;
        bool object;
    };
    std::vector<frame> stack;
    const auto string_node = [&](const node & s)
    {
        node r = s;
        r.extra = 0;
        r.flags = static_cast<std::uint8_t>(s.flags & node_flags::storage);
        if (r.flags == node_flags::edited)
        {
            r.off = static_cast<std::uint32_t>(arena_size + arena_tail.size());
            arena_tail.append(d.str(s), s.len);
            r.flags = node_flags::escaped;
        }
        return r;
    };
    const auto emit = [&](const node * v)
    {
        node r = *v;
        switch (static_cast<value_t>(v->kind))
        {
            case value_t::object:
            case value_t::array:
                r.flags = 0;
                r.extra = 0;
                r.off = (v->flags & (node_flags::moved | node_flags::is_new)) != 0 ? 0 : v->off;
                r.len = 0;  // counted below
                r.next = 0; // set when the container is complete
                stack.push_back(frame{d.first_child_edited(v), d.child_end_edited(v), out.size(), 0, v->kind == static_cast<std::uint8_t>(value_t::object)});
                break;
            case value_t::string:
                r = string_node(*v);
                break;
            case value_t::number_integer:
            case value_t::number_unsigned:
                if ((v->flags & node_flags::storage) == node_flags::edited)
                {
                    r.off = static_cast<std::uint32_t>(d.size + text_tail.size());
                    text_tail.append(d.str(*v), number_length(*v));
                }
                r.flags = 0;
                break;
            case value_t::number_float:
                if ((v->flags & node_flags::storage) == node_flags::edited)
                {
                    const char* const t = d.str(*v);
                    if (t[0] == 'n' || t[0] == 'i' || (v->len > 1 && t[1] == 'i'))
                    {
                        r = node{}; // nan and infinity: null, as dump() writes them
                        r.kind = static_cast<std::uint8_t>(value_t::null);
                        break;
                    }
                    r.off = static_cast<std::uint32_t>(d.size + text_tail.size());
                    text_tail.append(t, v->len);
                    r.extra = 0xFFFFu; // the digit layout is not recorded
                }
                r.flags = 0;
                break;
            case value_t::boolean:
                r.flags = static_cast<std::uint8_t>(v->flags & node_flags::is_true);
                break;
            case value_t::null:
            case value_t::binary:
            case value_t::discarded:
            default:
                r.flags = 0;
                break;
        }
        out.push_back(r);
    };
    emit(d.tape);
    while (!stack.empty())
    {
        frame& top = stack.back();
        if (top.cur == top.end)
        {
            node& c = out[top.index];
            c.len = top.count;
            c.next = static_cast<std::uint32_t>(out.size() - top.index);
            stack.pop_back();
            continue;
        }
        ++top.count;
        const node* v = nullptr;
        if (top.object)
        {
            out.push_back(string_node(*top.cur));
            v = document_data::deref(top.cur + 1);
            top.cur = document_data::after(top.cur + 1);
        }
        else
        {
            v = document_data::deref(top.cur);
            top.cur = document_data::after(top.cur);
        }
        emit(v); // may grow the stack (top is not used afterwards)
    }
}

/// the document as an image
inline std::vector<std::uint8_t> save_image(const document_data& d)
{
#if !NLOHMANN_VIEW_LITTLE_ENDIAN
    throw_type_error(320, "json_document images need a little-endian target"); // LCOV_EXCL_LINE
#endif
    const std::size_t arena_size = d.arena_size;
    const node* nodes = d.tape;
    std::size_t count = d.tape_size;
    std::vector<node> compacted;
    std::string text_tail;
    std::string arena_tail;
    if (d.edits)
    {
        compact_nodes(d, arena_size, compacted, text_tail, arena_tail);
        nodes = compacted.data();
        count = compacted.size();
    }
    const std::size_t text_size = d.size + text_tail.size();
    const std::size_t total_arena = arena_size + arena_tail.size();
    if (NLOHMANN_VIEW_UNLIKELY(text_size >= image_limit || total_arena >= image_limit || count >= image_limit))
    {
        // LCOV_EXCL_START (4 GiB)
        throw_out_of_range(416, "images of 4 GiB or more are not supported by json_document");
        // LCOV_EXCL_STOP
    }
    image_header h{};
    h.magic = {{'N', 'J', 'V', 'I'}};
    h.version = image_version;
    h.node_count = count;
    h.text_size = text_size;
    h.arena_size = total_arena;
    std::vector<std::uint8_t> image(sizeof(h) + (count * sizeof(node)) + text_size + 1 + total_arena + 1);
    std::uint8_t* o = image.data();
    std::memcpy(o, &h, sizeof(h));
    o += sizeof(h);
    std::memcpy(o, nodes, count * sizeof(node));
    // the hash indexes are rebuilt by load()
    for (std::size_t i = 0; i < count; ++i)
    {
        if (nodes[i].kind == static_cast<std::uint8_t>(value_t::object) && nodes[i].extra != 0)
        {
            node n = nodes[i];
            n.extra = 0;
            std::memcpy(o + (i * sizeof(node)), &n, sizeof(node));
        }
    }
    o += count * sizeof(node);
    const auto append = [&o](const char* s, std::size_t n)
    {
        if (n != 0)
        {
            std::memcpy(o, s, n);
            o += n;
        }
    };
    append(d.src, d.size);
    append(text_tail.data(), text_tail.size());
    *o++ = 0;
    append(d.base[1], arena_size);
    append(arena_tail.data(), arena_tail.size());
    *o = 0;
    return image;
}

/// whether a number node matches its token the way the parser records it
/// (after the bounds check)
inline bool check_number(const node& n, const unsigned char* text)
{
    const std::size_t len = number_length(n);
    const unsigned char* const s = text + n.off;
    const unsigned char* const e = s + len;
    const unsigned char* p = s;
    const bool negative = *p == '-';
    p += negative ? 1 : 0;
    const unsigned char* const int_start = p;
    if (p == e)
    {
        return false;
    }
    if (*p == '0')
    {
        ++p;
    }
    else if (*p >= '1' && *p <= '9')
    {
        while (p != e && is_digit(*p))
        {
            ++p;
        }
    }
    else
    {
        return false;
    }
    const auto int_digits = static_cast<std::size_t>(p - int_start);
    std::size_t frac_digits = 0;
    bool is_float = false;
    if (p != e && *p == '.')
    {
        const unsigned char* const f0 = ++p;
        while (p != e && is_digit(*p))
        {
            ++p;
        }
        if (p == f0)
        {
            return false;
        }
        frac_digits = static_cast<std::size_t>(p - f0);
        is_float = true;
    }
    std::int64_t exponent = 0;
    if (p != e && (*p | 0x20u) == 'e')
    {
        ++p;
        const bool exp_negative = p != e && *p == '-';
        p += (p != e && (*p == '+' || *p == '-')) ? 1 : 0;
        if (p == e || !is_digit(*p))
        {
            return false;
        }
        while (p != e && is_digit(*p))
        {
            exponent = exponent < 100000 ? (exponent * 10) + (*p - '0') : exponent;
            ++p;
        }
        exponent = exp_negative ? -exponent : exponent;
        is_float = true;
    }
    if (p != e)
    {
        return false;
    }
    if (n.kind == static_cast<std::uint8_t>(value_t::number_float))
    {
        // the digit layout the parser records (or "many", as compaction
        // writes it), and a finite value
        const auto layout = static_cast<std::uint16_t>((int_digits < 255 ? int_digits : 255) | ((frac_digits < 255 ? frac_digits : 255) << 8u));
        if (n.extra != layout && n.extra != 0xFFFFu)
        {
            return false;
        }
        // parse() rejects floats that overflow; as there, only a number whose
        // magnitude could reach 1e308 needs the conversion
        if (static_cast<std::int64_t>(int_digits) + exponent > 300)
        {
            const auto v = float_value<double>(reinterpret_cast<const char*>(s), n); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
            return v <= (std::numeric_limits<double>::max)() && v >= -(std::numeric_limits<double>::max)();
        }
        return true;
    }
    // integers: the token's value is the stored one; number_integer nodes of
    // edits can be non-negative (as basic_json keeps the type of a value)
    const bool integer = n.kind == static_cast<std::uint8_t>(value_t::number_integer);
    if (is_float || int_digits > 20 || (negative && !integer))
    {
        return false;
    }
    // (at most 19 digits cannot overflow; 20 digits are compared with 2^64 - 1)
    if (int_digits == 20 && std::memcmp(int_start, "18446744073709551615", 20) > 0)
    {
        return false;
    }
    std::uint64_t m = 0;
    for (const unsigned char* d = int_start; d != int_start + int_digits; ++d)
    {
        m = (m * 10) + static_cast<std::uint64_t>(*d - '0');
    }
    if (integer && m > (negative ? std::uint64_t{1} << 63u : (std::uint64_t{1} << 63u) - 1))
    {
        return false;
    }
    return integer_bits(n) == (negative ? 0 - m : m);
}

/// Check the nodes of a loaded image against its text and decoded strings:
/// kinds, flags, and `extra`; extents and element counts of arrays and
/// objects; keys; bounds; string contents (source strings as the parser
/// leaves them: no quotes, backslashes, or control characters; all strings
/// valid UTF-8); and number tokens.
inline bool check_image(const node* nodes, std::size_t count, const unsigned char* text, std::size_t text_size,
                        const unsigned char* arena, std::size_t arena_size, bool full)
{
    struct frame
    {
        std::size_t end;
        std::uint32_t len;
        std::uint32_t seen;
        bool object;
        bool expect_key;
    };
    std::vector<frame> stack;
    const auto check_string = [&](const node & n) -> bool
    {
        if ((n.flags & ~node_flags::escaped) != 0 || n.extra != 0)
        {
            return false;
        }
        const bool decoded = (n.flags & node_flags::escaped) != 0;
        const unsigned char* const base = decoded ? arena : text;
        const std::size_t limit = decoded ? arena_size : text_size;
        if (n.off > limit || n.len > limit - n.off)
        {
            return false;
        }
        if (!full)
        {
            return true;
        }
        const unsigned char* const b = base + n.off;
        return decoded ? valid_utf8_prefix(b, n.len) == n.len : scan_string_run(b, b + n.len) == b + n.len;
    };
    // bounds of a number token; the recorded digit layout must lie within it
    const auto number_in_bounds = [&](const node & n) -> bool
    {
        const std::size_t len = number_length(n);
        if (len == 0 || n.off > text_size || len > text_size - n.off)
        {
            return false;
        }
        if (n.kind != static_cast<std::uint8_t>(value_t::number_float))
        {
            return (n.extra >> 8u) == 0;
        }
        // float_value() reads the sign, the integer digits, and the point and
        // fraction digits the layout records (a layout of more than 19 digits
        // means the general conversion, which stays within the token)
        const std::size_t int_digits = n.extra & 0xFFu;
        const std::size_t frac_digits = n.extra >> 8u;
        const std::size_t need = (text[n.off] == '-' ? 1u : 0u) + int_digits + (frac_digits != 0 ? frac_digits + 1 : 0);
        return int_digits + frac_digits > 19 || need <= len;
    };
    std::size_t i = 0;
    for (;;)
    {
        // close finished arrays and objects
        while (!stack.empty() && i == stack.back().end)
        {
            const frame f = stack.back();
            if (f.seen != f.len || (f.object && !f.expect_key))
            {
                return false;
            }
            stack.pop_back();
            if (!stack.empty())
            {
                ++stack.back().seen;
                stack.back().expect_key = true;
            }
        }
        if (i == count)
        {
            return stack.empty();
        }
        if (i != 0 && stack.empty())
        {
            return false; // nodes after the root
        }
        const node& n = nodes[i];
        if (!stack.empty() && stack.back().object && stack.back().expect_key)
        {
            if (n.kind != static_cast<std::uint8_t>(value_t::string) || !check_string(n))
            {
                return false;
            }
            stack.back().expect_key = false;
            ++i;
            continue;
        }
        bool complete = true;
        switch (static_cast<value_t>(n.kind))
        {
            case value_t::null:
                // (the offset of a literal is read to size the output of dump())
                if (n.flags != 0 || n.extra != 0 || n.off > text_size)
                {
                    return false;
                }
                break;
            case value_t::boolean:
                if ((n.flags & ~node_flags::is_true) != 0 || n.extra != 0 || n.off > text_size)
                {
                    return false;
                }
                break;
            case value_t::string:
                if (!check_string(n))
                {
                    return false;
                }
                break;
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::number_float:
                if (n.flags != 0 || !number_in_bounds(n) || (full && !check_number(n, text)))
                {
                    return false;
                }
                break;
            case value_t::array:
            case value_t::object:
            {
                const std::size_t limit = stack.empty() ? count : stack.back().end;
                if (n.flags != 0 || n.extra != 0 || n.next == 0 || n.next > limit - i || n.off > text_size)
                {
                    return false;
                }
                stack.push_back(frame{i + n.next, n.len, 0, n.kind == static_cast<std::uint8_t>(value_t::object), true});
                complete = false;
                break;
            }
            case value_t::binary:
            case value_t::discarded:
            default:
                return false;
        }
        ++i;
        if (complete && !stack.empty())
        {
            ++stack.back().seen;
            stack.back().expect_key = true;
        }
    }
}

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_invalid_image(const char* what)
{
    throw_parse_error(116, concat("invalid json_document image: ", what));
}

/// Read an image into d. The text and the decoded strings stay in the image;
/// the nodes are copied (so that they are aligned, and edits can change them).
inline void load_image(document_data& d, const std::uint8_t* image, std::size_t size, image_check check)
{
#if !NLOHMANN_VIEW_LITTLE_ENDIAN
    throw_type_error(320, "json_document images need a little-endian target"); // LCOV_EXCL_LINE
#endif
    if (image == nullptr || size < sizeof(image_header))
    {
        throw_invalid_image("too short");
    }
    image_header h{};
    std::memcpy(&h, image, sizeof(h));
    // (the reserved fields are for later versions)
    if (std::memcmp(h.magic.data(), "NJVI", 4) != 0 || h.version != image_version
            || (h.reserved[0] | h.reserved[1] | h.reserved[2] | h.reserved[3]) != 0)
    {
        throw_invalid_image("unknown format");
    }
    const std::size_t room = size - sizeof(h);
    if (h.node_count == 0 || h.node_count > room / sizeof(node) || h.node_count >= image_limit || h.text_size >= image_limit || h.arena_size >= image_limit)
    {
        throw_invalid_image("sizes out of range");
    }
    const auto count = static_cast<std::size_t>(h.node_count);
    const auto text_size = static_cast<std::size_t>(h.text_size);
    const auto arena_size = static_cast<std::size_t>(h.arena_size);
    const std::size_t text_at = sizeof(h) + (count * sizeof(node));
    // the text, a NUL, the decoded strings, a NUL, and nothing after them
    if (size - text_at < 2 || text_size > size - text_at - 2 || arena_size != size - text_at - text_size - 2
            || image[text_at + text_size] != 0 || image[size - 1] != 0)
    {
        throw_invalid_image("sizes out of range");
    }

    d.discarded = true;
    d.edits.reset();
    d.base[2] = nullptr;
    d.owned.clear();
    if (d.owned_image.empty() || image != d.owned_image.data())
    {
        d.owned_image.clear();
    }
    d.arena.clear();
    d.indexes.clear();
    d.index_slots.clear();
    d.large_objects.clear();
    d.tape_size = 0;
    d.reserve(count);
    std::memcpy(d.tape, image + sizeof(h), count * sizeof(node));
    d.tape_size = count;
    const std::uint8_t* const text = image + text_at;
    const std::uint8_t* const arena = text + text_size + 1;
    d.src = reinterpret_cast<const char*>(text); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    d.size = text_size;
    d.base[0] = d.src;
    d.base[1] = reinterpret_cast<const char*>(arena); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    d.arena_size = arena_size;
    if (check != image_check::none && !check_image(d.tape, count, text, text_size, arena, arena_size, check == image_check::full))
    {
        throw_invalid_image("the check failed");
    }
    // the hash indexes of large objects, as after parsing
    for (std::size_t i = 0; i < count; ++i)
    {
        node& n = d.tape[i];
        if (n.kind == static_cast<std::uint8_t>(value_t::object))
        {
            n.extra = 0;
            if (n.len >= document_data::index_min_members)
            {
                d.large_objects.push_back(static_cast<std::uint32_t>(i));
            }
        }
    }
    build_object_indexes(d);
    d.discarded = false;
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
