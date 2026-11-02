//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // min, sort
#include <array> // array
#include <cstddef> // offsetof, size_t
#include <cstdint> // int64_t, uint8_t, uint16_t, uint32_t, uint64_t
#include <cstring> // memcmp, memcpy, memset
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
/// are not finite become null, as dump() writes them. Nodes keep the flag
/// is_new: they have no source position (JSON_DIAGNOSTIC_POSITIONS).
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
        r.flags = static_cast<std::uint8_t>(r.flags | (s.flags & node_flags::is_new));
        return r;
    };
    const auto copy_node = [&](const node * v)
    {
        node r = *v;
        const auto is_new = static_cast<std::uint8_t>(v->flags & node_flags::is_new);
        switch (static_cast<value_t>(v->kind))
        {
            case value_t::object:
            case value_t::array:
                r.flags = is_new;
                r.extra = 0;
                r.off = (v->flags & (node_flags::moved | node_flags::is_new)) != 0 ? 0 : v->off;
                r.len = 0;  // counted below
                r.next = 0; // set when the container is complete
                stack.push_back(frame{d.first_child_edited(v), d.child_end_edited(v), out.size(), 0, v->kind == node_kind::object});
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
                r.flags = is_new;
                break;
            case value_t::number_float:
                if ((v->flags & node_flags::storage) == node_flags::edited)
                {
                    const char* const t = d.str(*v);
                    if (t[0] == 'n' || t[0] == 'i' || (v->len > 1 && t[1] == 'i'))
                    {
                        r = node{}; // nan and infinity: null, as dump() writes them
                        r.kind = node_kind::null;
                        r.flags = is_new;
                        break;
                    }
                    r.off = static_cast<std::uint32_t>(d.size + text_tail.size());
                    text_tail.append(t, v->len);
                    r.extra = 0xFFFFu; // the digit layout is not recorded
                }
                r.flags = is_new;
                break;
            case value_t::boolean:
                r.flags = static_cast<std::uint8_t>(v->flags & (node_flags::is_true | node_flags::is_new));
                break;
            case value_t::null:
            case value_t::binary:
            case value_t::discarded:
            default:
                r.flags = is_new;
                break;
        }
        out.push_back(r);
    };
    copy_node(d.nodes);
    while (!stack.empty())
    {
        const frame top = stack.back();
        if (top.cur == top.end)
        {
            node& c = out[top.index];
            c.len = top.count;
            c.next = static_cast<std::uint32_t>(out.size() - top.index);
            stack.pop_back();
            continue;
        }
        if (top.object)
        {
            out.push_back(string_node(*top.cur));
        }
        const node* const value = top.cur + (top.object ? 1 : 0);
        stack.back().cur = document_data::after(value);
        ++stack.back().count;
        copy_node(document_data::deref(value)); // may grow the stack
    }
}

#if NLOHMANN_VIEW_LITTLE_ENDIAN // (the image format is little-endian: no save() elsewhere)
/// the document as an image
inline std::vector<std::uint8_t> save_image(const document_data& d)
{
    const std::size_t arena_size = d.arena_size;
    std::vector<node> compacted;
    std::string text_tail;
    std::string arena_tail;
    if (d.edits)
    {
        compact_nodes(d, arena_size, compacted, text_tail, arena_tail);
    }
    const node* const nodes = d.edits ? compacted.data() : d.nodes;
    const std::size_t count = d.edits ? compacted.size() : d.node_count;
    const std::size_t text_size = d.size + text_tail.size();
    const std::size_t total_arena = arena_size + arena_tail.size();
    if (NLOHMANN_VIEW_UNLIKELY(text_size >= image_limit || total_arena >= image_limit || count >= image_limit))
    {
        // LCOV_EXCL_START (4 GiB)
        throw_out_of_range(exception_id::document_too_large, "images of 4 GiB or more are not supported by json_document");
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
    // the hash indexes are rebuilt by load(), whose check rejects any other
    // extra of an object, and the same document saves to the same bytes
    for (std::size_t i = 0; i < count; ++i)
    {
        if (nodes[i].kind == node_kind::object && nodes[i].extra != 0)
        {
            std::memset(o + (i * sizeof(node)) + offsetof(node, extra), 0, sizeof(nodes[i].extra));
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
#endif

/// the parts of a number token that the checks need
struct number_token
{
    const unsigned char* int_start;
    std::size_t int_digits;
    std::size_t frac_digits;
    std::int64_t exponent;
    bool negative;
    bool is_float; ///< a fraction or an exponent
};

/// advance over ASCII digits, eight bytes at a time
inline const unsigned char* digit_run(const unsigned char* p, const unsigned char* e) noexcept
{
    constexpr std::uint64_t ones = 0x0101010101010101ull;
    while (e - p >= 8)
    {
        // (the digits become 0..9; a byte above 9, or with bit 7 set, is no digit. A carry
        // out of a byte with bit 7 set only affects the bytes above, after the first one
        // that count_trailing_zeros finds.)
        const std::uint64_t x = read_eight_bytes(p) ^ (ones * 0x30u);
        const std::uint64_t not_digit = ((x + (ones * 0x76u)) | x) & (ones * 0x80u);
        if (not_digit != 0)
        {
            return p + (static_cast<std::size_t>(count_trailing_zeros(not_digit)) / 8);
        }
        p += 8;
    }
    while (p != e && is_digit(*p))
    {
        ++p;
    }
    return p;
}

/// whether the n bytes at p are ASCII digits (n > 0)
inline bool all_digits(const unsigned char* p, std::size_t n) noexcept
{
    const auto digits = [](const unsigned char* q)
    {
        constexpr std::uint64_t ones = 0x0101010101010101ull;
        const std::uint64_t x = read_eight_bytes(q) ^ (ones * 0x30u);
        return (((x + (ones * 0x76u)) | x) & (ones * 0x80u)) == 0;
    };
    if (n >= 8)
    {
        for (std::size_t i = 0; i + 8 < n; i += 8)
        {
            if (!digits(p + i))
            {
                return false;
            }
        }
        return digits(p + n - 8); // (overlapping the bytes before: they are digits)
    }
    for (std::size_t i = 0; i < n; ++i)
    {
        if (!is_digit(p[i]))
        {
            return false;
        }
    }
    return true;
}

/// Whether a float token has the shape that the parser records for most of
/// them: [-]digits.digits, with the numbers of digits of the node's layout
/// (extra). Then the token is a number of that layout, and the general scan
/// that follows is not needed.
inline bool plain_float_token(const unsigned char* s, std::size_t len, std::uint16_t extra) noexcept
{
    const std::size_t int_digits = extra & 0xFFu;
    const std::size_t frac_digits = extra >> 8u;
    if (int_digits == 0 || int_digits >= 255 || frac_digits == 0 || frac_digits >= 255 || len == 0)
    {
        return false;
    }
    const std::size_t negative = *s == '-' ? 1 : 0;
    if (len != negative + int_digits + 1 + frac_digits)
    {
        return false;
    }
    const unsigned char* const p = s + negative;
    return !(int_digits > 1 && *p == '0') && p[int_digits] == '.' && all_digits(p, int_digits) && all_digits(p + int_digits + 1, frac_digits);
}

/// whether [s, s + len) is a JSON number (the grammar the parser accepts)
inline bool scan_number_token(const unsigned char* s, std::size_t len, number_token& t)
{
    const unsigned char* const e = s + len;
    const unsigned char* p = s;
    t.negative = p != e && *p == '-';
    p += t.negative ? 1 : 0;
    if (p == e)
    {
        return false;
    }
    t.int_start = p;
    if (*p == '0')
    {
        ++p;
    }
    else if (*p >= '1' && *p <= '9')
    {
        p = digit_run(p + 1, e);
    }
    else
    {
        return false;
    }
    t.int_digits = static_cast<std::size_t>(p - t.int_start);
    t.frac_digits = 0;
    t.is_float = false;
    if (p != e && *p == '.')
    {
        const unsigned char* const f0 = ++p;
        p = digit_run(p, e);
        if (p == f0)
        {
            return false;
        }
        t.frac_digits = static_cast<std::size_t>(p - f0);
        t.is_float = true;
    }
    t.exponent = 0;
    if (p != e && (*p | 0x20u) == 'e')
    {
        ++p;
        const bool exp_negative = p != e && *p == '-';
        p += (p != e && (*p == '+' || *p == '-')) ? 1 : 0;
        if (p == e || !is_digit(*p))
        {
            return false;
        }
        do
        {
            t.exponent = t.exponent < 100000 ? (t.exponent * 10) + (*p - '0') : t.exponent;
            ++p;
        }
        while (p != e && is_digit(*p));
        t.exponent = exp_negative ? -t.exponent : t.exponent;
        t.is_float = true;
    }
    return p == e;
}

/// the digit layout the parser records for a float token (compaction
/// writes "many" instead; the caller accepts both)
inline std::uint16_t float_layout(const number_token& t)
{
    return static_cast<std::uint16_t>((std::min)(t.int_digits, std::size_t{255}) | ((std::min)(t.frac_digits, std::size_t{255}) << 8u));
}

/// whether a float token (well-formed, per scan_number_token) is finite as
/// double; parse() rejects floats that overflow, and as there, only a number
/// whose magnitude could reach 1e308 needs the conversion
inline bool float_token_finite(const unsigned char* s, std::size_t len, const number_token& t)
{
    if (static_cast<std::int64_t>(t.int_digits) + t.exponent > 300)
    {
        node n{};
        n.kind = node_kind::number_float;
        n.len = static_cast<std::uint32_t>(len);
        const auto v = float_value<double>(reinterpret_cast<const char*>(s), n); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        return v <= (std::numeric_limits<double>::max)() && v >= -(std::numeric_limits<double>::max)();
    }
    return true;
}

/// whether an integer node matches its token the way the parser records it
/// (after the bounds check; the token has at most 256 characters)
inline bool check_integer(const node& n, const unsigned char* text)
{
    const std::size_t len = number_length(n);
    const unsigned char* const s = text + n.off;
    number_token t{};
    if (!scan_number_token(s, len, t))
    {
        return false;
    }
    // the token's value is the stored one; number_integer nodes of edits can
    // be non-negative (as basic_json keeps the type of a value)
    const bool integer = n.kind == node_kind::number_integer;
    if (t.is_float || t.int_digits > 20 || (t.negative && !integer))
    {
        return false;
    }
    // (at most 19 digits cannot overflow; 20 digits are compared with 2^64 - 1)
    if (t.int_digits == 20 && std::memcmp(t.int_start, "18446744073709551615", 20) > 0)
    {
        return false;
    }
    std::uint64_t m = 0;
    for (const unsigned char* d = t.int_start; d != t.int_start + t.int_digits; ++d)
    {
        m = (m * 10) + static_cast<std::uint64_t>(*d - '0');
    }
    if (integer && m > (t.negative ? std::uint64_t{1} << 63u : (std::uint64_t{1} << 63u) - 1))
    {
        return false;
    }
    return integer_bits(n) == (t.negative ? 0 - m : m);
}

/// a byte range of the text or of the decoded strings
struct byte_range
{
    std::uint32_t off;
    std::uint32_t len;
};

/// a float token and the digit layout its node records
struct float_range
{
    std::uint32_t off;
    std::uint32_t len;
    std::uint16_t extra;
};

/// Run check once for each distinct range of ranges (which are within bounds
/// and not empty). Ranges that are not identical must not overlap: save()
/// writes every string and token to a place of its own, and nodes that share
/// a value (copies within a document) share the whole range. This bounds the
/// work by the size of the text, however many nodes point to the same bytes.
template<typename Check>
bool check_distinct_ranges(std::vector<byte_range>& ranges, Check check)
{
    // (save() writes the ranges in the order of the nodes, which is sorted already)
    const auto before = [](const byte_range & a, const byte_range & b)
    {
        return a.off != b.off ? a.off < b.off : a.len < b.len;
    };
    if (!std::is_sorted(ranges.begin(), ranges.end(), before))
    {
        std::sort(ranges.begin(), ranges.end(), before);
    }
    std::size_t end = 0;
    for (std::size_t i = 0; i < ranges.size(); ++i)
    {
        const byte_range r = ranges[i];
        if (i != 0 && r.off == ranges[i - 1].off && r.len == ranges[i - 1].len)
        {
            continue;
        }
        if (r.off < end || !check(r))
        {
            return false;
        }
        end = static_cast<std::size_t>(r.off) + r.len;
    }
    return true;
}

/// Check the float nodes: each token once (nodes of the same token must
/// record layouts that match it), tokens must not overlap.
inline bool check_float_ranges(std::vector<float_range>& ranges, const unsigned char* text)
{
    // (save() writes the tokens in the order of the nodes, which is sorted already)
    const auto before = [](const float_range & a, const float_range & b)
    {
        if (a.off != b.off)
        {
            return a.off < b.off;
        }
        if (a.len != b.len)
        {
            return a.len < b.len;
        }
        return a.extra < b.extra;
    };
    if (!std::is_sorted(ranges.begin(), ranges.end(), before))
    {
        std::sort(ranges.begin(), ranges.end(), before);
    }
    std::size_t end = 0;
    std::size_t i = 0;
    while (i < ranges.size())
    {
        const float_range r = ranges[i];
        if (r.off < end)
        {
            return false;
        }
        const unsigned char* const s = text + r.off;
        std::uint16_t layout = r.extra;
        if (!plain_float_token(s, r.len, r.extra))
        {
            number_token t{};
            if (!scan_number_token(s, r.len, t) || !float_token_finite(s, r.len, t))
            {
                return false;
            }
            // the digit layout the parser records (or "many", as compaction writes it)
            layout = float_layout(t);
        }
        for (; i < ranges.size() && ranges[i].off == r.off && ranges[i].len == r.len; ++i)
        {
            if (ranges[i].extra != layout && ranges[i].extra != 0xFFFFu)
            {
                return false;
            }
        }
        end = static_cast<std::size_t>(r.off) + r.len;
    }
    return true;
}

/// the content checks of check_image: source strings as the parser leaves
/// them (no quotes, backslashes, or control characters), decoded strings
/// (valid UTF-8), and float tokens
inline bool check_contents(const unsigned char* text, const unsigned char* arena,
                           std::vector<byte_range>& source_strings, std::vector<byte_range>& decoded_strings,
                           std::vector<float_range>& floats)
{
    return check_distinct_ranges(source_strings, [text](const byte_range & r)
    {
        const unsigned char* const b = text + r.off;
        return scan_string_run(b, b + r.len) == b + r.len;
    })
    && check_distinct_ranges(decoded_strings, [arena](const byte_range & r)
    {
        return valid_utf8_prefix(arena + r.off, r.len) == r.len;
    })
    && check_float_ranges(floats, text);
}

/// Check the nodes of a loaded image against its text and decoded strings:
/// kinds, flags, and `extra`; extents and element counts of arrays and
/// objects; keys; bounds; string contents (source strings as the parser
/// leaves them: no quotes, backslashes, or control characters; all strings
/// valid UTF-8); and number tokens.
///
/// The structure and the bounds are checked node by node. The contents of
/// strings and of float tokens are checked afterwards, once for each distinct
/// range (see check_distinct_ranges), so that the full check is linear in the
/// size of the image plus the sorting of the ranges, and not in the number of
/// nodes times the size of the text.
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
    std::vector<byte_range> source_strings;
    std::vector<byte_range> decoded_strings;
    std::vector<float_range> floats;
    const auto check_string = [&](const node & n) -> bool
    {
        if ((n.flags & ~(node_flags::escaped | node_flags::is_new)) != 0 || n.extra != 0)
        {
            return false;
        }
        const bool decoded = (n.flags & node_flags::escaped) != 0;
        const std::size_t limit = decoded ? arena_size : text_size;
        // (next: the source offset of a decoded string's opening quote plus
        // one, or 0; see node)
        if (n.off > limit || n.len > limit - n.off || n.next > text_size)
        {
            return false;
        }
        if (full && n.len != 0)
        {
            (decoded ? decoded_strings : source_strings).push_back(byte_range{n.off, n.len});
        }
        return true;
    };
    // bounds of a number token; the recorded digit layout must lie within it
    const auto number_in_bounds = [&](const node & n) -> bool
    {
        const std::size_t len = number_length(n);
        if (len == 0 || n.off > text_size || len > text_size - n.off)
        {
            return false;
        }
        if (n.kind != node_kind::number_float)
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
            return stack.empty() && (!full || check_contents(text, arena, source_strings, decoded_strings, floats));
        }
        if (i != 0 && stack.empty())
        {
            return false; // nodes after the root
        }
        const node& n = nodes[i];
        if (!stack.empty() && stack.back().object && stack.back().expect_key)
        {
            if (n.kind != node_kind::string || !check_string(n))
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
                if ((n.flags & ~node_flags::is_new) != 0 || n.extra != 0 || n.off > text_size)
                {
                    return false;
                }
                break;
            case value_t::boolean:
                if ((n.flags & ~(node_flags::is_true | node_flags::is_new)) != 0 || n.extra != 0 || n.off > text_size)
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
                if ((n.flags & ~node_flags::is_new) != 0 || !number_in_bounds(n))
                {
                    return false;
                }
                if (full)
                {
                    // (the contents of float tokens are checked later; the token of an
                    // integer has at most 256 characters)
                    if (n.kind == node_kind::number_float)
                    {
                        floats.push_back(float_range{n.off, n.len, n.extra});
                    }
                    else if (!check_integer(n, text))
                    {
                        return false;
                    }
                }
                break;
            case value_t::array:
            case value_t::object:
            {
                const std::size_t limit = stack.empty() ? count : stack.back().end;
                if ((n.flags & ~node_flags::is_new) != 0 || n.extra != 0 || n.next == 0 || n.next > limit - i || n.off > text_size)
                {
                    return false;
                }
                stack.push_back(frame{i + n.next, n.len, 0, n.kind == node_kind::object, true});
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
    throw_parse_error(exception_id::invalid_document_image, concat("invalid json_document image: ", what));
}

#if NLOHMANN_VIEW_LITTLE_ENDIAN // (the image format is little-endian: no load() elsewhere)
/// Read an image into d. The text and the decoded strings stay in the image;
/// the nodes are copied (so that they are aligned, and edits can change them).
inline void load_image(document_data& d, const std::uint8_t* image, std::size_t size, image_check check)
{
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
    d.node_count = 0;
    d.reserve(count);
    std::memcpy(d.nodes, image + sizeof(h), count * sizeof(node));
    d.node_count = count;
    const std::uint8_t* const text = image + text_at;
    const std::uint8_t* const arena = text + text_size + 1;
    d.src = reinterpret_cast<const char*>(text); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    d.size = text_size;
    d.base[0] = d.src;
    d.base[1] = reinterpret_cast<const char*>(arena); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    d.arena_size = arena_size;
    if (check != image_check::none && !check_image(d.nodes, count, text, text_size, arena, arena_size, check == image_check::full))
    {
        throw_invalid_image("the check failed");
    }
    // the hash indexes of large objects, as after parsing
    for (std::size_t i = 0; i < count; ++i)
    {
        const node& n = d.nodes[i];
        if (n.kind == node_kind::object && n.len >= document_data::index_min_members)
        {
            d.large_objects.push_back(static_cast<std::uint32_t>(i));
        }
    }
    build_object_indexes(d);
    std::vector<std::uint32_t>().swap(d.large_objects); // (only needed while building)
    d.discarded = false;
}
#endif

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
