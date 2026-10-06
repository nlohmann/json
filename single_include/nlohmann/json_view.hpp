//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

/****************************************************************************\
 * Zero-copy, read-only view of a parsed JSON text.                          *
 *                                                                           *
 * json_document::parse() builds a flat index of the values of a JSON text   *
 * (16 bytes per value) instead of a tree of basic_json values. Strings and  *
 * numbers stay in the source text; only strings with escapes are decoded,   *
 * into one buffer. json_view is a handle to one value of the document, with *
 * the read-only part of the basic_json interface; materialize() turns a     *
 * subtree into the basic_json value that parse() would produce.             *
 *                                                                           *
 * The source text must outlive a document that borrows it (lvalue byte     *
 * containers, C strings); rvalue strings, streams, and other inputs are     *
 * owned by the document.                                                    *
\****************************************************************************/

#ifndef INCLUDE_NLOHMANN_JSON_VIEW_HPP_
#define INCLUDE_NLOHMANN_JSON_VIEW_HPP_

#include <cstddef> // size_t
#include <cstring> // memcpy, strlen
#include <iterator> // distance, input_iterator_tag, iterator_traits
#include <map> // map
#include <memory> // unique_ptr
#include <string> // string
#include <tuple> // tuple_element, tuple_size
#include <type_traits> // decay, enable_if, integral_constant, is_arithmetic, is_base_of, is_integral, is_same, remove_cv, remove_extent
#include <unordered_map> // unordered_map
#include <utility> // forward, move
#include <vector> // vector

#include <nlohmann/json.hpp>

// the view builds on internals of the library: both must be the same version
#if NLOHMANN_JSON_VERSION_MAJOR != 3 || NLOHMANN_JSON_VERSION_MINOR != 12 || NLOHMANN_JSON_VERSION_PATCH != 0
    #error "json_view.hpp requires json.hpp of the same version (3.12.0)"
#endif

// #include <nlohmann/detail/view/builder.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-FileCopyrightText: 2020 YaoYuan <https://github.com/ibireme/yyjson>
// SPDX-License-Identifier: MIT



#include <algorithm> // find, find_if, max
#include <array> // array
#include <cstddef> // size_t, ptrdiff_t
#include <cstdint> // int64_t, uint8_t, uint16_t, uint32_t, uint64_t
#include <cstring> // memcmp, memcpy
#include <limits> // numeric_limits
#include <string> // string
#include <vector> // vector

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/document_data.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <array> // array
#include <cstddef> // size_t
#include <cstring> // memcpy
#include <new> // operator new, placement new
#include <string> // string

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/macro_scope.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



// Macros of json_view.hpp and its detail headers. json.hpp undefines its own
// macros at its end (macro_unscope.hpp), so the view defines the few it needs
// under its own prefix; json_view.hpp undefines them all at its end
// (detail/view/macro_unscope.hpp). Configuration that json.hpp undefines is
// read from detail::abi_config instead.

#if (defined(__cplusplus) && __cplusplus >= 201703L) || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
    #define NLOHMANN_VIEW_HAS_CPP_17 1
#else
    #define NLOHMANN_VIEW_HAS_CPP_17 0
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define NLOHMANN_VIEW_LIKELY(x) __builtin_expect(!!(x), 1)
    #define NLOHMANN_VIEW_UNLIKELY(x) __builtin_expect(!!(x), 0)
    #define NLOHMANN_VIEW_ALWAYS_INLINE inline __attribute__((always_inline))
    #define NLOHMANN_VIEW_NOINLINE __attribute__((noinline))
#elif defined(_MSC_VER)
    #define NLOHMANN_VIEW_LIKELY(x) (x)
    #define NLOHMANN_VIEW_UNLIKELY(x) (x)
    #define NLOHMANN_VIEW_ALWAYS_INLINE __forceinline
    #define NLOHMANN_VIEW_NOINLINE __declspec(noinline)
#else
    #define NLOHMANN_VIEW_LIKELY(x) (x)
    #define NLOHMANN_VIEW_UNLIKELY(x) (x)
    #define NLOHMANN_VIEW_ALWAYS_INLINE inline
    #define NLOHMANN_VIEW_NOINLINE
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define NLOHMANN_VIEW_NODISCARD __attribute__((warn_unused_result))
#elif defined(_MSC_VER)
    #define NLOHMANN_VIEW_NODISCARD _Check_return_
#else
    #define NLOHMANN_VIEW_NODISCARD
#endif

// exceptions as in json.hpp (JSON_NOEXCEPTION, JSON_THROW_USER)
#if (defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)) && !defined(JSON_NOEXCEPTION)
    #define NLOHMANN_VIEW_THROW(exception) throw exception
#else
    #include <cstdlib>
    // (the exception is built first, so that the arguments of the throwing
    // helpers count as used; the program ends anyway)
    #define NLOHMANN_VIEW_THROW(exception) (static_cast<void>(exception), std::abort())
#endif
#if defined(JSON_THROW_USER)
    #undef NLOHMANN_VIEW_THROW
    #define NLOHMANN_VIEW_THROW JSON_THROW_USER
#endif

// the parser stores a node's first word at once where the layout of `node` is
// known to be little-endian (MSVC targets are); elsewhere field by field
#if (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_MSC_VER)
    #define NLOHMANN_VIEW_LITTLE_ENDIAN 1
#else
    #define NLOHMANN_VIEW_LITTLE_ENDIAN 0
#endif

/// sixteen checks at fixed offsets 0..15
#define NLOHMANN_VIEW_REPEAT16(X) X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7) X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15)

// #include <nlohmann/detail/view/node.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint16_t, uint32_t, uint64_t
#include <cstring> // memcpy

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/macro_scope.hpp>


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

// the node kinds are value_t values; the tests of is_container() and of the
// number kinds depend on this numbering
static_assert(static_cast<std::uint8_t>(value_t::null) == 0 && static_cast<std::uint8_t>(value_t::object) == 1
              && static_cast<std::uint8_t>(value_t::array) == 2 && static_cast<std::uint8_t>(value_t::string) == 3
              && static_cast<std::uint8_t>(value_t::boolean) == 4 && static_cast<std::uint8_t>(value_t::number_integer) == 5
              && static_cast<std::uint8_t>(value_t::number_unsigned) == 6 && static_cast<std::uint8_t>(value_t::number_float) == 7,
              "the node format depends on the numbering of value_t");

/// node flags
struct node_flags
{
    static constexpr std::uint8_t escaped = 1; ///< string payload lives in the decode arena, not the source
    static constexpr std::uint8_t storage = 3; ///< mask: where a string or number token lives (index into document_data::base)
    static constexpr std::uint8_t is_true = 4; ///< boolean value
};

/// One entry of the flat index, in document order. An object's members are
/// stored as key node followed by the value's subtree. Integers keep their
/// converted 64-bit value in the len/next bytes (the node after a scalar is
/// always the next one, and the token length follows from `extra`).
struct node
{
    std::uint8_t kind;   ///< value_t
    std::uint8_t flags;  ///< node_flags
    std::uint16_t extra; ///< numbers: integer digits (low byte) and fraction digits (high byte), 255 = "many"; otherwise 0
    std::uint32_t off;   ///< source offset (string content, number token, literal, bracket); arena offset if node_flags::escaped
    std::uint32_t len;   ///< string: decoded bytes; float: token bytes; array/object: element count
    std::uint32_t next;  ///< array/object: number of nodes of the subtree (its extent in the enclosing sequence)
};
static_assert(sizeof(node) == 16, "node must stay 16 bytes");

NLOHMANN_VIEW_ALWAYS_INLINE bool is_container(const node& n) noexcept
{
    return static_cast<unsigned>(n.kind) - 1u <= 1u;
}

/// the converted value of an integer node (stored in len/next)
NLOHMANN_VIEW_ALWAYS_INLINE std::uint64_t integer_bits(const node& n) noexcept
{
    std::uint64_t v = 0;
    std::memcpy(&v, reinterpret_cast<const unsigned char*>(&n) + 8, 8); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    return v;
}

NLOHMANN_VIEW_ALWAYS_INLINE void set_integer_bits(node& n, std::uint64_t v) noexcept
{
    std::memcpy(reinterpret_cast<unsigned char*>(&n) + 8, &v, 8); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
}

/// token length of a number node
NLOHMANN_VIEW_ALWAYS_INLINE std::uint32_t number_length(const node& n) noexcept
{
    return n.kind == static_cast<std::uint8_t>(value_t::number_float) ? n.len
           : (n.extra & 0xFFu) + (n.kind == static_cast<std::uint8_t>(value_t::number_integer) ? 1u : 0u);
}

/// estimated number of nodes for an input of `size` bytes (one node per ~12
/// bytes covers typical documents without regrowth)
inline std::size_t estimate_nodes(std::size_t size) noexcept
{
    return (size / 12) + 16;
}

/// estimated number of nodes for the input [src, src + size): pretty-printed
/// input (whitespace after the first byte) needs about a node per 12 bytes,
/// minified input up to one per 4 (yyjson tells the two apart the same way)
inline std::size_t estimate_nodes(const char* src, std::size_t size) noexcept
{
    return size >= 2 && (src[1] == ' ' || src[1] == '\n' || src[1] == '\r' || src[1] == '\t') ? estimate_nodes(size) : (size / 4) + 16;
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END


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

    document_data() noexcept = default;
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

// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/node.hpp>

// #include <nlohmann/detail/view/scan.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-FileCopyrightText: 2020 YaoYuan <https://github.com/ibireme/yyjson>
// SPDX-License-Identifier: MIT



#include <array> // array
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint16_t, uint64_t
#include <cstring> // memcpy

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/macro_scope.hpp>


// Scanning primitives of the view's parser. The unrolled checks at fixed
// offsets follow yyjson (https://github.com/ibireme/yyjson, MIT license): the
// loads do not depend on each other, so the CPU can run ahead. Words are read
// with read_eight_bytes(), so nothing here depends on the byte order.

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// 1 for bytes that may appear verbatim in a string: 0x20..0x7F except '"' and '\\'
inline const std::uint8_t* string_plain() noexcept
{
    static const std::array<std::uint8_t, 256> table =
    {
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x00..0x1F
            1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x20..0x3F ('"')
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, // 0x40..0x5F ('\\')
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0x60..0x7F
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0x80..0x9F
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xA0..0xBF
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xC0..0xDF
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0xE0..0xFF
        }
    };
    return table.data();
}

NLOHMANN_VIEW_ALWAYS_INLINE bool is_digit(unsigned char c) noexcept
{
    return static_cast<unsigned char>(c - '0') <= 9;
}

/// two bytes as they are in memory (only compared with byte-symmetric patterns)
NLOHMANN_VIEW_ALWAYS_INLINE std::uint16_t load16(const unsigned char* p) noexcept
{
    std::uint16_t w = 0;
    std::memcpy(&w, p, 2);
    return w;
}

/// Advance over plain string bytes and well-formed UTF-8. Stops at a quote,
/// a backslash, a control character, ill-formed UTF-8, or the end. The first
/// 16 bytes are checked one by one, so that the position advances by
/// constants in predicted branches (most strings are short); longer runs
/// continue eight bytes at a time.
NLOHMANN_VIEW_ALWAYS_INLINE const unsigned char* scan_string_run(const unsigned char* p, const unsigned char* e) noexcept
{
    const std::uint8_t* plain = string_plain();
    for (;;)
    {
        if (e - p >= 16)
        {
#define NLOHMANN_VIEW_STEP(i) if (NLOHMANN_VIEW_LIKELY(plain[p[i]] != 0)) {} else { p += (i); goto stop; }
            NLOHMANN_VIEW_REPEAT16(NLOHMANN_VIEW_STEP)
#undef NLOHMANN_VIEW_STEP
            p += 16;
            while (e - p >= 8)
            {
                const std::uint64_t special = swar_string_special(read_eight_bytes(p));
                if (special != 0)
                {
                    p += count_trailing_zeros(special) / 8;
                    goto stop;
                }
                p += 8;
            }
            continue;
        }
        while (p != e && plain[*p] != 0)
        {
            ++p;
        }
        if (p == e)
        {
            return p;
        }
stop:
        if (*p < 0x80)
        {
            return p; // quote, backslash, or control character
        }
        // non-ASCII: a run of well-formed sequences (the library's check, so
        // that exactly what json::parse accepts is accepted)
        do
        {
            const std::size_t n = validate_one_utf8(p, static_cast<std::size_t>(e - p));
            if (n == 0)
            {
                return p;
            }
            p += n;
        }
        while (p != e && *p >= 0x80);
    }
}

/// advance over ASCII digits
NLOHMANN_VIEW_ALWAYS_INLINE const unsigned char* skip_digits(const unsigned char* p, const unsigned char* e) noexcept
{
    while (e - p >= 16)
    {
#define NLOHMANN_VIEW_STEP(i) if (NLOHMANN_VIEW_LIKELY(is_digit(p[i]))) {} else { return p + (i); }
        NLOHMANN_VIEW_REPEAT16(NLOHMANN_VIEW_STEP)
#undef NLOHMANN_VIEW_STEP
        p += 16;
    }
    while (p != e && is_digit(*p))
    {
        ++p;
    }
    return p;
}

/// powers of ten up to 10^19 as integers
inline std::uint64_t int_pow10(unsigned k) noexcept
{
    static const std::array<std::uint64_t, 20> table =
    {
        {
            1u, 10u, 100u, 1000u, 10000u, 100000u, 1000000u, 10000000u, 100000000u, 1000000000u,
            10000000000u, 100000000000u, 1000000000000u, 10000000000000u, 100000000000000u, 1000000000000000u,
            10000000000000000u, 100000000000000000u, 1000000000000000000u, 10000000000000000000u
        }
    };
    return table[k];
}

/// value of 0 < k < 8 digits at p in one step if [p, p + 8) lies below
/// limit, else one digit at a time (whole blocks of eight digits are read by
/// parse_upto19() directly)
NLOHMANN_VIEW_ALWAYS_INLINE std::uint64_t parse_upto8(const unsigned char* p, unsigned k, const unsigned char* limit) noexcept
{
    if (NLOHMANN_VIEW_LIKELY(limit - p >= 8))
    {
        // move the k digits to the top and pad the vacated low bytes with '0'
        const unsigned shift = 8 * (8 - k);
        return parse_eight_digits((read_eight_bytes(p) << shift) | (0x3030303030303030u >> (8 * k)));
    }
    std::uint64_t v = 0;
    for (unsigned i = 0; i < k; ++i)
    {
        v = (v * 10) + static_cast<std::uint64_t>(p[i] - '0');
    }
    return v;
}

/// value of k <= 19 digits at p
NLOHMANN_VIEW_ALWAYS_INLINE std::uint64_t parse_upto19(const unsigned char* p, unsigned k, const unsigned char* limit) noexcept
{
    std::uint64_t w = 0;
    while (k >= 8)
    {
        // (eight digits of the token: they lie below limit)
        w = (w * 100000000u) + parse_eight_digits(read_eight_bytes(p));
        p += 8;
        k -= 8;
    }
    if (k != 0)
    {
        w = (w * int_pow10(k)) + parse_upto8(p, k, limit);
    }
    return w;
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END


// The view's parser: one pass over the input that emits the node index (see
// node.hpp). The table-driven decoding of \u escapes and the fast paths for
// ": " and indentation follow yyjson (https://github.com/ibireme/yyjson, MIT
// license).

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

enum class error_code : std::uint8_t
{
    none,
    empty_input,
    unexpected_value,
    invalid_literal,
    expected_key,
    expected_colon,
    expected_array_end,
    expected_object_end,
    trailing_characters,
    number_after_minus,
    number_after_dot,
    number_after_exponent,
    number_overflow,
    string_missing_quote,
    string_control_character,
    string_utf8,
    string_escape,
    string_unicode_hex,
    string_surrogate_high,
    string_surrogate_low,
    comment_start,
    comment_unterminated,
    input_too_large,
};

struct parse_failure
{
    error_code code = error_code::none;
    std::size_t offset = 0; ///< byte offset of the offending character
};

/// FloatType: the number_float_t of the document, whose overflow parse() rejects
template<typename FloatType, bool Comments, bool TrailingCommas, bool NulIsEnd, bool Sentinel>
class builder
{
  public:
    builder(document_data& d, const char* src, std::size_t size) noexcept
        : doc(d)
        , b(reinterpret_cast<const unsigned char*>(src))
        , e(b + size)
    {}

    /// returns false and fills `failure` on error
    bool run()
    {
        cursor c(*this);
        return c.run();
    }

    builder(const builder&) = delete;
    builder& operator=(const builder&) = delete;
    builder(builder&&) = delete;
    builder& operator=(builder&&) = delete;
    ~builder() = default;

    /// where and why the parse failed (after run() returned false)
    const parse_failure& failure() const noexcept
    {
        return m_failure;
    }

  private:
    struct frame
    {
        std::uint32_t idx;
        std::uint32_t count;
        bool is_object;
    };

    document_data& doc;
    const unsigned char* const b;
    const unsigned char* const e;
    parse_failure m_failure{};

    // the open array/object is in the cursor; enclosing ones on a stack that is
    // inline for the first 64 levels
    frame shallow[64]; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays): not initialized on purpose; filled as containers open
    std::vector<frame> deep{};

    NLOHMANN_VIEW_NOINLINE bool fail(error_code c, const unsigned char* at) noexcept
    {
        m_failure.code = c;
        m_failure.offset = static_cast<std::size_t>(at - b);
        doc.tape_size = 0;
        return false;
    }

    /// a failure (recorded by fail) as a comment() result
    const unsigned char* fail_at(error_code c, const unsigned char* at) noexcept
    {
        fail(c, at);
        return nullptr;
    }

    /// a decoded string: p after its closing quote (nullptr: an error), and
    /// its bytes in the arena
    struct decoded
    {
        const unsigned char* p;
        std::size_t start;
        std::size_t len;
    };

    decoded failed(error_code c, const unsigned char* at) noexcept
    {
        fail(c, at);
        return decoded{nullptr, 0, 0};
    }

    /// the comment at p (*p == '/'): the position after it, or nullptr on error
    NLOHMANN_VIEW_NOINLINE const unsigned char* comment(const unsigned char* p)
    {
        if (e - p < 2)
        {
            ++p;
            return fail_at(error_code::comment_start, p);
        }
        if (p[1] == '/')
        {
            p += 2;
            // (as in parse(), a null byte is the end of the input, so it is
            // left for the caller to see)
            while (p != e && *p != '\n' && *p != '\r' && !(NulIsEnd && *p == 0))
            {
                ++p;
            }
            return p;
        }
        if (p[1] == '*')
        {
            p += 2;
            for (;;)
            {
                if (p == e || (NulIsEnd && *p == 0))
                {
                    return fail_at(error_code::comment_unterminated, p);
                }
                if (*p == '*' && p + 1 != e && p[1] == '/')
                {
                    p += 2;
                    return p;
                }
                ++p;
            }
        }
        ++p;
        return fail_at(error_code::comment_start, p);
    }

    /// the index is full (n nodes, parsed up to at): extrapolate the node
    /// count from the nodes per input byte so far (with headroom, and at least
    /// 1.5 times as many), so that dense inputs regrow once instead of
    /// doubling repeatedly; returns the new node array
    NLOHMANN_VIEW_NOINLINE node* grow(std::size_t n, const unsigned char* at)
    {
        const std::uint64_t done = static_cast<std::uint64_t>(at - b) + 1;
        const std::uint64_t guess = static_cast<std::uint64_t>(n) * static_cast<std::uint64_t>(e - b + 1) / done;
        const std::uint64_t grown = guess + (guess / 4) + 64; // a variable: GCC calls a cast of the sum useless where std::uint64_t is std::size_t
        doc.tape_size = n;
        doc.reserve((std::max)(static_cast<std::size_t>(grown), n + (n / 2) + 64));
        return doc.tape;
    }

    /// four hex digits at p as a code unit (p moves past them), or -1 (p at
    /// the first bad digit); one table lookup per digit and a single check,
    /// the four hex digits of a unicode escape (the library's table, after
    /// yyjson's read_hex_u16), or -1
    NLOHMANN_VIEW_ALWAYS_INLINE int hex4(const unsigned char*& p) noexcept
    {
        if (NLOHMANN_VIEW_LIKELY(e - p >= 4))
        {
            const int cp = hex_codepoint(p);
            if (NLOHMANN_VIEW_LIKELY(cp >= 0))
            {
                p += 4;
                return cp;
            }
        }
        p = hex4_error(p);
        return -1;
    }

    /// hex4() failed: the first bad digit (none: p)
    NLOHMANN_VIEW_NOINLINE const unsigned char* hex4_error(const unsigned char* p) noexcept
    {
        if (e - p >= 4)
        {
            while (is_hex(*p))
            {
                ++p;
            }
        }
        return p;
    }

    /// escapes present (or an error) in the string at s, scanned up to p:
    /// decode into the arena
    NLOHMANN_VIEW_NOINLINE decoded slow_string(const unsigned char* s, const unsigned char* p)
    {
        // single-character escapes; 0: invalid (and 'u', handled separately)
        static const std::array<char, 128> simple_escape =
        {
            {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, '"', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '/', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, '\\', 0, 0, 0,
                0, 0, '\b', 0, 0, 0, '\f', 0, 0, 0, 0, 0, 0, 0, '\n', 0, 0, 0, '\r', 0, '\t', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            }
        };
        const std::size_t start = arena_used();
        arena_run(s, static_cast<std::size_t>(p - s));
        for (;;)
        {
            if (p == e)
            {
                return failed(error_code::string_missing_quote, p);
            }
            const unsigned char c = *p;
            if (c == '"')
            {
                ++p;
                return decoded{p, start, arena_used() - start};
            }
            if (c != '\\')
            {
                // (a NUL before the end of the input is a control character, as
                // for json::parse, also where a NUL ends the input between values)
                return failed(c < 0x20 ? error_code::string_control_character : error_code::string_utf8, p);
            }
            ++p;
            if (p == e)
            {
                return failed(error_code::string_missing_quote, p);
            }
            const unsigned char d = *p++;
            arena_ensure(4);
            if (d == 'u')
            {
                int cp = hex4(p);
                if (NLOHMANN_VIEW_UNLIKELY(cp < 0))
                {
                    return failed(error_code::string_unicode_hex, p);
                }
                if (NLOHMANN_VIEW_UNLIKELY((cp & 0xF800) == 0xD800)) // a surrogate
                {
                    if (cp >= 0xDC00)
                    {
                        return failed(error_code::string_surrogate_low, p);
                    }
                    if (e - p < 2 || p[0] != '\\' || p[1] != 'u')
                    {
                        return failed(error_code::string_surrogate_high, p);
                    }
                    p += 2;
                    const int lo = hex4(p);
                    if (lo < 0)
                    {
                        return failed(error_code::string_unicode_hex, p);
                    }
                    if (lo < 0xDC00 || lo > 0xDFFF)
                    {
                        return failed(error_code::string_surrogate_high, p);
                    }
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                }
                aw = put_utf8(aw, cp);
            }
            else if (NLOHMANN_VIEW_LIKELY(d < 128 && simple_escape[d] != 0))
            {
                *aw++ = simple_escape[d];
            }
            else
            {
                --p;
                return failed(error_code::string_escape, p);
            }
            if (p != e && *p == '\\')
            {
                continue; // consecutive escapes ("\u00e4\u00f6"): no run in between
            }
            const unsigned char* const r = p;
            p = scan_string_run(p, e);
            arena_run(r, static_cast<std::size_t>(p - r));
        }
    }

    /// does the float token [s, p) overflow FloatType? (parse() rejects it)
    NLOHMANN_VIEW_NOINLINE static bool float_overflows(const unsigned char* s, const unsigned char* p)
    {
        const auto* const first = reinterpret_cast<const char*>(s); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto* const last = reinterpret_cast<const char*>(p); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        const char* const dot = std::find(first, last, '.');
        const char* const exponent = std::find_if(first, last, [](char c)
        {
            return c == 'e' || c == 'E';
        });
        const auto v = convert_float<FloatType>(first, last, dot == last ? std::string::npos : static_cast<std::size_t>(dot - first),
                                                static_cast<std::size_t>(exponent - first));
        return v > (std::numeric_limits<FloatType>::max)() || v < -(std::numeric_limits<FloatType>::max)();
    }

    /// does the magnitude digits [d, d + n) exceed the given limit (same length)?
    static bool digits_exceed(const unsigned char* d, const char* limit, std::size_t n) noexcept
    {
        return std::memcmp(d, limit, n) > 0;
    }

    static bool is_hex(unsigned char c) noexcept
    {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }

    // decode arena: the std::string in the document, written through a raw
    // pointer (resized ahead in large steps; trimmed when parsing succeeds)
    char* aw = nullptr;
    char* aend = nullptr;

    NLOHMANN_VIEW_ALWAYS_INLINE std::size_t arena_used() const noexcept
    {
        return aw != nullptr ? static_cast<std::size_t>(aw - doc.arena.data()) : 0;
    }

    NLOHMANN_VIEW_ALWAYS_INLINE void arena_ensure(std::size_t n)
    {
        if (NLOHMANN_VIEW_UNLIKELY(static_cast<std::size_t>(aend - aw) < n))
        {
            arena_grow(n);
        }
    }

    NLOHMANN_VIEW_NOINLINE void arena_grow(std::size_t n)
    {
        const std::size_t used = arena_used();
        doc.arena.resize((std::max)(doc.arena.size() * 2, used + n + 256));
        aw = &doc.arena[0] + used; // NOLINT(readability-container-data-pointer): data() is const before C++17
        aend = &doc.arena[0] + doc.arena.size(); // NOLINT(readability-container-data-pointer)
    }

    /// append the run [r, r + n) to the arena; short runs as one fixed-size
    /// 16-byte move when both sides have the room (no library call)
    NLOHMANN_VIEW_ALWAYS_INLINE void arena_run(const unsigned char* r, std::size_t n)
    {
        arena_ensure(n + 16);
        if (n <= 16 && e - r >= 16)
        {
            std::memcpy(aw, r, 16);
        }
        else
        {
            std::memcpy(aw, r, n);
        }
        aw += n;
    }

    /// UTF-8 encoding of cp at w (room for 4 bytes)
    static char* put_utf8(char* w, int cp) noexcept
    {
        if (cp < 0x80)
        {
            *w++ = static_cast<char>(cp);
        }
        else if (cp < 0x800)
        {
            *w++ = static_cast<char>(0xC0 | (cp >> 6));
            *w++ = static_cast<char>(0x80 | (cp & 0x3F));
        }
        else if (cp < 0x10000)
        {
            *w++ = static_cast<char>(0xE0 | (cp >> 12));
            *w++ = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            *w++ = static_cast<char>(0x80 | (cp & 0x3F));
        }
        else
        {
            *w++ = static_cast<char>(0xF0 | (cp >> 18));
            *w++ = static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            *w++ = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            *w++ = static_cast<char>(0x80 | (cp & 0x3F));
        }
        return w;
    }

    /// a compile-time option as a runtime condition: testing the template
    /// argument directly makes a condition like `TrailingCommas && c == ']'`
    /// constant when the option is off, which MSVC reports as C4127
    static NLOHMANN_VIEW_ALWAYS_INLINE bool enabled(bool option) noexcept
    {
        return option;
    }

    /// The parse state and the parser proper. The cursor is a local object of
    /// run() whose address never escapes (everything it calls out of line is a
    /// member of the builder and gets the positions it needs), so that the
    /// compiler keeps the state in registers instead of reloading it from
    /// memory after every node store and call.
    struct cursor
    {
        explicit cursor(builder& owner) noexcept
            : cold(owner)
            , b(owner.b)
            , p(owner.b)
            , e(owner.e)
        {}

        builder& cold; ///< out-of-line helpers and state that needs no registers
        const unsigned char* const b;
        const unsigned char* p;
        const unsigned char* const e;
        node* base = nullptr;
        node* out = nullptr;
        node* cap = nullptr;

        // the open array/object
        std::uint32_t cur_idx = 0;
        std::uint32_t cur_count = 0;
        bool cur_is_object = false;
        std::size_t depth = 0;

        NLOHMANN_VIEW_ALWAYS_INLINE bool run()
        {
            cold.doc.reserve(estimate_nodes(reinterpret_cast<const char*>(b), static_cast<std::size_t>(e - b)));
            base = cold.doc.tape;
            out = base;
            cap = base + cold.doc.tape_cap;

            if (e - p >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)
            {
                p += 3; // byte order mark
            }
            if (!ws())
            {
                return false;
            }
            if (p == e || (NulIsEnd && *p == 0))
            {
                return fail(error_code::empty_input);
            }

            // root value
            switch (cur())
            {
                case '{':
                    open(value_t::object);
                    ++p;
                    goto obj_first;
                case '[':
                    open(value_t::array);
                    ++p;
                    goto arr_first;
                default:
                    if (!scalar())
                    {
                        return false;
                    }
                    goto root_done;
            }

            // value dispatch, expanded once for array elements and once for member
            // values: each jump has its own history (arrays tend to hold one kind of
            // value), and the continuation needs no branch on the container kind
#define NLOHMANN_VIEW_VALUE(NEXT)                                                                   \
    switch (cur())                                                                              \
    {                                                                                           \
        case '"':                                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!string())) { return false; }                      \
            goto NEXT;                                                                          \
        case '{':                                                                               \
            open(value_t::object);                                                              \
            ++p;                                                                                \
            goto obj_first;                                                                     \
        case '[':                                                                               \
            open(value_t::array);                                                               \
            ++p;                                                                                \
            goto arr_first;                                                                     \
        case '-':                                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!number<true>())) { return false; }                      \
            goto NEXT;                                                                          \
        case '0': case '1': case '2': case '3':                                                 \
        case '4': case '5': case '6': case '7': case '8': case '9':                             \
            if (NLOHMANN_VIEW_UNLIKELY(!number<false>())) { return false; }                     \
            goto NEXT;                                                                          \
        case 't':                                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!literal("true", 4, value_t::boolean, node_flags::is_true))) { return false; } \
            goto NEXT;                                                                          \
        case 'f':                                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!literal_false())) { return false; }                     \
            goto NEXT;                                                                          \
        case 'n':                                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!literal("null", 4, value_t::null, 0))) { return false; } \
            goto NEXT;                                                                          \
        default:                                                                                \
            return fail(error_code::unexpected_value);                                          \
    }

arr_first:
            if (!ws())
            {
                return false;
            }
            if (cur() == ']')
            {
                ++p;
                goto close_container;
            }
value:
            NLOHMANN_VIEW_VALUE(arr_next)
arr_next:
            ++cur_count;
            if (!ws())
            {
                return false;
            }
            if (NLOHMANN_VIEW_LIKELY(cur() == ','))
            {
                ++p;
                if (!ws())
                {
                    return false;
                }
                if (enabled(TrailingCommas) && cur() == ']')
                {
                    ++p;
                    goto close_container;
                }
                goto value;
            }
            if (cur() == ']')
            {
                ++p;
                goto close_container;
            }
            return fail(error_code::expected_array_end);

obj_first:
            if (!ws())
            {
                return false;
            }
            if (cur() == '}')
            {
                ++p;
                goto close_container;
            }
obj_key:
            if (NLOHMANN_VIEW_UNLIKELY(cur() != '"'))
            {
                return fail(error_code::expected_key);
            }
            if (NLOHMANN_VIEW_UNLIKELY(!string()))
            {
                return false;
            }
            if (NLOHMANN_VIEW_LIKELY(cur() == ':' && (Sentinel || e - p >= 2) && p[1] == ' '))
            {
                p += 2; // ": " (pretty-printed input; a fast path of yyjson)
            }
            else
            {
                if (!ws())
                {
                    return false;
                }
                if (NLOHMANN_VIEW_UNLIKELY(cur() != ':'))
                {
                    return fail(error_code::expected_colon);
                }
                ++p;
            }
            if (!ws())
            {
                return false;
            }
            NLOHMANN_VIEW_VALUE(obj_next)
obj_next:
            ++cur_count;
            if (!ws())
            {
                return false;
            }
            if (NLOHMANN_VIEW_LIKELY(cur() == ','))
            {
                ++p;
                if (!ws())
                {
                    return false;
                }
                if (enabled(TrailingCommas) && cur() == '}')
                {
                    ++p;
                    goto close_container;
                }
                goto obj_key;
            }
            if (cur() == '}')
            {
                ++p;
                goto close_container;
            }
            return fail(error_code::expected_object_end);

#undef NLOHMANN_VIEW_VALUE

close_container:
            close();
            if (NLOHMANN_VIEW_UNLIKELY(depth == 0))
            {
                goto root_done;
            }
            if (cur_is_object)
            {
                goto obj_next;
            }
            goto arr_next;

root_done:
            if (!ws())
            {
                return false;
            }
            if (p != e && !(NulIsEnd && *p == 0))
            {
                return fail(error_code::trailing_characters);
            }
            cold.doc.tape_size = static_cast<std::size_t>(out - base);
            cold.doc.arena.resize(cold.arena_used());
            return true;
        }

        NLOHMANN_VIEW_ALWAYS_INLINE bool fail(error_code c) noexcept
        {
            return cold.fail(c, p);
        }

        /// the current byte, or 0 at the end. With a NUL-terminated input
        /// (Sentinel) the terminator is read instead of checking the bounds; a 0
        /// never matches a JSON token, so the error paths tell the end apart.
        NLOHMANN_VIEW_ALWAYS_INLINE unsigned char cur() const noexcept
        {
            if (Sentinel)
            {
                return *p;
            }
            return p != e ? *p : 0;
        }

        /// root scalar
        NLOHMANN_VIEW_ALWAYS_INLINE bool scalar()
        {
            switch (cur())
            {
                case '"':
                    return string();
                case 't':
                    return literal("true", 4, value_t::boolean, node_flags::is_true);
                case 'f':
                    return literal_false();
                case 'n':
                    return literal("null", 4, value_t::null, 0);
                case '-':
                    return number<true>();
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    return number<false>();
                default:
                    return fail(error_code::unexpected_value);
            }
        }

        NLOHMANN_VIEW_ALWAYS_INLINE bool literal_false()
        {
            return literal("false", 5, value_t::boolean, 0);
        }

        /// skip whitespace (and comments); false on a malformed comment
        NLOHMANN_VIEW_ALWAYS_INLINE bool ws()
        {
            const unsigned char c = cur();
            if (NLOHMANN_VIEW_LIKELY(c > ' ' && (!Comments || c != '/')))
            {
                return true; // no whitespace: the common case in minified input
            }
            return ws_slow();
        }

        NLOHMANN_VIEW_ALWAYS_INLINE bool ws_slow()
        {
            for (;;)
            {
                if (cur() == ' ' && (Sentinel || e - p >= 2) && p[1] > ' ' && (!Comments || p[1] != '/'))
                {
                    ++p; // single space, e.g. after ':' or ','
                    return true;
                }
                if (cur() == '\n' || cur() == '\r')
                {
                    // (a branch, not an add of the comparison: p must not
                    // wait for the byte after the line break)
                    if (NLOHMANN_VIEW_UNLIKELY(cur() == '\r') && (Sentinel || e - p >= 2) && p[1] == '\n')
                    {
                        p += 2;
                    }
                    else
                    {
                        ++p;
                    }
                    // indentation: two spaces per step, fixed offsets (after yyjson)
                    while (e - p >= 32)
                    {
#define NLOHMANN_VIEW_STEP(i) if (NLOHMANN_VIEW_LIKELY(load16(p + (std::ptrdiff_t{2} * (i))) == 0x2020)) {} else { p += std::ptrdiff_t{2} * (i); goto indent_done; }
                        NLOHMANN_VIEW_REPEAT16(NLOHMANN_VIEW_STEP)
#undef NLOHMANN_VIEW_STEP
                        p += 32;
                    }
indent_done:
                    ;
                }
                for (unsigned char c = cur(); c == ' ' || c == '\n' || c == '\r' || c == '\t'; c = cur())
                {
                    ++p;
                }
                if (enabled(Comments) && cur() == '/')
                {
                    const unsigned char* const q = cold.comment(p);
                    if (q == nullptr)
                    {
                        return false;
                    }
                    p = q;
                    continue;
                }
                return true;
            }
        }

        /// append a node: (kind, flags, extra, off) and the second word (len, or
        /// an integer's value); two stores on little-endian targets
        NLOHMANN_VIEW_ALWAYS_INLINE node* emit(value_t k, std::uint8_t flags, std::uint16_t extra, std::size_t off, std::uint64_t second)
        {
            if (NLOHMANN_VIEW_UNLIKELY(out == cap))
            {
                const auto n = static_cast<std::size_t>(out - base);
                base = cold.grow(n, p);
                out = base + n;
                cap = base + cold.doc.tape_cap;
            }
            node* n = out++;
#if NLOHMANN_VIEW_LITTLE_ENDIAN
            const std::uint64_t first = static_cast<std::uint64_t>(k) | (static_cast<std::uint64_t>(flags) << 8)
                                        | (static_cast<std::uint64_t>(extra) << 16) | (static_cast<std::uint64_t>(off) << 32);
            std::memcpy(reinterpret_cast<unsigned char*>(n), &first, 8);
            std::memcpy(reinterpret_cast<unsigned char*>(n) + 8, &second, 8);
#else
            n->kind = static_cast<std::uint8_t>(k);
            n->flags = flags;
            n->extra = extra;
            n->off = static_cast<std::uint32_t>(off);
            set_integer_bits(*n, second);
#endif
            return n;
        }

        NLOHMANN_VIEW_ALWAYS_INLINE void open(value_t k)
        {
            const auto idx = static_cast<std::uint32_t>(emit(k, 0, 0, static_cast<std::size_t>(p - b), 0) - base);
            if (depth != 0)
            {
                const frame f = {cur_idx, cur_count, cur_is_object};
                if (NLOHMANN_VIEW_LIKELY(depth <= 64))
                {
                    cold.shallow[depth - 1] = f;
                }
                else
                {
                    cold.deep.push_back(f);
                }
            }
            ++depth;
            cur_idx = idx;
            cur_count = 0;
            cur_is_object = k == value_t::object;
        }

        NLOHMANN_VIEW_ALWAYS_INLINE void close()
        {
            node& n = base[cur_idx];
            n.len = cur_count;
            n.next = static_cast<std::uint32_t>(out - base) - cur_idx;
            if (--depth != 0)
            {
                frame f{};
                if (NLOHMANN_VIEW_LIKELY(depth <= 64))
                {
                    f = cold.shallow[depth - 1];
                }
                else
                {
                    f = cold.deep.back();
                    cold.deep.pop_back();
                }
                cur_idx = f.idx;
                cur_count = f.count;
                cur_is_object = f.is_object;
            }
        }

        NLOHMANN_VIEW_ALWAYS_INLINE bool literal(const char* text, std::size_t n, value_t k, std::uint8_t flags)
        {
            if (NLOHMANN_VIEW_UNLIKELY(e - p < static_cast<std::ptrdiff_t>(n) || std::memcmp(p, text, n) != 0))
            {
                return fail(error_code::invalid_literal);
            }
            emit(k, flags, 0, static_cast<std::size_t>(p - b), n);
            p += n;
            return true;
        }

        /// a number at p; the sign is known from the dispatch (so that p does
        /// not have to wait for the first byte)
        template<bool negative>
        NLOHMANN_VIEW_ALWAYS_INLINE bool number()
        {
            const unsigned char* const s = p;
            if (negative)
            {
                ++p;
            }
            const unsigned char* const int_start = p;
            if (p != e && *p == '0')
            {
                ++p;
            }
            else if (NLOHMANN_VIEW_LIKELY(p != e && *p >= '1' && *p <= '9'))
            {
                p = skip_digits(p + 1, e);
            }
            else
            {
                return fail(error_code::number_after_minus);
            }
            const auto int_digits = static_cast<std::size_t>(p - int_start);
            std::size_t frac_digits = 0;
            bool is_float = false;
            if (p != e && *p == '.')
            {
                ++p;
                const unsigned char* const f0 = p;
                p = skip_digits(p, e);
                if (NLOHMANN_VIEW_UNLIKELY(p == f0))
                {
                    return fail(error_code::number_after_dot);
                }
                frac_digits = static_cast<std::size_t>(p - f0);
                is_float = true;
            }
            std::int64_t exponent = 0;
            if (p != e && (*p | 0x20) == 'e')
            {
                ++p;
                bool exp_negative = false;
                if (p != e && (*p == '+' || *p == '-'))
                {
                    exp_negative = *p == '-';
                    ++p;
                }
                if (NLOHMANN_VIEW_UNLIKELY(p == e || !is_digit(*p)))
                {
                    return fail(error_code::number_after_exponent);
                }
                while (p != e && is_digit(*p))
                {
                    if (exponent < 100000)
                    {
                        exponent = (exponent * 10) + (*p - '0');
                    }
                    ++p;
                }
                if (exp_negative)
                {
                    exponent = -exponent;
                }
                is_float = true;
            }

            value_t kind = value_t::number_float;
            if (!is_float)
            {
                kind = negative ? value_t::number_integer : value_t::number_unsigned;
            }
            if (!is_float)
            {
                // integers that do not fit become floats, as in parse()
                if (NLOHMANN_VIEW_UNLIKELY(int_digits >= 19))
                {
                    if (negative)
                    {
                        if (int_digits > 19 || (int_digits == 19 && digits_exceed(int_start, "9223372036854775808", 19)))
                        {
                            kind = value_t::number_float;
                        }
                    }
                    else if (int_digits > 20 || (int_digits == 20 && digits_exceed(int_start, "18446744073709551615", 20)))
                    {
                        kind = value_t::number_float;
                    }
                }
            }
            // parse() rejects floats that overflow; only numbers whose magnitude
            // could reach the largest FloatType (1e308 for double, 1e38 for
            // float) need the conversion
            if (NLOHMANN_VIEW_UNLIKELY(static_cast<std::int64_t>(int_digits) + exponent > std::numeric_limits<FloatType>::max_exponent10 - 8 && kind == value_t::number_float))
            {
                if (builder::float_overflows(s, p))
                {
                    p = s;
                    return fail(error_code::number_overflow);
                }
            }
            const auto layout = static_cast<std::uint16_t>((int_digits < 255 ? int_digits : 255) | ((frac_digits < 255 ? frac_digits : 255) << 8));
            auto second = static_cast<std::uint64_t>(p - s);
            if (kind != value_t::number_float)
            {
                // integers are converted now, while their digits are in cache
                const std::uint64_t m = int_digits <= 19 ? parse_upto19(int_start, static_cast<unsigned>(int_digits), e)
                                        : (parse_upto19(int_start, 19, e) * 10) + static_cast<std::uint64_t>(int_start[19] - '0');
                second = negative ? 0 - m : m;
            }
            emit(kind, 0, layout, static_cast<std::size_t>(s - b), second);
            return true;
        }

        /// a string (value or key) at p
        NLOHMANN_VIEW_ALWAYS_INLINE bool string()
        {
            ++p; // opening quote
            const unsigned char* const s = p;
            p = scan_string_run(p, e);
            if (NLOHMANN_VIEW_LIKELY(p != e && *p == '"'))
            {
                emit(value_t::string, 0, 0, static_cast<std::size_t>(s - b), static_cast<std::uint64_t>(p - s));
                ++p;
                return true;
            }
            const decoded r = cold.slow_string(s, p);
            if (r.p == nullptr)
            {
                return false;
            }
            p = r.p;
            emit(value_t::string, node_flags::escaped, 0, r.start, r.len);
            return true;
        }
    };
};

/// run the builder with compile-time options
template<typename FloatType, bool NulIsEnd, bool Comments, bool TrailingCommas>
inline bool build_with(document_data& d, const char* src, std::size_t size, bool sentinel, parse_failure& failure)
{
    if (sentinel)
    {
        builder<FloatType, Comments, TrailingCommas, NulIsEnd, true> bld(d, src, size);
        const bool ok = bld.run();
        failure = bld.failure();
        return ok;
    }
    builder<FloatType, Comments, TrailingCommas, NulIsEnd, false> bld(d, src, size);
    const bool ok = bld.run();
    failure = bld.failure();
    return ok;
}

/// sentinel: src[size] is readable and 0 (e.g. std::string); FloatType: the
/// number_float_t of the document
template<typename FloatType, bool NulIsEnd>
inline bool build(document_data& d, const char* src, std::size_t size, bool comments, bool trailing_commas, bool sentinel, parse_failure& failure)
{
    if (comments)
    {
        return trailing_commas ? build_with<FloatType, NulIsEnd, true, true>(d, src, size, sentinel, failure)
               : build_with<FloatType, NulIsEnd, true, false>(d, src, size, sentinel, failure);
    }
    return trailing_commas ? build_with<FloatType, NulIsEnd, false, true>(d, src, size, sentinel, failure)
           : build_with<FloatType, NulIsEnd, false, false>(d, src, size, sentinel, failure);
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/view/document_data.hpp>

// #include <nlohmann/detail/view/errors.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <algorithm> // min
#include <cstddef> // size_t
#include <string> // string

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/builder.hpp>

// #include <nlohmann/detail/view/macro_scope.hpp>


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

// Exceptions are thrown out of line, so that the accessors that may throw stay
// small enough to be inlined.

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_type_error(int id, const char* prefix, const char* type)
{
    NLOHMANN_VIEW_THROW(type_error::create(id, concat(prefix, type), nullptr));
}

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_out_of_range(int id, const std::string& msg)
{
    NLOHMANN_VIEW_THROW(out_of_range::create(id, msg, nullptr));
}

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_invalid_iterator(int id, const char* msg)
{
    NLOHMANN_VIEW_THROW(invalid_iterator::create(id, msg, nullptr));
}

/// a parse error without a position (as those of json_pointer)
[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_parse_error(int id, const std::string& msg)
{
    NLOHMANN_VIEW_THROW(parse_error::create(id, 0, msg, nullptr));
}

/*!
@brief throw the exception BasicJsonType::parse would throw for this input

The view accepts exactly the inputs parse() accepts, so on a failure the
library parser is run on the same bytes: it throws the exception parse() would
throw, with the same message, position, and "last read" token. The error path
is cold, so this costs nothing on valid input. Should parse() accept the input
nevertheless (a bug), the view's own failure is reported.
*/
template<typename BasicJsonType>
[[noreturn]] NLOHMANN_VIEW_NOINLINE void throw_parse_failure(const parse_failure& f, const char* src, std::size_t size,
        bool ignore_comments, bool ignore_trailing_commas)
{
    if (f.code == error_code::input_too_large)
    {
        // LCOV_EXCL_START (4 GiB)
        NLOHMANN_VIEW_THROW(out_of_range::create(416, "input of 4 GiB or more is not supported by json_document", nullptr));
        // LCOV_EXCL_STOP
    }
    const BasicJsonType accepted = BasicJsonType::parse(src, src + size, nullptr, true, ignore_comments, ignore_trailing_commas);
    // LCOV_EXCL_START (only if parse() accepts what the view rejects: a bug)
    static_cast<void>(accepted);

    position_t pos;
    const std::size_t off = (std::min)(f.offset, size);
    pos.chars_read_total = off + 1;
    std::size_t line_start = 0;
    for (std::size_t i = 0; i < off; ++i)
    {
        if (src[i] == '\n')
        {
            ++pos.lines_read;
            line_start = i + 1;
        }
    }
    pos.chars_read_current_line = off + 1 - line_start;
    NLOHMANN_VIEW_THROW(parse_error::create(101, pos, "syntax error while parsing value", nullptr));
    // LCOV_EXCL_STOP
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/view/input.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <string> // basic_string, char_traits, string
#include <type_traits> // decay, integral_constant, is_array, is_lvalue_reference, is_pointer, is_same, remove_reference
#include <utility> // forward

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/macro_scope.hpp>


#if NLOHMANN_VIEW_HAS_CPP_17
    #include <string_view> // string_view
#endif

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// how a document takes its input
enum class input_kind
{
    move_string,  ///< rvalue std::string: owned without a copy
    c_string,     ///< const char* (NUL-terminated): borrowed
    char_array,   ///< char array (e.g. a string literal): borrowed
    borrow_range, ///< lvalue contiguous byte container, or std::string_view: borrowed
    copy_range,   ///< rvalue contiguous byte container: copied
    adapter,      ///< anything else parse() accepts (streams, wide strings, ...): read into a buffer
};

template<typename InputType>
struct classify_input
{
    using R = typename std::remove_reference<InputType>::type;
    using D = typename std::decay<InputType>::type;
    static constexpr bool is_rvalue = !std::is_lvalue_reference<InputType>::value;
    static constexpr bool is_bytes = is_contiguous_byte_container<D>::value;
#if NLOHMANN_VIEW_HAS_CPP_17
    static constexpr bool is_string_view = std::is_same<D, std::string_view>::value;
#else
    static constexpr bool is_string_view = false;
#endif
    // NOLINTBEGIN(readability-avoid-nested-conditional-operator): a constant expression of C++11
    static constexpr input_kind value =
        std::is_array<R>::value ? input_kind::char_array
        : std::is_pointer<D>::value ? input_kind::c_string
        : (is_rvalue && std::is_same<D, std::string>::value) ? input_kind::move_string
        : (is_bytes && (!is_rvalue || is_string_view)) ? input_kind::borrow_range
        : is_bytes ? input_kind::copy_range
        : input_kind::adapter;
    // NOLINTEND(readability-avoid-nested-conditional-operator)
};

/// std::basic_string guarantees a NUL at data()[size()] (the parser's sentinel)
template<typename T>
struct is_std_string : std::false_type {};

template<typename Traits, typename Alloc>
struct is_std_string<std::basic_string<char, Traits, Alloc>> : std::true_type {};

/// drain a json input adapter (UTF-16/32 inputs arrive as UTF-8)
template<typename Adapter>
std::string collect_adapter(Adapter ia)
{
    std::string buf;
    for (;;)
    {
        const auto ch = ia.get_character();
        if (ch == std::char_traits<char>::eof())
        {
            break;
        }
        buf.push_back(static_cast<char>(ch));
    }
    return buf;
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/view/iterator.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <cstddef> // ptrdiff_t, size_t
#include <iterator> // forward_iterator_tag
#include <string> // string, to_string
#include <type_traits> // enable_if

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/document_data.hpp>

// #include <nlohmann/detail/view/errors.hpp>

// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/node.hpp>


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// the result of view_iterator::operator->: keeps the view alive for the
/// duration of the member access
template<typename View>
class arrow_proxy
{
  public:
    explicit arrow_proxy(const View& v) noexcept
        : m_view(v)
    {}

    const View* operator->() const noexcept
    {
        return &m_view;
    }

  private:
    View m_view;
};

/*!
@brief forward iterator over the elements of a basic_json_view

Iterates over the elements of an array or the member values of an object, in
document order; key() gives the key of an object member. As for basic_json, a
primitive value iterates as a range of one element (itself), and null as an
empty range.
*/
template<typename View>
class view_iterator
{
  public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = View;
    using difference_type = std::ptrdiff_t;
    using pointer = arrow_proxy<View>;
    using reference = View;
    using string_view_t = typename View::string_view_t;

    view_iterator() noexcept = default;

    /// @param[in] pos  the element, or the key of the member
    /// @param[in] object  whether pos is a key (its value is the next node)
    view_iterator(const document_data* d, const node* pos, bool object) noexcept
        : m_doc(d), m_pos(pos), m_value_offset(object ? 1 : 0)
    {}

    NLOHMANN_VIEW_ALWAYS_INLINE View operator*() const noexcept
    {
        return View(m_doc, m_pos + m_value_offset);
    }

    pointer operator->() const noexcept
    {
        return pointer(**this);
    }

    NLOHMANN_VIEW_ALWAYS_INLINE view_iterator& operator++() noexcept
    {
        m_pos = document_data::after(m_pos + m_value_offset);
        return *this;
    }

    view_iterator operator++(int) noexcept
    {
        const view_iterator r = *this;
        ++*this;
        return r;
    }

    friend bool operator==(const view_iterator& a, const view_iterator& b) noexcept
    {
        return a.m_pos == b.m_pos;
    }

    friend bool operator!=(const view_iterator& a, const view_iterator& b) noexcept
    {
        return a.m_pos != b.m_pos;
    }

    /// the key of the current object member; throws invalid_iterator.207 for
    /// other iterators, like basic_json's iterators
    string_view_t key() const
    {
        if (NLOHMANN_VIEW_UNLIKELY(m_value_offset == 0))
        {
            throw_invalid_iterator(207, "cannot use key() for non-object iterators");
        }
        return string_view_t(m_doc->str(*m_pos), m_pos->len);
    }

    View value() const noexcept
    {
        return **this;
    }

    /// whether the iterator runs over the members of an object
    bool is_object_iterator() const noexcept
    {
        return m_value_offset != 0;
    }

  private:
    const document_data* m_doc = nullptr;
    const node* m_pos = nullptr;
    std::size_t m_value_offset = 0; ///< 1 for objects: the value follows its key
};

/*!
@brief a (key, value) item of basic_json_view::items()

The key of an array element is its index, as for basic_json::items().
Supports structured bindings: for (const auto [key, value] : view.items())
*/
template<typename View>
class view_item
{
  public:
    using string_view_t = typename View::string_view_t;
    using iterator = view_iterator<View>;

    view_item(const iterator& it, std::size_t index)
        : m_it(it)
    {
        if (!it.is_object_iterator())
        {
            m_index = std::to_string(index);
        }
    }

    /// the member key, or the element index for arrays
    string_view_t key() const
    {
        if (m_it.is_object_iterator())
        {
            return m_it.key();
        }
        return string_view_t(m_index.data(), m_index.size());
    }

    View value() const noexcept
    {
        return *m_it;
    }

    template<std::size_t N, typename std::enable_if<N == 0, int>::type = 0>
    string_view_t get() const
    {
        return key();
    }

    template<std::size_t N, typename std::enable_if<N == 1, int>::type = 0>
    View get() const noexcept
    {
        return value();
    }

  private:
    iterator m_it;
    std::string m_index{}; // NOLINT(readability-redundant-member-init)
};

/// the range returned by basic_json_view::items()
template<typename View>
class view_items
{
  public:
    using item = view_item<View>;

    class iterator
    {
      public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = item;
        using difference_type = std::ptrdiff_t;
        using pointer = void;
        using reference = item;

        explicit iterator(const view_iterator<View>& it) noexcept
            : m_it(it)
        {}

        item operator*() const
        {
            return item(m_it, m_index);
        }

        iterator& operator++() noexcept
        {
            ++m_it;
            ++m_index;
            return *this;
        }

        iterator operator++(int) noexcept
        {
            const iterator r = *this;
            ++*this;
            return r;
        }

        friend bool operator==(const iterator& a, const iterator& b) noexcept
        {
            return a.m_it == b.m_it;
        }

        friend bool operator!=(const iterator& a, const iterator& b) noexcept
        {
            return a.m_it != b.m_it;
        }

      private:
        view_iterator<View> m_it;
        std::size_t m_index = 0;
    };

    explicit view_items(const View& v) noexcept
        : m_view(v)
    {}

    iterator begin() const noexcept
    {
        return iterator(m_view.begin());
    }

    iterator end() const noexcept
    {
        return iterator(m_view.end());
    }

  private:
    View m_view;
};

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/view/lookup.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <cstddef> // size_t
#include <cstdint> // uint16_t, uint32_t, uint64_t
#include <cstring> // memcmp, memcpy

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/document_data.hpp>

// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/node.hpp>


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
inline const node* find_member(const document_data& d, const node* object, const char* key, std::size_t n) noexcept
{
    const node* const end = document_data::child_end(object);
    const auto* const k = reinterpret_cast<const unsigned char*>(key); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    if (NLOHMANN_VIEW_LIKELY(n <= 16))
    {
        const short_key probe(k, n);
        for (const node* m = document_data::first_child(object); m != end; m = document_data::after(m + 1))
        {
            if (m->len == n && probe.matches(reinterpret_cast<const unsigned char*>(d.str(*m)))) // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
            {
                return m;
            }
        }
        return nullptr;
    }
    for (const node* m = document_data::first_child(object); m != end; m = document_data::after(m + 1))
    {
        if (m->len == n && std::memcmp(d.str(*m), key, n) == 0)
        {
            return m;
        }
    }
    return nullptr;
}

/// the element of an array at an index below its size
inline const node* element_at(const node* array, std::size_t idx) noexcept
{
    const node* e = document_data::first_child(array);
    for (std::size_t i = 0; i < idx; ++i)
    {
        e = document_data::after(e);
    }
    return e;
}

/// the last element of a non-empty array, or the key of the last member of a
/// non-empty object
inline const node* last_child(const node* container) noexcept
{
    const std::size_t value_offset = container->kind == static_cast<std::uint8_t>(value_t::object) ? 1 : 0;
    const node* const end = document_data::child_end(container);
    const node* last = document_data::first_child(container);
    for (const node* c = document_data::after(last + value_offset); c != end; c = document_data::after(c + value_offset))
    {
        last = c;
    }
    return last;
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/materialize.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <cstdint> // int64_t, uint8_t
#include <string> // string
#include <vector> // vector

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/document_data.hpp>

// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/node.hpp>

// #include <nlohmann/detail/view/number.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <cstddef> // size_t
#include <string> // string

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/node.hpp>


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/*!
@brief the value of the float token of a node, as parse() converts it

Uses the lexer's conversion (detail::convert_float), so that the values are
bit-identical to parse(): float and double are converted without allocation
and independent of the locale. The digit layout recorded while parsing locates
the decimal point and the exponent without scanning the token.
*/
template<typename FloatType>
NLOHMANN_VIEW_NOINLINE FloatType float_value(const char* first, const node& n)
{
    const char* const last = first + n.len;
    const std::size_t neg = first[0] == '-' ? 1 : 0;
    const std::size_t int_digits = n.extra & 0xFFu;
    const std::size_t frac_digits = n.extra >> 8u;
    std::size_t dot = std::string::npos;
    std::size_t mantissa_end = n.len;
    if (int_digits != 255 && frac_digits != 255)
    {
        dot = frac_digits != 0 ? neg + int_digits : std::string::npos;
        mantissa_end = neg + int_digits + (frac_digits != 0 ? 1 + frac_digits : 0);
    }
    else
    {
        // more digits than the layout records: locate them
        for (std::size_t i = 0; i < n.len; ++i)
        {
            if (first[i] == '.')
            {
                dot = i;
            }
            else if (first[i] == 'e' || first[i] == 'E')
            {
                mantissa_end = i;
                break;
            }
        }
    }
    return convert_float<FloatType>(first, last, dot, mantissa_end);
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/*!
@brief the basic_json value of the subtree at n

The subtree is replayed into the SAX handler that parse() uses to build its
values, so the result is the value parse() would produce: duplicate keys keep
the last value, and with JSON_DIAGNOSTICS the parent pointers are set. It is
iterative, so the nesting depth is limited by memory only, as for parse().
Without a lexer the handler records no source positions
(JSON_DIAGNOSTIC_POSITIONS).
*/
template<typename BasicJsonType>
BasicJsonType materialize(const document_data& d, const node* n)
{
    using string_t = typename BasicJsonType::string_t;
    using sax_t = json_sax_dom_parser<BasicJsonType, iterator_input_adapter<const char*>>;

    BasicJsonType result;
    sax_t sax(result, true);
    const string_t no_token{};
    // the ends of the open containers, and whether they are objects
    std::vector<std::pair<const node*, bool>> open;
    for (;;)
    {
        switch (static_cast<value_t>(n->kind))
        {
            case value_t::object:
            case value_t::array:
            {
                const bool object = n->kind == static_cast<std::uint8_t>(value_t::object);
                if (object)
                {
                    sax.start_object(n->len);
                }
                else
                {
                    sax.start_array(n->len);
                }
                open.emplace_back(document_data::child_end(n), object);
                n = document_data::first_child(n);
                break;
            }
            case value_t::string:
            {
                string_t s(d.str(*n), n->len);
                sax.string(s);
                ++n;
                break;
            }
            case value_t::number_integer:
                sax.number_integer(static_cast<typename BasicJsonType::number_integer_t>(static_cast<std::int64_t>(integer_bits(*n))));
                ++n;
                break;
            case value_t::number_unsigned:
                sax.number_unsigned(static_cast<typename BasicJsonType::number_unsigned_t>(integer_bits(*n)));
                ++n;
                break;
            case value_t::number_float:
                sax.number_float(float_value<typename BasicJsonType::number_float_t>(d.str(*n), *n), no_token);
                ++n;
                break;
            case value_t::boolean:
                sax.boolean((n->flags & node_flags::is_true) != 0);
                ++n;
                break;
            case value_t::null:
            case value_t::binary:
            case value_t::discarded:
            default:
                sax.null();
                ++n;
                break;
        }
        for (;;)
        {
            if (open.empty())
            {
                return result;
            }
            if (n != open.back().first)
            {
                break;
            }
            if (open.back().second)
            {
                sax.end_object();
            }
            else
            {
                sax.end_array();
            }
            open.pop_back();
        }
        if (open.back().second)
        {
            // the key of the next member
            string_t key(d.str(*n), n->len);
            sax.key(key);
            ++n;
        }
    }
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/view/node.hpp>

// #include <nlohmann/detail/view/pointer.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <cstddef> // size_t
#include <cstdint> // uint64_t
#include <limits> // numeric_limits
#include <string> // string, to_string

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/errors.hpp>

// #include <nlohmann/detail/view/macro_scope.hpp>


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// what resolving a JSON pointer does where it cannot continue
enum class pointer_mode
{
    unchecked, ///< as const basic_json::operator[]: a discarded view where basic_json's behavior is undefined
    checked,   ///< as basic_json::at(): out_of_range.401/403
    value,     ///< as basic_json::value(): no out_of_range exceptions (the default value is used)
    contains,  ///< as basic_json::contains(): no exceptions at all
};

/// the outcome of reading an array index from a reference token
enum class index_status
{
    ok,
    leading_zero, ///< parse_error.106
    not_number,   ///< parse_error.109
    unresolved,   ///< out_of_range.404
    too_large,    ///< out_of_range.410
};

/// reads an array index like json_pointer::array_index (RFC 6901, Sect. 4),
/// but reports errors instead of throwing them
template<typename StringType>
index_status array_index(const StringType& s, std::size_t& idx) noexcept
{
    if (s.size() > 1 && s[0] == '0')
    {
        return index_status::leading_zero;
    }
    if (s.size() > 1 && !(s[0] >= '1' && s[0] <= '9'))
    {
        return index_status::not_number;
    }
    if (s.empty())
    {
        return index_status::unresolved;
    }
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < s.size(); ++i)
    {
        const auto d = static_cast<unsigned>(static_cast<unsigned char>(s[i])) - '0';
        if (d > 9 || v > ((std::numeric_limits<std::uint64_t>::max)() - d) / 10)
        {
            return index_status::unresolved; // not a number, or beyond unsigned long long
        }
        v = (v * 10) + d;
    }
    if (v >= (std::numeric_limits<std::size_t>::max)()) // (std::size_t converts to std::uint64_t implicitly)
    {
        return index_status::too_large;
    }
    idx = static_cast<std::size_t>(v);
    return index_status::ok;
}

/// throws the exception json_pointer::array_index throws for this status
template<typename StringType>
[[noreturn]] NLOHMANN_VIEW_NOINLINE void throw_array_index_error(index_status status, const StringType& s)
{
    switch (status)
    {
        case index_status::leading_zero:
            throw_parse_error(106, concat("array index '", s, "' must not begin with '0'"));
        case index_status::not_number:
            throw_parse_error(109, concat("array index '", s, "' is not a number"));
        case index_status::too_large:
            throw_out_of_range(410, concat("array index ", s, " exceeds size_type")); // LCOV_EXCL_LINE
        case index_status::unresolved:
        case index_status::ok:
        default:
            throw_out_of_range(404, concat("unresolved reference token '", s, "'"));
    }
}

/*!
@brief resolve the reference tokens of a JSON pointer, starting at a view

The exceptions are those basic_json throws for the same pointer; where
basic_json's behavior is undefined (a missing key or an index out of range
with const operator[]), the result is a discarded view.
*/
template<typename View, typename Tokens>
View resolve_pointer(View cur, const Tokens& tokens, pointer_mode mode)
{
    using string_view_t = typename View::string_view_t;
    const bool throwing = mode == pointer_mode::unchecked || mode == pointer_mode::checked;
    for (const auto& token : tokens)
    {
        if (cur.is_object())
        {
            const auto it = cur.find(string_view_t(token.data(), token.size()));
            if (it == cur.end())
            {
                if (mode == pointer_mode::checked)
                {
                    throw_out_of_range(403, concat("key '", token, "' not found"));
                }
                return View();
            }
            cur = *it;
        }
        else if (cur.is_array())
        {
            if (token.size() == 1 && token[0] == '-')
            {
                if (throwing)
                {
                    throw_out_of_range(402, concat("array index '-' (", std::to_string(cur.size()), ") is out of range"));
                }
                return View();
            }
            std::size_t idx = 0;
            const index_status status = array_index(token, idx);
            if (status != index_status::ok)
            {
                const bool parse_error = status == index_status::leading_zero || status == index_status::not_number;
                if (throwing || (mode == pointer_mode::value && parse_error))
                {
                    throw_array_index_error(status, token);
                }
                return View();
            }
            if (idx >= cur.size())
            {
                if (mode == pointer_mode::checked)
                {
                    throw_out_of_range(401, concat("array index ", std::to_string(idx), " is out of range"));
                }
                return View();
            }
            cur = cur[idx];
        }
        else
        {
            if (throwing)
            {
                throw_out_of_range(404, concat("unresolved reference token '", token, "'"));
            }
            return View();
        }
    }
    return cur;
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/view/string_ref.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <algorithm> // min
#include <cstddef> // size_t
#include <cstring> // memcmp, strlen
#include <string> // basic_string

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/macro_scope.hpp>


#if NLOHMANN_VIEW_HAS_CPP_17
    #include <string_view> // string_view
#endif
#ifndef JSON_NO_IO
    #include <ostream> // ostream
#endif

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

#if NLOHMANN_VIEW_HAS_CPP_17
using string_ref = std::string_view;
#else
/// minimal C++11 stand-in for std::string_view
class string_ref
{
  public:
    using size_type = std::size_t;
    using const_iterator = const char*;

    string_ref() noexcept = default;
    // s must be null-terminated, as for std::string_view(const char*)
    // flawfinder: ignore
    string_ref(const char* s) : m_data(s), m_size(std::strlen(s)) {} // NOLINT(google-explicit-constructor,hicpp-explicit-conversions)
    string_ref(const char* s, std::size_t n) noexcept : m_data(s), m_size(n) {}
    template<typename Traits, typename Alloc>
    string_ref(const std::basic_string<char, Traits, Alloc>& s) noexcept : m_data(s.data()), m_size(s.size()) {} // NOLINT(google-explicit-constructor,hicpp-explicit-conversions)

    const char* data() const noexcept
    {
        return m_data;
    }
    std::size_t size() const noexcept
    {
        return m_size;
    }
    std::size_t length() const noexcept
    {
        return m_size;
    }
    bool empty() const noexcept
    {
        return m_size == 0;
    }
    const char* begin() const noexcept
    {
        return m_data;
    }
    const char* end() const noexcept
    {
        return m_data + m_size;
    }
    char operator[](std::size_t i) const noexcept
    {
        return m_data[i];
    }

    template<typename Traits, typename Alloc>
    explicit operator std::basic_string<char, Traits, Alloc>() const
    {
        return std::basic_string<char, Traits, Alloc>(m_data, m_size);
    }

    friend bool operator==(string_ref a, string_ref b) noexcept
    {
        return a.m_size == b.m_size && (a.m_size == 0 || std::memcmp(a.m_data, b.m_data, a.m_size) == 0);
    }
    friend bool operator!=(string_ref a, string_ref b) noexcept
    {
        return !(a == b);
    }
    friend bool operator<(string_ref a, string_ref b) noexcept
    {
        const int c = std::memcmp(a.m_data, b.m_data, (std::min)(a.m_size, b.m_size));
        return c != 0 ? c < 0 : a.m_size < b.m_size;
    }
#ifndef JSON_NO_IO
    friend std::ostream& operator<<(std::ostream& o, string_ref s)
    {
        return o.write(s.m_data, static_cast<std::streamsize>(s.m_size));
    }
#endif

  private:
    const char* m_data = "";
    std::size_t m_size = 0;
};
#endif

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/view/value.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <cstdint> // int64_t
#include <map> // map
#include <string> // basic_string
#include <type_traits> // enable_if, is_constructible
#include <unordered_map> // unordered_map
#include <vector> // vector

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/document_data.hpp>

// #include <nlohmann/detail/view/errors.hpp>

// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/node.hpp>

// #include <nlohmann/detail/view/number.hpp>


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// selects a conversion by its target type
template<typename T>
struct value_tag {};

/*!
@brief the number or boolean of a node converted to an arithmetic type

As basic_json's get<T>() for arithmetic types: integers and floats are
converted with static_cast, booleans give 0 or 1, and other types throw
type_error.302.
*/
template<typename T, typename BasicJsonType>
NLOHMANN_VIEW_ALWAYS_INLINE T arithmetic_value(const document_data& d, const node& n)
{
    switch (static_cast<value_t>(n.kind))
    {
        case value_t::number_unsigned:
            return static_cast<T>(static_cast<typename BasicJsonType::number_unsigned_t>(integer_bits(n)));
        case value_t::number_integer:
            return static_cast<T>(static_cast<typename BasicJsonType::number_integer_t>(static_cast<std::int64_t>(integer_bits(n))));
        case value_t::number_float:
            return static_cast<T>(float_value<typename BasicJsonType::number_float_t>(d.str(n), n));
        case value_t::boolean:
            return static_cast<T>((n.flags & node_flags::is_true) != 0);
        case value_t::null:
        case value_t::object:
        case value_t::array:
        case value_t::string:
        case value_t::binary:
        case value_t::discarded:
        default:
            throw_type_error(302, "type must be number, but is ", value_type_name(static_cast<value_t>(n.kind)));
    }
}

/// std::vector from an array, element by element (type_error.302 otherwise)
template<typename View, typename U, typename A>
std::vector<U, A> vector_value(const View& v)
{
    if (NLOHMANN_VIEW_UNLIKELY(!v.is_array()))
    {
        throw_type_error(302, "type must be array, but is ", v.type_name());
    }
    std::vector<U, A> r;
    r.reserve(v.size());
    for (const View e : v)
    {
        r.push_back(e.template get<U>());
    }
    return r;
}

/// a map with string keys from an object; with duplicate keys, the last
/// value is kept, as parse() does (type_error.302 for other types)
template<typename Map, typename View>
Map map_value(const View& v)
{
    if (NLOHMANN_VIEW_UNLIKELY(!v.is_object()))
    {
        throw_type_error(302, "type must be object, but is ", v.type_name());
    }
    Map r;
    for (auto it = v.begin(); it != v.end(); ++it)
    {
        const auto key = it.key();
        r[typename Map::key_type(key.data(), key.size())] = it.value().template get<typename Map::mapped_type>();
    }
    return r;
}

/// whether a map type is read member by member (its keys are made from
/// characters and a length); other maps go through basic_json
template<typename Key>
struct is_string_key : std::is_constructible<Key, const char*, std::size_t> {};

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END


NLOHMANN_JSON_NAMESPACE_BEGIN

template<typename BasicJsonType>
class basic_json_document;

/*!
@brief read-only handle to one value of a basic_json_document

Trivially copyable (two pointers). Valid as long as the document is alive and
has not been re-parsed, and as long as a borrowed source text is alive.
*/
template<typename BasicJsonType>
class basic_json_view
{
    using node = detail::view::node;
    using document_data = detail::view::document_data;

  public:
    using value_t = detail::value_t;
    using string_t = typename BasicJsonType::string_t;
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using json_pointer = typename BasicJsonType::json_pointer;
    using size_type = std::size_t;
    /// std::string_view from C++17 on
    using string_view_t = detail::view::string_ref;
    /// forward iterator over elements (arrays) or member values (objects)
    using iterator = detail::view::view_iterator<basic_json_view>;
    using const_iterator = iterator;
    /// a (key, value) item of items()
    using item = detail::view::view_item<basic_json_view>;

    /// an invalid view (type() == value_t::discarded)
    basic_json_view() noexcept = default;

    //////////
    // type //
    //////////

    NLOHMANN_VIEW_ALWAYS_INLINE value_t type() const noexcept
    {
        return m_node != nullptr ? static_cast<value_t>(m_node->kind) : value_t::discarded;
    }

    bool is_null() const noexcept
    {
        return type() == value_t::null;
    }

    bool is_boolean() const noexcept
    {
        return type() == value_t::boolean;
    }

    bool is_number() const noexcept
    {
        return is_number_integer() || is_number_float();
    }

    bool is_number_integer() const noexcept
    {
        return type() == value_t::number_integer || type() == value_t::number_unsigned;
    }

    bool is_number_unsigned() const noexcept
    {
        return type() == value_t::number_unsigned;
    }

    bool is_number_float() const noexcept
    {
        return type() == value_t::number_float;
    }

    bool is_string() const noexcept
    {
        return type() == value_t::string;
    }

    bool is_array() const noexcept
    {
        return type() == value_t::array;
    }

    bool is_object() const noexcept
    {
        return type() == value_t::object;
    }

    /// always false: JSON text has no binary values
    bool is_binary() const noexcept
    {
        return false;
    }

    bool is_primitive() const noexcept
    {
        return is_null() || is_string() || is_boolean() || is_number();
    }

    bool is_structured() const noexcept
    {
        return is_array() || is_object();
    }

    /// the root of a failed parse with allow_exceptions == false, or a
    /// default-constructed view
    bool is_discarded() const noexcept
    {
        return type() == value_t::discarded;
    }

    /// false for discarded views
    explicit operator bool() const noexcept
    {
        return m_node != nullptr;
    }

    /// the name of the type, as basic_json::type_name()
    const char* type_name() const noexcept
    {
        return detail::value_type_name(type());
    }

    //////////////
    // capacity //
    //////////////

    /// the number of elements (arrays, objects), 0 for null and discarded,
    /// 1 otherwise, as basic_json::size()
    size_type size() const noexcept
    {
        switch (type())
        {
            case value_t::null:
            case value_t::discarded:
                return 0;
            case value_t::array:
            case value_t::object:
                return m_node->len;
            case value_t::string:
            case value_t::boolean:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::number_float:
            case value_t::binary:
            default:
                return 1;
        }
    }

    /// as basic_json::empty()
    bool empty() const noexcept
    {
        switch (type())
        {
            case value_t::null:
            case value_t::discarded:
                return true;
            case value_t::array:
            case value_t::object:
                return m_node->len == 0;
            case value_t::string:
            case value_t::boolean:
            case value_t::number_integer:
            case value_t::number_unsigned:
            case value_t::number_float:
            case value_t::binary:
            default:
                return false;
        }
    }

    ////////////////////
    // element access //
    ////////////////////

    /// the value of the member with this key (the first one, should the key
    /// occur more than once); a discarded view if there is none. Throws
    /// type_error.305 if this is not an object.
    NLOHMANN_VIEW_ALWAYS_INLINE basic_json_view operator[](string_view_t key) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_object()))
        {
            detail::view::throw_type_error(305, "cannot use operator[] with a string argument with ", type_name());
        }
        return lookup(key);
    }

    basic_json_view operator[](const char* key) const
    {
        return operator[](string_view_t(key));
    }

    basic_json_view operator[](const string_t& key) const
    {
        return operator[](string_view_t(key.data(), key.size()));
    }

    /// the element at this index; a discarded view if the index is out of
    /// range. Throws type_error.305 if this is not an array.
    basic_json_view operator[](size_type idx) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_array()))
        {
            detail::view::throw_type_error(305, "cannot use operator[] with a numeric argument with ", type_name());
        }
        return idx < m_node->len ? basic_json_view(m_doc, detail::view::element_at(m_node, idx)) : basic_json_view();
    }

    /// (an int argument would be ambiguous between size_type and const char*)
    basic_json_view operator[](int idx) const
    {
        return operator[](static_cast<size_type>(idx));
    }

    /// the value a JSON pointer refers to; a discarded view if a key is
    /// missing or an index is out of range. Other errors throw what const
    /// basic_json::operator[] throws.
    basic_json_view operator[](const json_pointer& ptr) const
    {
        return detail::view::resolve_pointer(*this, detail::json_pointer_access::reference_tokens(ptr), detail::view::pointer_mode::unchecked);
    }

    /// the value of the member with this key (the first one, should the key
    /// occur more than once). Throws type_error.304 if this is not an object,
    /// and out_of_range.403 if there is no such member.
    basic_json_view at(string_view_t key) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_object()))
        {
            detail::view::throw_type_error(304, "cannot use at() with ", type_name());
        }
        const basic_json_view r = lookup(key);
        if (NLOHMANN_VIEW_UNLIKELY(!r))
        {
            detail::view::throw_out_of_range(403, detail::concat("key '", std::string(key.data(), key.size()), "' not found"));
        }
        return r;
    }

    basic_json_view at(const char* key) const
    {
        return at(string_view_t(key));
    }

    basic_json_view at(const string_t& key) const
    {
        return at(string_view_t(key.data(), key.size()));
    }

    /// the element at this index. Throws type_error.304 if this is not an
    /// array, and out_of_range.401 if the index is out of range.
    basic_json_view at(size_type idx) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_array()))
        {
            detail::view::throw_type_error(304, "cannot use at() with ", type_name());
        }
        if (NLOHMANN_VIEW_UNLIKELY(idx >= m_node->len))
        {
            detail::view::throw_out_of_range(401, detail::concat("array index ", std::to_string(idx), " is out of range"));
        }
        return basic_json_view(m_doc, detail::view::element_at(m_node, idx));
    }

    basic_json_view at(int idx) const
    {
        return at(static_cast<size_type>(idx));
    }

    /// the value a JSON pointer refers to; throws what basic_json::at()
    /// throws if it cannot be resolved
    basic_json_view at(const json_pointer& ptr) const
    {
        return detail::view::resolve_pointer(*this, detail::json_pointer_access::reference_tokens(ptr), detail::view::pointer_mode::checked);
    }

    /// the member with this key converted to T, or the default value if there
    /// is no such member (the first one, should the key occur more than
    /// once). Throws type_error.306 if this is not an object.
    template < typename T, typename std::enable_if < !std::is_same<typename std::decay<T>::type, const char*>::value, int >::type = 0 >
    T value(string_view_t key, const T& default_value) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_object()))
        {
            detail::view::throw_type_error(306, "cannot use value() with ", type_name());
        }
        const basic_json_view r = lookup(key);
        return r ? r.template get<T>() : default_value;
    }

    string_t value(string_view_t key, const char* default_value) const
    {
        return value(key, string_t(default_value));
    }

    /// the value a JSON pointer refers to converted to T, or the default
    /// value if the pointer cannot be resolved. Throws type_error.306 if this
    /// is neither an object nor an array.
    template < typename T, typename std::enable_if < !std::is_same<typename std::decay<T>::type, const char*>::value, int >::type = 0 >
    T value(const json_pointer& ptr, const T& default_value) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_structured()))
        {
            detail::view::throw_type_error(306, "cannot use value() with ", type_name());
        }
        const basic_json_view r = detail::view::resolve_pointer(*this, detail::json_pointer_access::reference_tokens(ptr), detail::view::pointer_mode::value);
        return r ? r.template get<T>() : default_value;
    }

    string_t value(const json_pointer& ptr, const char* default_value) const
    {
        return value(ptr, string_t(default_value));
    }

    /// the first element or member value; a primitive value itself. Throws
    /// invalid_iterator.214 for null, discarded views, and empty containers.
    basic_json_view front() const
    {
        const iterator it = begin();
        if (NLOHMANN_VIEW_UNLIKELY(it == end()))
        {
            detail::view::throw_invalid_iterator(214, "cannot get value");
        }
        return *it;
    }

    /// the last element or member value (linear in the size); a primitive
    /// value itself. Throws invalid_iterator.214 for null, discarded views,
    /// and empty containers.
    basic_json_view back() const
    {
        if (is_structured() && m_node->len != 0)
        {
            return basic_json_view(m_doc, detail::view::last_child(m_node) + (is_object() ? 1 : 0));
        }
        return front();
    }

    ////////////
    // lookup //
    ////////////

    /// an iterator to the member with this key (the first one, should the
    /// key occur more than once), or end(); end() also for non-objects
    iterator find(string_view_t key) const
    {
        if (!is_object())
        {
            return end();
        }
        const node* const k = detail::view::find_member(*m_doc, m_node, key.data(), key.size());
        return k != nullptr ? iterator(m_doc, k, true) : end();
    }

    iterator find(const char* key) const
    {
        return find(string_view_t(key));
    }

    iterator find(const string_t& key) const
    {
        return find(string_view_t(key.data(), key.size()));
    }

    /// whether this is an object with a member with this key
    bool contains(string_view_t key) const
    {
        return is_object() && detail::view::find_member(*m_doc, m_node, key.data(), key.size()) != nullptr;
    }

    bool contains(const char* key) const
    {
        return contains(string_view_t(key));
    }

    bool contains(const string_t& key) const
    {
        return contains(string_view_t(key.data(), key.size()));
    }

    /// whether a JSON pointer can be resolved (never throws, as
    /// basic_json::contains())
    bool contains(const json_pointer& ptr) const
    {
        return static_cast<bool>(detail::view::resolve_pointer(*this, detail::json_pointer_access::reference_tokens(ptr), detail::view::pointer_mode::contains));
    }

    /// 1 if this is an object with a member with this key, else 0 (duplicate
    /// keys count once)
    size_type count(string_view_t key) const
    {
        return contains(key) ? 1 : 0;
    }

    size_type count(const char* key) const
    {
        return count(string_view_t(key));
    }

    size_type count(const string_t& key) const
    {
        return count(string_view_t(key.data(), key.size()));
    }

    ///////////////
    // iteration //
    ///////////////

    /// the first element or member value, in document order; a primitive
    /// value is a range of one element (itself), null an empty range
    NLOHMANN_VIEW_ALWAYS_INLINE iterator begin() const noexcept
    {
        if (NLOHMANN_VIEW_LIKELY(is_structured()))
        {
            return iterator(m_doc, document_data::first_child(m_node), is_object());
        }
        return iterator(m_doc, m_node, false);
    }

    NLOHMANN_VIEW_ALWAYS_INLINE iterator end() const noexcept
    {
        if (NLOHMANN_VIEW_LIKELY(is_structured()))
        {
            return iterator(m_doc, document_data::child_end(m_node), is_object());
        }
        return iterator(m_doc, (is_null() || is_discarded()) ? m_node : m_node + 1, false);
    }

    iterator cbegin() const noexcept
    {
        return begin();
    }

    iterator cend() const noexcept
    {
        return end();
    }

    /// (key, value) items; the key of an array element is its index
    detail::view::view_items<basic_json_view> items() const noexcept
    {
        return detail::view::view_items<basic_json_view>(*this);
    }

    ////////////////
    // conversion //
    ////////////////

    /// the value converted to T, as BasicJsonType::get<T>(): arithmetic types,
    /// strings (string_view_t without a copy), std::nullptr_t, std::vector,
    /// maps with string keys, and views are converted directly; other types
    /// through materialize().get<T>()
    template<typename T>
    NLOHMANN_VIEW_ALWAYS_INLINE T get() const
    {
        return get_impl(detail::view::value_tag<T> {}, detail::priority_tag<2> {});
    }

    template<typename T>
    T& get_to(T& v) const
    {
        v = get<T>();
        return v;
    }

    /// the string, without a copy; valid as long as the view is. Throws
    /// type_error.302 for other types.
    string_view_t get_string() const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_string()))
        {
            detail::view::throw_type_error(302, "type must be string, but is ", type_name());
        }
        return {m_doc->str(*m_node), m_node->len};
    }

    /// the text of a number as it appears in the source (e.g. "1.50", "1E2",
    /// or an integer with more digits than any number type holds). Throws
    /// type_error.302 for other types.
    string_view_t number_token() const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_number()))
        {
            detail::view::throw_type_error(302, "type must be number, but is ", type_name());
        }
        return {m_doc->str(*m_node), detail::view::number_length(*m_node)};
    }

    /////////////////
    // materialize //
    /////////////////

    /// the basic_json value of this subtree, as parse() would produce it
    /// (a discarded value for a discarded view)
    BasicJsonType materialize() const
    {
        if (m_node == nullptr)
        {
            return BasicJsonType(value_t::discarded);
        }
        return detail::view::materialize<BasicJsonType>(*m_doc, m_node);
    }

    /// byte offset of this value in the source text (for strings: of the
    /// first byte after the opening quote); static_cast<std::size_t>(-1) for
    /// a discarded view and for strings with escapes, which are decoded
    std::size_t source_offset() const noexcept
    {
        return m_node != nullptr && (m_node->flags & detail::view::node_flags::storage) == 0
               ? m_node->off : static_cast<std::size_t>(-1);
    }

  private:
    template<typename> friend class basic_json_document;
    friend iterator;

    basic_json_view(const document_data* d, const node* n) noexcept
        : m_doc(d), m_node(n)
    {}

    /// the value of the first member with this key, or a discarded view
    /// (object required)
    NLOHMANN_VIEW_ALWAYS_INLINE basic_json_view lookup(string_view_t key) const noexcept
    {
        const node* const k = detail::view::find_member(*m_doc, m_node, key.data(), key.size());
        return k != nullptr ? basic_json_view(m_doc, k + 1) : basic_json_view();
    }

    // --- get() dispatch ---

    bool get_impl(detail::view::value_tag<bool> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_boolean()))
        {
            detail::view::throw_type_error(302, "type must be boolean, but is ", type_name());
        }
        return (m_node->flags & detail::view::node_flags::is_true) != 0;
    }

    template < typename T, typename std::enable_if < std::is_arithmetic<T>::value && !std::is_same<T, bool>::value, int >::type = 0 >
    NLOHMANN_VIEW_ALWAYS_INLINE T get_impl(detail::view::value_tag<T> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(m_node == nullptr))
        {
            detail::view::throw_type_error(302, "type must be number, but is ", type_name());
        }
        return detail::view::arithmetic_value<T, BasicJsonType>(*m_doc, *m_node);
    }

    std::nullptr_t get_impl(detail::view::value_tag<std::nullptr_t> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_null()))
        {
            detail::view::throw_type_error(302, "type must be null, but is ", type_name());
        }
        return nullptr;
    }

    string_view_t get_impl(detail::view::value_tag<string_view_t> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        return get_string();
    }

    template<typename Traits, typename Alloc>
    std::basic_string<char, Traits, Alloc> get_impl(detail::view::value_tag<std::basic_string<char, Traits, Alloc>> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        const string_view_t s = get_string();
        return std::basic_string<char, Traits, Alloc>(s.data(), s.size());
    }

    BasicJsonType get_impl(detail::view::value_tag<BasicJsonType> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        return materialize();
    }

    basic_json_view get_impl(detail::view::value_tag<basic_json_view> /*unused*/, detail::priority_tag<2> /*unused*/) const noexcept
    {
        return *this;
    }

    template<typename U, typename A>
    std::vector<U, A> get_impl(detail::view::value_tag<std::vector<U, A>> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        return detail::view::vector_value<basic_json_view, U, A>(*this);
    }

    template<typename K, typename V, typename C, typename A, typename std::enable_if<detail::view::is_string_key<K>::value, int>::type = 0>
    std::map<K, V, C, A> get_impl(detail::view::value_tag<std::map<K, V, C, A>> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        return detail::view::map_value<std::map<K, V, C, A>>(*this);
    }

    template<typename K, typename V, typename H, typename E, typename A, typename std::enable_if<detail::view::is_string_key<K>::value, int>::type = 0>
    std::unordered_map<K, V, H, E, A> get_impl(detail::view::value_tag<std::unordered_map<K, V, H, E, A>> /*unused*/, detail::priority_tag<2> /*unused*/) const
    {
        return detail::view::map_value<std::unordered_map<K, V, H, E, A>>(*this);
    }

    /// everything else through the BasicJsonType value (from_json included)
    template<typename T>
    T get_impl(detail::view::value_tag<T> /*unused*/, detail::priority_tag<0> /*unused*/) const
    {
        return materialize().template get<T>();
    }

    const document_data* m_doc = nullptr;
    const node* m_node = nullptr;
};

/*!
@brief a parsed JSON text: owns the node index (and, optionally, the text)

Borrowed parses keep a pointer to the caller's text, which must outlive the
document. Owned parses (parse_copy, rvalue std::string, streams, and inputs
that are not contiguous byte ranges) keep their own copy.
*/
template<typename BasicJsonType>
class basic_json_document
{
    using document_data = detail::view::document_data;

    static_assert(sizeof(typename BasicJsonType::number_integer_t) == 8 && sizeof(typename BasicJsonType::number_unsigned_t) == 8,
                  "json_view supports 64-bit integer types only");

  public:
    using view_type = basic_json_view<BasicJsonType>;
    using value_t = detail::value_t;

    /// an empty (discarded) document
    basic_json_document() = default;
    basic_json_document(basic_json_document&&) noexcept = default;
    basic_json_document& operator=(basic_json_document&&) noexcept = default;
    basic_json_document(const basic_json_document&) = delete;
    basic_json_document& operator=(const basic_json_document&) = delete;
    ~basic_json_document() = default;

    /////////////
    // parsing //
    /////////////

    /// parse a JSON text; contiguous byte inputs are borrowed, everything else
    /// (and rvalue std::string) is owned
    template<typename InputType>
    NLOHMANN_VIEW_NODISCARD
    static basic_json_document parse(InputType&& input,
                                     const bool allow_exceptions = true,
                                     const bool ignore_comments = false,
                                     const bool ignore_trailing_commas = false)
    {
        basic_json_document d;
        d.read(std::forward<InputType>(input), allow_exceptions, ignore_comments, ignore_trailing_commas);
        return d;
    }

    /// parse [first, last)
    template<typename IteratorType, typename std::enable_if<
                 std::is_base_of<std::input_iterator_tag, typename std::iterator_traits<IteratorType>::iterator_category>::value, int>::type = 0>
    NLOHMANN_VIEW_NODISCARD
    static basic_json_document parse(IteratorType first, IteratorType last,
                                     const bool allow_exceptions = true,
                                     const bool ignore_comments = false,
                                     const bool ignore_trailing_commas = false)
    {
        basic_json_document d;
        d.read_range(first, last, allow_exceptions, ignore_comments, ignore_trailing_commas);
        return d;
    }

    /// parse a copy of the input; the document does not depend on it afterwards
    template<typename InputType>
    NLOHMANN_VIEW_NODISCARD
    static basic_json_document parse_copy(InputType&& input,
                                          const bool allow_exceptions = true,
                                          const bool ignore_comments = false,
                                          const bool ignore_trailing_commas = false)
    {
        basic_json_document d;
        d.build_owned(collect(std::forward<InputType>(input)), allow_exceptions, ignore_comments, ignore_trailing_commas);
        return d;
    }

    /// check whether the input is valid JSON (the result of basic_json::accept)
    template<typename InputType>
    static bool accept(InputType&& input, const bool ignore_comments = false, const bool ignore_trailing_commas = false)
    {
        basic_json_document d;
        d.read(std::forward<InputType>(input), false, ignore_comments, ignore_trailing_commas);
        return !d.is_discarded();
    }

    /// parse into this document, reusing its memory
    template<typename InputType>
    // flawfinder: ignore (a member function, not POSIX read())
    void read(InputType&& input,
              const bool allow_exceptions = true,
              const bool ignore_comments = false,
              const bool ignore_trailing_commas = false)
    {
        read_kind(std::forward<InputType>(input), allow_exceptions, ignore_comments, ignore_trailing_commas,
                  std::integral_constant<detail::view::input_kind, detail::view::classify_input<InputType>::value> {});
    }

    ////////////
    // access //
    ////////////

    /// the root value (discarded if parsing failed without exceptions)
    view_type root() const noexcept
    {
        if (!m_data || m_data->discarded)
        {
            return view_type();
        }
        return view_type(m_data.get(), m_data->tape);
    }

    bool is_discarded() const noexcept
    {
        return !m_data || m_data->discarded;
    }

    /// the parsed text
    typename view_type::string_view_t source() const noexcept
    {
        return m_data ? typename view_type::string_view_t(m_data->src, m_data->size) : typename view_type::string_view_t();
    }

    /// whether the document holds its own copy of the text
    bool owns_source() const noexcept
    {
        return m_data && !m_data->owned.empty() && m_data->src == m_data->owned.data();
    }

    /// number of index nodes (values plus object keys)
    std::size_t node_count() const noexcept
    {
        return m_data ? m_data->tape_size : 0;
    }

    /// bytes held by the document (index, decoded strings, owned text)
    std::size_t memory_usage() const noexcept
    {
        if (!m_data)
        {
            return 0;
        }
        return sizeof(document_data) + (m_data->inline_cap * sizeof(detail::view::node))
               + (m_data->tape != m_data->inline_tape ? m_data->tape_cap * sizeof(detail::view::node) : 0)
               + m_data->arena.capacity() + m_data->owned.capacity();
    }

    /// release unused capacity of the index and the decoded strings; like
    /// std::vector::shrink_to_fit, this invalidates the views of the document
    /// (take new ones from root())
    void shrink_to_fit()
    {
        if (!m_data)
        {
            return;
        }
        using detail::view::node;
        document_data& d = *m_data;

        // allocate everything first, so that an exception leaves the document
        // unchanged
        const bool shrink_arena = d.arena.capacity() > d.arena.size();
        std::string arena(shrink_arena ? d.arena : std::string());
        const bool shrink_tape = d.tape != d.inline_tape && d.tape_size != d.tape_cap;
        const bool into_header = d.tape_size <= d.inline_cap;
        node* fresh = (shrink_tape && !into_header) ? static_cast<node*>(::operator new (d.tape_size * sizeof(node))) : d.inline_tape;

        if (shrink_tape)
        {
            std::memcpy(fresh, d.tape, d.tape_size * sizeof(node));
            ::operator delete (d.tape);
            d.tape = fresh;
            d.tape_cap = into_header ? d.inline_cap : d.tape_size;
        }
        if (shrink_arena)
        {
            d.arena.swap(arena);
            d.base[1] = d.arena.data();
        }
    }

  private:
    using input_kind = detail::view::input_kind;

    /// create the storage (sized for the input) on first use
    void ensure_data(const char* src, std::size_t size)
    {
        if (!m_data)
        {
            m_data.reset(document_data::create(detail::view::estimate_nodes(src, size)));
        }
    }

    /// parse a buffer the document takes ownership of
    void build_owned(std::string&& buf, bool allow_exceptions, bool comments, bool trailing_commas)
    {
        ensure_data(buf.data(), buf.size());
        m_data->owned = std::move(buf);
        build(m_data->owned.data(), m_data->owned.size(), allow_exceptions, comments, trailing_commas, true, true);
    }

    /// sentinel: src[size] is readable and 0 (std::string, C strings)
    void build(const char* src, std::size_t size, bool allow_exceptions, bool comments, bool trailing_commas, bool owned, bool sentinel)
    {
        ensure_data(src, size);
        document_data& d = *m_data;
        if (!owned)
        {
            d.owned.clear();
        }
        d.src = src;
        d.size = size;
        d.tape_size = 0;
        d.arena.clear();
        d.discarded = true;
        detail::view::parse_failure failure;
        bool ok = false;
        if (NLOHMANN_VIEW_UNLIKELY(size >= 0xFFFFFFF0u))
        {
            failure.code = detail::view::error_code::input_too_large; // LCOV_EXCL_LINE (4 GiB)
        }
        else
        {
            ok = detail::view::build < typename BasicJsonType::number_float_t, !detail::abi_config::strict_nul_handling > (d, src, size, comments, trailing_commas, sentinel, failure);
        }
        if (NLOHMANN_VIEW_LIKELY(ok))
        {
            d.base[0] = d.src;
            d.base[1] = d.arena.data();
            d.discarded = false;
            return;
        }
        if (allow_exceptions)
        {
            detail::view::throw_parse_failure<BasicJsonType>(failure, src, size, comments, trailing_commas);
        }
    }

    // --- input dispatch (see detail::view::input_kind) ---

    void read_kind(std::string&& s, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::move_string> /*unused*/)
    {
        build_owned(std::move(s), ae, c, tc);
    }

    template<typename CharT>
    void read_kind(CharT* s, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::c_string> /*unused*/)
    {
        static_assert(sizeof(CharT) == 1 && std::is_integral<typename std::remove_cv<CharT>::type>::value, "json_view parses byte (char-like) input");
        if (s == nullptr)
        {
            build("", 0, ae, c, tc, false, true);
            return;
        }
        const char* cs = reinterpret_cast<const char*>(s); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        // C strings are null-terminated, as for json::parse(const char*)
        // flawfinder: ignore
        build(cs, std::strlen(cs), ae, c, tc, false, true);
    }

    template<typename Array>
    void read_kind(Array& a, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::char_array> /*unused*/)
    {
        using CharT = typename std::remove_cv<typename std::remove_extent<Array>::type>::type;
        static_assert(sizeof(CharT) == 1 && std::is_integral<CharT>::value, "json_view parses byte (char-like) input");
        const std::size_t n = std::extent<Array>::value;
        // a trailing NUL (string literals) is not part of the text, as for
        // parse(), and serves as sentinel
        const bool terminated = n > 0 && a[n - 1] == 0 && (!detail::abi_config::strict_nul_handling || std::is_same<CharT, char>::value);
        build(reinterpret_cast<const char*>(&a[0]), terminated ? n - 1 : n, ae, c, tc, false, terminated); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }

    template<typename T>
    void read_kind(const T& s, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::borrow_range> /*unused*/)
    {
        // std::basic_string guarantees data()[size()] == 0: use it as sentinel
        const auto size = static_cast<std::size_t>(s.size());
        build(size == 0 ? "" : reinterpret_cast<const char*>(s.data()), size, ae, c, tc, false, // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
              detail::view::is_std_string<T>::value || size == 0);
    }

    template<typename T>
    void read_kind(const T& s, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::copy_range> /*unused*/)
    {
        build_owned(std::string(reinterpret_cast<const char*>(s.data()), static_cast<std::size_t>(s.size())), ae, c, tc); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }

    template<typename T>
    void read_kind(T&& input, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::adapter> /*unused*/)
    {
        build_owned(detail::view::collect_adapter(detail::input_adapter(std::forward<T>(input))), ae, c, tc);
    }

    template<typename IteratorType>
    void read_range(IteratorType first, IteratorType last, bool ae, bool c, bool tc)
    {
        using value_type = typename std::remove_cv<typename std::iterator_traits<IteratorType>::value_type>::type;
        // borrow the range where the library's input adapter scans it as one
        // block: pointers and, in C++20, contiguous iterators (std::vector,
        // std::string, ...) over single bytes
        read_range_impl(first, last, ae, c, tc, std::integral_constant < bool, std::is_integral<value_type>::value
                        && detail::iterator_input_adapter<IteratorType>::supports_bulk_scan > {});
    }

    template<typename IteratorType>
    void read_range_impl(IteratorType first, IteratorType last, bool ae, bool c, bool tc, std::true_type /*contiguous bytes*/)
    {
        const auto size = static_cast<std::size_t>(std::distance(first, last));
        build(size == 0 ? "" : reinterpret_cast<const char*>(&*first), size, ae, c, tc, false, size == 0); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }

    template<typename IteratorType>
    void read_range_impl(IteratorType first, IteratorType last, bool ae, bool c, bool tc, std::false_type /*other*/)
    {
        build_owned(detail::view::collect_adapter(detail::input_adapter(first, last)), ae, c, tc);
    }

    template<typename T>
    static std::string collect(T&& input)
    {
        return collect_impl(std::forward<T>(input), std::integral_constant<bool, detail::is_contiguous_byte_container<typename std::decay<T>::type>::value> {});
    }

    template<typename T>
    static std::string collect_impl(const T& s, std::true_type /*contiguous*/)
    {
        return {reinterpret_cast<const char*>(s.data()), static_cast<std::size_t>(s.size())}; // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }

    template<typename T>
    static std::string collect_impl(T&& s, std::false_type /*other*/)
    {
        return detail::view::collect_adapter(detail::input_adapter(std::forward<T>(s)));
    }

    std::unique_ptr<document_data, document_data::deleter> m_data{}; // NOLINT(readability-redundant-member-init)
};

/// a parsed JSON text for json
using json_document = basic_json_document<json>;
/// a value of a json_document
using json_view = basic_json_view<json>;
/// a parsed JSON text for ordered_json
using ordered_json_document = basic_json_document<ordered_json>;
/// a value of an ordered_json_document
using ordered_json_view = basic_json_view<ordered_json>;

NLOHMANN_JSON_NAMESPACE_END

// tuple protocol for the items of basic_json_view::items() (structured bindings)
namespace std // NOLINT(cert-dcl58-cpp)
{

#if defined(__clang__)
    // Fix: https://github.com/nlohmann/json/issues/1401
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wmismatched-tags"
#endif
template<typename View>
class tuple_size<::nlohmann::detail::view::view_item<View>> // NOLINT(cert-dcl58-cpp)
    : public std::integral_constant<std::size_t, 2> {};

template<std::size_t N, typename View>
class tuple_element<N, ::nlohmann::detail::view::view_item<View>> // NOLINT(cert-dcl58-cpp)
{
  public:
    using type = decltype(std::declval<::nlohmann::detail::view::view_item<View>>().template get<N>());
};
#if defined(__clang__)
    #pragma clang diagnostic pop
#endif

}  // namespace std

// #include <nlohmann/detail/view/macro_unscope.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



// undefine the macros of detail/view/macro_scope.hpp (at the end of json_view.hpp)

#undef NLOHMANN_VIEW_HAS_CPP_17
#undef NLOHMANN_VIEW_LIKELY
#undef NLOHMANN_VIEW_UNLIKELY
#undef NLOHMANN_VIEW_ALWAYS_INLINE
#undef NLOHMANN_VIEW_NOINLINE
#undef NLOHMANN_VIEW_NODISCARD
#undef NLOHMANN_VIEW_THROW
#undef NLOHMANN_VIEW_LITTLE_ENDIAN
#undef NLOHMANN_VIEW_REPEAT16


#endif  // INCLUDE_NLOHMANN_JSON_VIEW_HPP_
