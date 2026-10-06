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
#include <cstdint> // uint8_t, uint32_t
#include <cstring> // memcpy, strlen
#include <iterator> // distance, input_iterator_tag, iterator_traits
#include <map> // map
#include <memory> // unique_ptr
#ifndef JSON_NO_IO
    #include <ostream> // ostream
#endif
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
#include <cstdint> // uint8_t, uint32_t
#include <cstring> // memcpy
#include <functional> // less
#include <map> // map
#include <memory> // unique_ptr
#include <new> // operator new, placement new
#include <string> // string
#include <vector> // vector

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
    static constexpr std::uint8_t edited = 2;  ///< string or number token lives in the edit arena (editable documents)
    static constexpr std::uint8_t storage = 3; ///< mask: where a string or number token lives (index into document_data::base)
    static constexpr std::uint8_t is_true = 4; ///< boolean value
    static constexpr std::uint8_t moved = 8;   ///< array/object: the elements live in a separate sequence (editable documents)
    static constexpr std::uint8_t is_new = 16; ///< written by an edit: no source position
};

/// kind of an entry of an edited sequence that stands for a value stored
/// elsewhere (the address of the value's node is kept in the len/next bytes)
constexpr std::uint8_t kind_link = 10;

/// One entry of the flat index, in document order. An object's members are
/// stored as key node followed by the value's subtree. Integers keep their
/// converted 64-bit value in the len/next bytes (the node after a scalar is
/// always the next one, and the token length follows from `extra`).
struct node
{
    std::uint8_t kind;   ///< value_t, or kind_link
    std::uint8_t flags;  ///< node_flags
    std::uint16_t extra; ///< numbers: integer digits (low byte) and fraction digits (high byte), 255 = "many"; objects: number of the hash index; otherwise 0
    std::uint32_t off;   ///< source offset (string content, number token, literal, bracket); arena offset if escaped/edited; number of the element sequence if moved
    std::uint32_t len;   ///< string: decoded bytes; float: token bytes; array/object: element count
    std::uint32_t next;  ///< array/object: number of nodes of the subtree (its extent in the enclosing sequence)
};
static_assert(sizeof(node) == 16, "node must stay 16 bytes");

NLOHMANN_VIEW_ALWAYS_INLINE bool is_container(const node& n) noexcept
{
    return static_cast<unsigned>(n.kind) - 1u <= 1u;
}

/// the value a link node stands for
NLOHMANN_VIEW_ALWAYS_INLINE const node* link_target(const node& n) noexcept
{
    const node* t = nullptr;
    std::memcpy(static_cast<void*>(&t), reinterpret_cast<const unsigned char*>(&n) + 8, sizeof(const node*)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    return t;
}

inline void make_link(node& n, const node* target) noexcept
{
    n = node{};
    n.kind = kind_link;
    std::memcpy(reinterpret_cast<unsigned char*>(&n) + 8, static_cast<const void*>(&target), sizeof(const node*)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
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
    std::size_t arena_size = 0; ///< bytes of decoded strings at base[1] (the arena, or those of a loaded image)
    std::string owned{}; ///< owned copy of the input, if any // NOLINT(readability-redundant-member-init)
    std::vector<std::uint8_t> owned_image{}; ///< a loaded image the document owns (the text and the decoded strings point into it) // NOLINT(readability-redundant-member-init)

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

// #include <nlohmann/detail/view/simd.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-FileCopyrightText: 2018-2025 The simdjson authors <https://github.com/simdjson/simdjson>
// SPDX-License-Identifier: MIT



#include <array> // array
#include <atomic> // atomic
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint64_t

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/macro_scope.hpp>


// Vector code for long runs of string bytes. NEON (AArch64) and SSE2 (x86-64)
// belong to the baseline instruction sets and are used by default. The vector
// UTF-8 check needs NEON or SSSE3. SSSE3 is not part of x86-64, and the code
// must not depend on the flags of a translation unit (two translation units
// with different flags would have different definitions of the same inline
// functions): the check is compiled for SSSE3 with a function attribute and
// used where the CPU has SSSE3 (all x86-64 CPUs since about 2011), else the
// portable check. JSON_VIEW_USE_SSSE3 skips the CPU check (for code compiled
// for SSSE3 anyway); JSON_VIEW_NO_SIMD selects the portable code.
#if !defined(JSON_VIEW_NO_SIMD) && defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__)) && NLOHMANN_VIEW_LITTLE_ENDIAN
    #include <arm_neon.h>
    #define NLOHMANN_VIEW_NEON 1
#else
    #define NLOHMANN_VIEW_NEON 0
#endif
#if !defined(JSON_VIEW_NO_SIMD) && !NLOHMANN_VIEW_NEON && (defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2))
    #include <emmintrin.h>
    #define NLOHMANN_VIEW_SSE2 1
#else
    #define NLOHMANN_VIEW_SSE2 0
#endif
#if NLOHMANN_VIEW_SSE2 && defined(JSON_VIEW_USE_SSSE3)
    #include <tmmintrin.h>
    #define NLOHMANN_VIEW_SSSE3 1 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#else
    #define NLOHMANN_VIEW_SSSE3 0 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#endif
#if NLOHMANN_VIEW_SSE2 && !NLOHMANN_VIEW_SSSE3 && ((defined(__clang__) && __clang_major__ >= 4) || (defined(__GNUC__) && !defined(__clang__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9))))
    // (GCC before 4.9 has no SSSE3 intrinsics without -mssse3)
    #include <cpuid.h>
    #include <tmmintrin.h>
    #define NLOHMANN_VIEW_SSSE3_DISPATCH 1 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
    #define NLOHMANN_VIEW_SSSE3_TARGET __attribute__((target("ssse3")))
#elif NLOHMANN_VIEW_SSE2 && !NLOHMANN_VIEW_SSSE3 && defined(_MSC_VER)
    // (MSVC compiles intrinsics of any instruction set)
    #include <intrin.h>
    #include <tmmintrin.h>
    #define NLOHMANN_VIEW_SSSE3_DISPATCH 1 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
    #define NLOHMANN_VIEW_SSSE3_TARGET
#else
    #define NLOHMANN_VIEW_SSSE3_DISPATCH 0 // NOLINT(cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
    #define NLOHMANN_VIEW_SSSE3_TARGET
#endif
#define NLOHMANN_VIEW_VECTOR (NLOHMANN_VIEW_NEON || NLOHMANN_VIEW_SSE2)
#define NLOHMANN_VIEW_VECTOR_UTF8 (NLOHMANN_VIEW_NEON || NLOHMANN_VIEW_SSSE3 || NLOHMANN_VIEW_SSSE3_DISPATCH)

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

#if NLOHMANN_VIEW_VECTOR
/*!
@brief the first byte of a string run that is a quote, a backslash, a control
character, or not ASCII, 16 bytes per step

Stops at such a byte, or where fewer than 16 bytes are left (the caller tells
the two apart). A signed compare with 0x20 finds control characters and
non-ASCII bytes at once.
*/
NLOHMANN_VIEW_ALWAYS_INLINE const unsigned char* vector_plain_run(const unsigned char* p, const unsigned char* e) noexcept
{
    while (e - p >= 16)
    {
#if NLOHMANN_VIEW_NEON
        const uint8x16_t in = vld1q_u8(p);
        const uint8x16_t special = vorrq_u8(vorrq_u8(vceqq_u8(in, vdupq_n_u8('"')), vceqq_u8(in, vdupq_n_u8('\\'))),
                                            vcltq_s8(vreinterpretq_s8_u8(in), vdupq_n_s8(0x20)));
        // one nibble per byte (the usual NEON replacement of x86's movemask, see
        // D. Kutenin, "Porting x86 vector bitmask optimizations to Arm NEON", 2022)
        const std::uint64_t bits = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(special), 4)), 0);
        if (bits != 0)
        {
            return p + (count_trailing_zeros(bits) >> 2u);
        }
#else
        const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(p)));
        const __m128i special = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(in, _mm_set1_epi8('"')), _mm_cmpeq_epi8(in, _mm_set1_epi8('\\'))),
                                             _mm_cmplt_epi8(in, _mm_set1_epi8(0x20)));
        const auto bits = static_cast<std::uint64_t>(static_cast<unsigned>(_mm_movemask_epi8(special)));
        if (bits != 0)
        {
            return p + count_trailing_zeros(bits);
        }
#endif
        p += 16;
    }
    return p;
}
#endif

#if NLOHMANN_VIEW_SSSE3_DISPATCH
/// whether the CPU has SSSE3 (CPUID leaf 1, ECX bit 9)
inline bool cpu_ssse3() noexcept
{
#if defined(_MSC_VER) && !defined(__clang__)
    std::array<int, 4> regs {{}};
    __cpuid(regs.data(), 1);
    return (static_cast<unsigned>(regs[2]) & (1u << 9u)) != 0;
#else
    unsigned eax = 0;
    unsigned ebx = 0;
    unsigned ecx = 0;
    unsigned edx = 0;
    return __get_cpuid(1, &eax, &ebx, &ecx, &edx) != 0 && (ecx & (1u << 9u)) != 0;
#endif
}

/// whether the CPU has SSSE3, asked once: the answer is kept in an atomic
/// that is initialized at compile time, so that neither a guard of a local
/// static nor a global constructor is needed (threads that ask at the same
/// time all store the same answer)
NLOHMANN_VIEW_ALWAYS_INLINE bool cpu_has_ssse3() noexcept
{
    static std::atomic<int> known{0}; // 0: not asked yet, 1: no, 2: yes
    int state = known.load(std::memory_order_relaxed);
    if (NLOHMANN_VIEW_UNLIKELY(state == 0))
    {
        state = cpu_ssse3() ? 2 : 1;
        known.store(state, std::memory_order_relaxed);
    }
    return state == 2;
}
#endif

#if NLOHMANN_VIEW_VECTOR_UTF8
/// Tables of the UTF-8 check of J. Keiser and D. Lemire, "Validating UTF-8 In
/// Less Than One Instruction Per Byte" (2021), as in simdjson ("lookup4"): each
/// maps a nibble (high and low nibble of the previous byte, high nibble of the
/// current byte) to the errors it allows; a byte pair is ill-formed if all
/// three have an error bit in common.
template<typename Dummy = void>
struct utf8_lookup4
{
    static constexpr std::uint8_t too_short = 1u << 0u, too_long = 1u << 1u, overlong_3 = 1u << 2u, too_large = 1u << 3u;
    static constexpr std::uint8_t surrogate = 1u << 4u, overlong_2 = 1u << 5u, too_large_1000 = 1u << 6u, overlong_4 = 1u << 6u;
    static constexpr std::uint8_t two_conts = 1u << 7u, carry = too_short | too_long | two_conts;
    static const std::array<std::uint8_t, 16> byte_1_high;
    static const std::array<std::uint8_t, 16> byte_1_low;
    static const std::array<std::uint8_t, 16> byte_2_high;
};

template<typename Dummy>
const std::array<std::uint8_t, 16> utf8_lookup4<Dummy>::byte_1_high =
{
    {
        too_long, too_long, too_long, too_long, too_long, too_long, too_long, too_long,
        two_conts, two_conts, two_conts, two_conts,
        too_short | overlong_2, too_short, too_short | overlong_3 | surrogate, too_short | too_large | too_large_1000 | overlong_4
    }
};

template<typename Dummy>
const std::array<std::uint8_t, 16> utf8_lookup4<Dummy>::byte_1_low =
{
    {
        carry | overlong_3 | overlong_2 | overlong_4, carry | overlong_2, carry, carry,
        carry | too_large, carry | too_large | too_large_1000, carry | too_large | too_large_1000, carry | too_large | too_large_1000,
        carry | too_large | too_large_1000, carry | too_large | too_large_1000, carry | too_large | too_large_1000, carry | too_large | too_large_1000,
        carry | too_large | too_large_1000, carry | too_large | too_large_1000 | surrogate, carry | too_large | too_large_1000, carry | too_large | too_large_1000
    }
};

template<typename Dummy>
const std::array<std::uint8_t, 16> utf8_lookup4<Dummy>::byte_2_high =
{
    {
        too_short, too_short, too_short, too_short, too_short, too_short, too_short, too_short,
        static_cast<std::uint8_t>(too_long | overlong_2 | two_conts | overlong_3 | too_large_1000 | overlong_4),
        static_cast<std::uint8_t>(too_long | overlong_2 | two_conts | overlong_3 | too_large),
        static_cast<std::uint8_t>(too_long | overlong_2 | two_conts | surrogate | too_large),
        static_cast<std::uint8_t>(too_long | overlong_2 | two_conts | surrogate | too_large),
        too_short, too_short, too_short, too_short
    }
};

/// the end of scan_string_vector from block, where the vector loop stopped
/// (ill-formed UTF-8, or fewer than 16 bytes left): one byte or sequence at a
/// time, from the start of a sequence that crosses into the block
inline const unsigned char* scan_string_finish(const unsigned char* p, const unsigned char* block, const unsigned char* e, const std::uint8_t* plain) noexcept
{
    for (int i = 1; i <= 3 && block - i >= p; ++i)
    {
        const unsigned char c = block[-i];
        if (c < 0x80)
        {
            break;
        }
        if (c >= 0xC0)
        {
            const int len = 2 + static_cast<int>(c >= 0xE0) + static_cast<int>(c >= 0xF0);
            if (len > i)
            {
                block -= i;
            }
            break;
        }
    }
    for (p = block; p != e;)
    {
        if (*p < 0x80)
        {
            if (plain[*p] == 0)
            {
                return p;
            }
            ++p;
            continue;
        }
        const std::size_t n = validate_one_utf8(p, static_cast<std::size_t>(e - p));
        if (n == 0)
        {
            return p;
        }
        p += n;
    }
    return p;
}

/*!
@brief the rest of a string from p (a character boundary), 16 bytes per step

The first quote, backslash, or control character is found with vector
compares, and the UTF-8 check covers the bytes up to it. Returns where the
string scan stops, like scan_string_run: before ill-formed UTF-8 and for the
last bytes of the input, the bytes are checked one sequence at a time. Out of
line, so that no constants of the check occupy registers in the parse loop.
On x86-64, it is compiled for SSSE3 (see cpu_has_ssse3()).
*/
NLOHMANN_VIEW_SSSE3_TARGET NLOHMANN_VIEW_NOINLINE inline const unsigned char* scan_string_vector(const unsigned char* p, const unsigned char* e, const std::uint8_t* plain) noexcept
{
    using lookup = utf8_lookup4<>;
    const unsigned char* block = p;
#if NLOHMANN_VIEW_NEON
    const uint8x16_t t1h = vld1q_u8(lookup::byte_1_high.data());
    const uint8x16_t t1l = vld1q_u8(lookup::byte_1_low.data());
    const uint8x16_t t2h = vld1q_u8(lookup::byte_2_high.data());
    uint8x16_t prev = vdupq_n_u8(0);
    while (e - block >= 16)
    {
        const uint8x16_t in = vld1q_u8(block);
        const uint8x16_t special = vorrq_u8(vorrq_u8(vceqq_u8(in, vdupq_n_u8('"')), vceqq_u8(in, vdupq_n_u8('\\'))), vcltq_u8(in, vdupq_n_u8(0x20)));
        const uint8x16_t prev1 = vextq_u8(prev, in, 15);
        const uint8x16_t sc = vandq_u8(vandq_u8(vqtbl1q_u8(t1h, vshrq_n_u8(prev1, 4)), vqtbl1q_u8(t1l, vandq_u8(prev1, vdupq_n_u8(0x0F)))), vqtbl1q_u8(t2h, vshrq_n_u8(in, 4)));
        const uint8x16_t must23 = vorrq_u8(vqsubq_u8(vextq_u8(prev, in, 14), vdupq_n_u8(0xE0 - 0x80)), vqsubq_u8(vextq_u8(prev, in, 13), vdupq_n_u8(0xF0 - 0x80)));
        const uint8x16_t err = veorq_u8(vandq_u8(must23, vdupq_n_u8(0x80)), sc);
        const std::uint64_t special_bits = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(special), 4)), 0);
        const std::uint64_t err_bits = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(vtstq_u8(err, err)), 4)), 0);
        if (special_bits != 0)
        {
            // errors up to the special byte count (an incomplete sequence
            // before a quote shows at the quote); the bytes after it do not
            const unsigned k = static_cast<unsigned>(count_trailing_zeros(special_bits)) >> 2u;
            const std::uint64_t upto = k == 15 ? ~std::uint64_t{0} :
                                       (std::uint64_t{1} << (4u * (k + 1u))) - 1u;
            if ((err_bits & upto) == 0)
            {
                return block + k;
            }
            break;
        }
        if (err_bits != 0)
        {
            break;
        }
        prev = in;
        block += 16;
    }
#else
    // the same with SSSE3 (pshufb for the table lookups; nibbles from 16-bit
    // shifts, as there are no byte shifts)
    const __m128i t1h = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_1_high.data())));
    const __m128i t1l = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_1_low.data())));
    const __m128i t2h = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_2_high.data())));
    const __m128i nibble = _mm_set1_epi8(0x0F);
    const __m128i zero = _mm_setzero_si128();
    __m128i prev = zero;
    while (e - block >= 16)
    {
        const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(block)));
        const __m128i special = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(in, _mm_set1_epi8('"')), _mm_cmpeq_epi8(in, _mm_set1_epi8('\\'))),
                                             _mm_cmpeq_epi8(_mm_subs_epu8(in, _mm_set1_epi8(0x1F)), zero)); // in < 0x20
        const __m128i prev1 = _mm_alignr_epi8(in, prev, 15);
        const __m128i sc = _mm_and_si128(_mm_and_si128(_mm_shuffle_epi8(t1h, _mm_and_si128(_mm_srli_epi16(prev1, 4), nibble)),
                                         _mm_shuffle_epi8(t1l, _mm_and_si128(prev1, nibble))),
                                         _mm_shuffle_epi8(t2h, _mm_and_si128(_mm_srli_epi16(in, 4), nibble)));
        const __m128i must23 = _mm_or_si128(_mm_subs_epu8(_mm_alignr_epi8(in, prev, 14), _mm_set1_epi8(0xE0 - 0x80)),
                                            _mm_subs_epu8(_mm_alignr_epi8(in, prev, 13), _mm_set1_epi8(0xF0 - 0x80)));
        const __m128i err = _mm_xor_si128(_mm_and_si128(must23, _mm_set1_epi8(static_cast<char>(-128))), sc);
        const auto special_bits = static_cast<unsigned>(_mm_movemask_epi8(special));
        const auto err_bits = ~static_cast<unsigned>(_mm_movemask_epi8(_mm_cmpeq_epi8(err, zero))) & 0xFFFFu;
        if (special_bits != 0)
        {
            const unsigned k = static_cast<unsigned>(count_trailing_zeros(static_cast<std::uint64_t>(special_bits)));
            if ((err_bits & ((2u << k) - 1u)) == 0)
            {
                return block + k;
            }
            break;
        }
        if (err_bits != 0)
        {
            break;
        }
        prev = in;
        block += 16;
    }
#endif
    return scan_string_finish(p, block, e, plain);
}
#endif

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END


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
/// bytes are checked one by one, so that the position advances by constants
/// in predicted branches: 16 for keys, whose lengths repeat from record to
/// record, and 8 for string values (Value) where a vector loop follows, as
/// their lengths vary more. Longer runs continue 16 bytes at a time with NEON
/// or SSE2, else eight bytes at a time. With SSE2, the run is checked 16 bytes
/// at a time from its first byte instead: on x86-64, one compare that finds
/// the end of most keys and short values is faster than a branch per byte (on
/// AArch64, where a NEON mask costs more and branches predict well, slower).
template<bool Value = false>
NLOHMANN_VIEW_ALWAYS_INLINE const unsigned char* scan_string_run(const unsigned char* p, const unsigned char* e) noexcept
{
    const std::uint8_t* plain = string_plain();
    for (;;)
    {
#if NLOHMANN_VIEW_SSE2
        p = vector_plain_run(p, e);
#else
        if (e - p >= 16)
        {
#define NLOHMANN_VIEW_STEP(i) if (NLOHMANN_VIEW_LIKELY(plain[p[i]] != 0)) {} else { p += (i); goto stop; }
            NLOHMANN_VIEW_STEP(0) NLOHMANN_VIEW_STEP(1) NLOHMANN_VIEW_STEP(2) NLOHMANN_VIEW_STEP(3)
            NLOHMANN_VIEW_STEP(4) NLOHMANN_VIEW_STEP(5) NLOHMANN_VIEW_STEP(6) NLOHMANN_VIEW_STEP(7)
            if (!Value || !NLOHMANN_VIEW_VECTOR)
            {
                NLOHMANN_VIEW_STEP(8) NLOHMANN_VIEW_STEP(9) NLOHMANN_VIEW_STEP(10) NLOHMANN_VIEW_STEP(11)
                NLOHMANN_VIEW_STEP(12) NLOHMANN_VIEW_STEP(13) NLOHMANN_VIEW_STEP(14) NLOHMANN_VIEW_STEP(15)
                p += 8;
            }
#undef NLOHMANN_VIEW_STEP
            p += 8;
#if NLOHMANN_VIEW_VECTOR
            p = vector_plain_run(p, e);
            if (p != e && plain[*p] == 0)
            {
                goto stop;
            }
#else
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
#endif
            continue;
        }
#endif
        while (p != e && plain[*p] != 0)
        {
            ++p;
        }
        if (p == e)
        {
            return p;
        }
#if !NLOHMANN_VIEW_SSE2
stop:
#endif
        if (*p < 0x80)
        {
            return p; // quote, backslash, or control character
        }
#if NLOHMANN_VIEW_VECTOR_UTF8
#if NLOHMANN_VIEW_SSSE3_DISPATCH
        if (NLOHMANN_VIEW_LIKELY(cpu_has_ssse3()))
#endif
        {
            // non-ASCII: the vector check, out of line
            return scan_string_vector(p, e, plain);
        }
#endif
#if !NLOHMANN_VIEW_VECTOR_UTF8 || NLOHMANN_VIEW_SSSE3_DISPATCH
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
#endif
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

    /// remember an object to index after parsing (out of line, so that the
    /// parse loop only has a call for it)
    NLOHMANN_VIEW_NOINLINE void note_large_object(std::uint32_t idx)
    {
        doc.large_objects.push_back(idx);
    }

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
            if (NLOHMANN_VIEW_UNLIKELY(!string<true>())) { return false; }                \
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
            if (NLOHMANN_VIEW_UNLIKELY(!string<false>()))
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
                    goto close_object;
                }
                goto obj_key;
            }
            if (cur() == '}')
            {
                ++p;
                goto close_object;
            }
            return fail(error_code::expected_object_end);

#undef NLOHMANN_VIEW_VALUE

close_object:
            // a large object gets a hash index (objects only, so that closing
            // an array pays nothing for this)
            if (NLOHMANN_VIEW_UNLIKELY(cur_count >= document_data::index_min_members))
            {
                cold.note_large_object(cur_idx);
            }

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
                    return string<true>();
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
                if (NLOHMANN_VIEW_LIKELY(depth <= 64))
                {
                    // field by field: a frame put together on the stack and
                    // copied would be read back wider than it was written,
                    // and that load waits until the stores are done
                    frame& f = cold.shallow[depth - 1];
                    f.idx = cur_idx;
                    f.count = cur_count;
                    f.is_object = cur_is_object;
                }
                else
                {
                    cold.deep.push_back(frame{cur_idx, cur_count, cur_is_object});
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
                if (NLOHMANN_VIEW_LIKELY(depth <= 64))
                {
                    const frame& f = cold.shallow[depth - 1];
                    cur_idx = f.idx;
                    cur_count = f.count;
                    cur_is_object = f.is_object;
                }
                else
                {
                    const frame f = cold.deep.back();
                    cold.deep.pop_back();
                    cur_idx = f.idx;
                    cur_count = f.count;
                    cur_is_object = f.is_object;
                }
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

        /// a string at p: a value (Value) or a key
        template<bool Value>
        NLOHMANN_VIEW_ALWAYS_INLINE bool string()
        {
            ++p; // opening quote
            const unsigned char* const s = p;
            p = scan_string_run<Value>(p, e);
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

// #include <nlohmann/detail/view/compare.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <algorithm> // sort, stable_sort
#include <cstddef> // size_t
#include <string> // string
#include <utility> // move, pair
#include <vector> // vector

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/macro_scope.hpp>


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

/// one side of a comparison: a view
template<typename BasicJsonType, typename View>
class view_side
{
  public:
    using string_view_t = typename View::string_view_t;

    explicit view_side(const View& v) noexcept
        : m_view(v)
    {}

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

    void elements(std::vector<view_side>& out) const
    {
        out.reserve(m_view.size());
        for (const View e : m_view)
        {
            out.emplace_back(e);
        }
    }

    /// the members as parse() keeps them: one per key, the last value at the
    /// position of the first occurrence; in that order, or sorted by key
    void members(std::vector<std::pair<string_view_t, view_side>>& out, bool ordered) const
    {
        struct member
        {
            string_view_t key;
            View value;
            std::size_t position;
        };
        std::vector<member> all;
        all.reserve(m_view.size());
        std::size_t position = 0;
        for (auto it = m_view.begin(); it != m_view.end(); ++it)
        {
            all.push_back(member{it.key(), it.value(), position++});
        }
        std::stable_sort(all.begin(), all.end(), [](const member & a, const member & b)
        {
            return a.key < b.key;
        });
        std::vector<member> unique;
        unique.reserve(all.size());
        for (std::size_t i = 0; i < all.size();)
        {
            std::size_t last = i;
            while (last + 1 < all.size() && all[last + 1].key == all[i].key)
            {
                ++last;
            }
            unique.push_back(member{all[i].key, all[last].value, all[i].position});
            i = last + 1;
        }
        if (ordered)
        {
            std::sort(unique.begin(), unique.end(), [](const member & a, const member & b)
            {
                return a.position < b.position;
            });
        }
        out.reserve(unique.size());
        for (const member& m : unique)
        {
            out.emplace_back(m.key, view_side(m.value));
        }
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

    BasicJsonType scalar() const
    {
        return *m_json;
    }

    void elements(std::vector<json_side>& out) const
    {
        out.reserve(m_json->size());
        for (const auto& e : *m_json)
        {
            out.emplace_back(e);
        }
    }

    void members(std::vector<std::pair<string_view_t, json_side>>& out, bool ordered) const
    {
        out.reserve(m_json->size());
        for (auto it = m_json->cbegin(); it != m_json->cend(); ++it)
        {
            out.emplace_back(string_view_t(it.key().data(), it.key().size()), json_side(it.value()));
        }
        if (!ordered)
        {
            std::sort(out.begin(), out.end(), [](const std::pair<string_view_t, json_side>& a, const std::pair<string_view_t, json_side>& b)
            {
                return a.first < b.first;
            });
        }
    }

  private:
    const BasicJsonType* m_json;
};

/// whether two sides are equal; iterative, so that the nesting depth is
/// limited by memory only
template<typename BasicJsonType, typename A, typename B>
bool equal(const A& a0, const B& b0)
{
    using string_view_t = typename A::string_view_t;
    const bool ordered = is_ordered_map<typename BasicJsonType::object_t>::value;

    struct frame
    {
        std::vector<A> elements_a{};
        std::vector<B> elements_b{};
        std::vector<std::pair<string_view_t, A>> members_a{};
        std::vector<std::pair<string_view_t, B>> members_b{};
        bool object = false;
        std::size_t next = 0;
    };
    std::vector<frame> stack;
    A a = a0;
    B b = b0;
    for (;;)
    {
        const value_t ta = a.type();
        const value_t tb = b.type();
        const bool numbers = (ta == value_t::number_integer || ta == value_t::number_unsigned || ta == value_t::number_float)
                             && (tb == value_t::number_integer || tb == value_t::number_unsigned || tb == value_t::number_float);
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
            if (!numbers && ta != tb)
            {
                return false;
            }
            if (ta == value_t::string)
            {
                if (!(a.string() == b.string()))
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
                frame f;
                f.object = ta == value_t::object;
                if (f.object)
                {
                    a.members(f.members_a, ordered);
                    b.members(f.members_b, ordered);
                    if (f.members_a.size() != f.members_b.size())
                    {
                        return false;
                    }
                }
                else
                {
                    a.elements(f.elements_a);
                    b.elements(f.elements_b);
                }
                stack.push_back(std::move(f));
            }
            else if (!(a.scalar() == b.scalar())) // numbers (also of different types), null, boolean
            {
                return false;
            }
        }

        // the next pair of values
        for (;;)
        {
            if (stack.empty())
            {
                return true;
            }
            frame& f = stack.back();
            const std::size_t count = f.object ? f.members_a.size() : f.elements_a.size();
            if (f.next == count)
            {
                stack.pop_back();
                continue;
            }
            if (f.object)
            {
                if (!(f.members_a[f.next].first == f.members_b[f.next].first))
                {
                    return false;
                }
                a = f.members_a[f.next].second;
                b = f.members_b[f.next].second;
            }
            else
            {
                a = f.elements_a[f.next];
                b = f.elements_b[f.next];
            }
            ++f.next;
            break;
        }
    }
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/view/document_data.hpp>

// #include <nlohmann/detail/view/edit.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <array> // array
#include <cmath> // isinf, isnan
#include <cstddef> // size_t
#include <cstdint> // int64_t, uint8_t, uint32_t, uint64_t
#include <cstring> // memcmp, memmove
#include <limits> // numeric_limits
#include <string> // string, to_string
#include <type_traits> // decay, enable_if, integral_constant, is_arithmetic, is_convertible, is_floating_point, is_same, is_signed
#include <utility> // forward

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/document_data.hpp>

// #include <nlohmann/detail/view/edit_storage.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <algorithm> // max, min
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t
#include <cstring> // memcpy
#include <functional> // less
#include <memory> // unique_ptr
#include <utility> // move

// #include <nlohmann/json.hpp>
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

[[noreturn]] NLOHMANN_VIEW_NOINLINE inline void throw_type_error(int id, const std::string& msg)
{
    NLOHMANN_VIEW_THROW(type_error::create(id, msg, nullptr));
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

// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/node.hpp>


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

// #include <nlohmann/detail/view/errors.hpp>

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

// #include <nlohmann/detail/view/object_index.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <cstddef> // size_t
#include <cstdint> // uint32_t, uint64_t
#include <cstring> // memcmp

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/document_data.hpp>

// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/node.hpp>


// Hash indexes of large objects, so that a lookup does not compare thousands
// of keys (as Boost.JSON switches from a linear search to a hash table for
// large objects). An object with document_data::index_min_members members or
// more gets an open-addressing table after parsing; its node stores the
// number of the table (1-based) in `extra`. A slot holds the offset of a key
// node from its object node (0: empty). Of duplicate keys, the first is kept,
// as for the linear search.

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// hash of a key: its bytes, eight at a time, in a fixed byte order
inline std::uint64_t key_hash(const char* s, std::size_t n) noexcept
{
    std::uint64_t h = 0x9E3779B97F4A7C15u * (n + 1);
    const auto* p = reinterpret_cast<const unsigned char*>(s); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    while (n >= 8)
    {
        h = (h ^ read_eight_bytes(p)) * 0xBF58476D1CE4E5B9u;
        h ^= h >> 29u;
        p += 8;
        n -= 8;
    }
    std::uint64_t w = 0;
    for (std::size_t i = 0; i < n; ++i)
    {
        w |= static_cast<std::uint64_t>(p[i]) << (8u * i);
    }
    h = (h ^ w) * 0x94D049BB133111EBu;
    return h ^ (h >> 31u);
}

/// build the table of a large object
inline void build_object_index(document_data& d, node* obj)
{
    if (d.indexes.size() >= 0xFFFFu)
    {
        return; // LCOV_EXCL_LINE (the number must fit `extra`; more large objects are searched linearly)
    }
    std::size_t cap = 16;
    while (cap < 2 * static_cast<std::size_t>(obj->len))
    {
        cap *= 2;
    }
    const std::size_t start = d.index_slots.size();
    d.index_slots.resize(start + cap, 0);
    std::uint32_t* const slots = d.index_slots.data() + start;
    const std::size_t mask = cap - 1;
    for (const node* k = document_data::first_child(obj), *end = document_data::child_end(obj); k != end; k = document_data::after(k + 1))
    {
        const char* const key = d.str(*k);
        const std::uint64_t hash = key_hash(key, k->len); // (a cast of the call would be useless where std::uint64_t is std::size_t)
        std::size_t i = static_cast<std::size_t>(hash) & mask;
        bool duplicate = false;
        while (slots[i] != 0)
        {
            const node* const other = obj + slots[i];
            if (other->len == k->len && (k->len == 0 || std::memcmp(d.str(*other), key, k->len) == 0))
            {
                duplicate = true; // keep the first
                break;
            }
            i = (i + 1) & mask;
        }
        if (!duplicate)
        {
            slots[i] = static_cast<std::uint32_t>(k - obj);
        }
    }
    d.indexes.push_back(document_data::object_index{start, static_cast<std::uint32_t>(mask)});
    obj->extra = static_cast<std::uint16_t>(d.indexes.size());
}

/// build the tables of the large objects the parser noted
inline void build_object_indexes(document_data& d)
{
    for (const std::uint32_t i : d.large_objects)
    {
        build_object_index(d, d.tape + i);
    }
}

/// the key node of the first member with this key of an indexed object, or
/// nullptr
inline const node* find_indexed(const document_data& d, const node* obj, const char* key, std::size_t n) noexcept
{
    const document_data::object_index& ix = d.indexes[obj->extra - 1u];
    const std::uint32_t* const slots = d.index_slots.data() + ix.start;
    const std::uint64_t hash = key_hash(key, n); // (a cast of the call would be useless where std::uint64_t is std::size_t)
    std::size_t i = static_cast<std::size_t>(hash) & ix.mask;
    for (;;)
    {
        const std::uint32_t s = slots[i];
        if (s == 0)
        {
            return nullptr;
        }
        const node* const k = obj + s;
        if (k->len == n && (n == 0 || std::memcmp(d.str(*k), key, n) == 0))
        {
            return k;
        }
        i = (i + 1) & ix.mask;
    }
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END


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

// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/node.hpp>


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

// #include <nlohmann/detail/view/edit_storage.hpp>

// #include <nlohmann/detail/view/errors.hpp>

// #include <nlohmann/detail/view/image.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <array> // array
#include <cstddef> // size_t
#include <cstdint> // int64_t, uint8_t, uint16_t, uint32_t, uint64_t
#include <cstring> // memcmp, memcpy
#include <limits> // numeric_limits
#include <string> // string
#include <vector> // vector

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/document_data.hpp>

// #include <nlohmann/detail/view/errors.hpp>

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
#include <cstdint> // int64_t, uint64_t
#include <limits> // numeric_limits
#include <string> // string
#include <type_traits> // integral_constant

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/document_data.hpp>

// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/node.hpp>

// #include <nlohmann/detail/view/scan.hpp>


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/*!
@brief locate the decimal point and the end of the mantissa of a float token

Also checks that the token is a JSON number. Tokens of the parser and of edits
always are; an image loaded with image_check::bounds can hold any bytes, which
must not reach the conversion (it expects a well-formed token).
*/
inline bool float_token_layout(const char* first, const char* last, std::size_t& dot, std::size_t& mantissa_end) noexcept
{
    const auto digit = [last](const char* q)
    {
        return q != last && is_digit(static_cast<unsigned char>(*q));
    };
    const char* p = first;
    p += (p != last && *p == '-') ? 1 : 0;
    if (!digit(p) || (*p == '0' && digit(p + 1)))
    {
        return false;
    }
    while (digit(p))
    {
        ++p;
    }
    dot = std::string::npos;
    if (p != last && *p == '.')
    {
        dot = static_cast<std::size_t>(p - first);
        if (!digit(++p))
        {
            return false;
        }
        while (digit(p))
        {
            ++p;
        }
    }
    mantissa_end = static_cast<std::size_t>(p - first);
    if (p != last && (*p == 'e' || *p == 'E'))
    {
        ++p;
        p += (p != last && (*p == '+' || *p == '-')) ? 1 : 0;
        if (!digit(p))
        {
            return false;
        }
        while (digit(p))
        {
            ++p;
        }
    }
    return p == last;
}

/*!
@brief the value of the float token of a node, as parse() converts it

Uses the lexer's conversion (detail::convert_float), so that the values are
bit-identical to parse(): float and double are converted without allocation
and independent of the locale. A token that is not a JSON number (only in a
damaged image loaded with image_check::bounds) yields 0.
*/
template<typename FloatType>
NLOHMANN_VIEW_NOINLINE FloatType float_value(const char* first, const node& n)
{
    const char* const last = first + n.len;
    std::size_t dot = 0;
    std::size_t mantissa_end = 0;
    if (NLOHMANN_VIEW_UNLIKELY(!float_token_layout(first, last, dot, mantissa_end)))
    {
        return FloatType{};
    }
    return convert_float<FloatType>(first, last, dot, mantissa_end);
}

/*!
@brief the digits of a float token with at most 19 digits, from its layout

The digit layout recorded while parsing says where the integer digits, the
fraction digits, and the exponent are, so the digits are read eight at a
time without scanning.

@param[in] p  first character of the token
@param[in] e  end of the token
@param[in] limit  end of the readable memory (the source text)
*/
NLOHMANN_VIEW_ALWAYS_INLINE float_significand layout_decimal(const unsigned char* p, const unsigned char* e, unsigned int_digits, unsigned frac_digits, const unsigned char* limit) noexcept
{
    const bool negative = *p == '-';
    p += negative ? 1 : 0;
    std::uint64_t w = parse_upto19(p, int_digits, limit);
    p += int_digits;
    std::int64_t q = 0;
    if (frac_digits != 0)
    {
        w = (w * int_pow10(frac_digits)) + parse_upto19(p + 1, frac_digits, limit);
        p += 1 + frac_digits;
        q = -static_cast<std::int64_t>(frac_digits);
    }
    if (p != e)
    {
        // [eE][+-]digits; huge exponents saturate (the parser rejected
        // overflow). The token is not read beyond e, and the digits are taken
        // as unsigned, so that a token that is not well-formed (a damaged
        // image loaded with image_check::bounds) yields a wrong value, but no
        // overflow.
        ++p;
        const bool exp_negative = p != e && *p == '-';
        p += (p != e && (*p == '-' || *p == '+')) ? 1 : 0;
        std::int64_t exp_value = 0;
        for (; p != e; ++p)
        {
            if (exp_value < 0x10000000)
            {
                exp_value = (exp_value * 10) + static_cast<unsigned char>(*p - '0');
            }
        }
        q += exp_negative ? -exp_value : exp_value;
    }

    float_significand d;
    d.w = w;
    d.exponent = q;
    d.negative = negative;
    return d;
}

/*!
@brief the value of a float token with at most 19 digits, from its layout

The result is correctly rounded by the lexer's conversion
(detail::decimal_to_float(): Clinger's fast path where both operands are
exact, else the Eisel-Lemire algorithm, which needs no fallback for up to 19
digits), so it is the value parse() produces.
*/
template<typename FloatType>
NLOHMANN_VIEW_ALWAYS_INLINE FloatType layout_float(const unsigned char* p, const unsigned char* e, unsigned int_digits, unsigned frac_digits, const unsigned char* limit) noexcept
{
    return decimal_to_float<FloatType>(layout_decimal(p, e, int_digits, frac_digits, limit));
}

/// the value of a float set by an edit: its token (the shortest round-trip
/// text, or "nan", "inf", "-inf") in the edit arena
template<typename FloatType>
NLOHMANN_VIEW_NOINLINE FloatType edited_float(const char* token, const node& n)
{
    if (token[0] == 'n')
    {
        return std::numeric_limits<FloatType>::quiet_NaN();
    }
    if (token[0] == 'i' || (token[0] == '-' && token[1] == 'i'))
    {
        return token[0] == 'i' ? std::numeric_limits<FloatType>::infinity() : -std::numeric_limits<FloatType>::infinity();
    }
    return float_value<FloatType>(token, n);
}

/// the value of the float token of a node, as parse() converts it; floats and
/// doubles with at most 19 digits are converted from the digit layout
template<typename FloatType>
FloatType float_value(const document_data& d, const node& n)
{
    if (NLOHMANN_VIEW_UNLIKELY((n.flags & node_flags::storage) == node_flags::edited))
    {
        return edited_float<FloatType>(d.str(n), n);
    }
    return float_value<FloatType>(d, n, std::integral_constant<bool, has_native_float_format<FloatType>::value> {});
}

template<typename FloatType>
FloatType float_value(const document_data& d, const node& n, std::true_type /*binary32 or binary64*/)
{
    const unsigned int_digits = n.extra & 0xFFu;
    const unsigned frac_digits = n.extra >> 8u;
    if (NLOHMANN_VIEW_LIKELY(int_digits + frac_digits <= 19)) // (255 marks "many")
    {
        // (a float token not written by an edit is in the text)
        const auto* const first = reinterpret_cast<const unsigned char*>(d.src + n.off); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        return layout_float<FloatType>(first, first + n.len, int_digits, frac_digits, reinterpret_cast<const unsigned char*>(d.src + d.size)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }
    return float_value<FloatType>(d.str(n), n);
}

template<typename FloatType>
FloatType float_value(const document_data& d, const node& n, std::false_type /*other*/)
{
    return float_value<FloatType>(d.str(n), n);
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/view/object_index.hpp>

// #include <nlohmann/detail/view/scan.hpp>


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
        return View(m_doc, View::navigation::value(m_pos + m_value_offset));
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
template<typename BasicJsonType, bool Editable>
BasicJsonType materialize(const document_data& d, const node* n)
{
    using string_t = typename BasicJsonType::string_t;
    using sax_t = json_sax_dom_parser<BasicJsonType, iterator_input_adapter<const char*>>;
    using nav = navigation<Editable>;

    struct frame
    {
        const node* pos; ///< next element, or key of the next member
        const node* end;
        bool object;
    };

    BasicJsonType result;
    sax_t sax(result, true);
    const string_t no_token{};
    std::vector<frame> open;
    for (;;)
    {
        // false positive: n comes from nav::value(), which never returns null for a valid index
        // @infer-ignore NULLPTR_DEREFERENCE
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
                open.push_back(frame{nav::first(d, n), nav::end(d, n), object});
                break;
            }
            case value_t::string:
            {
                string_t s(d.str(*n), n->len);
                sax.string(s);
                break;
            }
            case value_t::number_integer:
                sax.number_integer(static_cast<typename BasicJsonType::number_integer_t>(static_cast<std::int64_t>(integer_bits(*n))));
                break;
            case value_t::number_unsigned:
                sax.number_unsigned(static_cast<typename BasicJsonType::number_unsigned_t>(integer_bits(*n)));
                break;
            case value_t::number_float:
                sax.number_float(float_value<typename BasicJsonType::number_float_t>(d, *n), no_token);
                break;
            case value_t::boolean:
                sax.boolean((n->flags & node_flags::is_true) != 0);
                break;
            case value_t::null:
            case value_t::binary:
            case value_t::discarded:
            default:
                sax.null();
                break;
        }

        // the next value: close finished containers, then read the key
        for (;;)
        {
            if (open.empty())
            {
                return result;
            }
            frame& f = open.back();
            if (f.pos == f.end)
            {
                if (f.object)
                {
                    sax.end_object();
                }
                else
                {
                    sax.end_array();
                }
                open.pop_back();
                continue;
            }
            const node* entry = f.pos;
            if (f.object)
            {
                string_t key(d.str(*entry), entry->len);
                sax.key(key);
                ++entry;
            }
            n = nav::value(entry);
            f.pos = document_data::after(entry);
            break;
        }
    }
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/view/node.hpp>

// #include <nlohmann/detail/view/object_index.hpp>

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

// #include <nlohmann/detail/view/serializer.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <algorithm> // max
#include <array> // array
#include <cmath> // isfinite
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t
#include <cstring> // memcpy, memset
#include <limits> // numeric_limits
#include <type_traits> // integral_constant
#include <vector> // vector

// #include <nlohmann/json.hpp>
// #include <nlohmann/detail/view/document_data.hpp>

// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/node.hpp>

// #include <nlohmann/detail/view/number.hpp>


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// append-only output buffer: writes through a raw pointer into a string that
/// is resized ahead, and trimmed by finish(). The estimate is reserved, and the
/// string grows in steps of 64 KiB within it: resize() fills the new bytes
/// with zeros (before C++23, a string cannot grow without), and a small step
/// is filled while the writer is about to use it, in the cache, instead of
/// filling the whole estimate in memory first.
template<typename StringType>
class output_buffer
{
  public:
    output_buffer(StringType& out, std::size_t estimate)
        : m_out(sized(out, estimate))
        , m_pos(&m_out[0])
        , m_end(m_pos + m_out.size())
    {}

    void finish()
    {
        m_out.resize(static_cast<std::size_t>(m_pos - m_out.data()));
    }

    NLOHMANN_VIEW_ALWAYS_INLINE void reserve(std::size_t n)
    {
        if (NLOHMANN_VIEW_UNLIKELY(static_cast<std::size_t>(m_end - m_pos) < n))
        {
            grow(n);
        }
    }

    NLOHMANN_VIEW_ALWAYS_INLINE void put(char c)
    {
        reserve(1);
        *m_pos++ = c;
    }

    NLOHMANN_VIEW_ALWAYS_INLINE void put(const char* s, std::size_t n)
    {
        reserve(n);
        std::memcpy(m_pos, s, n);
        m_pos += n;
    }

    void put_repeated(char c, std::size_t n)
    {
        reserve(n);
        std::memset(m_pos, c, n);
        m_pos += n;
    }

    /// the write position and the end of the writable space, for a writer
    /// that keeps the position in a local variable (set_cursor() hands it back)
    char* cursor() const noexcept
    {
        return m_pos;
    }

    char* limit() const noexcept
    {
        return m_end;
    }

    void set_cursor(char* p) noexcept
    {
        m_pos = p;
    }

  private:
    /// the size of a growth step (a function: std::min() takes a reference,
    /// which a static constexpr member does not have before C++17)
    static constexpr std::size_t step() noexcept
    {
        return 65536;
    }

    static StringType& sized(StringType& out, std::size_t estimate)
    {
        out.reserve(estimate);
        out.resize((std::min)((std::max)(estimate, static_cast<std::size_t>(64)), step()));
        return out;
    }

    NLOHMANN_VIEW_NOINLINE void grow(std::size_t n)
    {
        const auto used = static_cast<std::size_t>(m_pos - m_out.data());
        // (a step does not go beyond the reserved estimate, so that a good
        // estimate is never copied to a larger allocation)
        const std::size_t size = (std::max)((std::min)(m_out.size() + step(), m_out.capacity()), used + n + 256);
        if (size > m_out.capacity())
        {
            m_out.reserve((std::max)(m_out.capacity() * 2, size));
        }
        m_out.resize(size);
        m_pos = &m_out[0] + used;
        m_end = &m_out[0] + m_out.size();
    }

    StringType& m_out;
    char* m_pos;
    char* m_end;
};

/// The length of the run at s that dump() writes unchanged without
/// ensure_ascii: all bytes but quotes, backslashes, and control characters.
/// Unlike detail::string_bulk_run(), non-ASCII bytes are not validated: the
/// strings of a document are valid UTF-8 (a damaged image loaded with
/// image_check::bounds can have others, which are then written unchanged).
inline std::size_t plain_output_run(const unsigned char* s, std::size_t n) noexcept
{
    constexpr std::uint64_t ones = 0x0101010101010101ull;
    constexpr std::uint64_t high = 0x8080808080808080ull;
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8)
    {
        const std::uint64_t v = read_eight_bytes(s + i);
        const std::uint64_t q = v ^ 0x2222222222222222ull; // '"'
        const std::uint64_t b = v ^ 0x5C5C5C5C5C5C5C5Cull; // '\\'
        const std::uint64_t stop = (((q - ones) & ~q) | ((b - ones) & ~b) | ((v - 0x2020202020202020ull) & ~v)) & high;
        if (stop != 0)
        {
            // the lowest flagged byte is the first stop: borrows only flag bytes above a true one
            return i + (static_cast<std::size_t>(count_trailing_zeros(stop)) / 8);
        }
    }
    for (; i < n; ++i)
    {
        if (s[i] == '"' || s[i] == '\\' || s[i] < 0x20)
        {
            return i;
        }
    }
    return n;
}

/// A stack that starts in a buffer of the caller (a local array) and moves to
/// the heap (a vector of the caller) only when that is full, so that dumps of
/// shallow documents need no allocation. The top is a pointer, as in
/// std::vector. The address of the stack never escapes (the growth gets the
/// vector and returns the new storage), so its pointers stay in registers.
template<typename T>
class small_stack
{
  public:
    small_stack(T* buffer, std::size_t capacity, std::vector<T>& heap) noexcept
        : m_begin(buffer), m_top(buffer), m_end(buffer + capacity), m_heap(&heap)
    {}
    small_stack(const small_stack&) = delete;
    small_stack(small_stack&&) = delete;
    small_stack& operator=(const small_stack&) = delete;
    small_stack& operator=(small_stack&&) = delete;
    ~small_stack() = default;

    NLOHMANN_VIEW_ALWAYS_INLINE void push_back(const T& x)
    {
        if (NLOHMANN_VIEW_UNLIKELY(m_top == m_end))
        {
            const std::size_t used = size();
            const std::size_t capacity = 2 * static_cast<std::size_t>(m_end - m_begin);
            m_begin = grow(*m_heap, m_begin, used, capacity);
            m_top = m_begin + used;
            m_end = m_begin + capacity;
        }
        *m_top++ = x;
    }

    NLOHMANN_VIEW_ALWAYS_INLINE T& back() noexcept
    {
        return m_top[-1];
    }

    NLOHMANN_VIEW_ALWAYS_INLINE void pop_back() noexcept
    {
        --m_top;
    }

    NLOHMANN_VIEW_ALWAYS_INLINE bool empty() const noexcept
    {
        return m_top == m_begin;
    }

    NLOHMANN_VIEW_ALWAYS_INLINE std::size_t size() const noexcept
    {
        return static_cast<std::size_t>(m_top - m_begin);
    }

  private:
    /// the used entries moved to heap storage of the given capacity
    NLOHMANN_VIEW_NOINLINE static T* grow(std::vector<T>& heap, const T* begin, std::size_t used, std::size_t capacity)
    {
        std::vector<T> bigger(capacity);
        std::copy(begin, begin + used, bigger.begin());
        heap.swap(bigger);
        return heap.data();
    }

    T* m_begin;
    T* m_top;
    T* m_end;
    std::vector<T>* m_heap;
};

/// how the view's dump() writes a value
struct dump_style
{
    bool pretty = false;           ///< indent >= 0
    std::size_t indent = 0;        ///< characters per level
    char indent_char = ' ';
    bool ensure_ascii = false;
    bool source_numbers = false;   ///< copy number tokens from the source
};

/*!
@brief write a view's subtree as basic_json::dump() writes the value

The output of a subtree equals ordered_json::parse(text).dump() of it for
the same arguments (members in document order): strings are escaped by the
same rules, with the library's scanning kernels; floats are written with
the library's conversion; integers are copied from the source, where they
are canonical (except "-0", which parse() reads as 0). The walk is
iterative, so the nesting depth is limited by memory only.
*/
template<typename BasicJsonType, bool Editable>
class view_serializer
{
    using nav = navigation<Editable>;
    using string_t = typename BasicJsonType::string_t;
    using number_float_t = typename BasicJsonType::number_float_t;

  public:
    view_serializer(const document_data& d, string_t& out, std::size_t estimate, const dump_style& style)
        : m_doc(d), m_out(out, estimate), m_style(style)
    {}

    void dump(const node* root)
    {
        if (!m_style.pretty && !m_style.ensure_ascii)
        {
            if (m_style.source_numbers)
            {
                dump_compact<true>(root);
            }
            else
            {
                dump_compact<false>(root);
            }
            return;
        }
        struct frame
        {
            const node* pos; ///< next element, or key of the next member
            const node* end;
            bool object;
            bool first;  ///< nothing written yet
        };
        std::array<frame, 32> buffer; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
        std::vector<frame> heap;
        small_stack<frame> stack(buffer.data(), buffer.size(), heap);
        const node* n = root;
        for (;;)
        {
            // write the value at n
            if (is_container(*n))
            {
                const bool object = n->kind == static_cast<std::uint8_t>(value_t::object);
                if (n->len == 0)
                {
                    m_out.put(object ? "{}" : "[]", 2);
                }
                else
                {
                    m_out.put(object ? '{' : '[');
                    stack.push_back(frame{nav::first(m_doc, n), nav::end(m_doc, n), object, true});
                }
            }
            else
            {
                write_scalar(*n);
            }

            // go to the next value: close finished containers, then separate
            for (;;)
            {
                if (stack.empty())
                {
                    m_out.finish();
                    return;
                }
                frame& f = stack.back();
                if (f.pos == f.end)
                {
                    const bool object = f.object;
                    stack.pop_back();
                    newline(stack.size());
                    m_out.put(object ? '}' : ']');
                    continue;
                }
                if (!f.first)
                {
                    m_out.put(',');
                }
                f.first = false;
                newline(stack.size());
                if (f.object)
                {
                    write_string(*f.pos);
                    if (m_style.pretty)
                    {
                        m_out.put(": ", 2);
                    }
                    else
                    {
                        m_out.put(':');
                    }
                    n = nav::value(f.pos + 1);
                    f.pos = document_data::after(f.pos + 1);
                }
                else
                {
                    n = nav::value(f.pos);
                    f.pos = document_data::after(f.pos);
                }
                break;
            }
        }
    }

  private:
    /*!
    @brief the compact output without ensure_ascii (the default dump())

    The same walk as dump(), with the write position in a local variable
    (stores through char pointers would otherwise force a reload of the
    buffer's members after each one), and with strings and number tokens of
    the source copied by fixed-size moves of 32 bytes where the source has
    that many bytes left, instead of a library call per token. The buffer
    keeps 64 bytes of slack for the overshoot.
    */
    /// a string that is not a plain string of the source (decoded, or written
    /// by an edit), without ensure_ascii: runs without characters to escape
    /// are copied
    NLOHMANN_VIEW_NOINLINE void write_decoded(const node& n)
    {
        const auto* const s = reinterpret_cast<const unsigned char*>(m_doc.str(n)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        m_out.put('"');
        for (std::size_t i = 0; i < n.len;)
        {
            const std::size_t run = plain_output_run(s + i, n.len - i);
            if (run != 0)
            {
                m_out.put(reinterpret_cast<const char*>(s + i), run); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
                i += run;
                continue;
            }
            write_codepoint<false>(s[i], s + i, 1); // a quote, a backslash, or a control character
            ++i;
        }
        m_out.put('"');
    }

    /// the copies of dump_compact() that are not fixed-size moves (long
    /// strings, or near the end of the source); out of line, so that the
    /// compiler does not merge the fixed-size moves into this call
    NLOHMANN_VIEW_NOINLINE static void copy_long(char* to, const char* from, std::size_t n) noexcept
    {
        std::memcpy(to, from, n);
    }

    template<bool SourceNumbers>
    void dump_compact(const node* root)
    {
        struct frame
        {
            const node* pos; ///< (editable documents) next element, or key of the next member
            const node* end;
            bool object;
        };
        std::array<frame, 32> buffer; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
        std::vector<frame> heap;
        small_stack<frame> stack(buffer.data(), buffer.size(), heap);
        const char* const src = m_doc.src;
        const char* const src_end = src + m_doc.size;
        char* w = m_out.cursor();
        char* lim = m_out.limit();
        // room for n bytes and the slack
        const auto room = [&](std::size_t n)
        {
            if (NLOHMANN_VIEW_UNLIKELY(static_cast<std::size_t>(lim - w) < n + 64))
            {
                m_out.set_cursor(w);
                m_out.reserve(n + 64);
                w = m_out.cursor();
                lim = m_out.limit();
            }
        };
        // copy n bytes of the source (after room(n))
        const auto copy = [&](const char* from, std::size_t n)
        {
            if (n <= 32 && static_cast<std::size_t>(src_end - from) >= 32)
            {
                std::memcpy(w, from, 32);
            }
            else if (n <= 256 && static_cast<std::size_t>(src_end - from) >= n + 32)
            {
                for (std::size_t i = 0; i < n; i += 32)
                {
                    std::memcpy(w + i, from + i, 32);
                }
            }
            else
            {
                copy_long(w, from, n);
            }
            w += n;
        };
        // a literal of n bytes (after room(n))
        const auto literal = [&](const char* text, std::size_t n)
        {
            std::memcpy(w, text, n);
            w += n;
        };
        // a string that is not a plain string of the source (out of line, so
        // that the cursor stays in a register here)
        const auto escaped = [&](const node & n)
        {
            m_out.set_cursor(w);
            write_decoded(n);
            w = m_out.cursor();
            lim = m_out.limit();
        };

        // Read-only documents: the elements of a container follow it in the
        // node array, so the walk goes through the array in order, and a
        // frame only needs the end of its container. Editable documents: the
        // elements of a moved container live elsewhere, so a frame keeps the
        // position of the next element (see navigation).
        // The innermost open container is kept in registers (cur; end ==
        // nullptr: none), the stack holds the ones around it.
        frame cur{nullptr, nullptr, false};
        const node* n = root;
        for (;;)
        {
            // write the value at n (read-only documents: and advance n)
            bool opened = false;
            switch (static_cast<value_t>(n->kind))
            {
                case value_t::string:
                    if ((n->flags & node_flags::storage) == 0)
                    {
                        room(n->len + 2);
                        *w++ = '"';
                        copy(src + n->off, n->len);
                        *w++ = '"';
                    }
                    else
                    {
                        escaped(*n);
                    }
                    break;
                case value_t::number_integer:
                case value_t::number_unsigned:
                {
                    const std::uint32_t len = number_length(*n);
                    room(len);
                    if (Editable && (n->flags & node_flags::storage) != 0)
                    {
                        copy_long(w, m_doc.str(*n), len); // a canonical token written by an edit
                        w += len;
                        break;
                    }
                    const char* const token = src + n->off;
                    if (!SourceNumbers && NLOHMANN_VIEW_UNLIKELY(len == 2 && token[0] == '-' && token[1] == '0'))
                    {
                        *w++ = '0'; // parse() reads -0 as the integer 0
                    }
                    else
                    {
                        copy(token, len);
                    }
                    break;
                }
                case value_t::number_float:
                    if (SourceNumbers && (n->flags & node_flags::storage) != node_flags::edited)
                    {
                        room(n->len);
                        copy(src + n->off, n->len);
                    }
                    else if (std::is_same<number_float_t, double>::value)
                    {
                        room(64);
                        w = write_double_at(w, *n);
                    }
                    else
                    {
                        m_out.set_cursor(w);
                        write_float_node(*n);
                        w = m_out.cursor();
                        lim = m_out.limit();
                    }
                    break;
                case value_t::boolean:
                    room(8);
                    if ((n->flags & node_flags::is_true) != 0)
                    {
                        literal("true", 4);
                    }
                    else
                    {
                        literal("false", 5);
                    }
                    break;
                case value_t::object:
                case value_t::array:
                {
                    const bool object = n->kind == static_cast<std::uint8_t>(value_t::object);
                    room(8);
                    if (n->len == 0)
                    {
                        literal(object ? "{}" : "[]", 2);
                    }
                    else
                    {
                        *w++ = object ? '{' : '[';
                        stack.push_back(cur);
                        if (Editable)
                        {
                            cur = frame{nav::first(m_doc, n), nav::end(m_doc, n), object};
                        }
                        else
                        {
                            cur = frame{nullptr, n + n->next, object};
                        }
                        opened = true;
                    }
                    break;
                }
                case value_t::null:
                    room(8);
                    literal("null", 4);
                    break;
                case value_t::binary:    // LCOV_EXCL_LINE (not in a document)
                case value_t::discarded: // LCOV_EXCL_LINE
                default:                 // LCOV_EXCL_LINE
                    break;               // LCOV_EXCL_LINE
            }
            if (!Editable)
            {
                ++n; // the next node: the first element of an opened container, or the node after a scalar
            }

            // go to the next value: close finished containers, then separate
            // (a container just opened has an element)
            if (!opened)
            {
                for (;;)
                {
                    if (cur.end == nullptr)
                    {
                        m_out.set_cursor(w);
                        m_out.finish();
                        return;
                    }
                    if ((Editable ? cur.pos : n) != cur.end)
                    {
                        break;
                    }
                    room(1);
                    *w++ = cur.object ? '}' : ']';
                    cur = stack.back();
                    stack.pop_back();
                }
                room(1);
                *w++ = ',';
            }
            const node* const at = Editable ? cur.pos : n;
            if (cur.object)
            {
                const node& key = *at;
                if ((key.flags & node_flags::storage) == 0)
                {
                    room(key.len + 3);
                    *w++ = '"';
                    copy(src + key.off, key.len);
                    w[0] = '"';
                    w[1] = ':';
                    w += 2;
                }
                else
                {
                    escaped(key);
                    room(1);
                    *w++ = ':';
                }
                if (Editable)
                {
                    n = nav::value(at + 1);
                    cur.pos = document_data::after(at + 1);
                }
                else
                {
                    ++n;
                }
            }
            else if (Editable)
            {
                n = nav::value(at);
                cur.pos = document_data::after(at);
            }
        }
    }

    void newline(std::size_t level)
    {
        if (m_style.pretty)
        {
            m_out.put('\n');
            m_out.put_repeated(m_style.indent_char, level * m_style.indent);
        }
    }

    void write_scalar(const node& n)
    {
        switch (static_cast<value_t>(n.kind))
        {
            case value_t::null:
                m_out.put("null", 4);
                break;
            case value_t::boolean:
                if ((n.flags & node_flags::is_true) != 0)
                {
                    m_out.put("true", 4);
                }
                else
                {
                    m_out.put("false", 5);
                }
                break;
            case value_t::string:
                write_string(n);
                break;
            case value_t::number_integer:
            case value_t::number_unsigned:
            {
                const char* const token = m_doc.str(n);
                const std::uint32_t len = number_length(n);
                if (!m_style.source_numbers && len == 2 && token[0] == '-' && token[1] == '0')
                {
                    m_out.put('0'); // parse() reads -0 as the integer 0
                }
                else
                {
                    m_out.put(token, len);
                }
                break;
            }
            case value_t::number_float:
                if (m_style.source_numbers && (n.flags & node_flags::storage) != node_flags::edited)
                {
                    m_out.put(m_doc.str(n), n.len); // (a float set by an edit is written as with shortest)
                }
                else
                {
                    write_float_node(n);
                }
                break;
            case value_t::object:    // LCOV_EXCL_LINE (containers are written by dump())
            case value_t::array:     // LCOV_EXCL_LINE
            case value_t::binary:    // LCOV_EXCL_LINE (not in a document)
            case value_t::discarded: // LCOV_EXCL_LINE
            default:                 // LCOV_EXCL_LINE
                break;               // LCOV_EXCL_LINE
        }
    }

    /// a float node as dump() writes it
    void write_float_node(const node& n)
    {
        write_float_node(n, std::is_same<number_float_t, double> {});
    }

    void write_float_node(const node& n, std::false_type /*other*/)
    {
        write_float(float_value<number_float_t>(m_doc, n));
    }

    void write_float_node(const node& n, std::true_type /*double*/)
    {
        m_out.reserve(64);
        m_out.set_cursor(write_double_at(m_out.cursor(), n));
    }

    /*!
    @brief (doubles) the float at n as dump() writes it, at w (64 bytes of room)

    A token of at most 15 significant digits is written from its digits,
    without a conversion: two decimals of at most 15 digits are farther
    apart than the rounding interval of a (normal) double (the argument
    behind DBL_DIG), so the token's digits are the shortest ones of its
    double, which the library's conversion writes (Zmij). Other tokens are
    converted from the digits already read.
    */
    char* write_double_at(char* w, const node& n)
    {
        const unsigned int_digits = n.extra & 0xFFu;
        const unsigned frac_digits = n.extra >> 8u;
        if ((n.flags & node_flags::storage) != node_flags::edited && int_digits + frac_digits <= 19)
        {
            const auto* const first = reinterpret_cast<const unsigned char*>(m_doc.src + n.off); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
            const float_significand d = layout_decimal(first, first + n.len, int_digits, frac_digits, reinterpret_cast<const unsigned char*>(m_doc.src + m_doc.size)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
            // (the exponent keeps the value far from subnormals and overflow)
            if (d.w != 0 && d.w < 1000000000000000u && d.exponent >= -290 && d.exponent <= 290)
            {
                *w = '-';
                w += d.negative ? 1 : 0;
                // (without leading zeros, all digits of the token count)
                const unsigned char lead = first[d.negative ? 1 : 0];
                return lead != '0' ? ::nlohmann::detail::dtoa_impl::write_short_decimal(w, d.w, static_cast<int>(int_digits + frac_digits), static_cast<int>(d.exponent))
                       : ::nlohmann::detail::dtoa_impl::write_short_decimal(w, d.w, static_cast<int>(d.exponent));
            }
            return write_double_value_at(w, decimal_to_float<double>(d)); // (without reading the token again)
        }
        return write_double_value_at(w, static_cast<double>(float_value<number_float_t>(m_doc, n)));
    }

    /// n bytes of text at w
    static char* write_text_at(char* w, const char* text, std::size_t n) noexcept
    {
        std::memcpy(w, text, n);
        return w + n;
    }

    /// a double as dump() writes it, at w (64 bytes of room)
    static char* write_double_value_at(char* w, double x)
    {
        // (from the bits: without the checks of to_chars())
        std::uint64_t bits = 0;
        std::memcpy(&bits, &x, sizeof(bits));
        if (NLOHMANN_VIEW_UNLIKELY((bits & 0x7FF0000000000000u) == 0x7FF0000000000000u))
        {
            return write_text_at(w, "null", 4);
        }
        *w = '-';
        w += bits >> 63u;
        bits &= ~(std::uint64_t{1} << 63u);
        if (bits == 0)
        {
            return write_text_at(w, "0.0", 3);
        }
        return ::nlohmann::detail::dtoa_impl::write_shortest(w, ::nlohmann::detail::zmij::to_shortest(bits));
    }

    /// as serializer::dump_float()
    void write_float(number_float_t x)
    {
        if (!std::isfinite(x))
        {
            m_out.put("null", 4);
            return;
        }
        write_float(x, std::integral_constant < bool,
                    (std::numeric_limits<number_float_t>::is_iec559 && std::numeric_limits<number_float_t>::digits == 24 && std::numeric_limits<number_float_t>::max_exponent == 128)
                    || (std::numeric_limits<number_float_t>::is_iec559 && std::numeric_limits<number_float_t>::digits == 53 && std::numeric_limits<number_float_t>::max_exponent == 1024) > {});
    }

    void write_float(number_float_t x, std::true_type /*is_ieee_single_or_double*/)
    {
        std::array<char, 64> buf{};
        const char* const end = ::nlohmann::detail::to_chars(buf.data(), buf.data() + buf.size(), x);
        m_out.put(buf.data(), static_cast<std::size_t>(end - buf.data()));
    }

    void write_float(number_float_t x, std::false_type /*is_ieee_single_or_double*/)
    {
        // other types (e.g. long double) are rare: the library writes them
        const string_t s = BasicJsonType(x).dump();
        m_out.put(s.data(), s.size());
    }

    void write_string(const node& n)
    {
        const char* const s = m_doc.str(n);
        m_out.put('"');
        if ((n.flags & node_flags::storage) == 0 && !m_style.ensure_ascii)
        {
            // a string of the source without escape sequences has nothing to escape
            m_out.put(s, n.len);
        }
        else if (m_style.ensure_ascii)
        {
            write_escaped<true>(reinterpret_cast<const unsigned char*>(s), n.len); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        }
        else
        {
            write_escaped<false>(reinterpret_cast<const unsigned char*>(s), n.len); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        }
        m_out.put('"');
    }

    /// as serializer::dump_escaped(); strings of a document are valid UTF-8,
    /// except in a damaged image loaded with image_check::bounds, for which
    /// this throws what basic_json::dump() throws for the string
    template<bool EnsureAscii>
    void write_escaped(const unsigned char* s, std::size_t n)
    {
        std::size_t i = 0;
        while (i < n)
        {
            std::size_t run = 0;
            if (!EnsureAscii)
            {
                run = string_bulk_run(s + i, n - i);
            }
            else if (is_ascii_copyable(s[i]))
            {
                run = find_ascii_copyable_run(s + i, n - i);
            }
            if (run != 0)
            {
                m_out.put(reinterpret_cast<const char*>(s + i), run); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
                i += run;
                continue;
            }
            std::uint32_t codepoint = s[i];
            std::size_t len = 1;
            if (codepoint >= 0x80)
            {
                len = validate_one_utf8(s + i, n - i);
                if (NLOHMANN_VIEW_UNLIKELY(len == 0))
                {
                    invalid_utf8(s, n);
                    return;
                }
                codepoint &= 0xFFu >> (len + 1);
                for (std::size_t k = 1; k < len; ++k)
                {
                    codepoint = (codepoint << 6u) | (s[i + k] & 0x3Fu);
                }
            }
            write_codepoint<EnsureAscii>(codepoint, s + i, len);
            i += len;
        }
    }

    /// throw what basic_json::dump() throws for a string that is not valid UTF-8
    NLOHMANN_VIEW_NOINLINE static void invalid_utf8(const unsigned char* s, std::size_t n)
    {
        const string_t dumped = BasicJsonType(string_t(reinterpret_cast<const char*>(s), n)).dump(); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        static_cast<void>(dumped);
    }

    template<bool EnsureAscii>
    void write_codepoint(std::uint32_t codepoint, const unsigned char* bytes, std::size_t len)
    {
        switch (codepoint)
        {
            case 0x08:
                m_out.put("\\b", 2);
                return;
            case 0x09:
                m_out.put("\\t", 2);
                return;
            case 0x0A:
                m_out.put("\\n", 2);
                return;
            case 0x0C:
                m_out.put("\\f", 2);
                return;
            case 0x0D:
                m_out.put("\\r", 2);
                return;
            case 0x22:
                m_out.put("\\\"", 2);
                return;
            case 0x5C:
                m_out.put("\\\\", 2);
                return;
            default:
                break;
        }
        if (codepoint <= 0x1F || (EnsureAscii && codepoint >= 0x7F))
        {
            if (codepoint <= 0xFFFF)
            {
                write_u_escape(codepoint);
            }
            else
            {
                write_u_escape(0xD7C0u + (codepoint >> 10u));
                write_u_escape(0xDC00u + (codepoint & 0x3FFu));
            }
            return;
        }
        m_out.put(reinterpret_cast<const char*>(bytes), len); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast) LCOV_EXCL_LINE (printable characters are copied in runs)
    }

    void write_u_escape(std::uint32_t u)
    {
        static constexpr const char* hex = "0123456789abcdef";
        const std::array<char, 6> e = {{'\\', 'u', hex[(u >> 12u) & 0xFu], hex[(u >> 8u) & 0xFu], hex[(u >> 4u) & 0xFu], hex[u & 0xFu]}};
        m_out.put(e.data(), e.size());
    }

    const document_data& m_doc;
    output_buffer<string_t> m_out;
    const dump_style m_style;
};

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
            return static_cast<T>(float_value<typename BasicJsonType::number_float_t>(d, n));
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

template<typename BasicJsonType, bool Editable>
class basic_json_document;

/*!
@brief read-only handle to one value of a basic_json_document

Trivially copyable (two pointers). Valid as long as the document is alive and
has not been re-parsed, and as long as a borrowed source text is alive.
*/
template<typename BasicJsonType, bool Editable = false>
class basic_json_view
{
    using node = detail::view::node;
    using document_data = detail::view::document_data;
    /// how the index is walked (with edits only for editable documents)
    using navigation = detail::view::navigation<Editable>;

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
        return idx < m_node->len ? basic_json_view(m_doc, navigation::value(detail::view::element_at<Editable>(*m_doc, m_node, idx))) : basic_json_view();
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
        return basic_json_view(m_doc, navigation::value(detail::view::element_at<Editable>(*m_doc, m_node, idx)));
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
            return basic_json_view(m_doc, navigation::value(detail::view::last_child<Editable>(*m_doc, m_node) + (is_object() ? 1 : 0)));
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
        const node* const k = detail::view::find_member<Editable>(*m_doc, m_node, key.data(), key.size());
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
        return is_object() && detail::view::find_member<Editable>(*m_doc, m_node, key.data(), key.size()) != nullptr;
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
            return iterator(m_doc, navigation::first(*m_doc, m_node), is_object());
        }
        return iterator(m_doc, m_node, false);
    }

    NLOHMANN_VIEW_ALWAYS_INLINE iterator end() const noexcept
    {
        if (NLOHMANN_VIEW_LIKELY(is_structured()))
        {
            return iterator(m_doc, navigation::end(*m_doc, m_node), is_object());
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

    ///////////////////
    // serialization //
    ///////////////////

    /// how dump() writes numbers
    enum class number_format
    {
        /// as basic_json::dump(): integers canonically, floats with the
        /// library's shortest round-trip digits ("1.5", "100.0", "1e+100")
        shortest,
        /// the number text of the source as it is ("1.50", "1E2", "-0", all
        /// digits of a long integer)
        source,
    };

    /// the text of this value; with number_format::shortest, the output of
    /// ordered_json::parse(text).dump() with the same arguments (members in
    /// document order, all of them should a key occur more than once)
    string_t dump(const int indent = -1, const char indent_char = ' ', const bool ensure_ascii = false,
                  const number_format numbers = number_format::shortest) const
    {
        string_t out;
        if (m_node == nullptr)
        {
            out = "<discarded>"; // as basic_json::dump() of a discarded value
            return out;
        }
        detail::view::dump_style style;
        style.pretty = indent >= 0;
        style.indent = indent >= 0 ? static_cast<std::size_t>(indent) : 0;
        style.indent_char = indent_char;
        style.ensure_ascii = ensure_ascii;
        style.source_numbers = numbers == number_format::source;
        // the compact text is about as long as the source text of the value;
        // the compact writer keeps 64 bytes of slack, so that it does not grow
        // the buffer just before the end
        const std::size_t estimate = source_extent() + (style.pretty ? source_extent() / 2 : 0) + 160;
        detail::view::view_serializer<BasicJsonType, Editable>(*m_doc, out, estimate, style).dump(m_node);
        return out;
    }

#ifndef JSON_NO_IO
    /// as operator<< of basic_json: a stream width > 0 is the indentation,
    /// the fill character the indentation character
    friend std::ostream& operator<<(std::ostream& o, const basic_json_view& v)
    {
        const bool pretty = o.width() > 0;
        const auto indentation = pretty ? o.width() : 0;
        o.width(0);
        const string_t s = v.dump(pretty ? static_cast<int>(indentation) : -1, o.fill());
        return o.write(s.data(), static_cast<std::streamsize>(s.size()));
    }
#endif

    ////////////////
    // comparison //
    ////////////////

    /// whether the values parse() would produce for two views are equal, as
    /// by BasicJsonType's operator== (numbers by value, objects by their
    /// members with duplicate keys resolved as parse() resolves them)
    friend bool operator==(const basic_json_view& a, const basic_json_view& b)
    {
        return detail::view::equal<BasicJsonType>(side(a), side(b));
    }

    friend bool operator!=(const basic_json_view& a, const basic_json_view& b)
    {
        return !(a == b);
    }

    /// a view of an editable document compares with one of a read-only document
    template < bool E, typename std::enable_if < E != Editable, int >::type = 0 >
    friend bool operator==(const basic_json_view& a, const basic_json_view<BasicJsonType, E>& b)
    {
        return detail::view::equal<BasicJsonType>(side(a), detail::view::view_side<BasicJsonType, basic_json_view<BasicJsonType, E>>(b));
    }

    template < bool E, typename std::enable_if < E != Editable, int >::type = 0 >
    friend bool operator!=(const basic_json_view& a, const basic_json_view<BasicJsonType, E>& b)
    {
        return !(a == b);
    }

    /// whether the value parse() would produce for a view equals a value
    friend bool operator==(const basic_json_view& a, const BasicJsonType& j)
    {
        return detail::view::equal<BasicJsonType>(side(a), json_side_t(j));
    }

    friend bool operator==(const BasicJsonType& j, const basic_json_view& a)
    {
        return a == j;
    }

    friend bool operator!=(const basic_json_view& a, const BasicJsonType& j)
    {
        return !(a == j);
    }

    friend bool operator!=(const BasicJsonType& j, const basic_json_view& a)
    {
        return !(a == j);
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
        return detail::view::materialize<BasicJsonType, Editable>(*m_doc, m_node);
    }

    /// byte offset of this value in the source text (for strings: of the
    /// first byte after the opening quote); static_cast<std::size_t>(-1) for
    /// a discarded view and for strings with escapes, which are decoded
    std::size_t source_offset() const noexcept
    {
        return m_node != nullptr && (m_node->flags & (detail::view::node_flags::storage | detail::view::node_flags::moved | detail::view::node_flags::is_new)) == 0
               ? m_node->off : static_cast<std::size_t>(-1);
    }

  private:
    template<typename, bool> friend class basic_json_document;
    template<typename, bool> friend class basic_json_view;
    template<typename, typename> friend class detail::view::editor;
    friend iterator;

    basic_json_view(const document_data* d, const node* n) noexcept
        : m_doc(d), m_node(n)
    {}

    using json_side_t = detail::view::json_side<BasicJsonType, string_view_t>;

    static detail::view::view_side<BasicJsonType, basic_json_view> side(const basic_json_view& v) noexcept
    {
        return detail::view::view_side<BasicJsonType, basic_json_view>(v);
    }

    /// the number of source bytes of this value (estimated for values with
    /// decoded strings)
    std::size_t source_extent() const noexcept
    {
        if (Editable && m_doc->edits != nullptr)
        {
            // positions of moved and new values are not source offsets
            return m_node == m_doc->tape ? m_doc->size + m_doc->edits->text_used : 64;
        }
        const node* const next = document_data::after(m_node);
        const bool in_source = (m_node->flags & detail::view::node_flags::storage) == 0;
        if (!in_source)
        {
            return m_node->len;
        }
        if (next != m_doc->tape + m_doc->tape_size && (next->flags & detail::view::node_flags::storage) == 0 && next->off >= m_node->off)
        {
            return next->off - m_node->off;
        }
        return m_doc->size - m_node->off;
    }

    /// the value of the first member with this key, or a discarded view
    /// (object required)
    NLOHMANN_VIEW_ALWAYS_INLINE basic_json_view lookup(string_view_t key) const noexcept
    {
        const node* const k = detail::view::find_member<Editable>(*m_doc, m_node, key.data(), key.size());
        return k != nullptr ? basic_json_view(m_doc, navigation::value(k + 1)) : basic_json_view();
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
template<typename BasicJsonType, bool Editable = false>
class basic_json_document
{
    using document_data = detail::view::document_data;

    static_assert(sizeof(typename BasicJsonType::number_integer_t) == 8 && sizeof(typename BasicJsonType::number_unsigned_t) == 8,
                  "json_view supports 64-bit integer types only");

  public:
    using view_type = basic_json_view<BasicJsonType, Editable>;
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
        return m_data && ((!m_data->owned.empty() && m_data->src == m_data->owned.data()) || !m_data->owned_image.empty());
    }

    /// number of index nodes (values plus object keys)
    std::size_t node_count() const noexcept
    {
        return m_data ? m_data->tape_size : 0;
    }

    /// bytes held by the document (index, decoded strings, owned text or image)
    std::size_t memory_usage() const noexcept
    {
        if (!m_data)
        {
            return 0;
        }
        return sizeof(document_data) + (m_data->inline_cap * sizeof(detail::view::node))
               + (m_data->tape != m_data->inline_tape ? m_data->tape_cap * sizeof(detail::view::node) : 0)
               + m_data->arena.capacity() + m_data->owned.capacity() + m_data->owned_image.capacity()
               + (m_data->indexes.capacity() * sizeof(document_data::object_index)) + (m_data->index_slots.capacity() * sizeof(std::uint32_t))
               + (m_data->large_objects.capacity() * sizeof(std::uint32_t))
               + (m_data->edits != nullptr ? m_data->edits->bytes : 0);
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
        // (the decoded strings of a loaded image stay in the image)
        const bool arena_in_use = d.base[1] == d.arena.data();
        const bool shrink_arena = d.arena.capacity() > d.arena.size();
        std::string arena(shrink_arena && arena_in_use ? d.arena : std::string());
        // (edits link to the nodes of the index, which then stays in place)
        const bool shrink_tape = d.tape != d.inline_tape && d.tape_size != d.tape_cap && d.edits == nullptr;
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
            if (arena_in_use)
            {
                d.base[1] = d.arena.data();
            }
        }
    }

    ////////////
    // images //
    ////////////

    /// how load() checks an image (full, bounds, or none)
    using image_check = detail::view::image_check;

    /// The document as an image that load() reads without parsing: the node
    /// index, the text, and the decoded strings. An edited document is
    /// written in its current state (floats that are not finite become null,
    /// as in dump()).
    std::vector<std::uint8_t> save() const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!m_data || m_data->discarded))
        {
            detail::view::throw_type_error(320, "cannot save a discarded json_document");
        }
        return detail::view::save_image(*m_data);
    }

    /// Read an image written by save(). The image is borrowed: it must stay
    /// alive and unchanged while the document is used.
    NLOHMANN_VIEW_NODISCARD
    static basic_json_document load(const std::uint8_t* image, std::size_t size, const image_check check = image_check::full)
    {
        basic_json_document d;
        d.ensure_data(nullptr, 0);
        detail::view::load_image(*d.m_data, image, size, check);
        return d;
    }

    /// read an image (borrowed)
    NLOHMANN_VIEW_NODISCARD
    static basic_json_document load(const std::vector<std::uint8_t>& image, const image_check check = image_check::full)
    {
        return load(image.data(), image.size(), check);
    }

    /// read an image and keep it (no copy)
    NLOHMANN_VIEW_NODISCARD
    static basic_json_document load(std::vector<std::uint8_t>&& image, const image_check check = image_check::full)
    {
        basic_json_document d;
        d.ensure_data(nullptr, 0);
        d.m_data->owned_image = std::move(image);
        detail::view::load_image(*d.m_data, d.m_data->owned_image.data(), d.m_data->owned_image.size(), check);
        return d;
    }

    ///////////
    // edits //
    ///////////

    // The source text is never written; new values go to storage owned by
    // the document. A view keeps referring to the same value: after an
    // assignment it sees the new value, and edits elsewhere do not affect it.
    // A view of an erased value keeps its last value. An edit of an
    // array/object invalidates the iterators over it. Values are accepted as
    // views (of any document), BasicJsonType values, and everything
    // BasicJsonType can be constructed from.

    using string_view_t = typename view_type::string_view_t;
    using json_pointer = typename BasicJsonType::json_pointer;

    /// replace a value (a view of this document); returns a view of it
    template<typename V>
    view_type set(view_type target, V&& value)
    {
        return editor().set(target, std::forward<V>(value));
    }

    /// set a member (added if missing; a null value becomes an object);
    /// returns a view of the member value
    template<typename V>
    view_type set(view_type object, string_view_t key, V&& value)
    {
        return editor().set(object, key, std::forward<V>(value));
    }

    /// assign an existing array element; returns a view of it
    template < typename I, typename V, typename std::enable_if < std::is_integral<I>::value && !std::is_same<I, bool>::value, int >::type = 0 >
    view_type set(view_type array, I idx, V && value)
    {
        return editor().set(array, index(idx), std::forward<V>(value));
    }

    /// set the value at a JSON pointer: its parent must exist; an object
    /// member is set (added if missing), an array element assigned, and "-"
    /// or the size of the array appends
    template<typename V>
    view_type set(const json_pointer& ptr, V&& value)
    {
        if (ptr.empty())
        {
            return set(root(), std::forward<V>(value));
        }
        const view_type parent = root().at(ptr.parent_pointer());
        const auto& token = ptr.back();
        if (parent.is_array())
        {
            const std::size_t idx = token == "-" ? parent.size() : pointer_index(token);
            if (idx == parent.size())
            {
                return push_back(parent, std::forward<V>(value));
            }
            return set(parent, idx, std::forward<V>(value));
        }
        return set(parent, string_view_t(token.data(), token.size()), std::forward<V>(value));
    }

    /// append to an array (a null value becomes an array); returns a view of
    /// the new element
    template<typename V>
    view_type push_back(view_type array, V&& value)
    {
        return editor().push_back(array, std::forward<V>(value));
    }

    /// insert into an array before position idx (idx <= size()); returns a
    /// view of the new element
    template < typename I, typename V, typename std::enable_if < std::is_integral<I>::value && !std::is_same<I, bool>::value, int >::type = 0 >
    view_type insert(view_type array, I idx, V && value)
    {
        return editor().insert(array, index(idx), std::forward<V>(value));
    }

    /// remove all members with this key; returns their number
    std::size_t erase(view_type object, string_view_t key)
    {
        return editor().erase(object, key);
    }

    /// remove an array element
    template < typename I, typename std::enable_if < std::is_integral<I>::value && !std::is_same<I, bool>::value, int >::type = 0 >
    void erase(view_type array, I idx)
    {
        editor().erase(array, index(idx));
    }

    /// remove the value at a JSON pointer; returns the number of removed
    /// values
    std::size_t erase(const json_pointer& ptr)
    {
        if (ptr.empty())
        {
            detail::view::throw_out_of_range(405, "JSON pointer has no parent");
        }
        const view_type parent = root().at(ptr.parent_pointer());
        const auto& token = ptr.back();
        if (parent.is_array())
        {
            erase(parent, pointer_index(token));
            return 1;
        }
        return erase(parent, string_view_t(token.data(), token.size()));
    }

  private:
    using input_kind = detail::view::input_kind;

    detail::view::editor<BasicJsonType, view_type> editor()
    {
        static_assert(Editable, "only an editable document can be edited: use basic_json_document<BasicJsonType, true> (json_editable_document)");
        if (NLOHMANN_VIEW_UNLIKELY(!m_data || m_data->discarded))
        {
            detail::view::throw_invalid_iterator(202, "view does not belong to this document");
        }
        return detail::view::editor<BasicJsonType, view_type>(*m_data);
    }

    /// an index (out_of_range.401 if negative)
    template<typename I>
    static std::size_t index(I idx)
    {
        return index(idx, std::is_signed<I> {});
    }

    template<typename I>
    static std::size_t index(I idx, std::true_type /*signed*/)
    {
        if (idx < 0)
        {
            detail::view::throw_out_of_range(401, detail::concat("array index ", std::to_string(idx), " is out of range"));
        }
        return static_cast<std::size_t>(idx);
    }

    template<typename I>
    static std::size_t index(I idx, std::false_type /*unsigned*/)
    {
        return static_cast<std::size_t>(idx);
    }

    /// the array index of a JSON pointer token (json_pointer's rules)
    template<typename StringType>
    static std::size_t pointer_index(const StringType& token)
    {
        std::size_t idx = 0;
        const detail::view::index_status status = detail::view::array_index(token, idx);
        if (status != detail::view::index_status::ok)
        {
            detail::view::throw_array_index_error(status, token);
        }
        return idx;
    }

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
        d.owned_image.clear();
        d.src = src;
        d.size = size;
        d.tape_size = 0;
        d.edits.reset(); // (views of the previous text end here anyway)
        d.base[2] = nullptr;
        d.arena.clear();
        d.indexes.clear();
        d.index_slots.clear();
        d.large_objects.clear();
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
            d.arena_size = d.arena.size();
            detail::view::build_object_indexes(d);
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
/// an editable parsed JSON text for json
using json_editable_document = basic_json_document<json, true>;
/// a value of a json_editable_document
using json_editable_view = basic_json_view<json, true>;
/// an editable parsed JSON text for ordered_json
using ordered_json_editable_document = basic_json_document<ordered_json, true>;
/// a value of an ordered_json_editable_document
using ordered_json_editable_view = basic_json_view<ordered_json, true>;

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
#undef NLOHMANN_VIEW_NEON
#undef NLOHMANN_VIEW_SSE2
#undef NLOHMANN_VIEW_SSSE3
#undef NLOHMANN_VIEW_SSSE3_DISPATCH
#undef NLOHMANN_VIEW_SSSE3_TARGET
#undef NLOHMANN_VIEW_VECTOR
#undef NLOHMANN_VIEW_VECTOR_UTF8


#endif  // INCLUDE_NLOHMANN_JSON_VIEW_HPP_
