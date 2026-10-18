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
 * The source text must outlive a document that borrows it (lvalue byte      *
 * containers, C strings); rvalue strings, streams, and other inputs are     *
 * owned by the document.                                                    *
\****************************************************************************/

#ifndef INCLUDE_NLOHMANN_JSON_VIEW_HPP_
#define INCLUDE_NLOHMANN_JSON_VIEW_HPP_

#include <algorithm> // min
#include <array> // array
#include <cstddef> // nullptr_t, size_t // IWYU pragma: keep
#include <cstdint> // uint32_t
#include <cstring> // memcpy, strlen
#include <istream> // istream // IWYU pragma: keep
#include <iterator> // distance, input_iterator_tag, iterator_traits
#include <map> // map
#include <memory> // unique_ptr
#ifndef JSON_NO_IO
    #include <ostream> // ostream // IWYU pragma: keep
#endif
#include <string> // string
#include <tuple> // tuple_element, tuple_size // IWYU pragma: keep
#include <type_traits> // decay, enable_if, integral_constant, is_arithmetic, is_base_of, is_integral, is_same, remove_cv, remove_extent
#include <unordered_map> // unordered_map
#include <utility> // forward, move
#include <vector> // vector

#include <nlohmann/json.hpp> // IWYU pragma: export

// json.hpp provides the library's types and macros used below (it includes
// the headers that define them); json_view.hpp must not include them again,
// because the amalgamated json_view.hpp only includes json.hpp
// IWYU pragma: no_include <version>
// IWYU pragma: no_include "nlohmann/detail/abi_config.hpp"
// IWYU pragma: no_include "nlohmann/detail/abi_macros.hpp"
// IWYU pragma: no_include "nlohmann/detail/input/input_adapters.hpp"
// IWYU pragma: no_include "nlohmann/detail/json_pointer.hpp"
// IWYU pragma: no_include "nlohmann/detail/meta/cpp_future.hpp"
// IWYU pragma: no_include "nlohmann/detail/string_concat.hpp"
// IWYU pragma: no_include "nlohmann/detail/value_t.hpp"
// IWYU pragma: no_include "nlohmann/json.hpp"
// IWYU pragma: no_include "nlohmann/json_fwd.hpp"

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



#include <algorithm> // find, find_if, max, min
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
#include <cstdint> // uint32_t
#include <cstring> // memcmp, memcpy
#include <limits> // numeric_limits
#include <new> // bad_alloc, operator new, placement new
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
    // plain inline: __forceinline makes MSVC report C4714 (not inlined) for
    // function templates it cannot inline, which is an error under /WX; the
    // forced inlining is only a performance hint
    #define NLOHMANN_VIEW_ALWAYS_INLINE inline
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

/// eight checks at fixed offsets 0..7
#define NLOHMANN_VIEW_REPEAT_FIRST_8(X) X(0) X(1) X(2) X(3) X(4) X(5) X(6) X(7)

/// eight checks at fixed offsets 8..15
#define NLOHMANN_VIEW_REPEAT_SECOND_8(X) X(8) X(9) X(10) X(11) X(12) X(13) X(14) X(15)

/// sixteen checks at fixed offsets 0..15
#define NLOHMANN_VIEW_REPEAT16(X) NLOHMANN_VIEW_REPEAT_FIRST_8(X) NLOHMANN_VIEW_REPEAT_SECOND_8(X)

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

/// The largest input a document accepts, in bytes. Offsets and node counts are
/// 32 bits wide; the limit keeps 16 bytes (the width of the scanner's steps)
/// below 2^32, so that a position one step past the end of the text fits.
constexpr std::size_t max_input_size() noexcept
{
    return 0xFFFFFFEFu;
}

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
    std::uint16_t extra; ///< numbers: integer digits (low byte) and fraction digits (high byte), 255 = "many"; objects: number of the object's key hash index (1-based, 0 = none); otherwise 0
    std::uint32_t off;   ///< source offset (string content, number token, literal, bracket); arena offset if node_flags::escaped
    std::uint32_t len;   ///< string: decoded bytes; float: token bytes; array/object: element count
    std::uint32_t next;  ///< array/object: number of nodes of the subtree (its extent in the enclosing sequence)
};
static_assert(sizeof(node) == 16, "node must stay 16 bytes");

// the node kinds are value_t values; the test below (object and array are 1
// and 2) and those of the number kinds depend on this numbering
static_assert(static_cast<std::uint8_t>(value_t::null) == 0 && static_cast<std::uint8_t>(value_t::object) == 1
              && static_cast<std::uint8_t>(value_t::array) == 2 && static_cast<std::uint8_t>(value_t::string) == 3
              && static_cast<std::uint8_t>(value_t::boolean) == 4 && static_cast<std::uint8_t>(value_t::number_integer) == 5
              && static_cast<std::uint8_t>(value_t::number_unsigned) == 6 && static_cast<std::uint8_t>(value_t::number_float) == 7,
              "the node format depends on the numbering of value_t");

NLOHMANN_VIEW_ALWAYS_INLINE bool is_container(const node& n) noexcept
{
    return static_cast<unsigned>(n.kind) - 1u <= 1u;
}

/// the converted value of an integer node: len is its low half, next its high
/// half (on little-endian targets the two words are the value in memory)
NLOHMANN_VIEW_ALWAYS_INLINE std::uint64_t integer_bits(const node& n) noexcept
{
#if NLOHMANN_VIEW_LITTLE_ENDIAN
    std::uint64_t v = 0;
    std::memcpy(&v, reinterpret_cast<const unsigned char*>(&n) + 8, 8); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    return v;
#else
    return static_cast<std::uint64_t>(n.len) | (static_cast<std::uint64_t>(n.next) << 32);
#endif
}

NLOHMANN_VIEW_ALWAYS_INLINE void set_integer_bits(node& n, std::uint64_t v) noexcept
{
#if NLOHMANN_VIEW_LITTLE_ENDIAN
    std::memcpy(reinterpret_cast<unsigned char*>(&n) + 8, &v, 8); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
#else
    n.len = static_cast<std::uint32_t>(v);
    n.next = static_cast<std::uint32_t>(v >> 32);
#endif
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
    node* nodes = nullptr; ///< the node index (see node.hpp)
    std::size_t node_count = 0;
    std::size_t node_capacity = 0;
    node* inline_nodes = nullptr; ///< node array allocated together with this header
    std::size_t inline_capacity = 0;
    std::size_t max_depth = 0; ///< deepest nesting of arrays and objects (the root container is depth 1)
    std::vector<char> arena; ///< decoded strings that contained escapes (no terminator: they are handed out with their length)
    std::string owned; ///< owned copy of the input, if any (a std::string, so that its NUL serves as the parser's sentinel)

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
    std::array<const char*, 4> base = {{nullptr, nullptr, nullptr, nullptr}}; ///< string bases: source, arena (indexed by flags & node_flags::storage)
    bool discarded = true;

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
        , indexes() // NOLINT(readability-redundant-member-init)
        , index_slots() // NOLINT(readability-redundant-member-init)
        , large_objects() // NOLINT(readability-redundant-member-init)
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
// NLOHMANN_VIEW_NO_TARGET_ATTRIBUTE (set by the GCC module interface, where GCC
// ignores the target attribute and then rejects the SSSE3 intrinsics) keeps the
// check portable without disabling the SSE2 code.
#if !defined(JSON_VIEW_NO_SIMD) && defined(__aarch64__) && (defined(__GNUC__) || defined(__clang__)) && NLOHMANN_VIEW_LITTLE_ENDIAN
    #include <arm_neon.h>
    #define NLOHMANN_VIEW_NEON 1
#else
    #define NLOHMANN_VIEW_NEON 0
#endif
// (x86 only: other targets can define __SSE2__ as well, e.g., WebAssembly with -msse2, but have no <cpuid.h>)
#if !defined(JSON_VIEW_NO_SIMD) && !NLOHMANN_VIEW_NEON && (defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)) && (defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2))
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
#if NLOHMANN_VIEW_SSE2 && !NLOHMANN_VIEW_SSSE3 && !defined(NLOHMANN_VIEW_NO_TARGET_ATTRIBUTE) && ((defined(__clang__) && __clang_major__ >= 4) || (defined(__GNUC__) && !defined(__clang__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9))))
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
        const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(p))); // NOLINT(bugprone-casting-through-void)
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
    const __m128i t1h = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_1_high.data()))); // NOLINT(bugprone-casting-through-void)
    const __m128i t1l = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_1_low.data()))); // NOLINT(bugprone-casting-through-void)
    const __m128i t2h = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(lookup::byte_2_high.data()))); // NOLINT(bugprone-casting-through-void)
    const __m128i nibble = _mm_set1_epi8(0x0F);
    const __m128i zero = _mm_setzero_si128();
    __m128i prev = zero;
    while (e - block >= 16)
    {
        const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(block))); // NOLINT(bugprone-casting-through-void)
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
            const auto k = static_cast<unsigned>(count_trailing_zeros(static_cast<std::uint64_t>(special_bits)));
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
            NLOHMANN_VIEW_REPEAT_FIRST_8(NLOHMANN_VIEW_STEP)
#if NLOHMANN_VIEW_VECTOR
            if (!Value) // (a plain `!Value || !NLOHMANN_VIEW_VECTOR` is a constant condition for MSVC, C4127)
#endif
            {
                NLOHMANN_VIEW_REPEAT_SECOND_8(NLOHMANN_VIEW_STEP)
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
            1u,
            10u,
            100u,
            1000u,
            10000u,
            100000u,
            1000000u,
            10000000u,
            100000000u,
            1000000000u,
            10000000000u,
            100000000000u,
            1000000000000u,
            10000000000000u,
            100000000000000u,
            1000000000000000u,
            10000000000000000u,
            100000000000000000u,
            1000000000000000000u,
            10000000000000000000u
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
        : m_doc(d)
        , m_begin(reinterpret_cast<const unsigned char*>(src))
        , m_end(m_begin + size)
        , m_shallow()
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

    /// 64 frames, left uninitialized: they are filled as containers open (the
    /// user-provided constructor keeps the member initialization, which
    /// -Weffc++ asks for, from zeroing them; that costs up to 30 % on small
    /// documents)
    struct frame_stack : std::array<frame, 64>
    {
        frame_stack() noexcept {} // NOLINT(modernize-use-equals-default,hicpp-use-equals-default,cppcoreguidelines-pro-type-member-init,hicpp-member-init): see above
    };

    document_data& m_doc;
    const unsigned char* const m_begin;
    const unsigned char* const m_end;
    parse_failure m_failure{};

    // the open array/object is in the cursor; enclosing ones on a stack that is
    // inline for the first 64 levels
    frame_stack m_shallow;
    std::vector<frame> m_deep{};

    /// remember an object to index after parsing (out of line, so that the
    /// parse loop only has a call for it)
    NLOHMANN_VIEW_NOINLINE void note_large_object(std::uint32_t idx)
    {
        m_doc.large_objects.push_back(idx);
    }

    NLOHMANN_VIEW_NOINLINE bool fail(error_code c, const unsigned char* at) noexcept
    {
        m_failure.code = c;
        m_failure.offset = static_cast<std::size_t>(at - m_begin);
        m_doc.node_count = 0;
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
        if (m_end - p < 2)
        {
            ++p;
            return fail_at(error_code::comment_start, p);
        }
        if (p[1] == '/')
        {
            p += 2;
            // (as in parse(), a null byte is the end of the input, so it is
            // left for the caller to see)
            while (p != m_end && *p != '\n' && *p != '\r' && !(NulIsEnd && *p == 0))
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
                if (p == m_end || (NulIsEnd && *p == 0))
                {
                    return fail_at(error_code::comment_unterminated, p);
                }
                if (*p == '*' && p + 1 != m_end && p[1] == '/')
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
        // (n nodes are written; at the limit there is no room for another one)
        const std::uint64_t limit = document_data::max_nodes();
        // LCOV_EXCL_START (a node array that fills the address space)
        if (NLOHMANN_VIEW_UNLIKELY(n >= limit))
        {
            document_data::throw_bad_alloc();
        }
        // LCOV_EXCL_STOP
        const std::uint64_t done = static_cast<std::uint64_t>(at - m_begin) + 1;
        const std::uint64_t guess = static_cast<std::uint64_t>(n) * static_cast<std::uint64_t>(m_end - m_begin + 1) / done;
        const std::uint64_t grown = guess + (guess / 4) + 64; // a variable: GCC calls a cast of the sum useless where std::uint64_t is std::size_t
        // (n is below 2^32: the input is smaller than 4 GiB; the sum cannot wrap)
        const std::uint64_t wanted = (std::max)(grown, static_cast<std::uint64_t>(n) + (n / 2) + 64);
        m_doc.node_count = n; // the number of nodes reserve() copies into the new array
        // (a count beyond the limit is cut: the index does not grow beyond what can be addressed)
        m_doc.reserve(static_cast<std::size_t>((std::min)(wanted, limit)));
        return m_doc.nodes;
    }

    /// the four hex digits of a unicode escape at p as a code unit, and p
    /// moved past them; or -1, and p at the first bad digit (one table lookup
    /// per digit and a single check: the library's table, after yyjson's
    /// read_hex_u16)
    NLOHMANN_VIEW_ALWAYS_INLINE int hex4(const unsigned char*& p) noexcept
    {
        if (NLOHMANN_VIEW_LIKELY(m_end - p >= 4))
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
        if (m_end - p >= 4)
        {
            while (is_hex(*p))
            {
                ++p;
            }
        }
        return p;
    }

    /// s points to the start of the string, p to a backslash, a control
    /// character, an ill-formed UTF-8 byte, or the end: decode the string into
    /// the arena
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
            if (p == m_end)
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
                // (without JSON_STRICT_NUL_HANDLING, a NUL between values ends
                // the input, as in json::parse; inside a string, a NUL is still
                // a control character and an error)
                return failed(c < 0x20 ? error_code::string_control_character : error_code::string_utf8, p);
            }
            ++p;
            if (p == m_end)
            {
                return failed(error_code::string_missing_quote, p);
            }
            const unsigned char d = *p++;
            if (d == 'u')
            {
                int cp = hex4(p); // (moves p past the four digits)
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
                    if (m_end - p < 2 || p[0] != '\\' || p[1] != 'u')
                    {
                        return failed(error_code::string_surrogate_high, p);
                    }
                    p += 2;
                    const int lo = hex4(p); // (moves p past the four digits)
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
                arena_ensure(4);
                m_arena_write = put_utf8(m_arena_write, cp);
            }
            else if (NLOHMANN_VIEW_LIKELY(d < 128 && simple_escape[d] != 0))
            {
                arena_ensure(1);
                *m_arena_write++ = simple_escape[d];
            }
            else
            {
                --p;
                return failed(error_code::string_escape, p);
            }
            if (p != m_end && *p == '\\')
            {
                continue; // consecutive escapes ("\u00e4\u00f6"): no run in between
            }
            const unsigned char* const r = p;
            p = scan_string_run(p, m_end);
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

    /// do the `digits` digits of a magnitude at d exceed `limit`, the largest
    /// magnitude that fits (a string literal: N counts its terminating NUL, so
    /// it has N - 1 digits)?
    template<std::size_t N>
    static NLOHMANN_VIEW_ALWAYS_INLINE bool digits_exceed(const unsigned char* d, std::size_t digits, const char (&limit)[N]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays): a string literal
    {
        if (NLOHMANN_VIEW_LIKELY(digits < N - 1))
        {
            return false;
        }
        return digits > N - 1 || std::memcmp(d, limit, N - 1) > 0;
    }

    static bool is_hex(unsigned char c) noexcept
    {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f');
    }

    // decode arena: the vector in the document, written through a raw
    // pointer (resized ahead in large steps; trimmed when parsing succeeds)
    char* m_arena_write = nullptr;
    char* m_arena_end = nullptr;

    NLOHMANN_VIEW_ALWAYS_INLINE std::size_t arena_used() const noexcept
    {
        return m_arena_write != nullptr ? static_cast<std::size_t>(m_arena_write - m_doc.arena.data()) : 0;
    }

    NLOHMANN_VIEW_ALWAYS_INLINE void arena_ensure(std::size_t n)
    {
        if (NLOHMANN_VIEW_UNLIKELY(static_cast<std::size_t>(m_arena_end - m_arena_write) < n))
        {
            arena_grow(n);
        }
    }

    NLOHMANN_VIEW_NOINLINE void arena_grow(std::size_t n)
    {
        const std::size_t used = arena_used();
        m_doc.arena.resize((std::max)(m_doc.arena.size() * 2, used + n + 256));
        m_arena_write = m_doc.arena.data() + used;
        m_arena_end = m_doc.arena.data() + m_doc.arena.size();
    }

    /// append the run [r, r + n) to the arena; short runs as one fixed-size
    /// 16-byte move when both sides have the room (no library call)
    NLOHMANN_VIEW_ALWAYS_INLINE void arena_run(const unsigned char* r, std::size_t n)
    {
        if (n <= 16 && m_end - r >= 16)
        {
            arena_ensure(16);
            std::memcpy(m_arena_write, r, 16);
        }
        else if (n != 0)
        {
            // (an empty run leaves an empty arena unallocated, and memcpy()
            // must not be passed its null pointer even for zero bytes)
            arena_ensure(n);
            std::memcpy(m_arena_write, r, n);
        }
        m_arena_write += n;
    }

    /// UTF-8 encoding of cp at w (room for 4 bytes); returns the position after
    /// it. (A returned pointer stays in a register; writing through a
    /// reference to m_arena_write would store and reload it around every byte.)
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
            , b(owner.m_begin)
            , p(owner.m_begin)
            , e(owner.m_end)
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
        std::size_t max_depth = 0;

        NLOHMANN_VIEW_ALWAYS_INLINE bool run()
        {
            cold.m_doc.reserve(estimate_nodes(reinterpret_cast<const char*>(b), static_cast<std::size_t>(e - b)));
            base = cold.m_doc.nodes;
            out = base;
            cap = base + cold.m_doc.node_capacity;

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
            // value), and the continuation needs no branch on the container kind;
            // after a scalar, the switch is left to the label that follows it
#define NLOHMANN_VIEW_VALUE                                                         \
    switch (cur())                                                              \
    {                                                                           \
        case '"':                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!string<true>())) { return false; }      \
            break;                                                              \
        case '{':                                                               \
            open(value_t::object);                                              \
            ++p;                                                                \
            goto obj_first;                                                     \
        case '[':                                                               \
            open(value_t::array);                                               \
            ++p;                                                                \
            goto arr_first;                                                     \
        case '-':                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!number<true>())) { return false; }      \
            break;                                                              \
        case '0': case '1': case '2': case '3': case '4':                       \
        case '5': case '6': case '7': case '8': case '9':                       \
            if (NLOHMANN_VIEW_UNLIKELY(!number<false>())) { return false; }     \
            break;                                                              \
        case 't':                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!literal_true())) { return false; }      \
            break;                                                              \
        case 'f':                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!literal_false())) { return false; }     \
            break;                                                              \
        case 'n':                                                               \
            if (NLOHMANN_VIEW_UNLIKELY(!literal_null())) { return false; }      \
            break;                                                              \
        default:                                                                \
            return fail(error_code::unexpected_value);                          \
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
            NLOHMANN_VIEW_VALUE
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
            NLOHMANN_VIEW_VALUE
#undef NLOHMANN_VIEW_VALUE
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

close_object:
            // a large object gets a hash index for its keys (objects only, so that closing
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
            cold.m_doc.node_count = static_cast<std::size_t>(out - base);
            cold.m_doc.max_depth = max_depth;
            // (so that size() is the number of bytes used: the arena grows ahead
            // in large steps, and shrink_to_fit() keeps size() bytes)
            cold.m_doc.arena.resize(cold.arena_used());
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
                    return literal_true();
                case 'f':
                    return literal_false();
                case 'n':
                    return literal_null();
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

        NLOHMANN_VIEW_ALWAYS_INLINE bool literal_true()
        {
            return literal("true", value_t::boolean, node_flags::is_true);
        }

        NLOHMANN_VIEW_ALWAYS_INLINE bool literal_false()
        {
            return literal("false", value_t::boolean, 0);
        }

        NLOHMANN_VIEW_ALWAYS_INLINE bool literal_null()
        {
            return literal("null", value_t::null, 0);
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
        NLOHMANN_VIEW_ALWAYS_INLINE node* push_node(value_t k, std::uint8_t flags, std::uint16_t extra, std::size_t off, std::uint64_t second)
        {
            if (NLOHMANN_VIEW_UNLIKELY(out == cap))
            {
                const auto n = static_cast<std::size_t>(out - base);
                base = cold.grow(n, p);
                out = base + n;
                cap = base + cold.m_doc.node_capacity;
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
            // len is the low half of the second word, next the high half
            // (not a native word over both, which swaps them on big-endian)
            n->len = static_cast<std::uint32_t>(second);
            n->next = static_cast<std::uint32_t>(second >> 32);
#endif
            return n;
        }

        NLOHMANN_VIEW_ALWAYS_INLINE void open(value_t k)
        {
            // (base is read after push_node(), which moves the node array when it
            // grows; in one expression the order of the two is unspecified)
            const node* const n = push_node(k, 0, 0, static_cast<std::size_t>(p - b), 0);
            const auto idx = static_cast<std::uint32_t>(n - base);
            if (depth != 0)
            {
                if (NLOHMANN_VIEW_LIKELY(depth <= 64))
                {
                    // field by field: a frame put together on the stack and
                    // copied would be read back wider than it was written,
                    // and that load waits until the stores are done
                    frame& f = cold.m_shallow[depth - 1];
                    f.idx = cur_idx;
                    f.count = cur_count;
                    f.is_object = cur_is_object;
                }
                else
                {
                    cold.m_deep.push_back(frame{cur_idx, cur_count, cur_is_object});
                }
            }
            ++depth;
            max_depth = (std::max)(max_depth, depth);
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
                    const frame& f = cold.m_shallow[depth - 1];
                    cur_idx = f.idx;
                    cur_count = f.count;
                    cur_is_object = f.is_object;
                }
                else
                {
                    const frame f = cold.m_deep.back();
                    cold.m_deep.pop_back();
                    cur_idx = f.idx;
                    cur_count = f.count;
                    cur_is_object = f.is_object;
                }
            }
        }

        /// the literal `text` at p (N counts the terminating NUL)
        template<std::size_t N>
        NLOHMANN_VIEW_ALWAYS_INLINE bool literal(const char (&text)[N], value_t k, std::uint8_t flags) // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays): a string literal
        {
            const std::size_t n = N - 1;
            if (NLOHMANN_VIEW_UNLIKELY(e - p < static_cast<std::ptrdiff_t>(n) || std::memcmp(p, text, n) != 0))
            {
                return fail(error_code::invalid_literal);
            }
            push_node(k, flags, 0, static_cast<std::size_t>(p - b), n);
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
                // integers that do not fit become floats, as in parse()
                if (negative)
                {
                    kind = digits_exceed(int_start, int_digits, "9223372036854775808") ? value_t::number_float : value_t::number_integer;
                }
                else
                {
                    kind = digits_exceed(int_start, int_digits, "18446744073709551615") ? value_t::number_float : value_t::number_unsigned;
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
                // (0 - m rather than -m: unary minus on an unsigned type is
                // MSVC's C4146, an error under /sdl; both give the bit pattern
                // of the negative std::int64_t)
                second = negative ? 0 - m : m;
            }
            push_node(kind, 0, layout, static_cast<std::size_t>(s - b), second);
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
                push_node(value_t::string, 0, 0, static_cast<std::size_t>(s - b), static_cast<std::uint64_t>(p - s));
                ++p;
                return true;
            }
            const decoded r = cold.slow_string(s, p);
            if (r.p == nullptr)
            {
                return false;
            }
            p = r.p;
            push_node(value_t::string, node_flags::escaped, 0, r.start, r.len);
            return true;
        }
    };
};

/// run the builder with compile-time options
template<typename FloatType, bool Comments, bool TrailingCommas, bool NulIsEnd>
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
        return trailing_commas ? build_with<FloatType, true, true, NulIsEnd>(d, src, size, sentinel, failure)
               : build_with<FloatType, true, false, NulIsEnd>(d, src, size, sentinel, failure);
    }
    return trailing_commas ? build_with<FloatType, false, true, NulIsEnd>(d, src, size, sentinel, failure)
           : build_with<FloatType, false, false, NulIsEnd>(d, src, size, sentinel, failure);
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
            if (ta != tb && !(is_number(ta) && is_number(tb))) // numbers of different types can be equal
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
            else if (a.scalar() != b.scalar()) // numbers (also of different types), null, boolean
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
                stack.pop_back(); // (f dangles now, and is bound again after continue)
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

/// SAX handler of the error replay: accepts every event without storing it,
/// and throws the exception the parser reports
template<typename BasicJsonType>
struct throwing_sax
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using binary_t = typename BasicJsonType::binary_t;

    bool null()
    {
        return true;
    }

    bool boolean(bool /*unused*/)
    {
        return true;
    }

    bool number_integer(number_integer_t /*unused*/)
    {
        return true;
    }

    bool number_unsigned(number_unsigned_t /*unused*/)
    {
        return true;
    }

    bool number_float(number_float_t /*unused*/, const string_t& /*unused*/)
    {
        return true;
    }

    bool string(string_t& /*unused*/)
    {
        return true;
    }

    bool binary(binary_t& /*unused*/)
    {
        return true;
    }

    bool start_object(std::size_t /*unused*/)
    {
        return true;
    }

    bool key(string_t& /*unused*/)
    {
        return true;
    }

    bool end_object()
    {
        return true;
    }

    bool start_array(std::size_t /*unused*/)
    {
        return true;
    }

    bool end_array()
    {
        return true;
    }

    /// (a template, as in json_sax_dom_parser: the parser passes the concrete
    /// exception type, which is thrown as is)
    template<class Exception>
    [[noreturn]] bool parse_error(std::size_t /*unused*/, const std::string& /*unused*/, const Exception& ex)
    {
        NLOHMANN_VIEW_THROW(ex);
    }
};

/*!
@brief throw the exception BasicJsonType::parse would throw for this input

The view accepts exactly the inputs parse() accepts, so on a failure the
library parser is run on the same bytes: it throws the exception parse() would
throw, with the same message, position, and "last read" token. The replay
uses a SAX handler that stores nothing, so it only lexes and parses up to the
error, without building values. The error path is cold, so this costs nothing
on valid input. Should parse() accept the input nevertheless (a bug), the
view's own failure is reported.
*/
template<typename BasicJsonType>
[[noreturn]] NLOHMANN_VIEW_NOINLINE void throw_parse_failure(const parse_failure& f, const char* src, std::size_t size,
        bool ignore_comments, bool ignore_trailing_commas)
{
    if (f.code == error_code::input_too_large)
    {
        // (the limit is detail::view::max_input_size(): 4 GiB minus 16 bytes)
        NLOHMANN_VIEW_THROW(out_of_range::create(416, "input of 4294967280 bytes or more is not supported by json_document", nullptr));
    }
    throwing_sax<BasicJsonType> sax;
    const bool accepted = BasicJsonType::sax_parse(src, src + size, &sax, input_format_t::json, true, ignore_comments, ignore_trailing_commas);
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



#include <algorithm> // max
#include <cstddef> // size_t
#include <istream> // istream, streambuf
#include <string> // basic_string, char_traits, string
#include <type_traits> // decay, integral_constant, is_array, is_const, is_integral, is_lvalue_reference, is_pointer, is_same, remove_cv, remove_extent, remove_pointer, remove_reference
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
    move_string,   ///< non-const rvalue std::string: owned without a copy
    c_string,      ///< pointer to single-byte characters (NUL-terminated): borrowed
    char_array,    ///< array of single-byte characters (e.g. a string literal): borrowed
    borrow_range,  ///< lvalue contiguous byte container, or std::string_view: borrowed
    copy_range,    ///< rvalue contiguous byte container (a const rvalue std::string too): copied
    wide_c_string, ///< pointer to wide characters (NUL-terminated): converted to UTF-8 into a buffer
    adapter,       ///< streams, FILE*, wide strings and arrays, and the rest of what the library's input adapter reads: read into a buffer
};

/// a single-byte character type (char, signed/unsigned char, char8_t, std::uint8_t, ...)
template<typename T>
struct is_byte_char : conjunction<std::is_integral<T>, std::integral_constant<bool, sizeof(T) == 1>> {}; // NOLINT(bugprone-sizeof-expression): T is any pointee or element type

/// a character type the library's input adapter converts to UTF-8
template<typename T>
struct is_wide_char : disjunction<std::is_same<T, wchar_t>, std::is_same<T, char16_t>, std::is_same<T, char32_t>> {};

template<typename InputType>
struct classify_input
{
    using R = typename std::remove_reference<InputType>::type;
    using D = typename std::decay<InputType>::type;
    using element = typename std::remove_cv<typename std::remove_extent<R>::type>::type;
    using pointee = typename std::remove_cv<typename std::remove_pointer<D>::type>::type;
    static constexpr bool is_rvalue = !std::is_lvalue_reference<InputType>::value;
    static constexpr bool is_bytes = is_contiguous_byte_container<D>::value;
#if NLOHMANN_VIEW_HAS_CPP_17
    static constexpr bool is_string_view = std::is_same<D, std::string_view>::value;
#else
    static constexpr bool is_string_view = false;
#endif
    // NOLINTBEGIN(readability-avoid-nested-conditional-operator): a constant expression of C++11
    // (arrays and pointers of other types, such as wide-character arrays and
    // FILE*, go to the library's input adapter)
    static constexpr input_kind value =
        (std::is_array<R>::value && is_byte_char<element>::value) ? input_kind::char_array
        : std::is_array<R>::value ? input_kind::adapter
        : (std::is_pointer<D>::value && is_byte_char<pointee>::value) ? input_kind::c_string
        : (std::is_pointer<D>::value && is_wide_char<pointee>::value) ? input_kind::wide_c_string
        : std::is_pointer<D>::value ? input_kind::adapter
        : (is_rvalue && !std::is_const<R>::value && std::is_same<D, std::string>::value) ? input_kind::move_string
        : (is_bytes && (!is_rvalue || is_string_view)) ? input_kind::borrow_range
        : is_bytes ? input_kind::copy_range
        : input_kind::adapter;
    // NOLINTEND(readability-avoid-nested-conditional-operator)
};

/// an integer type other than bool: a length passed where a flag is expected
template<typename T>
struct is_integer_not_bool : std::is_integral<T> {};

template<>
struct is_integer_not_bool<bool> : std::false_type {};

/// std::basic_string guarantees a NUL at data()[size()] (the parser's sentinel)
template<typename T>
struct is_std_string : std::false_type {};

template<typename Traits, typename Alloc>
struct is_std_string<std::basic_string<char, Traits, Alloc>> : std::true_type {};

/// append what a json input adapter yields (UTF-16/32 inputs arrive as UTF-8)
template<typename Adapter>
void append_adapter(std::string& buf, Adapter ia)
{
    for (;;)
    {
        const auto ch = ia.get_character();
        if (ch == std::char_traits<char>::eof())
        {
            break;
        }
        buf.push_back(static_cast<char>(ch));
    }
}

/// an input adapter made by the document for an input that the library's
/// input_adapter() does not take as one argument (an iterator range, a wide C
/// string), to be appended with append_adapter()
template<typename Adapter>
struct adapter_input
{
    Adapter ia;
};

template<typename T>
struct is_adapter_input : std::false_type {};

template<typename Adapter>
struct is_adapter_input<adapter_input<Adapter>> : std::true_type {};

template<typename Adapter>
adapter_input<typename std::decay<Adapter>::type> make_adapter_input(Adapter&& ia)
{
    return {std::forward<Adapter>(ia)};
}

/// append the rest of a stream: its characters need no conversion, so they are
/// read in blocks from the stream buffer, straight into buf (reusing its
/// capacity). As the library's stream adapter, this reads the stream buffer
/// directly and sets eofbit at the end.
inline void append_stream(std::string& buf, std::istream& is)
{
    std::streambuf* const sb = is.rdbuf();
    if (sb == nullptr)
    {
        return;
    }
    for (;;)
    {
        const std::size_t used = buf.size();
        const std::size_t room = (std::max)(buf.capacity() - used, std::size_t{4096});
        buf.resize(used + room);
        const std::streamsize got = sb->sgetn(&buf[used], static_cast<std::streamsize>(room));
        buf.resize(used + static_cast<std::size_t>((std::max)(got, std::streamsize{0})));
        if (got <= 0)
        {
            break;
        }
    }
    is.clear(is.rdstate() | std::ios::eofbit);
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
#include <limits> // numeric_limits
#include <type_traits> // integral_constant, is_integral, is_same

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
// #include <nlohmann/detail/meta/type_traits.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <limits> // numeric_limits
#include <map> // map, multimap
#include <string> // char_traits
#include <tuple> // tuple
#include <type_traits> // false_type, is_constructible, is_integral, is_same, true_type
#include <unordered_map> // unordered_map, unordered_multimap
#include <utility> // declval
#include <vector> // vector
#if defined(__cpp_lib_byte) && __cpp_lib_byte >= 201603L
    #include <cstddef> // byte
#endif
// #include <nlohmann/detail/iterators/iterator_traits.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <iterator> // random_access_iterator_tag

// #include <nlohmann/detail/abi_macros.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



// This file contains all macro definitions affecting or depending on the ABI

#ifndef JSON_SKIP_LIBRARY_VERSION_CHECK
    #if defined(NLOHMANN_JSON_VERSION_MAJOR) && defined(NLOHMANN_JSON_VERSION_MINOR) && defined(NLOHMANN_JSON_VERSION_PATCH)
        #if NLOHMANN_JSON_VERSION_MAJOR != 3 || NLOHMANN_JSON_VERSION_MINOR != 12 || NLOHMANN_JSON_VERSION_PATCH != 0
            #warning "Already included a different version of the library!"
        #endif
    #endif
#endif

#define NLOHMANN_JSON_VERSION_MAJOR 3   // NOLINT(modernize-macro-to-enum)
#define NLOHMANN_JSON_VERSION_MINOR 12  // NOLINT(modernize-macro-to-enum)
#define NLOHMANN_JSON_VERSION_PATCH 0   // NOLINT(modernize-macro-to-enum)

#ifndef JSON_DIAGNOSTICS
    #define JSON_DIAGNOSTICS 0
#endif

#ifndef JSON_DIAGNOSTIC_POSITIONS
    #define JSON_DIAGNOSTIC_POSITIONS 0
#endif

#ifndef JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON
    #define JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON 0
#endif

#ifndef JSON_BRACE_INIT_COPY_SEMANTICS
    #define JSON_BRACE_INIT_COPY_SEMANTICS 0
#endif

#ifndef JSON_PRECISE_STREAM_POSITION
    #define JSON_PRECISE_STREAM_POSITION 0
#endif

#ifndef JSON_STRICT_NUL_HANDLING
    #define JSON_STRICT_NUL_HANDLING 0
#endif

#ifndef JSON_STRICT_BINARY_UTF8
    #define JSON_STRICT_BINARY_UTF8 0
#endif

#ifndef JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS
    #define JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS 0
#endif

#if JSON_DIAGNOSTICS
    #define NLOHMANN_JSON_ABI_TAG_DIAGNOSTICS _diag
#else
    #define NLOHMANN_JSON_ABI_TAG_DIAGNOSTICS
#endif

#if JSON_DIAGNOSTIC_POSITIONS
    #define NLOHMANN_JSON_ABI_TAG_DIAGNOSTIC_POSITIONS _dp
#else
    #define NLOHMANN_JSON_ABI_TAG_DIAGNOSTIC_POSITIONS
#endif

#if JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON
    #define NLOHMANN_JSON_ABI_TAG_LEGACY_DISCARDED_VALUE_COMPARISON _ldvcmp
#else
    #define NLOHMANN_JSON_ABI_TAG_LEGACY_DISCARDED_VALUE_COMPARISON
#endif

#if JSON_BRACE_INIT_COPY_SEMANTICS
    #define NLOHMANN_JSON_ABI_TAG_BRACE_INIT_COPY_SEMANTICS _bics
#else
    #define NLOHMANN_JSON_ABI_TAG_BRACE_INIT_COPY_SEMANTICS
#endif

#if JSON_PRECISE_STREAM_POSITION
    #define NLOHMANN_JSON_ABI_TAG_PRECISE_STREAM_POSITION _psp
#else
    #define NLOHMANN_JSON_ABI_TAG_PRECISE_STREAM_POSITION
#endif

#if JSON_STRICT_NUL_HANDLING
    #define NLOHMANN_JSON_ABI_TAG_STRICT_NUL_HANDLING _snul
#else
    #define NLOHMANN_JSON_ABI_TAG_STRICT_NUL_HANDLING
#endif

#if JSON_STRICT_BINARY_UTF8
    #define NLOHMANN_JSON_ABI_TAG_STRICT_BINARY_UTF8 _sbu8
#else
    #define NLOHMANN_JSON_ABI_TAG_STRICT_BINARY_UTF8
#endif

#if JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS
    #define NLOHMANN_JSON_ABI_TAG_OBJECTS_FOR_ENUM_KEYED_MAPS _ekmo
#else
    #define NLOHMANN_JSON_ABI_TAG_OBJECTS_FOR_ENUM_KEYED_MAPS
#endif

#ifndef NLOHMANN_JSON_NAMESPACE_NO_VERSION
    #define NLOHMANN_JSON_NAMESPACE_NO_VERSION 0
#endif

// Construct the namespace ABI tags component
#define NLOHMANN_JSON_ABI_TAGS_CONCAT_EX(a, b, c, d, e, f, g, h) json_abi ## a ## b ## c ## d ## e ## f ## g ## h
#define NLOHMANN_JSON_ABI_TAGS_CONCAT(a, b, c, d, e, f, g, h) \
    NLOHMANN_JSON_ABI_TAGS_CONCAT_EX(a, b, c, d, e, f, g, h)

#define NLOHMANN_JSON_ABI_TAGS                                       \
    NLOHMANN_JSON_ABI_TAGS_CONCAT(                                   \
            NLOHMANN_JSON_ABI_TAG_DIAGNOSTICS,                       \
            NLOHMANN_JSON_ABI_TAG_LEGACY_DISCARDED_VALUE_COMPARISON, \
            NLOHMANN_JSON_ABI_TAG_DIAGNOSTIC_POSITIONS,              \
            NLOHMANN_JSON_ABI_TAG_BRACE_INIT_COPY_SEMANTICS,         \
            NLOHMANN_JSON_ABI_TAG_PRECISE_STREAM_POSITION,           \
            NLOHMANN_JSON_ABI_TAG_STRICT_NUL_HANDLING,               \
            NLOHMANN_JSON_ABI_TAG_STRICT_BINARY_UTF8,                \
            NLOHMANN_JSON_ABI_TAG_OBJECTS_FOR_ENUM_KEYED_MAPS)

// Construct the namespace version component
#define NLOHMANN_JSON_NAMESPACE_VERSION_CONCAT_EX(major, minor, patch) \
    _v ## major ## _ ## minor ## _ ## patch
#define NLOHMANN_JSON_NAMESPACE_VERSION_CONCAT(major, minor, patch) \
    NLOHMANN_JSON_NAMESPACE_VERSION_CONCAT_EX(major, minor, patch)

#if NLOHMANN_JSON_NAMESPACE_NO_VERSION
#define NLOHMANN_JSON_NAMESPACE_VERSION
#else
#define NLOHMANN_JSON_NAMESPACE_VERSION                                 \
    NLOHMANN_JSON_NAMESPACE_VERSION_CONCAT(NLOHMANN_JSON_VERSION_MAJOR, \
                                           NLOHMANN_JSON_VERSION_MINOR, \
                                           NLOHMANN_JSON_VERSION_PATCH)
#endif

// Combine namespace components
#define NLOHMANN_JSON_NAMESPACE_CONCAT_EX(a, b) a ## b
#define NLOHMANN_JSON_NAMESPACE_CONCAT(a, b) \
    NLOHMANN_JSON_NAMESPACE_CONCAT_EX(a, b)

#ifndef NLOHMANN_JSON_NAMESPACE
#define NLOHMANN_JSON_NAMESPACE               \
    nlohmann::NLOHMANN_JSON_NAMESPACE_CONCAT( \
            NLOHMANN_JSON_ABI_TAGS,           \
            NLOHMANN_JSON_NAMESPACE_VERSION)
#endif

#ifndef NLOHMANN_JSON_NAMESPACE_BEGIN
#define NLOHMANN_JSON_NAMESPACE_BEGIN                \
    namespace nlohmann                               \
    {                                                \
    inline namespace NLOHMANN_JSON_NAMESPACE_CONCAT( \
                NLOHMANN_JSON_ABI_TAGS,              \
                NLOHMANN_JSON_NAMESPACE_VERSION)     \
    {
#endif

#ifndef NLOHMANN_JSON_NAMESPACE_END
#define NLOHMANN_JSON_NAMESPACE_END                                     \
    }  /* namespace (inline namespace) NOLINT(readability/namespace) */ \
    }  // namespace nlohmann
#endif

// #include <nlohmann/detail/meta/void_t.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



// #include <nlohmann/detail/abi_macros.hpp>


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

template<typename ...Ts> struct make_void
{
    using type = void;
};
template<typename ...Ts> using void_t = typename make_void<Ts...>::type;

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/meta/cpp_future.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-FileCopyrightText: 2018 The Abseil Authors
// SPDX-License-Identifier: MIT AND Apache-2.0



#include <cstddef> // size_t
#include <type_traits> // conditional, enable_if, false_type, integral_constant, is_constructible, is_integral, is_same, remove_cv, remove_reference, true_type
#include <utility> // index_sequence, make_index_sequence, index_sequence_for

// #include <nlohmann/detail/macro_scope.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <utility> // declval, pair
// #include <nlohmann/thirdparty/hedley/hedley.hpp>


//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-FileCopyrightText: 2016-2021 Evan Nemerson <evan@nemerson.com>
// SPDX-License-Identifier: MIT

/* Hedley - https://nemequ.github.io/hedley
 * Created by Evan Nemerson <evan@nemerson.com>
 * SPDX-License-Identifier: CC0-1.0
 */

#if !defined(JSON_HEDLEY_VERSION) || (JSON_HEDLEY_VERSION < 15)
#if defined(JSON_HEDLEY_VERSION)
    #undef JSON_HEDLEY_VERSION
#endif
#define JSON_HEDLEY_VERSION 15

#if defined(JSON_HEDLEY_STRINGIFY_EX)
    #undef JSON_HEDLEY_STRINGIFY_EX
#endif
#define JSON_HEDLEY_STRINGIFY_EX(x) #x

#if defined(JSON_HEDLEY_STRINGIFY)
    #undef JSON_HEDLEY_STRINGIFY
#endif
#define JSON_HEDLEY_STRINGIFY(x) JSON_HEDLEY_STRINGIFY_EX(x)

#if defined(JSON_HEDLEY_CONCAT_EX)
    #undef JSON_HEDLEY_CONCAT_EX
#endif
#define JSON_HEDLEY_CONCAT_EX(a,b) a##b

#if defined(JSON_HEDLEY_CONCAT)
    #undef JSON_HEDLEY_CONCAT
#endif
#define JSON_HEDLEY_CONCAT(a,b) JSON_HEDLEY_CONCAT_EX(a,b)

#if defined(JSON_HEDLEY_CONCAT3_EX)
    #undef JSON_HEDLEY_CONCAT3_EX
#endif
#define JSON_HEDLEY_CONCAT3_EX(a,b,c) a##b##c

#if defined(JSON_HEDLEY_CONCAT3)
    #undef JSON_HEDLEY_CONCAT3
#endif
#define JSON_HEDLEY_CONCAT3(a,b,c) JSON_HEDLEY_CONCAT3_EX(a,b,c)

#if defined(JSON_HEDLEY_VERSION_ENCODE)
    #undef JSON_HEDLEY_VERSION_ENCODE
#endif
#define JSON_HEDLEY_VERSION_ENCODE(major,minor,revision) (((major) * 1000000) + ((minor) * 1000) + (revision))

#if defined(JSON_HEDLEY_VERSION_DECODE_MAJOR)
    #undef JSON_HEDLEY_VERSION_DECODE_MAJOR
#endif
#define JSON_HEDLEY_VERSION_DECODE_MAJOR(version) ((version) / 1000000)

#if defined(JSON_HEDLEY_VERSION_DECODE_MINOR)
    #undef JSON_HEDLEY_VERSION_DECODE_MINOR
#endif
#define JSON_HEDLEY_VERSION_DECODE_MINOR(version) (((version) % 1000000) / 1000)

#if defined(JSON_HEDLEY_VERSION_DECODE_REVISION)
    #undef JSON_HEDLEY_VERSION_DECODE_REVISION
#endif
#define JSON_HEDLEY_VERSION_DECODE_REVISION(version) ((version) % 1000)

#if defined(JSON_HEDLEY_GNUC_VERSION)
    #undef JSON_HEDLEY_GNUC_VERSION
#endif
#if defined(__GNUC__) && defined(__GNUC_PATCHLEVEL__)
    #define JSON_HEDLEY_GNUC_VERSION JSON_HEDLEY_VERSION_ENCODE(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__)
#elif defined(__GNUC__)
    #define JSON_HEDLEY_GNUC_VERSION JSON_HEDLEY_VERSION_ENCODE(__GNUC__, __GNUC_MINOR__, 0)
#endif

#if defined(JSON_HEDLEY_GNUC_VERSION_CHECK)
    #undef JSON_HEDLEY_GNUC_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_GNUC_VERSION)
    #define JSON_HEDLEY_GNUC_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_GNUC_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_GNUC_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_MSVC_VERSION)
    #undef JSON_HEDLEY_MSVC_VERSION
#endif
#if defined(_MSC_FULL_VER) && (_MSC_FULL_VER >= 140000000) && !defined(__ICL)
    #define JSON_HEDLEY_MSVC_VERSION JSON_HEDLEY_VERSION_ENCODE(_MSC_FULL_VER / 10000000, (_MSC_FULL_VER % 10000000) / 100000, (_MSC_FULL_VER % 100000) / 100)
#elif defined(_MSC_FULL_VER) && !defined(__ICL)
    #define JSON_HEDLEY_MSVC_VERSION JSON_HEDLEY_VERSION_ENCODE(_MSC_FULL_VER / 1000000, (_MSC_FULL_VER % 1000000) / 10000, (_MSC_FULL_VER % 10000) / 10)
#elif defined(_MSC_VER) && !defined(__ICL)
    #define JSON_HEDLEY_MSVC_VERSION JSON_HEDLEY_VERSION_ENCODE(_MSC_VER / 100, _MSC_VER % 100, 0)
#endif

#if defined(JSON_HEDLEY_MSVC_VERSION_CHECK)
    #undef JSON_HEDLEY_MSVC_VERSION_CHECK
#endif
#if !defined(JSON_HEDLEY_MSVC_VERSION)
    #define JSON_HEDLEY_MSVC_VERSION_CHECK(major,minor,patch) (0)
#elif defined(_MSC_VER) && (_MSC_VER >= 1400)
    #define JSON_HEDLEY_MSVC_VERSION_CHECK(major,minor,patch) (_MSC_FULL_VER >= ((major * 10000000) + (minor * 100000) + (patch)))
#elif defined(_MSC_VER) && (_MSC_VER >= 1200)
    #define JSON_HEDLEY_MSVC_VERSION_CHECK(major,minor,patch) (_MSC_FULL_VER >= ((major * 1000000) + (minor * 10000) + (patch)))
#else
    #define JSON_HEDLEY_MSVC_VERSION_CHECK(major,minor,patch) (_MSC_VER >= ((major * 100) + (minor)))
#endif

#if defined(JSON_HEDLEY_INTEL_VERSION)
    #undef JSON_HEDLEY_INTEL_VERSION
#endif
#if defined(__INTEL_COMPILER) && defined(__INTEL_COMPILER_UPDATE) && !defined(__ICL)
    #define JSON_HEDLEY_INTEL_VERSION JSON_HEDLEY_VERSION_ENCODE(__INTEL_COMPILER / 100, __INTEL_COMPILER % 100, __INTEL_COMPILER_UPDATE)
#elif defined(__INTEL_COMPILER) && !defined(__ICL)
    #define JSON_HEDLEY_INTEL_VERSION JSON_HEDLEY_VERSION_ENCODE(__INTEL_COMPILER / 100, __INTEL_COMPILER % 100, 0)
#endif

#if defined(JSON_HEDLEY_INTEL_VERSION_CHECK)
    #undef JSON_HEDLEY_INTEL_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_INTEL_VERSION)
    #define JSON_HEDLEY_INTEL_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_INTEL_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_INTEL_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_INTEL_CL_VERSION)
    #undef JSON_HEDLEY_INTEL_CL_VERSION
#endif
#if defined(__INTEL_COMPILER) && defined(__INTEL_COMPILER_UPDATE) && defined(__ICL)
    #define JSON_HEDLEY_INTEL_CL_VERSION JSON_HEDLEY_VERSION_ENCODE(__INTEL_COMPILER, __INTEL_COMPILER_UPDATE, 0)
#endif

#if defined(JSON_HEDLEY_INTEL_CL_VERSION_CHECK)
    #undef JSON_HEDLEY_INTEL_CL_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_INTEL_CL_VERSION)
    #define JSON_HEDLEY_INTEL_CL_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_INTEL_CL_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_INTEL_CL_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_PGI_VERSION)
    #undef JSON_HEDLEY_PGI_VERSION
#endif
#if defined(__PGI) && defined(__PGIC__) && defined(__PGIC_MINOR__) && defined(__PGIC_PATCHLEVEL__)
    #define JSON_HEDLEY_PGI_VERSION JSON_HEDLEY_VERSION_ENCODE(__PGIC__, __PGIC_MINOR__, __PGIC_PATCHLEVEL__)
#endif

#if defined(JSON_HEDLEY_PGI_VERSION_CHECK)
    #undef JSON_HEDLEY_PGI_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_PGI_VERSION)
    #define JSON_HEDLEY_PGI_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_PGI_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_PGI_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_SUNPRO_VERSION)
    #undef JSON_HEDLEY_SUNPRO_VERSION
#endif
#if defined(__SUNPRO_C) && (__SUNPRO_C > 0x1000)
    #define JSON_HEDLEY_SUNPRO_VERSION JSON_HEDLEY_VERSION_ENCODE((((__SUNPRO_C >> 16) & 0xf) * 10) + ((__SUNPRO_C >> 12) & 0xf), (((__SUNPRO_C >> 8) & 0xf) * 10) + ((__SUNPRO_C >> 4) & 0xf), (__SUNPRO_C & 0xf) * 10)
#elif defined(__SUNPRO_C)
    #define JSON_HEDLEY_SUNPRO_VERSION JSON_HEDLEY_VERSION_ENCODE((__SUNPRO_C >> 8) & 0xf, (__SUNPRO_C >> 4) & 0xf, (__SUNPRO_C) & 0xf)
#elif defined(__SUNPRO_CC) && (__SUNPRO_CC > 0x1000)
    #define JSON_HEDLEY_SUNPRO_VERSION JSON_HEDLEY_VERSION_ENCODE((((__SUNPRO_CC >> 16) & 0xf) * 10) + ((__SUNPRO_CC >> 12) & 0xf), (((__SUNPRO_CC >> 8) & 0xf) * 10) + ((__SUNPRO_CC >> 4) & 0xf), (__SUNPRO_CC & 0xf) * 10)
#elif defined(__SUNPRO_CC)
    #define JSON_HEDLEY_SUNPRO_VERSION JSON_HEDLEY_VERSION_ENCODE((__SUNPRO_CC >> 8) & 0xf, (__SUNPRO_CC >> 4) & 0xf, (__SUNPRO_CC) & 0xf)
#endif

#if defined(JSON_HEDLEY_SUNPRO_VERSION_CHECK)
    #undef JSON_HEDLEY_SUNPRO_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_SUNPRO_VERSION)
    #define JSON_HEDLEY_SUNPRO_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_SUNPRO_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_SUNPRO_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_EMSCRIPTEN_VERSION)
    #undef JSON_HEDLEY_EMSCRIPTEN_VERSION
#endif
#if defined(__EMSCRIPTEN__)
    #define JSON_HEDLEY_EMSCRIPTEN_VERSION JSON_HEDLEY_VERSION_ENCODE(__EMSCRIPTEN_major__, __EMSCRIPTEN_minor__, __EMSCRIPTEN_tiny__)
#endif

#if defined(JSON_HEDLEY_EMSCRIPTEN_VERSION_CHECK)
    #undef JSON_HEDLEY_EMSCRIPTEN_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_EMSCRIPTEN_VERSION)
    #define JSON_HEDLEY_EMSCRIPTEN_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_EMSCRIPTEN_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_EMSCRIPTEN_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_ARM_VERSION)
    #undef JSON_HEDLEY_ARM_VERSION
#endif
#if defined(__CC_ARM) && defined(__ARMCOMPILER_VERSION)
    #define JSON_HEDLEY_ARM_VERSION JSON_HEDLEY_VERSION_ENCODE(__ARMCOMPILER_VERSION / 1000000, (__ARMCOMPILER_VERSION % 1000000) / 10000, (__ARMCOMPILER_VERSION % 10000) / 100)
#elif defined(__CC_ARM) && defined(__ARMCC_VERSION)
    #define JSON_HEDLEY_ARM_VERSION JSON_HEDLEY_VERSION_ENCODE(__ARMCC_VERSION / 1000000, (__ARMCC_VERSION % 1000000) / 10000, (__ARMCC_VERSION % 10000) / 100)
#endif

#if defined(JSON_HEDLEY_ARM_VERSION_CHECK)
    #undef JSON_HEDLEY_ARM_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_ARM_VERSION)
    #define JSON_HEDLEY_ARM_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_ARM_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_ARM_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_IBM_VERSION)
    #undef JSON_HEDLEY_IBM_VERSION
#endif
#if defined(__ibmxl__)
    #define JSON_HEDLEY_IBM_VERSION JSON_HEDLEY_VERSION_ENCODE(__ibmxl_version__, __ibmxl_release__, __ibmxl_modification__)
#elif defined(__xlC__) && defined(__xlC_ver__)
    #define JSON_HEDLEY_IBM_VERSION JSON_HEDLEY_VERSION_ENCODE(__xlC__ >> 8, __xlC__ & 0xff, (__xlC_ver__ >> 8) & 0xff)
#elif defined(__xlC__)
    #define JSON_HEDLEY_IBM_VERSION JSON_HEDLEY_VERSION_ENCODE(__xlC__ >> 8, __xlC__ & 0xff, 0)
#endif

#if defined(JSON_HEDLEY_IBM_VERSION_CHECK)
    #undef JSON_HEDLEY_IBM_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_IBM_VERSION)
    #define JSON_HEDLEY_IBM_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_IBM_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_IBM_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_TI_VERSION)
    #undef JSON_HEDLEY_TI_VERSION
#endif
#if \
    defined(__TI_COMPILER_VERSION__) && \
    ( \
      defined(__TMS470__) || defined(__TI_ARM__) || \
      defined(__MSP430__) || \
      defined(__TMS320C2000__) \
    )
#if (__TI_COMPILER_VERSION__ >= 16000000)
    #define JSON_HEDLEY_TI_VERSION JSON_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif
#endif

#if defined(JSON_HEDLEY_TI_VERSION_CHECK)
    #undef JSON_HEDLEY_TI_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_TI_VERSION)
    #define JSON_HEDLEY_TI_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_TI_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_TI_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_TI_CL2000_VERSION)
    #undef JSON_HEDLEY_TI_CL2000_VERSION
#endif
#if defined(__TI_COMPILER_VERSION__) && defined(__TMS320C2000__)
    #define JSON_HEDLEY_TI_CL2000_VERSION JSON_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif

#if defined(JSON_HEDLEY_TI_CL2000_VERSION_CHECK)
    #undef JSON_HEDLEY_TI_CL2000_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_TI_CL2000_VERSION)
    #define JSON_HEDLEY_TI_CL2000_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_TI_CL2000_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_TI_CL2000_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_TI_CL430_VERSION)
    #undef JSON_HEDLEY_TI_CL430_VERSION
#endif
#if defined(__TI_COMPILER_VERSION__) && defined(__MSP430__)
    #define JSON_HEDLEY_TI_CL430_VERSION JSON_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif

#if defined(JSON_HEDLEY_TI_CL430_VERSION_CHECK)
    #undef JSON_HEDLEY_TI_CL430_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_TI_CL430_VERSION)
    #define JSON_HEDLEY_TI_CL430_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_TI_CL430_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_TI_CL430_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_TI_ARMCL_VERSION)
    #undef JSON_HEDLEY_TI_ARMCL_VERSION
#endif
#if defined(__TI_COMPILER_VERSION__) && (defined(__TMS470__) || defined(__TI_ARM__))
    #define JSON_HEDLEY_TI_ARMCL_VERSION JSON_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif

#if defined(JSON_HEDLEY_TI_ARMCL_VERSION_CHECK)
    #undef JSON_HEDLEY_TI_ARMCL_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_TI_ARMCL_VERSION)
    #define JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_TI_ARMCL_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_TI_CL6X_VERSION)
    #undef JSON_HEDLEY_TI_CL6X_VERSION
#endif
#if defined(__TI_COMPILER_VERSION__) && defined(__TMS320C6X__)
    #define JSON_HEDLEY_TI_CL6X_VERSION JSON_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif

#if defined(JSON_HEDLEY_TI_CL6X_VERSION_CHECK)
    #undef JSON_HEDLEY_TI_CL6X_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_TI_CL6X_VERSION)
    #define JSON_HEDLEY_TI_CL6X_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_TI_CL6X_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_TI_CL6X_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_TI_CL7X_VERSION)
    #undef JSON_HEDLEY_TI_CL7X_VERSION
#endif
#if defined(__TI_COMPILER_VERSION__) && defined(__C7000__)
    #define JSON_HEDLEY_TI_CL7X_VERSION JSON_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif

#if defined(JSON_HEDLEY_TI_CL7X_VERSION_CHECK)
    #undef JSON_HEDLEY_TI_CL7X_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_TI_CL7X_VERSION)
    #define JSON_HEDLEY_TI_CL7X_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_TI_CL7X_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_TI_CL7X_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_TI_CLPRU_VERSION)
    #undef JSON_HEDLEY_TI_CLPRU_VERSION
#endif
#if defined(__TI_COMPILER_VERSION__) && defined(__PRU__)
    #define JSON_HEDLEY_TI_CLPRU_VERSION JSON_HEDLEY_VERSION_ENCODE(__TI_COMPILER_VERSION__ / 1000000, (__TI_COMPILER_VERSION__ % 1000000) / 1000, (__TI_COMPILER_VERSION__ % 1000))
#endif

#if defined(JSON_HEDLEY_TI_CLPRU_VERSION_CHECK)
    #undef JSON_HEDLEY_TI_CLPRU_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_TI_CLPRU_VERSION)
    #define JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_TI_CLPRU_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_CRAY_VERSION)
    #undef JSON_HEDLEY_CRAY_VERSION
#endif
#if defined(_CRAYC)
    #if defined(_RELEASE_PATCHLEVEL)
        #define JSON_HEDLEY_CRAY_VERSION JSON_HEDLEY_VERSION_ENCODE(_RELEASE_MAJOR, _RELEASE_MINOR, _RELEASE_PATCHLEVEL)
    #else
        #define JSON_HEDLEY_CRAY_VERSION JSON_HEDLEY_VERSION_ENCODE(_RELEASE_MAJOR, _RELEASE_MINOR, 0)
    #endif
#endif

#if defined(JSON_HEDLEY_CRAY_VERSION_CHECK)
    #undef JSON_HEDLEY_CRAY_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_CRAY_VERSION)
    #define JSON_HEDLEY_CRAY_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_CRAY_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_CRAY_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_IAR_VERSION)
    #undef JSON_HEDLEY_IAR_VERSION
#endif
#if defined(__IAR_SYSTEMS_ICC__)
    #if __VER__ > 1000
        #define JSON_HEDLEY_IAR_VERSION JSON_HEDLEY_VERSION_ENCODE((__VER__ / 1000000), ((__VER__ / 1000) % 1000), (__VER__ % 1000))
    #else
        #define JSON_HEDLEY_IAR_VERSION JSON_HEDLEY_VERSION_ENCODE(__VER__ / 100, __VER__ % 100, 0)
    #endif
#endif

#if defined(JSON_HEDLEY_IAR_VERSION_CHECK)
    #undef JSON_HEDLEY_IAR_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_IAR_VERSION)
    #define JSON_HEDLEY_IAR_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_IAR_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_IAR_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_TINYC_VERSION)
    #undef JSON_HEDLEY_TINYC_VERSION
#endif
#if defined(__TINYC__)
    #define JSON_HEDLEY_TINYC_VERSION JSON_HEDLEY_VERSION_ENCODE(__TINYC__ / 1000, (__TINYC__ / 100) % 10, __TINYC__ % 100)
#endif

#if defined(JSON_HEDLEY_TINYC_VERSION_CHECK)
    #undef JSON_HEDLEY_TINYC_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_TINYC_VERSION)
    #define JSON_HEDLEY_TINYC_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_TINYC_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_TINYC_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_DMC_VERSION)
    #undef JSON_HEDLEY_DMC_VERSION
#endif
#if defined(__DMC__)
    #define JSON_HEDLEY_DMC_VERSION JSON_HEDLEY_VERSION_ENCODE(__DMC__ >> 8, (__DMC__ >> 4) & 0xf, __DMC__ & 0xf)
#endif

#if defined(JSON_HEDLEY_DMC_VERSION_CHECK)
    #undef JSON_HEDLEY_DMC_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_DMC_VERSION)
    #define JSON_HEDLEY_DMC_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_DMC_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_DMC_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_COMPCERT_VERSION)
    #undef JSON_HEDLEY_COMPCERT_VERSION
#endif
#if defined(__COMPCERT_VERSION__)
    #define JSON_HEDLEY_COMPCERT_VERSION JSON_HEDLEY_VERSION_ENCODE(__COMPCERT_VERSION__ / 10000, (__COMPCERT_VERSION__ / 100) % 100, __COMPCERT_VERSION__ % 100)
#endif

#if defined(JSON_HEDLEY_COMPCERT_VERSION_CHECK)
    #undef JSON_HEDLEY_COMPCERT_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_COMPCERT_VERSION)
    #define JSON_HEDLEY_COMPCERT_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_COMPCERT_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_COMPCERT_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_PELLES_VERSION)
    #undef JSON_HEDLEY_PELLES_VERSION
#endif
#if defined(__POCC__)
    #define JSON_HEDLEY_PELLES_VERSION JSON_HEDLEY_VERSION_ENCODE(__POCC__ / 100, __POCC__ % 100, 0)
#endif

#if defined(JSON_HEDLEY_PELLES_VERSION_CHECK)
    #undef JSON_HEDLEY_PELLES_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_PELLES_VERSION)
    #define JSON_HEDLEY_PELLES_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_PELLES_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_PELLES_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_MCST_LCC_VERSION)
    #undef JSON_HEDLEY_MCST_LCC_VERSION
#endif
#if defined(__LCC__) && defined(__LCC_MINOR__)
    #define JSON_HEDLEY_MCST_LCC_VERSION JSON_HEDLEY_VERSION_ENCODE(__LCC__ / 100, __LCC__ % 100, __LCC_MINOR__)
#endif

#if defined(JSON_HEDLEY_MCST_LCC_VERSION_CHECK)
    #undef JSON_HEDLEY_MCST_LCC_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_MCST_LCC_VERSION)
    #define JSON_HEDLEY_MCST_LCC_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_MCST_LCC_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_MCST_LCC_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_GCC_VERSION)
    #undef JSON_HEDLEY_GCC_VERSION
#endif
#if \
    defined(JSON_HEDLEY_GNUC_VERSION) && \
    !defined(__clang__) && \
    !defined(JSON_HEDLEY_INTEL_VERSION) && \
    !defined(JSON_HEDLEY_PGI_VERSION) && \
    !defined(JSON_HEDLEY_ARM_VERSION) && \
    !defined(JSON_HEDLEY_CRAY_VERSION) && \
    !defined(JSON_HEDLEY_TI_VERSION) && \
    !defined(JSON_HEDLEY_TI_ARMCL_VERSION) && \
    !defined(JSON_HEDLEY_TI_CL430_VERSION) && \
    !defined(JSON_HEDLEY_TI_CL2000_VERSION) && \
    !defined(JSON_HEDLEY_TI_CL6X_VERSION) && \
    !defined(JSON_HEDLEY_TI_CL7X_VERSION) && \
    !defined(JSON_HEDLEY_TI_CLPRU_VERSION) && \
    !defined(__COMPCERT__) && \
    !defined(JSON_HEDLEY_MCST_LCC_VERSION)
    #define JSON_HEDLEY_GCC_VERSION JSON_HEDLEY_GNUC_VERSION
#endif

#if defined(JSON_HEDLEY_GCC_VERSION_CHECK)
    #undef JSON_HEDLEY_GCC_VERSION_CHECK
#endif
#if defined(JSON_HEDLEY_GCC_VERSION)
    #define JSON_HEDLEY_GCC_VERSION_CHECK(major,minor,patch) (JSON_HEDLEY_GCC_VERSION >= JSON_HEDLEY_VERSION_ENCODE(major, minor, patch))
#else
    #define JSON_HEDLEY_GCC_VERSION_CHECK(major,minor,patch) (0)
#endif

#if defined(JSON_HEDLEY_HAS_ATTRIBUTE)
    #undef JSON_HEDLEY_HAS_ATTRIBUTE
#endif
#if \
  defined(__has_attribute) && \
  ( \
    (!defined(JSON_HEDLEY_IAR_VERSION) || JSON_HEDLEY_IAR_VERSION_CHECK(8,5,9)) \
  )
#  define JSON_HEDLEY_HAS_ATTRIBUTE(attribute) __has_attribute(attribute)
#else
#  define JSON_HEDLEY_HAS_ATTRIBUTE(attribute) (0)
#endif

#if defined(JSON_HEDLEY_GNUC_HAS_ATTRIBUTE)
    #undef JSON_HEDLEY_GNUC_HAS_ATTRIBUTE
#endif
#if defined(__has_attribute)
    #define JSON_HEDLEY_GNUC_HAS_ATTRIBUTE(attribute,major,minor,patch) JSON_HEDLEY_HAS_ATTRIBUTE(attribute)
#else
    #define JSON_HEDLEY_GNUC_HAS_ATTRIBUTE(attribute,major,minor,patch) JSON_HEDLEY_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_GCC_HAS_ATTRIBUTE)
    #undef JSON_HEDLEY_GCC_HAS_ATTRIBUTE
#endif
#if defined(__has_attribute)
    #define JSON_HEDLEY_GCC_HAS_ATTRIBUTE(attribute,major,minor,patch) JSON_HEDLEY_HAS_ATTRIBUTE(attribute)
#else
    #define JSON_HEDLEY_GCC_HAS_ATTRIBUTE(attribute,major,minor,patch) JSON_HEDLEY_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_HAS_CPP_ATTRIBUTE)
    #undef JSON_HEDLEY_HAS_CPP_ATTRIBUTE
#endif
#if \
    defined(__has_cpp_attribute) && \
    defined(__cplusplus) && \
    (!defined(JSON_HEDLEY_SUNPRO_VERSION) || JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,15,0))
    #define JSON_HEDLEY_HAS_CPP_ATTRIBUTE(attribute) __has_cpp_attribute(attribute)
#else
    #define JSON_HEDLEY_HAS_CPP_ATTRIBUTE(attribute) (0)
#endif

#if defined(JSON_HEDLEY_HAS_CPP_ATTRIBUTE_NS)
    #undef JSON_HEDLEY_HAS_CPP_ATTRIBUTE_NS
#endif
#if !defined(__cplusplus) || !defined(__has_cpp_attribute)
    #define JSON_HEDLEY_HAS_CPP_ATTRIBUTE_NS(ns,attribute) (0)
#elif \
    !defined(JSON_HEDLEY_PGI_VERSION) && \
    !defined(JSON_HEDLEY_IAR_VERSION) && \
    (!defined(JSON_HEDLEY_SUNPRO_VERSION) || JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,15,0)) && \
    (!defined(JSON_HEDLEY_MSVC_VERSION) || JSON_HEDLEY_MSVC_VERSION_CHECK(19,20,0))
    #define JSON_HEDLEY_HAS_CPP_ATTRIBUTE_NS(ns,attribute) JSON_HEDLEY_HAS_CPP_ATTRIBUTE(ns::attribute)
#else
    #define JSON_HEDLEY_HAS_CPP_ATTRIBUTE_NS(ns,attribute) (0)
#endif

#if defined(JSON_HEDLEY_GNUC_HAS_CPP_ATTRIBUTE)
    #undef JSON_HEDLEY_GNUC_HAS_CPP_ATTRIBUTE
#endif
#if defined(__has_cpp_attribute) && defined(__cplusplus)
    #define JSON_HEDLEY_GNUC_HAS_CPP_ATTRIBUTE(attribute,major,minor,patch) __has_cpp_attribute(attribute)
#else
    #define JSON_HEDLEY_GNUC_HAS_CPP_ATTRIBUTE(attribute,major,minor,patch) JSON_HEDLEY_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_GCC_HAS_CPP_ATTRIBUTE)
    #undef JSON_HEDLEY_GCC_HAS_CPP_ATTRIBUTE
#endif
#if defined(__has_cpp_attribute) && defined(__cplusplus)
    #define JSON_HEDLEY_GCC_HAS_CPP_ATTRIBUTE(attribute,major,minor,patch) __has_cpp_attribute(attribute)
#else
    #define JSON_HEDLEY_GCC_HAS_CPP_ATTRIBUTE(attribute,major,minor,patch) JSON_HEDLEY_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_HAS_BUILTIN)
    #undef JSON_HEDLEY_HAS_BUILTIN
#endif
#if defined(__has_builtin)
    #define JSON_HEDLEY_HAS_BUILTIN(builtin) __has_builtin(builtin)
#else
    #define JSON_HEDLEY_HAS_BUILTIN(builtin) (0)
#endif

#if defined(JSON_HEDLEY_GNUC_HAS_BUILTIN)
    #undef JSON_HEDLEY_GNUC_HAS_BUILTIN
#endif
#if defined(__has_builtin)
    #define JSON_HEDLEY_GNUC_HAS_BUILTIN(builtin,major,minor,patch) __has_builtin(builtin)
#else
    #define JSON_HEDLEY_GNUC_HAS_BUILTIN(builtin,major,minor,patch) JSON_HEDLEY_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_GCC_HAS_BUILTIN)
    #undef JSON_HEDLEY_GCC_HAS_BUILTIN
#endif
#if defined(__has_builtin)
    #define JSON_HEDLEY_GCC_HAS_BUILTIN(builtin,major,minor,patch) __has_builtin(builtin)
#else
    #define JSON_HEDLEY_GCC_HAS_BUILTIN(builtin,major,minor,patch) JSON_HEDLEY_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_HAS_FEATURE)
    #undef JSON_HEDLEY_HAS_FEATURE
#endif
#if defined(__has_feature)
    #define JSON_HEDLEY_HAS_FEATURE(feature) __has_feature(feature)
#else
    #define JSON_HEDLEY_HAS_FEATURE(feature) (0)
#endif

#if defined(JSON_HEDLEY_GNUC_HAS_FEATURE)
    #undef JSON_HEDLEY_GNUC_HAS_FEATURE
#endif
#if defined(__has_feature)
    #define JSON_HEDLEY_GNUC_HAS_FEATURE(feature,major,minor,patch) __has_feature(feature)
#else
    #define JSON_HEDLEY_GNUC_HAS_FEATURE(feature,major,minor,patch) JSON_HEDLEY_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_GCC_HAS_FEATURE)
    #undef JSON_HEDLEY_GCC_HAS_FEATURE
#endif
#if defined(__has_feature)
    #define JSON_HEDLEY_GCC_HAS_FEATURE(feature,major,minor,patch) __has_feature(feature)
#else
    #define JSON_HEDLEY_GCC_HAS_FEATURE(feature,major,minor,patch) JSON_HEDLEY_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_HAS_EXTENSION)
    #undef JSON_HEDLEY_HAS_EXTENSION
#endif
#if defined(__has_extension)
    #define JSON_HEDLEY_HAS_EXTENSION(extension) __has_extension(extension)
#else
    #define JSON_HEDLEY_HAS_EXTENSION(extension) (0)
#endif

#if defined(JSON_HEDLEY_GNUC_HAS_EXTENSION)
    #undef JSON_HEDLEY_GNUC_HAS_EXTENSION
#endif
#if defined(__has_extension)
    #define JSON_HEDLEY_GNUC_HAS_EXTENSION(extension,major,minor,patch) __has_extension(extension)
#else
    #define JSON_HEDLEY_GNUC_HAS_EXTENSION(extension,major,minor,patch) JSON_HEDLEY_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_GCC_HAS_EXTENSION)
    #undef JSON_HEDLEY_GCC_HAS_EXTENSION
#endif
#if defined(__has_extension)
    #define JSON_HEDLEY_GCC_HAS_EXTENSION(extension,major,minor,patch) __has_extension(extension)
#else
    #define JSON_HEDLEY_GCC_HAS_EXTENSION(extension,major,minor,patch) JSON_HEDLEY_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_HAS_DECLSPEC_ATTRIBUTE)
    #undef JSON_HEDLEY_HAS_DECLSPEC_ATTRIBUTE
#endif
#if defined(__has_declspec_attribute)
    #define JSON_HEDLEY_HAS_DECLSPEC_ATTRIBUTE(attribute) __has_declspec_attribute(attribute)
#else
    #define JSON_HEDLEY_HAS_DECLSPEC_ATTRIBUTE(attribute) (0)
#endif

#if defined(JSON_HEDLEY_GNUC_HAS_DECLSPEC_ATTRIBUTE)
    #undef JSON_HEDLEY_GNUC_HAS_DECLSPEC_ATTRIBUTE
#endif
#if defined(__has_declspec_attribute)
    #define JSON_HEDLEY_GNUC_HAS_DECLSPEC_ATTRIBUTE(attribute,major,minor,patch) __has_declspec_attribute(attribute)
#else
    #define JSON_HEDLEY_GNUC_HAS_DECLSPEC_ATTRIBUTE(attribute,major,minor,patch) JSON_HEDLEY_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_GCC_HAS_DECLSPEC_ATTRIBUTE)
    #undef JSON_HEDLEY_GCC_HAS_DECLSPEC_ATTRIBUTE
#endif
#if defined(__has_declspec_attribute)
    #define JSON_HEDLEY_GCC_HAS_DECLSPEC_ATTRIBUTE(attribute,major,minor,patch) __has_declspec_attribute(attribute)
#else
    #define JSON_HEDLEY_GCC_HAS_DECLSPEC_ATTRIBUTE(attribute,major,minor,patch) JSON_HEDLEY_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_HAS_WARNING)
    #undef JSON_HEDLEY_HAS_WARNING
#endif
#if defined(__has_warning)
    #define JSON_HEDLEY_HAS_WARNING(warning) __has_warning(warning)
#else
    #define JSON_HEDLEY_HAS_WARNING(warning) (0)
#endif

#if defined(JSON_HEDLEY_GNUC_HAS_WARNING)
    #undef JSON_HEDLEY_GNUC_HAS_WARNING
#endif
#if defined(__has_warning)
    #define JSON_HEDLEY_GNUC_HAS_WARNING(warning,major,minor,patch) __has_warning(warning)
#else
    #define JSON_HEDLEY_GNUC_HAS_WARNING(warning,major,minor,patch) JSON_HEDLEY_GNUC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_GCC_HAS_WARNING)
    #undef JSON_HEDLEY_GCC_HAS_WARNING
#endif
#if defined(__has_warning)
    #define JSON_HEDLEY_GCC_HAS_WARNING(warning,major,minor,patch) __has_warning(warning)
#else
    #define JSON_HEDLEY_GCC_HAS_WARNING(warning,major,minor,patch) JSON_HEDLEY_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if \
    (defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)) || \
    defined(__clang__) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(3,0,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_IAR_VERSION_CHECK(8,0,0) || \
    JSON_HEDLEY_PGI_VERSION_CHECK(18,4,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
    JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
    JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(4,7,0) || \
    JSON_HEDLEY_TI_CL430_VERSION_CHECK(2,0,1) || \
    JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,1,0) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,0,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) || \
    JSON_HEDLEY_CRAY_VERSION_CHECK(5,0,0) || \
    JSON_HEDLEY_TINYC_VERSION_CHECK(0,9,17) || \
    JSON_HEDLEY_SUNPRO_VERSION_CHECK(8,0,0) || \
    (JSON_HEDLEY_IBM_VERSION_CHECK(10,1,0) && defined(__C99_PRAGMA_OPERATOR))
    #define JSON_HEDLEY_PRAGMA(value) _Pragma(#value)
#elif JSON_HEDLEY_MSVC_VERSION_CHECK(15,0,0)
    #define JSON_HEDLEY_PRAGMA(value) __pragma(value)
#else
    #define JSON_HEDLEY_PRAGMA(value)
#endif

#if defined(JSON_HEDLEY_DIAGNOSTIC_PUSH)
    #undef JSON_HEDLEY_DIAGNOSTIC_PUSH
#endif
#if defined(JSON_HEDLEY_DIAGNOSTIC_POP)
    #undef JSON_HEDLEY_DIAGNOSTIC_POP
#endif
#if defined(__clang__)
    #define JSON_HEDLEY_DIAGNOSTIC_PUSH _Pragma("clang diagnostic push")
    #define JSON_HEDLEY_DIAGNOSTIC_POP _Pragma("clang diagnostic pop")
#elif JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_PUSH _Pragma("warning(push)")
    #define JSON_HEDLEY_DIAGNOSTIC_POP _Pragma("warning(pop)")
#elif JSON_HEDLEY_GCC_VERSION_CHECK(4,6,0)
    #define JSON_HEDLEY_DIAGNOSTIC_PUSH _Pragma("GCC diagnostic push")
    #define JSON_HEDLEY_DIAGNOSTIC_POP _Pragma("GCC diagnostic pop")
#elif \
    JSON_HEDLEY_MSVC_VERSION_CHECK(15,0,0) || \
    JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
    #define JSON_HEDLEY_DIAGNOSTIC_PUSH __pragma(warning(push))
    #define JSON_HEDLEY_DIAGNOSTIC_POP __pragma(warning(pop))
#elif JSON_HEDLEY_ARM_VERSION_CHECK(5,6,0)
    #define JSON_HEDLEY_DIAGNOSTIC_PUSH _Pragma("push")
    #define JSON_HEDLEY_DIAGNOSTIC_POP _Pragma("pop")
#elif \
    JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
    JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,2,0) || \
    JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,4,0) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(8,1,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0)
    #define JSON_HEDLEY_DIAGNOSTIC_PUSH _Pragma("diag_push")
    #define JSON_HEDLEY_DIAGNOSTIC_POP _Pragma("diag_pop")
#elif JSON_HEDLEY_PELLES_VERSION_CHECK(2,90,0)
    #define JSON_HEDLEY_DIAGNOSTIC_PUSH _Pragma("warning(push)")
    #define JSON_HEDLEY_DIAGNOSTIC_POP _Pragma("warning(pop)")
#else
    #define JSON_HEDLEY_DIAGNOSTIC_PUSH
    #define JSON_HEDLEY_DIAGNOSTIC_POP
#endif

/* JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_ is for
   HEDLEY INTERNAL USE ONLY.  API subject to change without notice. */
#if defined(JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_)
    #undef JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_
#endif
#if defined(__cplusplus)
#  if JSON_HEDLEY_HAS_WARNING("-Wc++98-compat")
#    if JSON_HEDLEY_HAS_WARNING("-Wc++17-extensions")
#      if JSON_HEDLEY_HAS_WARNING("-Wc++1z-extensions")
#        define JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(xpr) \
    JSON_HEDLEY_DIAGNOSTIC_PUSH \
    _Pragma("clang diagnostic ignored \"-Wc++98-compat\"") \
    _Pragma("clang diagnostic ignored \"-Wc++17-extensions\"") \
    _Pragma("clang diagnostic ignored \"-Wc++1z-extensions\"") \
    xpr \
    JSON_HEDLEY_DIAGNOSTIC_POP
#      else
#        define JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(xpr) \
    JSON_HEDLEY_DIAGNOSTIC_PUSH \
    _Pragma("clang diagnostic ignored \"-Wc++98-compat\"") \
    _Pragma("clang diagnostic ignored \"-Wc++17-extensions\"") \
    xpr \
    JSON_HEDLEY_DIAGNOSTIC_POP
#      endif
#    else
#      define JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(xpr) \
    JSON_HEDLEY_DIAGNOSTIC_PUSH \
    _Pragma("clang diagnostic ignored \"-Wc++98-compat\"") \
    xpr \
    JSON_HEDLEY_DIAGNOSTIC_POP
#    endif
#  endif
#endif
#if !defined(JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(x) x
#endif

#if defined(JSON_HEDLEY_CONST_CAST)
    #undef JSON_HEDLEY_CONST_CAST
#endif
#if defined(__cplusplus)
#  define JSON_HEDLEY_CONST_CAST(T, expr) (const_cast<T>(expr))
#elif \
  JSON_HEDLEY_HAS_WARNING("-Wcast-qual") || \
  JSON_HEDLEY_GCC_VERSION_CHECK(4,6,0) || \
  JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0)
#  define JSON_HEDLEY_CONST_CAST(T, expr) (__extension__ ({ \
        JSON_HEDLEY_DIAGNOSTIC_PUSH \
        JSON_HEDLEY_DIAGNOSTIC_DISABLE_CAST_QUAL \
        ((T) (expr)); \
        JSON_HEDLEY_DIAGNOSTIC_POP \
    }))
#else
#  define JSON_HEDLEY_CONST_CAST(T, expr) ((T) (expr))
#endif

#if defined(JSON_HEDLEY_REINTERPRET_CAST)
    #undef JSON_HEDLEY_REINTERPRET_CAST
#endif
#if defined(__cplusplus)
    #define JSON_HEDLEY_REINTERPRET_CAST(T, expr) (reinterpret_cast<T>(expr))
#else
    #define JSON_HEDLEY_REINTERPRET_CAST(T, expr) ((T) (expr))
#endif

#if defined(JSON_HEDLEY_STATIC_CAST)
    #undef JSON_HEDLEY_STATIC_CAST
#endif
#if defined(__cplusplus)
    #define JSON_HEDLEY_STATIC_CAST(T, expr) (static_cast<T>(expr))
#else
    #define JSON_HEDLEY_STATIC_CAST(T, expr) ((T) (expr))
#endif

#if defined(JSON_HEDLEY_CPP_CAST)
    #undef JSON_HEDLEY_CPP_CAST
#endif
#if defined(__cplusplus)
#  if JSON_HEDLEY_HAS_WARNING("-Wold-style-cast")
#    define JSON_HEDLEY_CPP_CAST(T, expr) \
    JSON_HEDLEY_DIAGNOSTIC_PUSH \
    _Pragma("clang diagnostic ignored \"-Wold-style-cast\"") \
    ((T) (expr)) \
    JSON_HEDLEY_DIAGNOSTIC_POP
#  elif JSON_HEDLEY_IAR_VERSION_CHECK(8,3,0)
#    define JSON_HEDLEY_CPP_CAST(T, expr) \
    JSON_HEDLEY_DIAGNOSTIC_PUSH \
    _Pragma("diag_suppress=Pe137") \
    JSON_HEDLEY_DIAGNOSTIC_POP
#  else
#    define JSON_HEDLEY_CPP_CAST(T, expr) ((T) (expr))
#  endif
#else
#  define JSON_HEDLEY_CPP_CAST(T, expr) (expr)
#endif

#if defined(JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED)
    #undef JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED
#endif
#if JSON_HEDLEY_HAS_WARNING("-Wdeprecated-declarations")
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
#elif JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("warning(disable:1478 1786)")
#elif JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED __pragma(warning(disable:1478 1786))
#elif JSON_HEDLEY_PGI_VERSION_CHECK(20,7,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("diag_suppress 1215,1216,1444,1445")
#elif JSON_HEDLEY_PGI_VERSION_CHECK(17,10,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("diag_suppress 1215,1444")
#elif JSON_HEDLEY_GCC_VERSION_CHECK(4,3,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#elif JSON_HEDLEY_MSVC_VERSION_CHECK(15,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED __pragma(warning(disable:4996))
#elif JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("diag_suppress 1215,1444")
#elif \
    JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
    (JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,2,0) || \
    (JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,4,0) || \
    (JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,3,0) || \
    (JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,5,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("diag_suppress 1291,1718")
#elif JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,13,0) && !defined(__cplusplus)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("error_messages(off,E_DEPRECATED_ATT,E_DEPRECATED_ATT_MESS)")
#elif JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,13,0) && defined(__cplusplus)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("error_messages(off,symdeprecated,symdeprecated2)")
#elif JSON_HEDLEY_IAR_VERSION_CHECK(8,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("diag_suppress=Pe1444,Pe1215")
#elif JSON_HEDLEY_PELLES_VERSION_CHECK(2,90,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED _Pragma("warn(disable:2241)")
#else
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_DEPRECATED
#endif

#if defined(JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS)
    #undef JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS
#endif
#if JSON_HEDLEY_HAS_WARNING("-Wunknown-pragmas")
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("clang diagnostic ignored \"-Wunknown-pragmas\"")
#elif JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("warning(disable:161)")
#elif JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS __pragma(warning(disable:161))
#elif JSON_HEDLEY_PGI_VERSION_CHECK(17,10,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("diag_suppress 1675")
#elif JSON_HEDLEY_GCC_VERSION_CHECK(4,3,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("GCC diagnostic ignored \"-Wunknown-pragmas\"")
#elif JSON_HEDLEY_MSVC_VERSION_CHECK(15,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS __pragma(warning(disable:4068))
#elif \
    JSON_HEDLEY_TI_VERSION_CHECK(16,9,0) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(8,0,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,3,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("diag_suppress 163")
#elif JSON_HEDLEY_TI_CL6X_VERSION_CHECK(8,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("diag_suppress 163")
#elif JSON_HEDLEY_IAR_VERSION_CHECK(8,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("diag_suppress=Pe161")
#elif JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS _Pragma("diag_suppress 161")
#else
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS
#endif

#if defined(JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES)
    #undef JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES
#endif
#if JSON_HEDLEY_HAS_WARNING("-Wunknown-attributes")
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("clang diagnostic ignored \"-Wunknown-attributes\"")
#elif JSON_HEDLEY_GCC_VERSION_CHECK(4,6,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("GCC diagnostic ignored \"-Wdeprecated-declarations\"")
#elif JSON_HEDLEY_INTEL_VERSION_CHECK(17,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("warning(disable:1292)")
#elif JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES __pragma(warning(disable:1292))
#elif JSON_HEDLEY_MSVC_VERSION_CHECK(19,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES __pragma(warning(disable:5030))
#elif JSON_HEDLEY_PGI_VERSION_CHECK(20,7,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("diag_suppress 1097,1098")
#elif JSON_HEDLEY_PGI_VERSION_CHECK(17,10,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("diag_suppress 1097")
#elif JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,14,0) && defined(__cplusplus)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("error_messages(off,attrskipunsup)")
#elif \
    JSON_HEDLEY_TI_VERSION_CHECK(18,1,0) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(8,3,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("diag_suppress 1173")
#elif JSON_HEDLEY_IAR_VERSION_CHECK(8,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("diag_suppress=Pe1097")
#elif JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES _Pragma("diag_suppress 1097")
#else
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_CPP_ATTRIBUTES
#endif

#if defined(JSON_HEDLEY_DIAGNOSTIC_DISABLE_CAST_QUAL)
    #undef JSON_HEDLEY_DIAGNOSTIC_DISABLE_CAST_QUAL
#endif
#if JSON_HEDLEY_HAS_WARNING("-Wcast-qual")
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_CAST_QUAL _Pragma("clang diagnostic ignored \"-Wcast-qual\"")
#elif JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_CAST_QUAL _Pragma("warning(disable:2203 2331)")
#elif JSON_HEDLEY_GCC_VERSION_CHECK(3,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_CAST_QUAL _Pragma("GCC diagnostic ignored \"-Wcast-qual\"")
#else
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_CAST_QUAL
#endif

#if defined(JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION)
    #undef JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION
#endif
#if JSON_HEDLEY_HAS_WARNING("-Wunused-function")
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION _Pragma("clang diagnostic ignored \"-Wunused-function\"")
#elif JSON_HEDLEY_GCC_VERSION_CHECK(3,4,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION _Pragma("GCC diagnostic ignored \"-Wunused-function\"")
#elif JSON_HEDLEY_MSVC_VERSION_CHECK(1,0,0)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION __pragma(warning(disable:4505))
#elif JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION _Pragma("diag_suppress 3142")
#else
    #define JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNUSED_FUNCTION
#endif

#if defined(JSON_HEDLEY_DEPRECATED)
    #undef JSON_HEDLEY_DEPRECATED
#endif
#if defined(JSON_HEDLEY_DEPRECATED_FOR)
    #undef JSON_HEDLEY_DEPRECATED_FOR
#endif
#if \
    JSON_HEDLEY_MSVC_VERSION_CHECK(14,0,0) || \
    JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
    #define JSON_HEDLEY_DEPRECATED(since) __declspec(deprecated("Since " # since))
    #define JSON_HEDLEY_DEPRECATED_FOR(since, replacement) __declspec(deprecated("Since " #since "; use " #replacement))
#elif \
    (JSON_HEDLEY_HAS_EXTENSION(attribute_deprecated_with_message) && !defined(JSON_HEDLEY_IAR_VERSION)) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(4,5,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(5,6,0) || \
    JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,13,0) || \
    JSON_HEDLEY_PGI_VERSION_CHECK(17,10,0) || \
    JSON_HEDLEY_TI_VERSION_CHECK(18,1,0) || \
    JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(18,1,0) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(8,3,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,3,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_DEPRECATED(since) __attribute__((__deprecated__("Since " #since)))
    #define JSON_HEDLEY_DEPRECATED_FOR(since, replacement) __attribute__((__deprecated__("Since " #since "; use " #replacement)))
#elif defined(__cplusplus) && (__cplusplus >= 201402L)
    #define JSON_HEDLEY_DEPRECATED(since) JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[deprecated("Since " #since)]])
    #define JSON_HEDLEY_DEPRECATED_FOR(since, replacement) JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[deprecated("Since " #since "; use " #replacement)]])
#elif \
    JSON_HEDLEY_HAS_ATTRIBUTE(deprecated) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(3,1,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
    JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
    (JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,2,0) || \
    (JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,4,0) || \
    (JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,3,0) || \
    (JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,5,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10) || \
    JSON_HEDLEY_IAR_VERSION_CHECK(8,10,0)
    #define JSON_HEDLEY_DEPRECATED(since) __attribute__((__deprecated__))
    #define JSON_HEDLEY_DEPRECATED_FOR(since, replacement) __attribute__((__deprecated__))
#elif \
    JSON_HEDLEY_MSVC_VERSION_CHECK(13,10,0) || \
    JSON_HEDLEY_PELLES_VERSION_CHECK(6,50,0) || \
    JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
    #define JSON_HEDLEY_DEPRECATED(since) __declspec(deprecated)
    #define JSON_HEDLEY_DEPRECATED_FOR(since, replacement) __declspec(deprecated)
#elif JSON_HEDLEY_IAR_VERSION_CHECK(8,0,0)
    #define JSON_HEDLEY_DEPRECATED(since) _Pragma("deprecated")
    #define JSON_HEDLEY_DEPRECATED_FOR(since, replacement) _Pragma("deprecated")
#else
    #define JSON_HEDLEY_DEPRECATED(since)
    #define JSON_HEDLEY_DEPRECATED_FOR(since, replacement)
#endif

#if defined(JSON_HEDLEY_UNAVAILABLE)
    #undef JSON_HEDLEY_UNAVAILABLE
#endif
#if \
    JSON_HEDLEY_HAS_ATTRIBUTE(warning) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(4,3,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_UNAVAILABLE(available_since) __attribute__((__warning__("Not available until " #available_since)))
#else
    #define JSON_HEDLEY_UNAVAILABLE(available_since)
#endif

#if defined(JSON_HEDLEY_WARN_UNUSED_RESULT)
    #undef JSON_HEDLEY_WARN_UNUSED_RESULT
#endif
#if defined(JSON_HEDLEY_WARN_UNUSED_RESULT_MSG)
    #undef JSON_HEDLEY_WARN_UNUSED_RESULT_MSG
#endif
#if \
    JSON_HEDLEY_HAS_ATTRIBUTE(warn_unused_result) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(3,4,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
    (JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,2,0) || \
    (JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,4,0) || \
    (JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,3,0) || \
    (JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,5,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) || \
    (JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,15,0) && defined(__cplusplus)) || \
    JSON_HEDLEY_PGI_VERSION_CHECK(17,10,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_WARN_UNUSED_RESULT __attribute__((__warn_unused_result__))
    #define JSON_HEDLEY_WARN_UNUSED_RESULT_MSG(msg) __attribute__((__warn_unused_result__))
#elif (JSON_HEDLEY_HAS_CPP_ATTRIBUTE(nodiscard) >= 201907L)
    #define JSON_HEDLEY_WARN_UNUSED_RESULT JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[nodiscard]])
    #define JSON_HEDLEY_WARN_UNUSED_RESULT_MSG(msg) JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[nodiscard(msg)]])
#elif JSON_HEDLEY_HAS_CPP_ATTRIBUTE(nodiscard)
    #define JSON_HEDLEY_WARN_UNUSED_RESULT JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[nodiscard]])
    #define JSON_HEDLEY_WARN_UNUSED_RESULT_MSG(msg) JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[nodiscard]])
#elif defined(_Check_return_) /* SAL */
    #define JSON_HEDLEY_WARN_UNUSED_RESULT _Check_return_
    #define JSON_HEDLEY_WARN_UNUSED_RESULT_MSG(msg) _Check_return_
#else
    #define JSON_HEDLEY_WARN_UNUSED_RESULT
    #define JSON_HEDLEY_WARN_UNUSED_RESULT_MSG(msg)
#endif

#if defined(JSON_HEDLEY_SENTINEL)
    #undef JSON_HEDLEY_SENTINEL
#endif
#if \
    JSON_HEDLEY_HAS_ATTRIBUTE(sentinel) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(4,0,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(5,4,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_SENTINEL(position) __attribute__((__sentinel__(position)))
#else
    #define JSON_HEDLEY_SENTINEL(position)
#endif

#if defined(JSON_HEDLEY_NO_RETURN)
    #undef JSON_HEDLEY_NO_RETURN
#endif
#if JSON_HEDLEY_IAR_VERSION_CHECK(8,0,0)
    #define JSON_HEDLEY_NO_RETURN __noreturn
#elif \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_NO_RETURN __attribute__((__noreturn__))
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    #define JSON_HEDLEY_NO_RETURN _Noreturn
#elif defined(__cplusplus) && (__cplusplus >= 201103L)
    #define JSON_HEDLEY_NO_RETURN JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[noreturn]])
#elif \
    JSON_HEDLEY_HAS_ATTRIBUTE(noreturn) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(3,2,0) || \
    JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,11,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
    JSON_HEDLEY_IBM_VERSION_CHECK(10,1,0) || \
    JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
    (JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,2,0) || \
    (JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,4,0) || \
    (JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,3,0) || \
    (JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,5,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) || \
    JSON_HEDLEY_IAR_VERSION_CHECK(8,10,0)
    #define JSON_HEDLEY_NO_RETURN __attribute__((__noreturn__))
#elif JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,10,0)
    #define JSON_HEDLEY_NO_RETURN _Pragma("does_not_return")
#elif \
    JSON_HEDLEY_MSVC_VERSION_CHECK(13,10,0) || \
    JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
    #define JSON_HEDLEY_NO_RETURN __declspec(noreturn)
#elif JSON_HEDLEY_TI_CL6X_VERSION_CHECK(6,0,0) && defined(__cplusplus)
    #define JSON_HEDLEY_NO_RETURN _Pragma("FUNC_NEVER_RETURNS;")
#elif JSON_HEDLEY_COMPCERT_VERSION_CHECK(3,2,0)
    #define JSON_HEDLEY_NO_RETURN __attribute((noreturn))
#elif JSON_HEDLEY_PELLES_VERSION_CHECK(9,0,0)
    #define JSON_HEDLEY_NO_RETURN __declspec(noreturn)
#else
    #define JSON_HEDLEY_NO_RETURN
#endif

#if defined(JSON_HEDLEY_NO_ESCAPE)
    #undef JSON_HEDLEY_NO_ESCAPE
#endif
#if JSON_HEDLEY_HAS_ATTRIBUTE(noescape)
    #define JSON_HEDLEY_NO_ESCAPE __attribute__((__noescape__))
#else
    #define JSON_HEDLEY_NO_ESCAPE
#endif

#if defined(JSON_HEDLEY_UNREACHABLE)
    #undef JSON_HEDLEY_UNREACHABLE
#endif
#if defined(JSON_HEDLEY_UNREACHABLE_RETURN)
    #undef JSON_HEDLEY_UNREACHABLE_RETURN
#endif
#if defined(JSON_HEDLEY_ASSUME)
    #undef JSON_HEDLEY_ASSUME
#endif
#if \
    JSON_HEDLEY_MSVC_VERSION_CHECK(13,10,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
    #define JSON_HEDLEY_ASSUME(expr) __assume(expr)
#elif JSON_HEDLEY_HAS_BUILTIN(__builtin_assume)
    #define JSON_HEDLEY_ASSUME(expr) __builtin_assume(expr)
#elif \
    JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,2,0) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(4,0,0)
    #if defined(__cplusplus)
        #define JSON_HEDLEY_ASSUME(expr) std::_nassert(expr)
    #else
        #define JSON_HEDLEY_ASSUME(expr) _nassert(expr)
    #endif
#endif
#if \
    (JSON_HEDLEY_HAS_BUILTIN(__builtin_unreachable) && (!defined(JSON_HEDLEY_ARM_VERSION))) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(4,5,0) || \
    JSON_HEDLEY_PGI_VERSION_CHECK(18,10,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_IBM_VERSION_CHECK(13,1,5) || \
    JSON_HEDLEY_CRAY_VERSION_CHECK(10,0,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_UNREACHABLE() __builtin_unreachable()
#elif defined(JSON_HEDLEY_ASSUME)
    #define JSON_HEDLEY_UNREACHABLE() JSON_HEDLEY_ASSUME(0)
#endif
#if !defined(JSON_HEDLEY_ASSUME)
    #if defined(JSON_HEDLEY_UNREACHABLE)
        #define JSON_HEDLEY_ASSUME(expr) JSON_HEDLEY_STATIC_CAST(void, ((expr) ? 1 : (JSON_HEDLEY_UNREACHABLE(), 1)))
    #else
        #define JSON_HEDLEY_ASSUME(expr) JSON_HEDLEY_STATIC_CAST(void, expr)
    #endif
#endif
#if defined(JSON_HEDLEY_UNREACHABLE)
    #if  \
        JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,2,0) || \
        JSON_HEDLEY_TI_CL6X_VERSION_CHECK(4,0,0)
        #define JSON_HEDLEY_UNREACHABLE_RETURN(value) return (JSON_HEDLEY_STATIC_CAST(void, JSON_HEDLEY_ASSUME(0)), (value))
    #else
        #define JSON_HEDLEY_UNREACHABLE_RETURN(value) JSON_HEDLEY_UNREACHABLE()
    #endif
#else
    #define JSON_HEDLEY_UNREACHABLE_RETURN(value) return (value)
#endif
#if !defined(JSON_HEDLEY_UNREACHABLE)
    #define JSON_HEDLEY_UNREACHABLE() JSON_HEDLEY_ASSUME(0)
#endif

JSON_HEDLEY_DIAGNOSTIC_PUSH
#if JSON_HEDLEY_HAS_WARNING("-Wpedantic")
    #pragma clang diagnostic ignored "-Wpedantic"
#endif
#if JSON_HEDLEY_HAS_WARNING("-Wc++98-compat-pedantic") && defined(__cplusplus)
    #pragma clang diagnostic ignored "-Wc++98-compat-pedantic"
#endif
#if JSON_HEDLEY_GCC_HAS_WARNING("-Wvariadic-macros",4,0,0)
    #if defined(__clang__)
        #pragma clang diagnostic ignored "-Wvariadic-macros"
    #elif defined(JSON_HEDLEY_GCC_VERSION)
        #pragma GCC diagnostic ignored "-Wvariadic-macros"
    #endif
#endif
#if defined(JSON_HEDLEY_NON_NULL)
    #undef JSON_HEDLEY_NON_NULL
#endif
#if \
    JSON_HEDLEY_HAS_ATTRIBUTE(nonnull) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(3,3,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0)
    #define JSON_HEDLEY_NON_NULL(...) __attribute__((__nonnull__(__VA_ARGS__)))
#else
    #define JSON_HEDLEY_NON_NULL(...)
#endif
JSON_HEDLEY_DIAGNOSTIC_POP

#if defined(JSON_HEDLEY_PRINTF_FORMAT)
    #undef JSON_HEDLEY_PRINTF_FORMAT
#endif
#if defined(__MINGW32__) && JSON_HEDLEY_GCC_HAS_ATTRIBUTE(format,4,4,0) && !defined(__USE_MINGW_ANSI_STDIO)
    #define JSON_HEDLEY_PRINTF_FORMAT(string_idx,first_to_check) __attribute__((__format__(ms_printf, string_idx, first_to_check)))
#elif defined(__MINGW32__) && JSON_HEDLEY_GCC_HAS_ATTRIBUTE(format,4,4,0) && defined(__USE_MINGW_ANSI_STDIO)
    #define JSON_HEDLEY_PRINTF_FORMAT(string_idx,first_to_check) __attribute__((__format__(gnu_printf, string_idx, first_to_check)))
#elif \
    JSON_HEDLEY_HAS_ATTRIBUTE(format) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(3,1,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(5,6,0) || \
    JSON_HEDLEY_IBM_VERSION_CHECK(10,1,0) || \
    JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
    (JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,2,0) || \
    (JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,4,0) || \
    (JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,3,0) || \
    (JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,5,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_PRINTF_FORMAT(string_idx,first_to_check) __attribute__((__format__(__printf__, string_idx, first_to_check)))
#elif JSON_HEDLEY_PELLES_VERSION_CHECK(6,0,0)
    #define JSON_HEDLEY_PRINTF_FORMAT(string_idx,first_to_check) __declspec(vaformat(printf,string_idx,first_to_check))
#else
    #define JSON_HEDLEY_PRINTF_FORMAT(string_idx,first_to_check)
#endif

#if defined(JSON_HEDLEY_CONSTEXPR)
    #undef JSON_HEDLEY_CONSTEXPR
#endif
#if defined(__cplusplus)
    #if __cplusplus >= 201103L
        #define JSON_HEDLEY_CONSTEXPR JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(constexpr)
    #endif
#endif
#if !defined(JSON_HEDLEY_CONSTEXPR)
    #define JSON_HEDLEY_CONSTEXPR
#endif

#if defined(JSON_HEDLEY_PREDICT)
    #undef JSON_HEDLEY_PREDICT
#endif
#if defined(JSON_HEDLEY_LIKELY)
    #undef JSON_HEDLEY_LIKELY
#endif
#if defined(JSON_HEDLEY_UNLIKELY)
    #undef JSON_HEDLEY_UNLIKELY
#endif
#if defined(JSON_HEDLEY_UNPREDICTABLE)
    #undef JSON_HEDLEY_UNPREDICTABLE
#endif
#if JSON_HEDLEY_HAS_BUILTIN(__builtin_unpredictable)
    #define JSON_HEDLEY_UNPREDICTABLE(expr) __builtin_unpredictable((expr))
#endif
#if \
  (JSON_HEDLEY_HAS_BUILTIN(__builtin_expect_with_probability) && !defined(JSON_HEDLEY_PGI_VERSION)) || \
  JSON_HEDLEY_GCC_VERSION_CHECK(9,0,0) || \
  JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
#  define JSON_HEDLEY_PREDICT(expr, value, probability) __builtin_expect_with_probability(  (expr), (value), (probability))
#  define JSON_HEDLEY_PREDICT_TRUE(expr, probability)   __builtin_expect_with_probability(!!(expr),    1   , (probability))
#  define JSON_HEDLEY_PREDICT_FALSE(expr, probability)  __builtin_expect_with_probability(!!(expr),    0   , (probability))
#  define JSON_HEDLEY_LIKELY(expr)                      __builtin_expect                 (!!(expr),    1                  )
#  define JSON_HEDLEY_UNLIKELY(expr)                    __builtin_expect                 (!!(expr),    0                  )
#elif \
  (JSON_HEDLEY_HAS_BUILTIN(__builtin_expect) && !defined(JSON_HEDLEY_INTEL_CL_VERSION)) || \
  JSON_HEDLEY_GCC_VERSION_CHECK(3,0,0) || \
  JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
  (JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,15,0) && defined(__cplusplus)) || \
  JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
  JSON_HEDLEY_IBM_VERSION_CHECK(10,1,0) || \
  JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
  JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(4,7,0) || \
  JSON_HEDLEY_TI_CL430_VERSION_CHECK(3,1,0) || \
  JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,1,0) || \
  JSON_HEDLEY_TI_CL6X_VERSION_CHECK(6,1,0) || \
  JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
  JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  JSON_HEDLEY_TINYC_VERSION_CHECK(0,9,27) || \
  JSON_HEDLEY_CRAY_VERSION_CHECK(8,1,0) || \
  JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
#  define JSON_HEDLEY_PREDICT(expr, expected, probability) \
    (((probability) >= 0.9) ? __builtin_expect((expr), (expected)) : (JSON_HEDLEY_STATIC_CAST(void, expected), (expr)))
#  define JSON_HEDLEY_PREDICT_TRUE(expr, probability) \
    (__extension__ ({ \
        double hedley_probability_ = (probability); \
        ((hedley_probability_ >= 0.9) ? __builtin_expect(!!(expr), 1) : ((hedley_probability_ <= 0.1) ? __builtin_expect(!!(expr), 0) : !!(expr))); \
    }))
#  define JSON_HEDLEY_PREDICT_FALSE(expr, probability) \
    (__extension__ ({ \
        double hedley_probability_ = (probability); \
        ((hedley_probability_ >= 0.9) ? __builtin_expect(!!(expr), 0) : ((hedley_probability_ <= 0.1) ? __builtin_expect(!!(expr), 1) : !!(expr))); \
    }))
#  define JSON_HEDLEY_LIKELY(expr)   __builtin_expect(!!(expr), 1)
#  define JSON_HEDLEY_UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#else
#  define JSON_HEDLEY_PREDICT(expr, expected, probability) (JSON_HEDLEY_STATIC_CAST(void, expected), (expr))
#  define JSON_HEDLEY_PREDICT_TRUE(expr, probability) (!!(expr))
#  define JSON_HEDLEY_PREDICT_FALSE(expr, probability) (!!(expr))
#  define JSON_HEDLEY_LIKELY(expr) (!!(expr))
#  define JSON_HEDLEY_UNLIKELY(expr) (!!(expr))
#endif
#if !defined(JSON_HEDLEY_UNPREDICTABLE)
    #define JSON_HEDLEY_UNPREDICTABLE(expr) JSON_HEDLEY_PREDICT(expr, 1, 0.5)
#endif

#if defined(JSON_HEDLEY_MALLOC)
    #undef JSON_HEDLEY_MALLOC
#endif
#if \
    JSON_HEDLEY_HAS_ATTRIBUTE(malloc) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(3,1,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,11,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
    JSON_HEDLEY_IBM_VERSION_CHECK(12,1,0) || \
    JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
    (JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,2,0) || \
    (JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,4,0) || \
    (JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,3,0) || \
    (JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,5,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_MALLOC __attribute__((__malloc__))
#elif JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,10,0)
    #define JSON_HEDLEY_MALLOC _Pragma("returns_new_memory")
#elif \
    JSON_HEDLEY_MSVC_VERSION_CHECK(14,0,0) || \
    JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
    #define JSON_HEDLEY_MALLOC __declspec(restrict)
#else
    #define JSON_HEDLEY_MALLOC
#endif

#if defined(JSON_HEDLEY_PURE)
    #undef JSON_HEDLEY_PURE
#endif
#if \
  JSON_HEDLEY_HAS_ATTRIBUTE(pure) || \
  JSON_HEDLEY_GCC_VERSION_CHECK(2,96,0) || \
  JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
  JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,11,0) || \
  JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
  JSON_HEDLEY_IBM_VERSION_CHECK(10,1,0) || \
  JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
  (JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,2,0) || \
  (JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,4,0) || \
  (JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,3,0) || \
  (JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,5,0) || \
  JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
  JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  JSON_HEDLEY_PGI_VERSION_CHECK(17,10,0) || \
  JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
#  define JSON_HEDLEY_PURE __attribute__((__pure__))
#elif JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,10,0)
#  define JSON_HEDLEY_PURE _Pragma("does_not_write_global_data")
#elif defined(__cplusplus) && \
    ( \
      JSON_HEDLEY_TI_CL430_VERSION_CHECK(2,0,1) || \
      JSON_HEDLEY_TI_CL6X_VERSION_CHECK(4,0,0) || \
      JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) \
    )
#  define JSON_HEDLEY_PURE _Pragma("FUNC_IS_PURE;")
#else
#  define JSON_HEDLEY_PURE
#endif

#if defined(JSON_HEDLEY_CONST)
    #undef JSON_HEDLEY_CONST
#endif
#if \
    JSON_HEDLEY_HAS_ATTRIBUTE(const) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(2,5,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,11,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
    JSON_HEDLEY_IBM_VERSION_CHECK(10,1,0) || \
    JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
    (JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,2,0) || \
    (JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,4,0) || \
    (JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,3,0) || \
    (JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,5,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) || \
    JSON_HEDLEY_PGI_VERSION_CHECK(17,10,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_CONST __attribute__((__const__))
#elif \
    JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,10,0)
    #define JSON_HEDLEY_CONST _Pragma("no_side_effect")
#else
    #define JSON_HEDLEY_CONST JSON_HEDLEY_PURE
#endif

#if defined(JSON_HEDLEY_RESTRICT)
    #undef JSON_HEDLEY_RESTRICT
#endif
#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && !defined(__cplusplus)
    #define JSON_HEDLEY_RESTRICT restrict
#elif \
    JSON_HEDLEY_GCC_VERSION_CHECK(3,1,0) || \
    JSON_HEDLEY_MSVC_VERSION_CHECK(14,0,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
    JSON_HEDLEY_IBM_VERSION_CHECK(10,1,0) || \
    JSON_HEDLEY_PGI_VERSION_CHECK(17,10,0) || \
    JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,3,0) || \
    JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,2,4) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(8,1,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    (JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,14,0) && defined(__cplusplus)) || \
    JSON_HEDLEY_IAR_VERSION_CHECK(8,0,0) || \
    defined(__clang__) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_RESTRICT __restrict
#elif JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,3,0) && !defined(__cplusplus)
    #define JSON_HEDLEY_RESTRICT _Restrict
#else
    #define JSON_HEDLEY_RESTRICT
#endif

#if defined(JSON_HEDLEY_INLINE)
    #undef JSON_HEDLEY_INLINE
#endif
#if \
    (defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L)) || \
    (defined(__cplusplus) && (__cplusplus >= 199711L))
    #define JSON_HEDLEY_INLINE inline
#elif \
    defined(JSON_HEDLEY_GCC_VERSION) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(6,2,0)
    #define JSON_HEDLEY_INLINE __inline__
#elif \
    JSON_HEDLEY_MSVC_VERSION_CHECK(12,0,0) || \
    JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
    JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,1,0) || \
    JSON_HEDLEY_TI_CL430_VERSION_CHECK(3,1,0) || \
    JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,2,0) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(8,0,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_INLINE __inline
#else
    #define JSON_HEDLEY_INLINE
#endif

#if defined(JSON_HEDLEY_ALWAYS_INLINE)
    #undef JSON_HEDLEY_ALWAYS_INLINE
#endif
#if \
  JSON_HEDLEY_HAS_ATTRIBUTE(always_inline) || \
  JSON_HEDLEY_GCC_VERSION_CHECK(4,0,0) || \
  JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
  JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,11,0) || \
  JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
  JSON_HEDLEY_IBM_VERSION_CHECK(10,1,0) || \
  JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
  (JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,2,0) || \
  (JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,4,0) || \
  (JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,3,0) || \
  (JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
  JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,5,0) || \
  JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
  JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) || \
  JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10) || \
  JSON_HEDLEY_IAR_VERSION_CHECK(8,10,0)
#  define JSON_HEDLEY_ALWAYS_INLINE __attribute__((__always_inline__)) JSON_HEDLEY_INLINE
#elif \
  JSON_HEDLEY_MSVC_VERSION_CHECK(12,0,0) || \
  JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define JSON_HEDLEY_ALWAYS_INLINE __forceinline
#elif defined(__cplusplus) && \
    ( \
      JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,2,0) || \
      JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,3,0) || \
      JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,4,0) || \
      JSON_HEDLEY_TI_CL6X_VERSION_CHECK(6,1,0) || \
      JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
      JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) \
    )
#  define JSON_HEDLEY_ALWAYS_INLINE _Pragma("FUNC_ALWAYS_INLINE;")
#elif JSON_HEDLEY_IAR_VERSION_CHECK(8,0,0)
#  define JSON_HEDLEY_ALWAYS_INLINE _Pragma("inline=forced")
#else
#  define JSON_HEDLEY_ALWAYS_INLINE JSON_HEDLEY_INLINE
#endif

#if defined(JSON_HEDLEY_NEVER_INLINE)
    #undef JSON_HEDLEY_NEVER_INLINE
#endif
#if \
    JSON_HEDLEY_HAS_ATTRIBUTE(noinline) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(4,0,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,11,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
    JSON_HEDLEY_IBM_VERSION_CHECK(10,1,0) || \
    JSON_HEDLEY_TI_VERSION_CHECK(15,12,0) || \
    (JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(4,8,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_ARMCL_VERSION_CHECK(5,2,0) || \
    (JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL2000_VERSION_CHECK(6,4,0) || \
    (JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,0,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL430_VERSION_CHECK(4,3,0) || \
    (JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,5,0) || \
    JSON_HEDLEY_TI_CL7X_VERSION_CHECK(1,2,0) || \
    JSON_HEDLEY_TI_CLPRU_VERSION_CHECK(2,1,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10) || \
    JSON_HEDLEY_IAR_VERSION_CHECK(8,10,0)
    #define JSON_HEDLEY_NEVER_INLINE __attribute__((__noinline__))
#elif \
    JSON_HEDLEY_MSVC_VERSION_CHECK(13,10,0) || \
    JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
    #define JSON_HEDLEY_NEVER_INLINE __declspec(noinline)
#elif JSON_HEDLEY_PGI_VERSION_CHECK(10,2,0)
    #define JSON_HEDLEY_NEVER_INLINE _Pragma("noinline")
#elif JSON_HEDLEY_TI_CL6X_VERSION_CHECK(6,0,0) && defined(__cplusplus)
    #define JSON_HEDLEY_NEVER_INLINE _Pragma("FUNC_CANNOT_INLINE;")
#elif JSON_HEDLEY_IAR_VERSION_CHECK(8,0,0)
    #define JSON_HEDLEY_NEVER_INLINE _Pragma("inline=never")
#elif JSON_HEDLEY_COMPCERT_VERSION_CHECK(3,2,0)
    #define JSON_HEDLEY_NEVER_INLINE __attribute((noinline))
#elif JSON_HEDLEY_PELLES_VERSION_CHECK(9,0,0)
    #define JSON_HEDLEY_NEVER_INLINE __declspec(noinline)
#else
    #define JSON_HEDLEY_NEVER_INLINE
#endif

#if defined(JSON_HEDLEY_PRIVATE)
    #undef JSON_HEDLEY_PRIVATE
#endif
#if defined(JSON_HEDLEY_PUBLIC)
    #undef JSON_HEDLEY_PUBLIC
#endif
#if defined(JSON_HEDLEY_IMPORT)
    #undef JSON_HEDLEY_IMPORT
#endif
#if defined(_WIN32) || defined(__CYGWIN__)
#  define JSON_HEDLEY_PRIVATE
#  define JSON_HEDLEY_PUBLIC   __declspec(dllexport)
#  define JSON_HEDLEY_IMPORT   __declspec(dllimport)
#else
#  if \
    JSON_HEDLEY_HAS_ATTRIBUTE(visibility) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(3,3,0) || \
    JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,11,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
    JSON_HEDLEY_IBM_VERSION_CHECK(13,1,0) || \
    ( \
      defined(__TI_EABI__) && \
      ( \
        (JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,2,0) && defined(__TI_GNU_ATTRIBUTE_SUPPORT__)) || \
        JSON_HEDLEY_TI_CL6X_VERSION_CHECK(7,5,0) \
      ) \
    ) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
#    define JSON_HEDLEY_PRIVATE __attribute__((__visibility__("hidden")))
#    define JSON_HEDLEY_PUBLIC  __attribute__((__visibility__("default")))
#  else
#    define JSON_HEDLEY_PRIVATE
#    define JSON_HEDLEY_PUBLIC
#  endif
#  define JSON_HEDLEY_IMPORT    extern
#endif

#if defined(JSON_HEDLEY_NO_THROW)
    #undef JSON_HEDLEY_NO_THROW
#endif
#if \
    JSON_HEDLEY_HAS_ATTRIBUTE(nothrow) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(3,3,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_NO_THROW __attribute__((__nothrow__))
#elif \
    JSON_HEDLEY_MSVC_VERSION_CHECK(13,1,0) || \
    JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0)
    #define JSON_HEDLEY_NO_THROW __declspec(nothrow)
#else
    #define JSON_HEDLEY_NO_THROW
#endif

#if defined(JSON_HEDLEY_FALL_THROUGH)
    #undef JSON_HEDLEY_FALL_THROUGH
#endif
#if \
    JSON_HEDLEY_HAS_ATTRIBUTE(fallthrough) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(7,0,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_FALL_THROUGH __attribute__((__fallthrough__))
#elif JSON_HEDLEY_HAS_CPP_ATTRIBUTE_NS(clang,fallthrough)
    #define JSON_HEDLEY_FALL_THROUGH JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[clang::fallthrough]])
#elif JSON_HEDLEY_HAS_CPP_ATTRIBUTE(fallthrough)
    #define JSON_HEDLEY_FALL_THROUGH JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_([[fallthrough]])
#elif defined(__fallthrough) /* SAL */
    #define JSON_HEDLEY_FALL_THROUGH __fallthrough
#else
    #define JSON_HEDLEY_FALL_THROUGH
#endif

#if defined(JSON_HEDLEY_RETURNS_NON_NULL)
    #undef JSON_HEDLEY_RETURNS_NON_NULL
#endif
#if \
    JSON_HEDLEY_HAS_ATTRIBUTE(returns_nonnull) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(4,9,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_RETURNS_NON_NULL __attribute__((__returns_nonnull__))
#elif defined(_Ret_notnull_) /* SAL */
    #define JSON_HEDLEY_RETURNS_NON_NULL _Ret_notnull_
#else
    #define JSON_HEDLEY_RETURNS_NON_NULL
#endif

#if defined(JSON_HEDLEY_ARRAY_PARAM)
    #undef JSON_HEDLEY_ARRAY_PARAM
#endif
#if \
    defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901L) && \
    !defined(__STDC_NO_VLA__) && \
    !defined(__cplusplus) && \
    !defined(JSON_HEDLEY_PGI_VERSION) && \
    !defined(JSON_HEDLEY_TINYC_VERSION)
    #define JSON_HEDLEY_ARRAY_PARAM(name) (name)
#else
    #define JSON_HEDLEY_ARRAY_PARAM(name)
#endif

#if defined(JSON_HEDLEY_IS_CONSTANT)
    #undef JSON_HEDLEY_IS_CONSTANT
#endif
#if defined(JSON_HEDLEY_REQUIRE_CONSTEXPR)
    #undef JSON_HEDLEY_REQUIRE_CONSTEXPR
#endif
/* JSON_HEDLEY_IS_CONSTEXPR_ is for
   HEDLEY INTERNAL USE ONLY.  API subject to change without notice. */
#if defined(JSON_HEDLEY_IS_CONSTEXPR_)
    #undef JSON_HEDLEY_IS_CONSTEXPR_
#endif
#if \
    JSON_HEDLEY_HAS_BUILTIN(__builtin_constant_p) || \
    JSON_HEDLEY_GCC_VERSION_CHECK(3,4,0) || \
    JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
    JSON_HEDLEY_TINYC_VERSION_CHECK(0,9,19) || \
    JSON_HEDLEY_ARM_VERSION_CHECK(4,1,0) || \
    JSON_HEDLEY_IBM_VERSION_CHECK(13,1,0) || \
    JSON_HEDLEY_TI_CL6X_VERSION_CHECK(6,1,0) || \
    (JSON_HEDLEY_SUNPRO_VERSION_CHECK(5,10,0) && !defined(__cplusplus)) || \
    JSON_HEDLEY_CRAY_VERSION_CHECK(8,1,0) || \
    JSON_HEDLEY_MCST_LCC_VERSION_CHECK(1,25,10)
    #define JSON_HEDLEY_IS_CONSTANT(expr) __builtin_constant_p(expr)
#endif
#if !defined(__cplusplus)
#  if \
       JSON_HEDLEY_HAS_BUILTIN(__builtin_types_compatible_p) || \
       JSON_HEDLEY_GCC_VERSION_CHECK(3,4,0) || \
       JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
       JSON_HEDLEY_IBM_VERSION_CHECK(13,1,0) || \
       JSON_HEDLEY_CRAY_VERSION_CHECK(8,1,0) || \
       JSON_HEDLEY_ARM_VERSION_CHECK(5,4,0) || \
       JSON_HEDLEY_TINYC_VERSION_CHECK(0,9,24)
#if defined(__INTPTR_TYPE__)
    #define JSON_HEDLEY_IS_CONSTEXPR_(expr) __builtin_types_compatible_p(__typeof__((1 ? (void*) ((__INTPTR_TYPE__) ((expr) * 0)) : (int*) 0)), int*)
#else
    #include <stdint.h>
    #define JSON_HEDLEY_IS_CONSTEXPR_(expr) __builtin_types_compatible_p(__typeof__((1 ? (void*) ((intptr_t) ((expr) * 0)) : (int*) 0)), int*)
#endif
#  elif \
       ( \
          defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L) && \
          !defined(JSON_HEDLEY_SUNPRO_VERSION) && \
          !defined(JSON_HEDLEY_PGI_VERSION) && \
          !defined(JSON_HEDLEY_IAR_VERSION)) || \
       (JSON_HEDLEY_HAS_EXTENSION(c_generic_selections) && !defined(JSON_HEDLEY_IAR_VERSION)) || \
       JSON_HEDLEY_GCC_VERSION_CHECK(4,9,0) || \
       JSON_HEDLEY_INTEL_VERSION_CHECK(17,0,0) || \
       JSON_HEDLEY_IBM_VERSION_CHECK(12,1,0) || \
       JSON_HEDLEY_ARM_VERSION_CHECK(5,3,0)
#if defined(__INTPTR_TYPE__)
    #define JSON_HEDLEY_IS_CONSTEXPR_(expr) _Generic((1 ? (void*) ((__INTPTR_TYPE__) ((expr) * 0)) : (int*) 0), int*: 1, void*: 0)
#else
    #include <stdint.h>
    #define JSON_HEDLEY_IS_CONSTEXPR_(expr) _Generic((1 ? (void*) ((intptr_t) * 0) : (int*) 0), int*: 1, void*: 0)
#endif
#  elif \
       defined(JSON_HEDLEY_GCC_VERSION) || \
       defined(JSON_HEDLEY_INTEL_VERSION) || \
       defined(JSON_HEDLEY_TINYC_VERSION) || \
       defined(JSON_HEDLEY_TI_ARMCL_VERSION) || \
       JSON_HEDLEY_TI_CL430_VERSION_CHECK(18,12,0) || \
       defined(JSON_HEDLEY_TI_CL2000_VERSION) || \
       defined(JSON_HEDLEY_TI_CL6X_VERSION) || \
       defined(JSON_HEDLEY_TI_CL7X_VERSION) || \
       defined(JSON_HEDLEY_TI_CLPRU_VERSION) || \
       defined(__clang__)
#    define JSON_HEDLEY_IS_CONSTEXPR_(expr) ( \
        sizeof(void) != \
        sizeof(*( \
                  1 ? \
                  ((void*) ((expr) * 0L) ) : \
((struct { char v[sizeof(void) * 2]; } *) 1) \
                ) \
              ) \
                                            )
#  endif
#endif
#if defined(JSON_HEDLEY_IS_CONSTEXPR_)
    #if !defined(JSON_HEDLEY_IS_CONSTANT)
        #define JSON_HEDLEY_IS_CONSTANT(expr) JSON_HEDLEY_IS_CONSTEXPR_(expr)
    #endif
    #define JSON_HEDLEY_REQUIRE_CONSTEXPR(expr) (JSON_HEDLEY_IS_CONSTEXPR_(expr) ? (expr) : (-1))
#else
    #if !defined(JSON_HEDLEY_IS_CONSTANT)
        #define JSON_HEDLEY_IS_CONSTANT(expr) (0)
    #endif
    #define JSON_HEDLEY_REQUIRE_CONSTEXPR(expr) (expr)
#endif

#if defined(JSON_HEDLEY_BEGIN_C_DECLS)
    #undef JSON_HEDLEY_BEGIN_C_DECLS
#endif
#if defined(JSON_HEDLEY_END_C_DECLS)
    #undef JSON_HEDLEY_END_C_DECLS
#endif
#if defined(JSON_HEDLEY_C_DECL)
    #undef JSON_HEDLEY_C_DECL
#endif
#if defined(__cplusplus)
    #define JSON_HEDLEY_BEGIN_C_DECLS extern "C" {
    #define JSON_HEDLEY_END_C_DECLS }
    #define JSON_HEDLEY_C_DECL extern "C"
#else
    #define JSON_HEDLEY_BEGIN_C_DECLS
    #define JSON_HEDLEY_END_C_DECLS
    #define JSON_HEDLEY_C_DECL
#endif

#if defined(JSON_HEDLEY_STATIC_ASSERT)
    #undef JSON_HEDLEY_STATIC_ASSERT
#endif
#if \
  !defined(__cplusplus) && ( \
      (defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)) || \
      (JSON_HEDLEY_HAS_FEATURE(c_static_assert) && !defined(JSON_HEDLEY_INTEL_CL_VERSION)) || \
      JSON_HEDLEY_GCC_VERSION_CHECK(6,0,0) || \
      JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0) || \
      defined(_Static_assert) \
    )
#  define JSON_HEDLEY_STATIC_ASSERT(expr, message) _Static_assert(expr, message)
#elif \
  (defined(__cplusplus) && (__cplusplus >= 201103L)) || \
  JSON_HEDLEY_MSVC_VERSION_CHECK(16,0,0) || \
  JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define JSON_HEDLEY_STATIC_ASSERT(expr, message) JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(static_assert(expr, message))
#else
#  define JSON_HEDLEY_STATIC_ASSERT(expr, message)
#endif

#if defined(JSON_HEDLEY_NULL)
    #undef JSON_HEDLEY_NULL
#endif
#if defined(__cplusplus)
    #if __cplusplus >= 201103L
        #define JSON_HEDLEY_NULL JSON_HEDLEY_DIAGNOSTIC_DISABLE_CPP98_COMPAT_WRAP_(nullptr)
    #elif defined(NULL)
        #define JSON_HEDLEY_NULL NULL
    #else
        #define JSON_HEDLEY_NULL JSON_HEDLEY_STATIC_CAST(void*, 0)
    #endif
#elif defined(NULL)
    #define JSON_HEDLEY_NULL NULL
#else
    #define JSON_HEDLEY_NULL ((void*) 0)
#endif

#if defined(JSON_HEDLEY_MESSAGE)
    #undef JSON_HEDLEY_MESSAGE
#endif
#if JSON_HEDLEY_HAS_WARNING("-Wunknown-pragmas")
#  define JSON_HEDLEY_MESSAGE(msg) \
    JSON_HEDLEY_DIAGNOSTIC_PUSH \
    JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS \
    JSON_HEDLEY_PRAGMA(message msg) \
    JSON_HEDLEY_DIAGNOSTIC_POP
#elif \
  JSON_HEDLEY_GCC_VERSION_CHECK(4,4,0) || \
  JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0)
#  define JSON_HEDLEY_MESSAGE(msg) JSON_HEDLEY_PRAGMA(message msg)
#elif JSON_HEDLEY_CRAY_VERSION_CHECK(5,0,0)
#  define JSON_HEDLEY_MESSAGE(msg) JSON_HEDLEY_PRAGMA(_CRI message msg)
#elif JSON_HEDLEY_IAR_VERSION_CHECK(8,0,0)
#  define JSON_HEDLEY_MESSAGE(msg) JSON_HEDLEY_PRAGMA(message(msg))
#elif JSON_HEDLEY_PELLES_VERSION_CHECK(2,0,0)
#  define JSON_HEDLEY_MESSAGE(msg) JSON_HEDLEY_PRAGMA(message(msg))
#else
#  define JSON_HEDLEY_MESSAGE(msg)
#endif

#if defined(JSON_HEDLEY_WARNING)
    #undef JSON_HEDLEY_WARNING
#endif
#if JSON_HEDLEY_HAS_WARNING("-Wunknown-pragmas")
#  define JSON_HEDLEY_WARNING(msg) \
    JSON_HEDLEY_DIAGNOSTIC_PUSH \
    JSON_HEDLEY_DIAGNOSTIC_DISABLE_UNKNOWN_PRAGMAS \
    JSON_HEDLEY_PRAGMA(clang warning msg) \
    JSON_HEDLEY_DIAGNOSTIC_POP
#elif \
  JSON_HEDLEY_GCC_VERSION_CHECK(4,8,0) || \
  JSON_HEDLEY_PGI_VERSION_CHECK(18,4,0) || \
  JSON_HEDLEY_INTEL_VERSION_CHECK(13,0,0)
#  define JSON_HEDLEY_WARNING(msg) JSON_HEDLEY_PRAGMA(GCC warning msg)
#elif \
  JSON_HEDLEY_MSVC_VERSION_CHECK(15,0,0) || \
  JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
#  define JSON_HEDLEY_WARNING(msg) JSON_HEDLEY_PRAGMA(message(msg))
#else
#  define JSON_HEDLEY_WARNING(msg) JSON_HEDLEY_MESSAGE(msg)
#endif

#if defined(JSON_HEDLEY_REQUIRE)
    #undef JSON_HEDLEY_REQUIRE
#endif
#if defined(JSON_HEDLEY_REQUIRE_MSG)
    #undef JSON_HEDLEY_REQUIRE_MSG
#endif
#if JSON_HEDLEY_HAS_ATTRIBUTE(diagnose_if)
#  if JSON_HEDLEY_HAS_WARNING("-Wgcc-compat")
#    define JSON_HEDLEY_REQUIRE(expr) \
    JSON_HEDLEY_DIAGNOSTIC_PUSH \
    _Pragma("clang diagnostic ignored \"-Wgcc-compat\"") \
    __attribute__((diagnose_if(!(expr), #expr, "error"))) \
    JSON_HEDLEY_DIAGNOSTIC_POP
#    define JSON_HEDLEY_REQUIRE_MSG(expr,msg) \
    JSON_HEDLEY_DIAGNOSTIC_PUSH \
    _Pragma("clang diagnostic ignored \"-Wgcc-compat\"") \
    __attribute__((diagnose_if(!(expr), msg, "error"))) \
    JSON_HEDLEY_DIAGNOSTIC_POP
#  else
#    define JSON_HEDLEY_REQUIRE(expr) __attribute__((diagnose_if(!(expr), #expr, "error")))
#    define JSON_HEDLEY_REQUIRE_MSG(expr,msg) __attribute__((diagnose_if(!(expr), msg, "error")))
#  endif
#else
#  define JSON_HEDLEY_REQUIRE(expr)
#  define JSON_HEDLEY_REQUIRE_MSG(expr,msg)
#endif

#if defined(JSON_HEDLEY_FLAGS)
    #undef JSON_HEDLEY_FLAGS
#endif
#if JSON_HEDLEY_HAS_ATTRIBUTE(flag_enum) && (!defined(__cplusplus) || JSON_HEDLEY_HAS_WARNING("-Wbitfield-enum-conversion"))
    #define JSON_HEDLEY_FLAGS __attribute__((__flag_enum__))
#else
    #define JSON_HEDLEY_FLAGS
#endif

#if defined(JSON_HEDLEY_FLAGS_CAST)
    #undef JSON_HEDLEY_FLAGS_CAST
#endif
#if JSON_HEDLEY_INTEL_VERSION_CHECK(19,0,0)
#  define JSON_HEDLEY_FLAGS_CAST(T, expr) (__extension__ ({ \
        JSON_HEDLEY_DIAGNOSTIC_PUSH \
        _Pragma("warning(disable:188)") \
        ((T) (expr)); \
        JSON_HEDLEY_DIAGNOSTIC_POP \
    }))
#else
#  define JSON_HEDLEY_FLAGS_CAST(T, expr) JSON_HEDLEY_STATIC_CAST(T, expr)
#endif

#if defined(JSON_HEDLEY_EMPTY_BASES)
    #undef JSON_HEDLEY_EMPTY_BASES
#endif
#if \
    (JSON_HEDLEY_MSVC_VERSION_CHECK(19,0,23918) && !JSON_HEDLEY_MSVC_VERSION_CHECK(20,0,0)) || \
    JSON_HEDLEY_INTEL_CL_VERSION_CHECK(2021,1,0)
    #define JSON_HEDLEY_EMPTY_BASES __declspec(empty_bases)
#else
    #define JSON_HEDLEY_EMPTY_BASES
#endif

/* Remaining macros are deprecated. */

#if defined(JSON_HEDLEY_GCC_NOT_CLANG_VERSION_CHECK)
    #undef JSON_HEDLEY_GCC_NOT_CLANG_VERSION_CHECK
#endif
#if defined(__clang__)
    #define JSON_HEDLEY_GCC_NOT_CLANG_VERSION_CHECK(major,minor,patch) (0)
#else
    #define JSON_HEDLEY_GCC_NOT_CLANG_VERSION_CHECK(major,minor,patch) JSON_HEDLEY_GCC_VERSION_CHECK(major,minor,patch)
#endif

#if defined(JSON_HEDLEY_CLANG_HAS_ATTRIBUTE)
    #undef JSON_HEDLEY_CLANG_HAS_ATTRIBUTE
#endif
#define JSON_HEDLEY_CLANG_HAS_ATTRIBUTE(attribute) JSON_HEDLEY_HAS_ATTRIBUTE(attribute)

#if defined(JSON_HEDLEY_CLANG_HAS_CPP_ATTRIBUTE)
    #undef JSON_HEDLEY_CLANG_HAS_CPP_ATTRIBUTE
#endif
#define JSON_HEDLEY_CLANG_HAS_CPP_ATTRIBUTE(attribute) JSON_HEDLEY_HAS_CPP_ATTRIBUTE(attribute)

#if defined(JSON_HEDLEY_CLANG_HAS_BUILTIN)
    #undef JSON_HEDLEY_CLANG_HAS_BUILTIN
#endif
#define JSON_HEDLEY_CLANG_HAS_BUILTIN(builtin) JSON_HEDLEY_HAS_BUILTIN(builtin)

#if defined(JSON_HEDLEY_CLANG_HAS_FEATURE)
    #undef JSON_HEDLEY_CLANG_HAS_FEATURE
#endif
#define JSON_HEDLEY_CLANG_HAS_FEATURE(feature) JSON_HEDLEY_HAS_FEATURE(feature)

#if defined(JSON_HEDLEY_CLANG_HAS_EXTENSION)
    #undef JSON_HEDLEY_CLANG_HAS_EXTENSION
#endif
#define JSON_HEDLEY_CLANG_HAS_EXTENSION(extension) JSON_HEDLEY_HAS_EXTENSION(extension)

#if defined(JSON_HEDLEY_CLANG_HAS_DECLSPEC_DECLSPEC_ATTRIBUTE)
    #undef JSON_HEDLEY_CLANG_HAS_DECLSPEC_DECLSPEC_ATTRIBUTE
#endif
#define JSON_HEDLEY_CLANG_HAS_DECLSPEC_ATTRIBUTE(attribute) JSON_HEDLEY_HAS_DECLSPEC_ATTRIBUTE(attribute)

#if defined(JSON_HEDLEY_CLANG_HAS_WARNING)
    #undef JSON_HEDLEY_CLANG_HAS_WARNING
#endif
#define JSON_HEDLEY_CLANG_HAS_WARNING(warning) JSON_HEDLEY_HAS_WARNING(warning)

#endif /* !defined(JSON_HEDLEY_VERSION) || (JSON_HEDLEY_VERSION < X) */


// This file contains all internal macro definitions (except those affecting ABI)
// You MUST include macro_unscope.hpp at the end of json.hpp to undef all of them

// #include <nlohmann/detail/abi_macros.hpp>


// exclude unsupported compilers
#if !defined(JSON_SKIP_UNSUPPORTED_COMPILER_CHECK)
    #if defined(__clang__)
        #if (__clang_major__ * 10000 + __clang_minor__ * 100 + __clang_patchlevel__) < 30400
            #error "unsupported Clang version - see https://github.com/nlohmann/json#supported-compilers"
        #endif
    #elif defined(__GNUC__) && !(defined(__ICC) || defined(__INTEL_COMPILER))
        #if (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) < 40800
            #error "unsupported GCC version - see https://github.com/nlohmann/json#supported-compilers"
        #endif
    #endif
#endif

// C++ language standard detection
// if the user manually specified the used C++ version, this is skipped
#if !defined(JSON_HAS_CPP_26) && !defined(JSON_HAS_CPP_23) && !defined(JSON_HAS_CPP_20) && !defined(JSON_HAS_CPP_17) && !defined(JSON_HAS_CPP_14) && !defined(JSON_HAS_CPP_11)
    #if (defined(__cplusplus) && __cplusplus > 202302L) || (defined(_MSVC_LANG) && _MSVC_LANG > 202302L)
        #define JSON_HAS_CPP_26
        #define JSON_HAS_CPP_23
        #define JSON_HAS_CPP_20
        #define JSON_HAS_CPP_17
        #define JSON_HAS_CPP_14
    #elif (defined(__cplusplus) && __cplusplus > 202002L) || (defined(_MSVC_LANG) && _MSVC_LANG > 202002L)
        #define JSON_HAS_CPP_23
        #define JSON_HAS_CPP_20
        #define JSON_HAS_CPP_17
        #define JSON_HAS_CPP_14
    #elif (defined(__cplusplus) && __cplusplus > 201703L) || (defined(_MSVC_LANG) && _MSVC_LANG > 201703L)
        #define JSON_HAS_CPP_20
        #define JSON_HAS_CPP_17
        #define JSON_HAS_CPP_14
    #elif (defined(__cplusplus) && __cplusplus > 201402L) || (defined(_HAS_CXX17) && _HAS_CXX17 == 1) // fix for issue #464
        #define JSON_HAS_CPP_17
        #define JSON_HAS_CPP_14
    #elif (defined(__cplusplus) && __cplusplus > 201103L) || (defined(_HAS_CXX14) && _HAS_CXX14 == 1)
        #define JSON_HAS_CPP_14
    #endif
    // the cpp 11 flag is always specified because it is the minimal required version
    #define JSON_HAS_CPP_11
#endif

#ifdef __has_include
    #if __has_include(<version>)
        #include <version>
    #endif
#endif

#if !defined(JSON_HAS_FILESYSTEM) && !defined(JSON_HAS_EXPERIMENTAL_FILESYSTEM)
    #ifdef JSON_HAS_CPP_17
        #if defined(__cpp_lib_filesystem)
            #define JSON_HAS_FILESYSTEM 1
        #elif defined(__cpp_lib_experimental_filesystem)
            #define JSON_HAS_EXPERIMENTAL_FILESYSTEM 1
        #elif !defined(__has_include)
            #define JSON_HAS_EXPERIMENTAL_FILESYSTEM 1
        #elif __has_include(<filesystem>)
            #define JSON_HAS_FILESYSTEM 1
        #elif __has_include(<experimental/filesystem>)
            #define JSON_HAS_EXPERIMENTAL_FILESYSTEM 1
        #endif

        // std::filesystem does not work on MinGW GCC 8: https://sourceforge.net/p/mingw-w64/bugs/737/
        #if defined(__MINGW32__) && defined(__GNUC__) && __GNUC__ == 8
            #undef JSON_HAS_FILESYSTEM
            #undef JSON_HAS_EXPERIMENTAL_FILESYSTEM
        #endif

        // no filesystem support before GCC 8: https://en.cppreference.com/w/cpp/compiler_support
        #if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 8
            #undef JSON_HAS_FILESYSTEM
            #undef JSON_HAS_EXPERIMENTAL_FILESYSTEM
        #endif

        // no filesystem support before Clang 7: https://en.cppreference.com/w/cpp/compiler_support
        #if defined(__clang_major__) && __clang_major__ < 7
            #undef JSON_HAS_FILESYSTEM
            #undef JSON_HAS_EXPERIMENTAL_FILESYSTEM
        #endif

        // no filesystem support before MSVC 19.14: https://en.cppreference.com/w/cpp/compiler_support
        #if defined(_MSC_VER) && _MSC_VER < 1914
            #undef JSON_HAS_FILESYSTEM
            #undef JSON_HAS_EXPERIMENTAL_FILESYSTEM
        #endif

        // no filesystem support before iOS 13
        #if defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && __IPHONE_OS_VERSION_MIN_REQUIRED < 130000
            #undef JSON_HAS_FILESYSTEM
            #undef JSON_HAS_EXPERIMENTAL_FILESYSTEM
        #endif

        // no filesystem support before macOS Catalina
        #if defined(__MAC_OS_X_VERSION_MIN_REQUIRED) && __MAC_OS_X_VERSION_MIN_REQUIRED < 101500
            #undef JSON_HAS_FILESYSTEM
            #undef JSON_HAS_EXPERIMENTAL_FILESYSTEM
        #endif
    #endif
#endif

#ifndef JSON_HAS_EXPERIMENTAL_FILESYSTEM
    #define JSON_HAS_EXPERIMENTAL_FILESYSTEM 0
#endif

#ifndef JSON_HAS_FILESYSTEM
    #define JSON_HAS_FILESYSTEM 0
#endif

#ifndef JSON_HAS_THREE_WAY_COMPARISON
    #if defined(__cpp_impl_three_way_comparison) && __cpp_impl_three_way_comparison >= 201907L \
        && defined(__cpp_lib_three_way_comparison) && __cpp_lib_three_way_comparison >= 201907L
        #define JSON_HAS_THREE_WAY_COMPARISON 1
    #else
        #define JSON_HAS_THREE_WAY_COMPARISON 0
    #endif
#endif

#ifndef JSON_HAS_RANGES
    // ranges header shipping in GCC 11.1.0 (released 2021-04-27) has a syntax error
    #if defined(__GLIBCXX__) && __GLIBCXX__ == 20210427
        #define JSON_HAS_RANGES 0
        // libstdc++ < 11 has incomplete C++20 ranges (issue #4440)
    #elif defined(_GLIBCXX_RELEASE) && _GLIBCXX_RELEASE < 11
        #define JSON_HAS_RANGES 0
        // clang < 16 with libstdc++ does not implement the ranges customization
        // points libstdc++ declares, so its C++20 ranges support is incomplete (issue #5161)
    #elif defined(__clang__) && !defined(__apple_build_version__) \
        && __clang_major__ < 16 && defined(__GLIBCXX__)
        #define JSON_HAS_RANGES 0
        // libc++ < 16 has incomplete C++20 ranges (issue #4440)
    #elif defined(_LIBCPP_VERSION) && _LIBCPP_VERSION < 160000
        #define JSON_HAS_RANGES 0
        // nvcc CUDA 12.0/12.1 chokes on the enable_borrowed_range variable-template
        // syntax when compiling as CUDA source; fixed in CUDA 12.2 (issue #3907)
    #elif defined(__CUDACC__) && defined(__CUDACC_VER_MAJOR__) && __CUDACC_VER_MAJOR__ == 12 \
        && defined(__CUDACC_VER_MINOR__) && (__CUDACC_VER_MINOR__ == 0 || __CUDACC_VER_MINOR__ == 1)
        #define JSON_HAS_RANGES 0
    #elif defined(__cpp_lib_ranges)
        #define JSON_HAS_RANGES 1
    #else
        #define JSON_HAS_RANGES 0
    #endif
#endif

// std::ranges view conversion (to_json/is_compatible_array_type_impl) additionally
// needs to be disabled on MinGW, whose std::ranges support is incomplete
// (issue #4916); this macro combines both conditions so the check and its
// reason are not duplicated at every use site.
#ifndef JSON_HAS_RANGE_VIEW_CONVERSION
    #if JSON_HAS_RANGES && !defined(__MINGW32__)
        #define JSON_HAS_RANGE_VIEW_CONVERSION 1
    #else
        #define JSON_HAS_RANGE_VIEW_CONVERSION 0
    #endif
#endif

#ifndef JSON_HAS_STD_FORMAT
    #if defined(JSON_HAS_CPP_20) && defined(__cpp_lib_format)
        #define JSON_HAS_STD_FORMAT 1
    #else
        #define JSON_HAS_STD_FORMAT 0
    #endif
#endif

#ifndef JSON_HAS_STATIC_RTTI
    #if !defined(_HAS_STATIC_RTTI) || _HAS_STATIC_RTTI != 0
        #define JSON_HAS_STATIC_RTTI 1
    #else
        #define JSON_HAS_STATIC_RTTI 0
    #endif
#endif

#ifdef JSON_HAS_CPP_17
    #define JSON_INLINE_VARIABLE inline
#else
    #define JSON_INLINE_VARIABLE
#endif

#if JSON_HEDLEY_HAS_ATTRIBUTE(no_unique_address)
    #define JSON_NO_UNIQUE_ADDRESS [[no_unique_address]]
#else
    #define JSON_NO_UNIQUE_ADDRESS
#endif

// Clang targeting MinGW does not survive the thread_local storage the copy
// constructor uses to bound its descent: every test that copies a value
// segfaults with clang 11.0.1 and clang 18.1.8, while the same tests pass with
// GCC targeting MinGW and with every other toolchain the library is tested on.
// Copying works the same way without the counter, only more slowly.
#if !defined(JSON_NO_THREAD_LOCAL) && defined(__clang__) && defined(__MINGW32__)
    #define JSON_NO_THREAD_LOCAL 1
#endif

// allow disabling exceptions
#if (defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)) && !defined(JSON_NOEXCEPTION)
    #define JSON_THROW(exception) throw exception
    #define JSON_TRY try
    #define JSON_CATCH(exception) catch(exception)
    #define JSON_INTERNAL_CATCH(exception) catch(exception)
#else
    #include <cstdlib>
    #define JSON_THROW(exception) std::abort()
    #define JSON_TRY if(true)
    #define JSON_CATCH(exception) if(false)
    #define JSON_INTERNAL_CATCH(exception) if(false)
#endif

// override exception macros
#if defined(JSON_THROW_USER)
    #undef JSON_THROW
    #define JSON_THROW JSON_THROW_USER
#endif
#if defined(JSON_TRY_USER)
    #undef JSON_TRY
    #define JSON_TRY JSON_TRY_USER
#endif
#if defined(JSON_CATCH_USER)
    #undef JSON_CATCH
    #define JSON_CATCH JSON_CATCH_USER
    #undef JSON_INTERNAL_CATCH
    #define JSON_INTERNAL_CATCH JSON_CATCH_USER
#endif
#if defined(JSON_INTERNAL_CATCH_USER)
    #undef JSON_INTERNAL_CATCH
    #define JSON_INTERNAL_CATCH JSON_INTERNAL_CATCH_USER
#endif

// allow overriding assert
#if !defined(JSON_ASSERT)
    #include <cassert> // assert
    #define JSON_ASSERT(x) assert(x)
#endif

// allow accessing some private functions (needed by the test suite)
#if defined(JSON_TESTS_PRIVATE)
    #define JSON_PRIVATE_UNLESS_TESTED public
#else
    #define JSON_PRIVATE_UNLESS_TESTED private
#endif

/*!
@brief macro to briefly define a mapping between an enum and JSON
@def NLOHMANN_JSON_SERIALIZE_ENUM
@since version 3.4.0
*/
#define NLOHMANN_JSON_SERIALIZE_ENUM(ENUM_TYPE, ...)                                            \
    template<typename BasicJsonType>                                                            \
    inline void to_json(BasicJsonType& j, const ENUM_TYPE& e)                                   \
    {                                                                                           \
        /* NOLINTNEXTLINE(modernize-type-traits) we use C++11 */                                \
        static_assert(std::is_enum<ENUM_TYPE>::value, #ENUM_TYPE " must be an enum!");          \
        /* NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) we don't want to depend on <array> */ \
        static const std::pair<ENUM_TYPE, BasicJsonType> m[] = __VA_ARGS__;                     \
        auto it = std::find_if(std::begin(m), std::end(m),                                      \
                               [e](const std::pair<ENUM_TYPE, BasicJsonType>& ej_pair) -> bool  \
        {                                                                                       \
            return ej_pair.first == e;                                                          \
        });                                                                                     \
        j = ((it != std::end(m)) ? it : std::begin(m))->second;                                 \
    }                                                                                           \
    template<typename BasicJsonType>                                                            \
    inline void from_json(const BasicJsonType& j, ENUM_TYPE& e)                                 \
    {                                                                                           \
        /* NOLINTNEXTLINE(modernize-type-traits) we use C++11 */                                \
        static_assert(std::is_enum<ENUM_TYPE>::value, #ENUM_TYPE " must be an enum!");          \
        /* NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) we don't want to depend on <array> */ \
        static const std::pair<ENUM_TYPE, BasicJsonType> m[] = __VA_ARGS__;                     \
        auto it = std::find_if(std::begin(m), std::end(m),                                      \
                               [&j](const std::pair<ENUM_TYPE, BasicJsonType>& ej_pair) -> bool \
        {                                                                                       \
            return ej_pair.second == j;                                                         \
        });                                                                                     \
        e = ((it != std::end(m)) ? it : std::begin(m))->first;                                  \
    }



/*!
@brief macro to briefly define a mapping between an enum and JSON with exception
       on invalid input
@def NLOHMANN_JSON_SERIALIZE_ENUM_STRICT
@since version 3.13.0
*/
#define NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(ENUM_TYPE, ...)                                     \
    template<typename BasicJsonType>                                                            \
    inline void to_json(BasicJsonType& j, const ENUM_TYPE& e)                                   \
    {                                                                                           \
        /* NOLINTNEXTLINE(modernize-type-traits) we use C++11 */                                \
        static_assert(std::is_enum<ENUM_TYPE>::value, #ENUM_TYPE " must be an enum!");          \
        /* NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) we don't want to depend on <array> */ \
        static const std::pair<ENUM_TYPE, BasicJsonType> m[] = __VA_ARGS__;                     \
        auto it = std::find_if(std::begin(m), std::end(m),                                      \
                               [e](const std::pair<ENUM_TYPE, BasicJsonType>& ej_pair) -> bool  \
        {                                                                                       \
            return ej_pair.first == e;                                                          \
        });                                                                                     \
        if (it != std::end(m)) j = it->second;                                                  \
        else ::nlohmann::detail::templated_json_throw<nlohmann::detail::out_of_range>(nlohmann::detail::out_of_range::create(nlohmann::detail::exception_id::value_out_of_range,"enum value out of range for " #ENUM_TYPE, nullptr)); \
    }                                                                                           \
    template<typename BasicJsonType>                                                            \
    inline void from_json(const BasicJsonType& j, ENUM_TYPE& e)                                 \
    {                                                                                           \
        /* NOLINTNEXTLINE(modernize-type-traits) we use C++11 */                                \
        static_assert(std::is_enum<ENUM_TYPE>::value, #ENUM_TYPE " must be an enum!");          \
        /* NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays) we don't want to depend on <array> */ \
        static const std::pair<ENUM_TYPE, BasicJsonType> m[] = __VA_ARGS__;                     \
        auto it = std::find_if(std::begin(m), std::end(m),                                      \
                               [&j](const std::pair<ENUM_TYPE, BasicJsonType>& ej_pair) -> bool \
        {                                                                                       \
            return ej_pair.second == j;                                                         \
        });                                                                                     \
        if (it != std::end(m)) e = it->first;                                                   \
        else ::nlohmann::detail::templated_json_throw<nlohmann::detail::out_of_range>(nlohmann::detail::out_of_range::create(nlohmann::detail::exception_id::value_out_of_range, nlohmann::detail::concat("enum value out of range for " #ENUM_TYPE ": ", j.dump(-1, ' ', false, nlohmann::detail::error_handler_t::replace)), &j)); \
    }

// Ugly macros to avoid uglier copy-paste when specializing basic_json. They
// may be removed in the future once the class is split.

#define NLOHMANN_BASIC_JSON_TPL_DECLARATION                                \
    template<template<typename, typename, typename...> class ObjectType,   \
             template<typename, typename...> class ArrayType,              \
             class StringType, class BooleanType, class NumberIntegerType, \
             class NumberUnsignedType, class NumberFloatType,              \
             template<typename> class AllocatorType,                       \
             template<typename, typename = void> class JSONSerializer,     \
             class BinaryType,                                             \
             class CustomBaseClass>

#define NLOHMANN_BASIC_JSON_TPL                                            \
    basic_json<ObjectType, ArrayType, StringType, BooleanType,             \
    NumberIntegerType, NumberUnsignedType, NumberFloatType,                \
    AllocatorType, JSONSerializer, BinaryType, CustomBaseClass>

// Macros to simplify conversion from/to types

// NLOHMANN_JSON_EXPAND to NLOHMANN_JSON_DOUBLE_PASTE63 are generated by tools/macro_builder (see its README.md)
#define NLOHMANN_JSON_EXPAND( x ) x
#define NLOHMANN_JSON_GET_MACRO(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, _62, _63, _64, NAME,...) NAME
#define NLOHMANN_JSON_PASTE(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_GET_MACRO(__VA_ARGS__, \
        NLOHMANN_JSON_PASTE64, \
        NLOHMANN_JSON_PASTE63, \
        NLOHMANN_JSON_PASTE62, \
        NLOHMANN_JSON_PASTE61, \
        NLOHMANN_JSON_PASTE60, \
        NLOHMANN_JSON_PASTE59, \
        NLOHMANN_JSON_PASTE58, \
        NLOHMANN_JSON_PASTE57, \
        NLOHMANN_JSON_PASTE56, \
        NLOHMANN_JSON_PASTE55, \
        NLOHMANN_JSON_PASTE54, \
        NLOHMANN_JSON_PASTE53, \
        NLOHMANN_JSON_PASTE52, \
        NLOHMANN_JSON_PASTE51, \
        NLOHMANN_JSON_PASTE50, \
        NLOHMANN_JSON_PASTE49, \
        NLOHMANN_JSON_PASTE48, \
        NLOHMANN_JSON_PASTE47, \
        NLOHMANN_JSON_PASTE46, \
        NLOHMANN_JSON_PASTE45, \
        NLOHMANN_JSON_PASTE44, \
        NLOHMANN_JSON_PASTE43, \
        NLOHMANN_JSON_PASTE42, \
        NLOHMANN_JSON_PASTE41, \
        NLOHMANN_JSON_PASTE40, \
        NLOHMANN_JSON_PASTE39, \
        NLOHMANN_JSON_PASTE38, \
        NLOHMANN_JSON_PASTE37, \
        NLOHMANN_JSON_PASTE36, \
        NLOHMANN_JSON_PASTE35, \
        NLOHMANN_JSON_PASTE34, \
        NLOHMANN_JSON_PASTE33, \
        NLOHMANN_JSON_PASTE32, \
        NLOHMANN_JSON_PASTE31, \
        NLOHMANN_JSON_PASTE30, \
        NLOHMANN_JSON_PASTE29, \
        NLOHMANN_JSON_PASTE28, \
        NLOHMANN_JSON_PASTE27, \
        NLOHMANN_JSON_PASTE26, \
        NLOHMANN_JSON_PASTE25, \
        NLOHMANN_JSON_PASTE24, \
        NLOHMANN_JSON_PASTE23, \
        NLOHMANN_JSON_PASTE22, \
        NLOHMANN_JSON_PASTE21, \
        NLOHMANN_JSON_PASTE20, \
        NLOHMANN_JSON_PASTE19, \
        NLOHMANN_JSON_PASTE18, \
        NLOHMANN_JSON_PASTE17, \
        NLOHMANN_JSON_PASTE16, \
        NLOHMANN_JSON_PASTE15, \
        NLOHMANN_JSON_PASTE14, \
        NLOHMANN_JSON_PASTE13, \
        NLOHMANN_JSON_PASTE12, \
        NLOHMANN_JSON_PASTE11, \
        NLOHMANN_JSON_PASTE10, \
        NLOHMANN_JSON_PASTE9, \
        NLOHMANN_JSON_PASTE8, \
        NLOHMANN_JSON_PASTE7, \
        NLOHMANN_JSON_PASTE6, \
        NLOHMANN_JSON_PASTE5, \
        NLOHMANN_JSON_PASTE4, \
        NLOHMANN_JSON_PASTE3, \
        NLOHMANN_JSON_PASTE2, \
        NLOHMANN_JSON_PASTE1)(__VA_ARGS__))
#define NLOHMANN_JSON_PASTE2(func, v1) func(v1)
#define NLOHMANN_JSON_PASTE3(func, v1, v2) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE2(func, v2)
#define NLOHMANN_JSON_PASTE4(func, v1, v2, v3) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE3(func, v2, v3)
#define NLOHMANN_JSON_PASTE5(func, v1, v2, v3, v4) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE4(func, v2, v3, v4)
#define NLOHMANN_JSON_PASTE6(func, v1, v2, v3, v4, v5) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE5(func, v2, v3, v4, v5)
#define NLOHMANN_JSON_PASTE7(func, v1, v2, v3, v4, v5, v6) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE6(func, v2, v3, v4, v5, v6)
#define NLOHMANN_JSON_PASTE8(func, v1, v2, v3, v4, v5, v6, v7) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE7(func, v2, v3, v4, v5, v6, v7)
#define NLOHMANN_JSON_PASTE9(func, v1, v2, v3, v4, v5, v6, v7, v8) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE8(func, v2, v3, v4, v5, v6, v7, v8)
#define NLOHMANN_JSON_PASTE10(func, v1, v2, v3, v4, v5, v6, v7, v8, v9) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE9(func, v2, v3, v4, v5, v6, v7, v8, v9)
#define NLOHMANN_JSON_PASTE11(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE10(func, v2, v3, v4, v5, v6, v7, v8, v9, v10)
#define NLOHMANN_JSON_PASTE12(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE11(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11)
#define NLOHMANN_JSON_PASTE13(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE12(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12)
#define NLOHMANN_JSON_PASTE14(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE13(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13)
#define NLOHMANN_JSON_PASTE15(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE14(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14)
#define NLOHMANN_JSON_PASTE16(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE15(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)
#define NLOHMANN_JSON_PASTE17(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE16(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16)
#define NLOHMANN_JSON_PASTE18(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE17(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17)
#define NLOHMANN_JSON_PASTE19(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE18(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18)
#define NLOHMANN_JSON_PASTE20(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE19(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19)
#define NLOHMANN_JSON_PASTE21(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE20(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20)
#define NLOHMANN_JSON_PASTE22(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE21(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21)
#define NLOHMANN_JSON_PASTE23(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE22(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22)
#define NLOHMANN_JSON_PASTE24(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE23(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23)
#define NLOHMANN_JSON_PASTE25(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE24(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24)
#define NLOHMANN_JSON_PASTE26(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE25(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25)
#define NLOHMANN_JSON_PASTE27(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE26(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26)
#define NLOHMANN_JSON_PASTE28(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE27(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27)
#define NLOHMANN_JSON_PASTE29(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE28(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28)
#define NLOHMANN_JSON_PASTE30(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE29(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29)
#define NLOHMANN_JSON_PASTE31(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE30(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30)
#define NLOHMANN_JSON_PASTE32(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE31(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31)
#define NLOHMANN_JSON_PASTE33(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE32(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32)
#define NLOHMANN_JSON_PASTE34(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE33(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33)
#define NLOHMANN_JSON_PASTE35(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE34(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34)
#define NLOHMANN_JSON_PASTE36(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE35(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35)
#define NLOHMANN_JSON_PASTE37(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE36(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36)
#define NLOHMANN_JSON_PASTE38(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE37(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37)
#define NLOHMANN_JSON_PASTE39(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE38(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38)
#define NLOHMANN_JSON_PASTE40(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE39(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39)
#define NLOHMANN_JSON_PASTE41(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE40(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40)
#define NLOHMANN_JSON_PASTE42(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE41(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41)
#define NLOHMANN_JSON_PASTE43(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE42(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42)
#define NLOHMANN_JSON_PASTE44(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE43(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43)
#define NLOHMANN_JSON_PASTE45(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE44(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44)
#define NLOHMANN_JSON_PASTE46(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE45(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45)
#define NLOHMANN_JSON_PASTE47(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE46(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46)
#define NLOHMANN_JSON_PASTE48(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE47(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47)
#define NLOHMANN_JSON_PASTE49(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE48(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48)
#define NLOHMANN_JSON_PASTE50(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE49(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49)
#define NLOHMANN_JSON_PASTE51(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE50(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50)
#define NLOHMANN_JSON_PASTE52(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE51(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51)
#define NLOHMANN_JSON_PASTE53(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE52(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52)
#define NLOHMANN_JSON_PASTE54(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE53(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53)
#define NLOHMANN_JSON_PASTE55(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE54(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54)
#define NLOHMANN_JSON_PASTE56(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE55(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55)
#define NLOHMANN_JSON_PASTE57(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE56(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56)
#define NLOHMANN_JSON_PASTE58(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE57(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57)
#define NLOHMANN_JSON_PASTE59(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE58(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58)
#define NLOHMANN_JSON_PASTE60(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE59(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59)
#define NLOHMANN_JSON_PASTE61(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59, v60) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE60(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59, v60)
#define NLOHMANN_JSON_PASTE62(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59, v60, v61) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE61(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59, v60, v61)
#define NLOHMANN_JSON_PASTE63(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59, v60, v61, v62) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE62(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59, v60, v61, v62)
#define NLOHMANN_JSON_PASTE64(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59, v60, v61, v62, v63) NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE63(func, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59, v60, v61, v62, v63)
#define NLOHMANN_JSON_DOUBLE_PASTE(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_GET_MACRO(__VA_ARGS__, \
        NLOHMANN_JSON_DOUBLE_PASTE63, \
        NLOHMANN_JSON_DOUBLE_PASTE63, \
        NLOHMANN_JSON_DOUBLE_PASTE61, \
        NLOHMANN_JSON_DOUBLE_PASTE61, \
        NLOHMANN_JSON_DOUBLE_PASTE59, \
        NLOHMANN_JSON_DOUBLE_PASTE59, \
        NLOHMANN_JSON_DOUBLE_PASTE57, \
        NLOHMANN_JSON_DOUBLE_PASTE57, \
        NLOHMANN_JSON_DOUBLE_PASTE55, \
        NLOHMANN_JSON_DOUBLE_PASTE55, \
        NLOHMANN_JSON_DOUBLE_PASTE53, \
        NLOHMANN_JSON_DOUBLE_PASTE53, \
        NLOHMANN_JSON_DOUBLE_PASTE51, \
        NLOHMANN_JSON_DOUBLE_PASTE51, \
        NLOHMANN_JSON_DOUBLE_PASTE49, \
        NLOHMANN_JSON_DOUBLE_PASTE49, \
        NLOHMANN_JSON_DOUBLE_PASTE47, \
        NLOHMANN_JSON_DOUBLE_PASTE47, \
        NLOHMANN_JSON_DOUBLE_PASTE45, \
        NLOHMANN_JSON_DOUBLE_PASTE45, \
        NLOHMANN_JSON_DOUBLE_PASTE43, \
        NLOHMANN_JSON_DOUBLE_PASTE43, \
        NLOHMANN_JSON_DOUBLE_PASTE41, \
        NLOHMANN_JSON_DOUBLE_PASTE41, \
        NLOHMANN_JSON_DOUBLE_PASTE39, \
        NLOHMANN_JSON_DOUBLE_PASTE39, \
        NLOHMANN_JSON_DOUBLE_PASTE37, \
        NLOHMANN_JSON_DOUBLE_PASTE37, \
        NLOHMANN_JSON_DOUBLE_PASTE35, \
        NLOHMANN_JSON_DOUBLE_PASTE35, \
        NLOHMANN_JSON_DOUBLE_PASTE33, \
        NLOHMANN_JSON_DOUBLE_PASTE33, \
        NLOHMANN_JSON_DOUBLE_PASTE31, \
        NLOHMANN_JSON_DOUBLE_PASTE31, \
        NLOHMANN_JSON_DOUBLE_PASTE29, \
        NLOHMANN_JSON_DOUBLE_PASTE29, \
        NLOHMANN_JSON_DOUBLE_PASTE27, \
        NLOHMANN_JSON_DOUBLE_PASTE27, \
        NLOHMANN_JSON_DOUBLE_PASTE25, \
        NLOHMANN_JSON_DOUBLE_PASTE25, \
        NLOHMANN_JSON_DOUBLE_PASTE23, \
        NLOHMANN_JSON_DOUBLE_PASTE23, \
        NLOHMANN_JSON_DOUBLE_PASTE21, \
        NLOHMANN_JSON_DOUBLE_PASTE21, \
        NLOHMANN_JSON_DOUBLE_PASTE19, \
        NLOHMANN_JSON_DOUBLE_PASTE19, \
        NLOHMANN_JSON_DOUBLE_PASTE17, \
        NLOHMANN_JSON_DOUBLE_PASTE17, \
        NLOHMANN_JSON_DOUBLE_PASTE15, \
        NLOHMANN_JSON_DOUBLE_PASTE15, \
        NLOHMANN_JSON_DOUBLE_PASTE13, \
        NLOHMANN_JSON_DOUBLE_PASTE13, \
        NLOHMANN_JSON_DOUBLE_PASTE11, \
        NLOHMANN_JSON_DOUBLE_PASTE11, \
        NLOHMANN_JSON_DOUBLE_PASTE9, \
        NLOHMANN_JSON_DOUBLE_PASTE9, \
        NLOHMANN_JSON_DOUBLE_PASTE7, \
        NLOHMANN_JSON_DOUBLE_PASTE7, \
        NLOHMANN_JSON_DOUBLE_PASTE5, \
        NLOHMANN_JSON_DOUBLE_PASTE5, \
        NLOHMANN_JSON_DOUBLE_PASTE3, \
        NLOHMANN_JSON_DOUBLE_PASTE3, \
        NLOHMANN_JSON_DOUBLE_PASTE1, \
        NLOHMANN_JSON_DOUBLE_PASTE1)(__VA_ARGS__))
#define NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) func(v1, v2)
#define NLOHMANN_JSON_DOUBLE_PASTE5(func, v1, v2, v3, v4) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE3(func, v3, v4)
#define NLOHMANN_JSON_DOUBLE_PASTE7(func, v1, v2, v3, v4, v5, v6) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE5(func, v3, v4, v5, v6)
#define NLOHMANN_JSON_DOUBLE_PASTE9(func, v1, v2, v3, v4, v5, v6, v7, v8) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE7(func, v3, v4, v5, v6, v7, v8)
#define NLOHMANN_JSON_DOUBLE_PASTE11(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE9(func, v3, v4, v5, v6, v7, v8, v9, v10)
#define NLOHMANN_JSON_DOUBLE_PASTE13(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE11(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12)
#define NLOHMANN_JSON_DOUBLE_PASTE15(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE13(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14)
#define NLOHMANN_JSON_DOUBLE_PASTE17(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE15(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16)
#define NLOHMANN_JSON_DOUBLE_PASTE19(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE17(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18)
#define NLOHMANN_JSON_DOUBLE_PASTE21(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE19(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20)
#define NLOHMANN_JSON_DOUBLE_PASTE23(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE21(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22)
#define NLOHMANN_JSON_DOUBLE_PASTE25(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE23(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24)
#define NLOHMANN_JSON_DOUBLE_PASTE27(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE25(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26)
#define NLOHMANN_JSON_DOUBLE_PASTE29(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE27(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28)
#define NLOHMANN_JSON_DOUBLE_PASTE31(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE29(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30)
#define NLOHMANN_JSON_DOUBLE_PASTE33(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE31(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32)
#define NLOHMANN_JSON_DOUBLE_PASTE35(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE33(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34)
#define NLOHMANN_JSON_DOUBLE_PASTE37(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE35(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36)
#define NLOHMANN_JSON_DOUBLE_PASTE39(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE37(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38)
#define NLOHMANN_JSON_DOUBLE_PASTE41(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE39(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40)
#define NLOHMANN_JSON_DOUBLE_PASTE43(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE41(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42)
#define NLOHMANN_JSON_DOUBLE_PASTE45(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE43(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44)
#define NLOHMANN_JSON_DOUBLE_PASTE47(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE45(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46)
#define NLOHMANN_JSON_DOUBLE_PASTE49(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE47(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48)
#define NLOHMANN_JSON_DOUBLE_PASTE51(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE49(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50)
#define NLOHMANN_JSON_DOUBLE_PASTE53(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE51(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52)
#define NLOHMANN_JSON_DOUBLE_PASTE55(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE53(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54)
#define NLOHMANN_JSON_DOUBLE_PASTE57(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE55(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56)
#define NLOHMANN_JSON_DOUBLE_PASTE59(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE57(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58)
#define NLOHMANN_JSON_DOUBLE_PASTE61(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59, v60) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE59(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59, v60)
#define NLOHMANN_JSON_DOUBLE_PASTE63(func, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59, v60, v61, v62) NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE61(func, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15, v16, v17, v18, v19, v20, v21, v22, v23, v24, v25, v26, v27, v28, v29, v30, v31, v32, v33, v34, v35, v36, v37, v38, v39, v40, v41, v42, v43, v44, v45, v46, v47, v48, v49, v50, v51, v52, v53, v54, v55, v56, v57, v58, v59, v60, v61, v62)

#define NLOHMANN_JSON_TO(v1) nlohmann_json_j[#v1] = nlohmann_json_t.v1;
#define NLOHMANN_JSON_FROM(v1) nlohmann_json_j.at(#v1).get_to(nlohmann_json_t.v1);
#define NLOHMANN_JSON_FROM_WITH_DEFAULT(v1) nlohmann_json_t.v1 = !nlohmann_json_j.is_null() ? nlohmann_json_j.value(#v1, nlohmann_json_default_obj.v1) : nlohmann_json_default_obj.v1;

#define NLOHMANN_JSON_TO_WITH_NAME(v1, v2) nlohmann_json_j[v1] = nlohmann_json_t.v2;
#define NLOHMANN_JSON_FROM_WITH_NAME(v1, v2) nlohmann_json_j.at(v1).get_to(nlohmann_json_t.v2);
#define NLOHMANN_JSON_FROM_WITH_DEFAULT_WITH_NAME(v1, v2) nlohmann_json_t.v2 = !nlohmann_json_j.is_null() ? nlohmann_json_j.value(v1, nlohmann_json_default_obj.v2) : nlohmann_json_default_obj.v2;

#define NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(...) template<typename BasicJsonType, nlohmann::detail::enable_if_t<nlohmann::detail::is_basic_json<BasicJsonType>::value, int> = 0> __VA_ARGS__

// Helpers used to dispatch the NLOHMANN_DEFINE_TYPE_*/NLOHMANN_DEFINE_DERIVED_TYPE_*
// macros below between a zero-member and a one-or-more-member implementation
// (issue #4041, e.g. NLOHMANN_DEFINE_TYPE_INTRUSIVE(Type) with no further
// arguments). NLOHMANN_JSON_TYPE_BODY(Prefix, ...) expands to the macro name
// Prefix##EMPTY when __VA_ARGS__ is a single argument (Type alone) and to
// Prefix##MEMBERS for two or more (Type, member...). It reuses the existing
// 64-slot NLOHMANN_JSON_GET_MACRO dispatch with one extra trailing sentinel
// token appended so its own trailing "..." is never left completely empty at
// the lowest supported argument count -- invoking a variadic macro so that
// "..." matches nothing is only granted unconditionally by the standard since
// C++20, and pre-C++20 compilers may reject it under -pedantic regardless of
// what the macro body does.
//
// The EMPTY/MEMBERS suffixes are pasted onto Prefix right in the slot table:
// operands of ## are not macro-expanded, so the dispatch keeps working even if
// user code defines macros named EMPTY or MEMBERS. Producing the bare suffix
// first and pasting it later would let such a macro replace it.
//
// NLOHMANN_JSON_DERIVED_TYPE_BODY(Prefix, ...) answers the same question for
// the derived-type macros, whose fixed prefix is Type,BaseType. It drops the
// leading Type and defers to NLOHMANN_JSON_TYPE_BODY rather than shifting the
// slot table by one: NLOHMANN_JSON_GET_MACRO only resolves 64 positional
// arguments, so dispatching on Type,BaseType,member... directly would run out
// one slot early and cap the derived-type macros at 62 members instead of the
// 63 that NLOHMANN_JSON_PASTE supports.
//
// The slot table below (down to the closing NLOHMANN_JSON_TYPE_BODY_SENTINEL))
// is generated by tools/macro_builder (see its README.md; run with the
// "type_body" argument).
#define NLOHMANN_JSON_TYPE_BODY(Prefix, ...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_GET_MACRO(__VA_ARGS__, \
        Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, \
        Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, \
        Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, \
        Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, \
        Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, \
        Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, \
        Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, \
        Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## MEMBERS, Prefix ## EMPTY, \
        NLOHMANN_JSON_TYPE_BODY_SENTINEL))

#define NLOHMANN_JSON_DERIVED_TYPE_BODY_(Prefix, Type, ...) NLOHMANN_JSON_TYPE_BODY(Prefix, __VA_ARGS__)
#define NLOHMANN_JSON_DERIVED_TYPE_BODY(Prefix, ...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DERIVED_TYPE_BODY_(Prefix, __VA_ARGS__))

/*!
@brief macro
@def NLOHMANN_DEFINE_TYPE_INTRUSIVE
@since version 3.9.0
@sa https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/
*/
#define NLOHMANN_JSON_DEFINE_TYPE_INTRUSIVE_MEMBERS(Type, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_FROM, __VA_ARGS__)) })

#define NLOHMANN_JSON_DEFINE_TYPE_INTRUSIVE_EMPTY(Type)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type&) { nlohmann_json_j = BasicJsonType::object(); }) \
    /* NOLINTNEXTLINE(bugprone-macro-parentheses) Type is used as a declarator type, not in an expression */ \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void from_json(const BasicJsonType&, Type&) noexcept { })

#define NLOHMANN_DEFINE_TYPE_INTRUSIVE(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_TYPE_BODY(NLOHMANN_JSON_DEFINE_TYPE_INTRUSIVE_, __VA_ARGS__)(__VA_ARGS__))

#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_NAMES(Type, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_TO_WITH_NAME, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_FROM_WITH_NAME, __VA_ARGS__)) })

/*!
@brief macro
@def NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT
@since version 3.11.0
@sa https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/
*/
#define NLOHMANN_JSON_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT_MEMBERS(Type, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { const Type nlohmann_json_default_obj{}; NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_FROM_WITH_DEFAULT, __VA_ARGS__)) })

// identical to NLOHMANN_JSON_DEFINE_TYPE_INTRUSIVE_EMPTY: with no members there is nothing to default
#define NLOHMANN_JSON_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT_EMPTY(Type) NLOHMANN_JSON_DEFINE_TYPE_INTRUSIVE_EMPTY(Type)

#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_TYPE_BODY(NLOHMANN_JSON_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT_, __VA_ARGS__)(__VA_ARGS__))

#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_WITH_DEFAULT_WITH_NAMES(Type, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_TO_WITH_NAME, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { const Type nlohmann_json_default_obj{}; NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_FROM_WITH_DEFAULT_WITH_NAME, __VA_ARGS__)) })

/*!
@brief macro
@def NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE
@since version 3.11.3
@sa https://json.nlohmann.me/api/macros/nlohmann_define_type_intrusive/
*/
#define NLOHMANN_JSON_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE_MEMBERS(Type, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) })

#define NLOHMANN_JSON_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE_EMPTY(Type)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type&) { nlohmann_json_j = BasicJsonType::object(); })

#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_TYPE_BODY(NLOHMANN_JSON_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE_, __VA_ARGS__)(__VA_ARGS__))

#define NLOHMANN_DEFINE_TYPE_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES(Type, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_TO_WITH_NAME, __VA_ARGS__)) })

/*!
@brief macro
@def NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE
@since version 3.9.0
@sa https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/
*/
#define NLOHMANN_JSON_DEFINE_TYPE_NON_INTRUSIVE_MEMBERS(Type, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_FROM, __VA_ARGS__)) })

#define NLOHMANN_JSON_DEFINE_TYPE_NON_INTRUSIVE_EMPTY(Type)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type&) { nlohmann_json_j = BasicJsonType::object(); }) \
    /* NOLINTNEXTLINE(bugprone-macro-parentheses) Type is used as a declarator type, not in an expression */ \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void from_json(const BasicJsonType&, Type&) noexcept { })

#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_TYPE_BODY(NLOHMANN_JSON_DEFINE_TYPE_NON_INTRUSIVE_, __VA_ARGS__)(__VA_ARGS__))

#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_NAMES(Type, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_TO_WITH_NAME, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_FROM_WITH_NAME, __VA_ARGS__)) })

/*!
@brief macro
@def NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT
@since version 3.11.0
@sa https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/
*/
#define NLOHMANN_JSON_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT_MEMBERS(Type, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { const Type nlohmann_json_default_obj{}; NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_FROM_WITH_DEFAULT, __VA_ARGS__)) })

// identical to NLOHMANN_JSON_DEFINE_TYPE_NON_INTRUSIVE_EMPTY: with no members there is nothing to default
#define NLOHMANN_JSON_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT_EMPTY(Type) NLOHMANN_JSON_DEFINE_TYPE_NON_INTRUSIVE_EMPTY(Type)

#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_TYPE_BODY(NLOHMANN_JSON_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT_, __VA_ARGS__)(__VA_ARGS__))

#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES(Type, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_TO_WITH_NAME, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { const Type nlohmann_json_default_obj{}; NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_FROM_WITH_DEFAULT_WITH_NAME, __VA_ARGS__)) })

/*!
@brief macro
@def NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE
@since version 3.11.3
@sa https://json.nlohmann.me/api/macros/nlohmann_define_type_non_intrusive/
*/
#define NLOHMANN_JSON_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_MEMBERS(Type, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) })

#define NLOHMANN_JSON_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_EMPTY(Type)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type&) { nlohmann_json_j = BasicJsonType::object(); })

#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_TYPE_BODY(NLOHMANN_JSON_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_, __VA_ARGS__)(__VA_ARGS__))

#define NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES(Type, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_TO_WITH_NAME, __VA_ARGS__)) })

/*!
@brief macro
@def NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE
@since version 3.12.0
@sa https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/
*/
#define NLOHMANN_JSON_DEFINE_DERIVED_TYPE_INTRUSIVE_MEMBERS(Type, BaseType, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { nlohmann::from_json(nlohmann_json_j, static_cast<BaseType&>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_FROM, __VA_ARGS__)) })

#define NLOHMANN_JSON_DEFINE_DERIVED_TYPE_INTRUSIVE_EMPTY(Type, BaseType)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); }) \
    /* NOLINTNEXTLINE(bugprone-macro-parentheses) Type/BaseType are used as declarator types, not in expressions */ \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { nlohmann::from_json(nlohmann_json_j, static_cast<BaseType&>(nlohmann_json_t)); })

#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DERIVED_TYPE_BODY(NLOHMANN_JSON_DEFINE_DERIVED_TYPE_INTRUSIVE_, __VA_ARGS__)(__VA_ARGS__))

#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_NAMES(Type, BaseType, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_TO_WITH_NAME, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { nlohmann::from_json(nlohmann_json_j, static_cast<BaseType&>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_FROM_WITH_NAME, __VA_ARGS__)) })

/*!
@brief macro
@def NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT
@since version 3.12.0
@sa https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/
*/
#define NLOHMANN_JSON_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT_MEMBERS(Type, BaseType, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType&>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { nlohmann::from_json(nlohmann_json_j, static_cast<BaseType&>(nlohmann_json_t)); const Type nlohmann_json_default_obj{}; NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_FROM_WITH_DEFAULT, __VA_ARGS__)) })

// identical to NLOHMANN_JSON_DEFINE_DERIVED_TYPE_INTRUSIVE_EMPTY: with no members there is nothing to default
#define NLOHMANN_JSON_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT_EMPTY(Type, BaseType) NLOHMANN_JSON_DEFINE_DERIVED_TYPE_INTRUSIVE_EMPTY(Type, BaseType)

#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DERIVED_TYPE_BODY(NLOHMANN_JSON_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT_, __VA_ARGS__)(__VA_ARGS__))

#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_WITH_DEFAULT_WITH_NAMES(Type, BaseType, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType&>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_TO_WITH_NAME, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { nlohmann::from_json(nlohmann_json_j, static_cast<BaseType&>(nlohmann_json_t)); const Type nlohmann_json_default_obj{}; NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_FROM_WITH_DEFAULT_WITH_NAME, __VA_ARGS__)) })

/*!
@brief macro
@def NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE
@since version 3.12.0
@sa https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/
*/
#define NLOHMANN_JSON_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE_MEMBERS(Type, BaseType, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) })

#define NLOHMANN_JSON_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE_EMPTY(Type, BaseType)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); })

#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DERIVED_TYPE_BODY(NLOHMANN_JSON_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE_, __VA_ARGS__)(__VA_ARGS__))

#define NLOHMANN_DEFINE_DERIVED_TYPE_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES(Type, BaseType, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(friend void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_TO_WITH_NAME, __VA_ARGS__)) })


/*!
@brief macro
@def NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE
@since version 3.12.0
@sa https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/
*/
#define NLOHMANN_JSON_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_MEMBERS(Type, BaseType, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { nlohmann::from_json(nlohmann_json_j, static_cast<BaseType&>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_FROM, __VA_ARGS__)) })

#define NLOHMANN_JSON_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_EMPTY(Type, BaseType)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); }) \
    /* NOLINTNEXTLINE(bugprone-macro-parentheses) Type/BaseType are used as declarator types, not in expressions */ \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { nlohmann::from_json(nlohmann_json_j, static_cast<BaseType&>(nlohmann_json_t)); })

#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DERIVED_TYPE_BODY(NLOHMANN_JSON_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_, __VA_ARGS__)(__VA_ARGS__))

#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_NAMES(Type, BaseType, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_TO_WITH_NAME, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { nlohmann::from_json(nlohmann_json_j, static_cast<BaseType&>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_FROM_WITH_NAME, __VA_ARGS__)) })

/*!
@brief macro
@def NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT
@since version 3.12.0
@sa https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/
*/
#define NLOHMANN_JSON_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT_MEMBERS(Type, BaseType, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { nlohmann::from_json(nlohmann_json_j, static_cast<BaseType&>(nlohmann_json_t)); const Type nlohmann_json_default_obj{}; NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_FROM_WITH_DEFAULT, __VA_ARGS__)) })

// identical to NLOHMANN_JSON_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_EMPTY: with no members there is nothing to default
#define NLOHMANN_JSON_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT_EMPTY(Type, BaseType) NLOHMANN_JSON_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_EMPTY(Type, BaseType)

#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DERIVED_TYPE_BODY(NLOHMANN_JSON_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT_, __VA_ARGS__)(__VA_ARGS__))

#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_WITH_DEFAULT_WITH_NAMES(Type, BaseType, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_TO_WITH_NAME, __VA_ARGS__)) }) \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void from_json(const BasicJsonType& nlohmann_json_j, Type& nlohmann_json_t) { nlohmann::from_json(nlohmann_json_j, static_cast<BaseType&>(nlohmann_json_t)); const Type nlohmann_json_default_obj{}; NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_FROM_WITH_DEFAULT_WITH_NAME, __VA_ARGS__)) })

/*!
@brief macro
@def NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE
@since version 3.12.0
@sa https://json.nlohmann.me/api/macros/nlohmann_define_derived_type/
*/
#define NLOHMANN_JSON_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_MEMBERS(Type, BaseType, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_PASTE(NLOHMANN_JSON_TO, __VA_ARGS__)) })

#define NLOHMANN_JSON_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_EMPTY(Type, BaseType)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); })

#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DERIVED_TYPE_BODY(NLOHMANN_JSON_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_, __VA_ARGS__)(__VA_ARGS__))

#define NLOHMANN_DEFINE_DERIVED_TYPE_NON_INTRUSIVE_ONLY_SERIALIZE_WITH_NAMES(Type, BaseType, ...)  \
    NLOHMANN_JSON_BASIC_TYPE_TEMPLATE(void to_json(BasicJsonType& nlohmann_json_j, const Type& nlohmann_json_t) { nlohmann::to_json(nlohmann_json_j, static_cast<const BaseType &>(nlohmann_json_t)); NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_DOUBLE_PASTE(NLOHMANN_JSON_TO_WITH_NAME, __VA_ARGS__)) })

// inspired from https://stackoverflow.com/a/26745591
// allows calling any std function as if (e.g., with begin):
// using std::begin; begin(x);
//
// it allows using the detected idiom to retrieve the return type
// of such an expression
#define NLOHMANN_CAN_CALL_STD_FUNC_IMPL(std_name)                                 \
    namespace detail {                                                            \
    using std::std_name;                                                          \
    \
    template<typename... T>                                                       \
    using result_of_##std_name = decltype(std_name(std::declval<T>()...));        \
    }

#ifndef JSON_USE_IMPLICIT_CONVERSIONS
    #define JSON_USE_IMPLICIT_CONVERSIONS 1
#endif

#if JSON_USE_IMPLICIT_CONVERSIONS
    #define JSON_EXPLICIT
#else
    #define JSON_EXPLICIT explicit
#endif

#ifndef JSON_DISABLE_ENUM_SERIALIZATION
    #define JSON_DISABLE_ENUM_SERIALIZATION 0
#endif

#ifndef JSON_DELETE_DEPRECATED_FUNCTIONS
    #define JSON_DELETE_DEPRECATED_FUNCTIONS 0
#endif

#ifndef JSON_DISABLE_TUPLE_REFERENCE_CONVERSION
    #define JSON_DISABLE_TUPLE_REFERENCE_CONVERSION 0
#endif


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

template<typename T>
using uncvref_t = typename std::remove_cv<typename std::remove_reference<T>::type>::type;

#ifdef JSON_HAS_CPP_14

// the following utilities are natively available in C++14
using std::enable_if_t;
using std::index_sequence;
using std::make_index_sequence;
using std::index_sequence_for;

#else

// alias templates to reduce boilerplate
template<bool B, typename T = void>
using enable_if_t = typename std::enable_if<B, T>::type;

// The following code is taken from https://github.com/abseil/abseil-cpp/blob/10cb35e459f5ecca5b2ff107635da0bfa41011b4/absl/utility/utility.h
// which is part of Google Abseil (https://github.com/abseil/abseil-cpp), licensed under the Apache License 2.0.

//// START OF CODE FROM GOOGLE ABSEIL

// integer_sequence
//
// Class template representing a compile-time integer sequence. An instantiation
// of `integer_sequence<T, Ints...>` has a sequence of integers encoded in its
// type through its template arguments (which is a common need when
// working with C++11 variadic templates). `absl::integer_sequence` is designed
// to be a drop-in replacement for C++14's `std::integer_sequence`.
//
// Example:
//
//   template< class T, T... Ints >
//   void user_function(integer_sequence<T, Ints...>);
//
//   int main()
//   {
//     // user_function's `T` will be deduced to `int` and `Ints...`
//     // will be deduced to `0, 1, 2, 3, 4`.
//     user_function(make_integer_sequence<int, 5>());
//   }
template <typename T, T... Ints>
struct integer_sequence
{
    using value_type = T;
    static constexpr std::size_t size() noexcept
    {
        return sizeof...(Ints);
    }
};

// index_sequence
//
// A helper template for an `integer_sequence` of `size_t`,
// `absl::index_sequence` is designed to be a drop-in replacement for C++14's
// `std::index_sequence`.
template <size_t... Ints>
using index_sequence = integer_sequence<size_t, Ints...>;

namespace utility_internal
{

template <typename Seq, size_t SeqSize, size_t Rem>
struct Extend;

// Note that SeqSize == sizeof...(Ints). It's passed explicitly for efficiency.
template <typename T, T... Ints, size_t SeqSize>
struct Extend<integer_sequence<T, Ints...>, SeqSize, 0>
{
    using type = integer_sequence < T, Ints..., (Ints + SeqSize)... >;
};

template <typename T, T... Ints, size_t SeqSize>
struct Extend<integer_sequence<T, Ints...>, SeqSize, 1>
{
    using type = integer_sequence < T, Ints..., (Ints + SeqSize)..., 2 * SeqSize >;
};

// Recursion helper for 'make_integer_sequence<T, N>'.
// 'Gen<T, N>::type' is an alias for 'integer_sequence<T, 0, 1, ... N-1>'.
template <typename T, size_t N>
struct Gen
{
    using type =
        typename Extend < typename Gen < T, N / 2 >::type, N / 2, N % 2 >::type;
};

template <typename T>
struct Gen<T, 0>
{
    using type = integer_sequence<T>;
};

}  // namespace utility_internal

// Compile-time sequences of integers

// make_integer_sequence
//
// This template alias is equivalent to
// `integer_sequence<int, 0, 1, ..., N-1>`, and is designed to be a drop-in
// replacement for C++14's `std::make_integer_sequence`.
template <typename T, T N>
using make_integer_sequence = typename utility_internal::Gen<T, N>::type;

// make_index_sequence
//
// This template alias is equivalent to `index_sequence<0, 1, ..., N-1>`,
// and is designed to be a drop-in replacement for C++14's
// `std::make_index_sequence`.
template <size_t N>
using make_index_sequence = make_integer_sequence<size_t, N>;

// index_sequence_for
//
// Converts a typename pack into an index sequence of the same length, and
// is designed to be a drop-in replacement for C++14's
// `std::index_sequence_for()`
template <typename... Ts>
using index_sequence_for = make_index_sequence<sizeof...(Ts)>;

//// END OF CODE FROM GOOGLE ABSEIL

#endif

// dispatch utility (taken from ranges-v3)
template<unsigned N> struct priority_tag : priority_tag < N - 1 > {};
template<> struct priority_tag<0> {};

// taken from ranges-v3
template<typename T>
struct static_const
{
    static JSON_INLINE_VARIABLE constexpr T value{};
};

#ifndef JSON_HAS_CPP_17
    template<typename T>
    constexpr T static_const<T>::value;
#endif

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

template<typename It, typename = void>
struct iterator_types {};

template<typename It>
struct iterator_types <
    It,
    void_t<typename It::difference_type, typename It::value_type, typename It::pointer,
    typename It::reference, typename It::iterator_category >>
{
    using difference_type = typename It::difference_type;
    using value_type = typename It::value_type;
    using pointer = typename It::pointer;
    using reference = typename It::reference;
    using iterator_category = typename It::iterator_category;
};

// This is required as some compilers implement std::iterator_traits in a way that
// doesn't work with SFINAE. See https://github.com/nlohmann/json/issues/1341.
template<typename T, typename = void>
struct iterator_traits
{
};

template<typename T>
struct iterator_traits < T, enable_if_t < !std::is_pointer<T>::value >>
    : iterator_types<T>
{
};

template<typename T>
struct iterator_traits<T*, enable_if_t<std::is_object<T>::value>>
{
    using iterator_category = std::random_access_iterator_tag;
    using value_type = T;
    using difference_type = ptrdiff_t;
    using pointer = T*;
    using reference = T&;
};

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/macro_scope.hpp>

#ifdef JSON_HAS_CPP_17
    #include <optional> // optional
#endif
// #include <nlohmann/detail/meta/call_std/begin.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



// #include <nlohmann/detail/macro_scope.hpp>


NLOHMANN_JSON_NAMESPACE_BEGIN

NLOHMANN_CAN_CALL_STD_FUNC_IMPL(begin)

NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/meta/call_std/end.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



// #include <nlohmann/detail/macro_scope.hpp>


NLOHMANN_JSON_NAMESPACE_BEGIN

NLOHMANN_CAN_CALL_STD_FUNC_IMPL(end)

NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/meta/cpp_future.hpp>

// #include <nlohmann/detail/meta/detected.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT



#include <type_traits>

// #include <nlohmann/detail/meta/void_t.hpp>


NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

// https://en.cppreference.com/w/cpp/experimental/is_detected
struct nonesuch
{
    nonesuch() = delete;
    ~nonesuch() = delete;
    nonesuch(nonesuch const&) = delete;
    nonesuch(nonesuch const&&) = delete;
    void operator=(nonesuch const&) = delete;
    void operator=(nonesuch&&) = delete;
};

template<class Default,
         class AlwaysVoid,
         template<class...> class Op,
         class... Args>
struct detector
{
    using value_t = std::false_type;
    using type = Default;
};

template<class Default, template<class...> class Op, class... Args>
struct detector<Default, void_t<Op<Args...>>, Op, Args...>
{
    using value_t = std::true_type;
    using type = Op<Args...>;
};

template<template<class...> class Op, class... Args>
using is_detected = typename detector<nonesuch, void, Op, Args...>::value_t;

template<template<class...> class Op, class... Args>
struct is_detected_lazy : is_detected<Op, Args...> { };

template<template<class...> class Op, class... Args>
using detected_t = typename detector<nonesuch, void, Op, Args...>::type;

template<class Default, template<class...> class Op, class... Args>
using detected_or = detector<Default, void, Op, Args...>;

template<class Default, template<class...> class Op, class... Args>
using detected_or_t = typename detected_or<Default, Op, Args...>::type;

template<class Expected, template<class...> class Op, class... Args>
using is_detected_exact = std::is_same<Expected, detected_t<Op, Args...>>;

template<class To, template<class...> class Op, class... Args>
using is_detected_convertible =
    std::is_convertible<detected_t<Op, Args...>, To>;

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/json_fwd.hpp>
//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#ifndef INCLUDE_NLOHMANN_JSON_FWD_HPP_
    #define INCLUDE_NLOHMANN_JSON_FWD_HPP_

    #include <cstdint> // int64_t, uint64_t
    #include <map> // map
    #include <string> // allocator, string
    #include <vector> // vector

    // #include <nlohmann/detail/abi_macros.hpp>


    /*!
    @brief namespace for Niels Lohmann
    @see https://github.com/nlohmann
    @since version 1.0.0
    */
    NLOHMANN_JSON_NAMESPACE_BEGIN

    /*!
    @brief default JSONSerializer template argument

    This serializer ignores the template arguments and uses ADL
    ([argument-dependent lookup](https://en.cppreference.com/w/cpp/language/adl))
    for serialization.
    */
    template<typename T = void, typename SFINAE = void>
    struct adl_serializer; // IWYU pragma: keep

    /// a class to store JSON values
    /// @sa https://json.nlohmann.me/api/basic_json/
    template<template<typename U, typename V, typename... Args> class ObjectType =
    std::map,
    template<typename U, typename... Args> class ArrayType = std::vector,
    class StringType = std::string, class BooleanType = bool,
    class NumberIntegerType = std::int64_t,
    class NumberUnsignedType = std::uint64_t,
    class NumberFloatType = double,
    template<typename U> class AllocatorType = std::allocator,
    template<typename T, typename SFINAE = void> class JSONSerializer =
    adl_serializer,
    class BinaryType = std::vector<std::uint8_t>, // cppcheck-suppress syntaxError
    class CustomBaseClass = void>
    class basic_json; // IWYU pragma: keep

    /// @brief JSON Pointer defines a string syntax for identifying a specific value within a JSON document
    /// @sa https://json.nlohmann.me/api/json_pointer/
    template<typename RefStringType>
    class json_pointer; // IWYU pragma: keep

    /*!
    @brief default specialization
    @sa https://json.nlohmann.me/api/json/
    */
    using json = basic_json<>;

    /// @brief a minimal map-like container that preserves insertion order
    /// @sa https://json.nlohmann.me/api/ordered_map/
    template<class Key, class T, class IgnoredLess, class Allocator>
    struct ordered_map; // IWYU pragma: keep

    /// @brief specialization that maintains the insertion order of object keys
    /// @sa https://json.nlohmann.me/api/ordered_json/
    using ordered_json = basic_json<nlohmann::ordered_map>;

    NLOHMANN_JSON_NAMESPACE_END

#endif  // INCLUDE_NLOHMANN_JSON_FWD_HPP_


NLOHMANN_JSON_NAMESPACE_BEGIN
/*!
@brief detail namespace with internal helper functions

This namespace collects functions that should not be exposed,
implementations of some @ref basic_json methods, and meta-programming helpers.

@since version 2.1.0
*/
namespace detail
{

/////////////
// helpers //
/////////////

// Note to maintainers:
//
// Every trait in this file expects a non-CV-qualified type.
// The only exceptions are in the 'aliases for detected' section
// (i.e., those of the form: decltype(T::member_function(std::declval<T>())))
//
// In this case, T has to be properly CV-qualified to constraint the function arguments
// (e.g., to_json(BasicJsonType&, const T&))

template<typename> struct is_basic_json : std::false_type {};

NLOHMANN_BASIC_JSON_TPL_DECLARATION
struct is_basic_json<NLOHMANN_BASIC_JSON_TPL> : std::true_type {};

// used by exceptions create() member functions
// true_type for the pointer to possibly cv-qualified basic_json or std::nullptr_t
// false_type otherwise
template<typename BasicJsonContext>
struct is_basic_json_context :
    std::integral_constant < bool,
    is_basic_json<typename std::remove_cv<typename std::remove_pointer<BasicJsonContext>::type>::type>::value
    || std::is_same<BasicJsonContext, std::nullptr_t>::value >
{};

//////////////////////
// json_ref helpers //
//////////////////////

template<typename>
class json_ref;

template<typename>
struct is_json_ref : std::false_type {};

template<typename T>
struct is_json_ref<json_ref<T>> : std::true_type {};

//////////////////////////
// aliases for detected //
//////////////////////////

template<typename T>
using mapped_type_t = typename T::mapped_type;

template<typename T>
using key_type_t = typename T::key_type;

template<typename T>
using value_type_t = typename T::value_type;

template<typename T>
using difference_type_t = typename T::difference_type;

template<typename T>
using pointer_t = typename T::pointer;

template<typename T>
using reference_t = typename T::reference;

template<typename T>
using iterator_category_t = typename T::iterator_category;

template<typename T, typename... Args>
using to_json_function = decltype(T::to_json(std::declval<Args>()...));

template<typename T, typename... Args>
using from_json_function = decltype(T::from_json(std::declval<Args>()...));

template<typename T, typename U>
using get_template_function = decltype(std::declval<T>().template get<U>());

// trait checking if JSONSerializer<T>::from_json(json const&, udt&) exists
template<typename BasicJsonType, typename T, typename = void>
struct has_from_json : std::false_type {};

// trait checking if j.get<T> is valid
// use this trait instead of std::is_constructible or std::is_convertible,
// both rely on, or make use of implicit conversions, and thus fail when T
// has several constructors/operator= (see https://github.com/nlohmann/json/issues/958)
template <typename BasicJsonType, typename T>
struct is_getable
{
    static constexpr bool value = is_detected<get_template_function, const BasicJsonType&, T>::value;
};

template<typename BasicJsonType, typename T>
struct has_from_json < BasicJsonType, T, enable_if_t < !is_basic_json<T>::value >>
{
    using serializer = typename BasicJsonType::template json_serializer<T, void>;

    static constexpr bool value =
        is_detected_exact<void, from_json_function, serializer,
        const BasicJsonType&, T&>::value;
};

// This trait checks if JSONSerializer<T>::from_json(json const&) exists
// this overload is used for non-default-constructible user-defined-types
template<typename BasicJsonType, typename T, typename = void>
struct has_non_default_from_json : std::false_type {};

template<typename BasicJsonType, typename T>
struct has_non_default_from_json < BasicJsonType, T, enable_if_t < !is_basic_json<T>::value >>
{
    using serializer = typename BasicJsonType::template json_serializer<T, void>;

    static constexpr bool value =
        is_detected_exact<T, from_json_function, serializer,
        const BasicJsonType&>::value;
};

// This trait checks if BasicJsonType::json_serializer<T>::to_json exists
// Do not evaluate the trait when T is a basic_json type, to avoid template instantiation infinite recursion.
template<typename BasicJsonType, typename T, typename = void>
struct has_to_json : std::false_type {};

template<typename BasicJsonType, typename T>
struct has_to_json < BasicJsonType, T, enable_if_t < !is_basic_json<T>::value >>
{
    using serializer = typename BasicJsonType::template json_serializer<T, void>;

    static constexpr bool value =
        is_detected_exact<void, to_json_function, serializer, BasicJsonType&,
        T>::value;
};

template<typename T>
using detect_key_compare = typename T::key_compare;

// detects whether two values of type T can be compared with operator==
template<typename T>
using detect_equal_comparable = decltype(static_cast<bool>(std::declval<const T&>() == std::declval<const T&>()));

// obtains the actual object key comparator: object_t::key_compare if the
// object type defines it, and default_object_comparator_t otherwise
//
// note detected_or_t is used rather than std::conditional, because the latter
// names both of its type arguments eagerly; object_t::key_compare would then
// be a hard error for an object type that does not define it
template<typename BasicJsonType>
struct actual_object_comparator
{
    using object_t = typename BasicJsonType::object_t;
    using object_comparator_t = typename BasicJsonType::default_object_comparator_t;
    using type = detected_or_t<object_comparator_t, detect_key_compare, object_t>;
};

template<typename BasicJsonType>
using actual_object_comparator_t = typename actual_object_comparator<BasicJsonType>::type;

template<typename T>
using detect_key_comp = decltype(std::declval<const T&>().key_comp());

// whether ObjectType can be constructed from a pair of Iterator together with
// a copy of its own comparator, the way std::map can: it needs a nested
// key_compare, a const key_comp() convertible to it, and a matching
// (Iterator, Iterator, const key_compare&) constructor.
//
// used to preserve a stateful comparator when a copy is built from a range
// past the iterative deep copy's nesting bound (see copy_object_level); an
// object type that does not satisfy this, such as nlohmann::ordered_map
// (which has key_compare for its std::map-like interface, but no key_comp()),
// keeps default-constructing its comparator, just as it always has
template<typename ObjectType, typename Iterator, typename = void>
struct is_comparator_constructible_object_type_impl : std::false_type {};

template<typename ObjectType, typename Iterator>
struct is_comparator_constructible_object_type_impl <
    ObjectType, Iterator, enable_if_t<is_detected<detect_key_compare, ObjectType>::value >>
{
    using key_compare = typename ObjectType::key_compare;

    static constexpr bool value =
        is_detected_convertible<key_compare, detect_key_comp, ObjectType>::value &&
        std::is_constructible<ObjectType, Iterator, Iterator, const key_compare&>::value;
};

template<typename ObjectType, typename Iterator>
struct is_comparator_constructible_object_type
    : is_comparator_constructible_object_type_impl<ObjectType, Iterator> {};

/////////////////
// char_traits //
/////////////////

// Primary template of char_traits calls std char_traits
template<typename T>
struct char_traits : std::char_traits<T>
{};

// Explicitly define char traits for unsigned char since it is not standard
template<>
struct char_traits<unsigned char> : std::char_traits<char>
{
    using char_type = unsigned char;
    using int_type = uint64_t;

    // Redefine to_int_type function
    static int_type to_int_type(char_type c) noexcept
    {
        return static_cast<int_type>(c);
    }

    static char_type to_char_type(int_type i) noexcept
    {
        return static_cast<char_type>(i);
    }

    static constexpr int_type eof() noexcept
    {
        return static_cast<int_type>(std::char_traits<char>::eof());
    }
};

// Explicitly define char traits for signed char since it is not standard
template<>
struct char_traits<signed char> : std::char_traits<char>
{
    using char_type = signed char;
    using int_type = uint64_t;

    // Redefine to_int_type function
    static int_type to_int_type(char_type c) noexcept
    {
        // cast via unsigned char: sign-extending a negative char_type would make
        // byte 0xFF indistinguishable from eof()
        return static_cast<int_type>(static_cast<unsigned char>(c));
    }

    static char_type to_char_type(int_type i) noexcept
    {
        return static_cast<char_type>(i);
    }

    static constexpr int_type eof() noexcept
    {
        return static_cast<int_type>(std::char_traits<char>::eof());
    }
};

#if defined(__cpp_lib_byte) && __cpp_lib_byte >= 201603L
template<>
struct char_traits<std::byte> : std::char_traits<char>
{
    using char_type = std::byte;
    using int_type = uint64_t;

    static int_type to_int_type(char_type c) noexcept
    {
        return static_cast<int_type>(std::to_integer<unsigned char>(c));
    }

    static char_type to_char_type(int_type i) noexcept
    {
        return std::byte(static_cast<unsigned char>(i));
    }

    static constexpr int_type eof() noexcept
    {
        return static_cast<int_type>(std::char_traits<char>::eof());
    }
};
#endif

///////////////////
// is_ functions //
///////////////////

// https://en.cppreference.com/w/cpp/types/conjunction
template<class...> struct conjunction : std::true_type { };
template<class B> struct conjunction<B> : B { };
template<class B, class... Bn>
struct conjunction<B, Bn...>
: std::conditional<static_cast<bool>(B::value), conjunction<Bn...>, B>::type {};

// https://en.cppreference.com/w/cpp/types/disjunction
template<class...> struct disjunction : std::false_type { };
template<class B> struct disjunction<B> : B { };
template<class B, class... Bn>
struct disjunction<B, Bn...>
: std::conditional<static_cast<bool>(B::value), B, disjunction<Bn...>>::type {};

// https://en.cppreference.com/w/cpp/types/negation
template<class B> struct negation : std::integral_constant < bool, !B::value > { };

// Reimplementation of is_constructible and is_default_constructible, due to them being broken for
// std::pair and std::tuple until LWG 2367 fix (see https://cplusplus.github.io/LWG/lwg-defects.html#2367).
// This causes compile errors in e.g., Clang 3.5 or GCC 4.9.
template <typename T>
struct is_default_constructible : std::is_default_constructible<T> {};

template <typename T1, typename T2>
struct is_default_constructible<std::pair<T1, T2>>
    : conjunction<is_default_constructible<T1>, is_default_constructible<T2>> {};

template <typename T1, typename T2>
struct is_default_constructible<const std::pair<T1, T2>>
    : conjunction<is_default_constructible<T1>, is_default_constructible<T2>> {};

template <typename... Ts>
struct is_default_constructible<std::tuple<Ts...>>
    : conjunction<is_default_constructible<Ts>...> {};

template <typename... Ts>
struct is_default_constructible<const std::tuple<Ts...>>
    : conjunction<is_default_constructible<Ts>...> {};

template <typename T, typename... Args>
struct is_constructible : std::is_constructible<T, Args...> {};

template <typename T1, typename T2>
struct is_constructible<std::pair<T1, T2>> : is_default_constructible<std::pair<T1, T2>> {};

template <typename T1, typename T2>
struct is_constructible<const std::pair<T1, T2>> : is_default_constructible<const std::pair<T1, T2>> {};

template <typename... Ts>
struct is_constructible<std::tuple<Ts...>> : is_default_constructible<std::tuple<Ts...>> {};

template <typename... Ts>
struct is_constructible<const std::tuple<Ts...>> : is_default_constructible<const std::tuple<Ts...>> {};

template<typename T, typename = void>
struct is_iterator_traits : std::false_type {};

template<typename T>
struct is_iterator_traits<iterator_traits<T>>
{
  private:
    using traits = iterator_traits<T>;

  public:
    static constexpr auto value =
        is_detected<value_type_t, traits>::value &&
        is_detected<difference_type_t, traits>::value &&
        is_detected<pointer_t, traits>::value &&
        is_detected<iterator_category_t, traits>::value &&
        is_detected<reference_t, traits>::value;
};

template<typename T>
struct is_range
{
  private:
    using t_ref = typename std::add_lvalue_reference<T>::type;

    using iterator = detected_t<result_of_begin, t_ref>;
    using sentinel = detected_t<result_of_end, t_ref>;

    // to be 100% correct, it should use https://en.cppreference.com/w/cpp/iterator/input_or_output_iterator
    // and https://en.cppreference.com/w/cpp/iterator/sentinel_for
    // but reimplementing these would be too much work, as a lot of other concepts are used underneath
    static constexpr auto is_iterator_begin =
        is_iterator_traits<iterator_traits<iterator>>::value;

  public:
    static constexpr bool value = !std::is_same<iterator, nonesuch>::value && !std::is_same<sentinel, nonesuch>::value && is_iterator_begin;
};

template<typename R>
using iterator_t = enable_if_t<is_range<R>::value, result_of_begin<decltype(std::declval<R&>())>>;

template<typename T>
using range_value_t = value_type_t<iterator_traits<iterator_t<T>>>;

// The following implementation of is_complete_type is taken from
// https://blogs.msdn.microsoft.com/vcblog/2015/12/02/partial-support-for-expression-sfinae-in-vs-2015-update-1/
// and is written by Xiang Fan who agreed to use it in this library.

template<typename T, typename = void>
struct is_complete_type : std::false_type {};

template<typename T>
struct is_complete_type<T, decltype(void(sizeof(T)))> : std::true_type {};

template<typename BasicJsonType, typename CompatibleObjectType,
         typename = void>
struct is_compatible_object_type_impl : std::false_type {};

template<typename BasicJsonType, typename CompatibleObjectType>
struct is_compatible_object_type_impl <
    BasicJsonType, CompatibleObjectType,
    enable_if_t < is_detected<mapped_type_t, CompatibleObjectType>::value&&
    is_detected<key_type_t, CompatibleObjectType>::value >>
{
    using object_t = typename BasicJsonType::object_t;

    // macOS's is_constructible does not play well with nonesuch...
    static constexpr bool value =
        is_constructible<typename object_t::key_type,
        typename CompatibleObjectType::key_type>::value &&
        is_constructible<typename object_t::mapped_type,
        typename CompatibleObjectType::mapped_type>::value;
};

template<typename BasicJsonType, typename CompatibleObjectType>
struct is_compatible_object_type
    : is_compatible_object_type_impl<BasicJsonType, CompatibleObjectType> {};

template<typename T>
using insert_result_t = decltype(std::declval<T&>().insert(std::declval<const value_type_t<T>&>()));

template<typename T>
using insert_result_second_t = decltype(std::declval<T&>().insert(std::declval<const value_type_t<T>&>()).second);

// a map-like type (std::map, std::unordered_map, ...) whose keys are enums; see
// JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS
template<typename T, typename = void>
struct is_enum_keyed_map : std::false_type {};

template<typename T>
struct is_enum_keyed_map <
    T, enable_if_t < is_detected<mapped_type_t, T>::value&&
    is_detected<key_type_t, T>::value >>
{
    // maps with non-unique keys (std::multimap, std::unordered_multimap, ...)
    // are excluded, because an object cannot hold duplicate keys; they are
    // detected by insert() returning an iterator instead of a pair<iterator, bool>
    // NOLINTNEXTLINE(modernize-type-traits) we use C++11
    static constexpr bool value = std::is_enum<typename T::key_type>::value &&
                                  !(is_detected<insert_result_t, T>::value && !is_detected<insert_result_second_t, T>::value);
};

template<typename BasicJsonType, typename ConstructibleObjectType,
         typename = void>
struct is_constructible_object_type_impl : std::false_type {};

template<typename BasicJsonType, typename ConstructibleObjectType>
struct is_constructible_object_type_impl <
    BasicJsonType, ConstructibleObjectType,
    enable_if_t < is_detected<mapped_type_t, ConstructibleObjectType>::value&&
    is_detected<key_type_t, ConstructibleObjectType>::value >>
{
    using object_t = typename BasicJsonType::object_t;

    static constexpr bool value =
        (is_default_constructible<ConstructibleObjectType>::value &&
         (std::is_move_assignable<ConstructibleObjectType>::value ||
          std::is_copy_assignable<ConstructibleObjectType>::value) &&
         (is_constructible<typename ConstructibleObjectType::key_type,
          typename object_t::key_type>::value &&
          std::is_same <
          typename object_t::mapped_type,
          typename ConstructibleObjectType::mapped_type >::value)) ||
        (has_from_json<BasicJsonType,
         typename ConstructibleObjectType::mapped_type>::value ||
         has_non_default_from_json <
         BasicJsonType,
         typename ConstructibleObjectType::mapped_type >::value);
};

template<typename BasicJsonType, typename ConstructibleObjectType>
struct is_constructible_object_type
    : is_constructible_object_type_impl<BasicJsonType,
      ConstructibleObjectType> {};

template<typename BasicJsonType, typename CompatibleStringType>
struct is_compatible_string_type
{
    static constexpr auto value =
        is_constructible<typename BasicJsonType::string_t, CompatibleStringType>::value;
};

template<typename BasicJsonType, typename ConstructibleStringType>
struct is_constructible_string_type
{
    // launder type through decltype() to fix compilation failure on ICPC
#ifdef __INTEL_COMPILER
    using laundered_type = decltype(std::declval<ConstructibleStringType>());
#else
    using laundered_type = ConstructibleStringType;
#endif

    static constexpr auto value =
        conjunction <
        is_constructible<laundered_type, typename BasicJsonType::string_t>,
        is_detected_exact<typename BasicJsonType::string_t::value_type,
        value_type_t, laundered_type >>::value;
};

// Forward declarations: iteration_proxy.hpp includes this file, so we cannot
// include it here.
template<typename IteratorType> class iteration_proxy;
template<typename IteratorType> class iteration_proxy_value;

// Identifies nlohmann's internal iteration-proxy types. These must be excluded
// before evaluating any std::ranges concept to avoid circular constraints.
template<typename T> struct is_iteration_proxy_type : std::false_type {};
template<typename T> struct is_iteration_proxy_type<iteration_proxy<T>>       : std::true_type {};
template<typename T> struct is_iteration_proxy_type<iteration_proxy_value<T>> : std::true_type {};

// In C++26, std::optional satisfies std::ranges::view; exclude it so the
// range-view overload does not hijack the optional serializer.
#ifdef JSON_HAS_CPP_17
template<typename T> struct is_range_view_optional_type : std::false_type {};
template<typename T> struct is_range_view_optional_type<std::optional<T>> : std::true_type {};
#else
template<typename T> struct is_range_view_optional_type : std::false_type {};
#endif

#if JSON_HAS_RANGE_VIEW_CONVERSION

// SafeToCheck guards against types that trigger circular constraints when
// std::ranges::view<T> is evaluated on GCC 12 / libstdc++ 12:
//   - iteration_proxy / iteration_proxy_value directly
//   - views wrapping the above (e.g. owning_view<iteration_proxy<...>>)
//   - views wrapping basic_json (e.g. ref_view<json>) — same circularity
//     via json's constructors → is_compatible_array_type → here
// nlohmann's plain range_value_t (iterator_traits-based) is safe to call
// before any std::ranges concept is touched, so we use it for the checks.
template < typename T, bool SafeToCheck =
           !is_iteration_proxy_type<T>::value &&
           !is_iteration_proxy_type<detected_t<range_value_t, T>>::value &&
           !is_basic_json<detected_t<range_value_t, T>>::value &&
           !is_range_view_optional_type<T>::value >
struct is_compatible_range_view : std::false_type {};

template<typename T>
struct is_compatible_range_view<T, true>
    : std::bool_constant<std::ranges::view<T>> {};

#endif

template<typename BasicJsonType, typename CompatibleArrayType, typename = void>
struct is_compatible_array_type_impl : std::false_type {};

template<typename BasicJsonType, typename CompatibleArrayType>
struct is_compatible_array_type_impl <
    BasicJsonType, CompatibleArrayType,
    enable_if_t <
    is_detected<iterator_t, CompatibleArrayType>::value&&
    is_iterator_traits<iterator_traits<detected_t<iterator_t, CompatibleArrayType>>>::value&&
// special case for types like std::filesystem::path whose iterator's value_type are themselves
// c.f. https://github.com/nlohmann/json/pull/3073
    !std::is_same<CompatibleArrayType, detected_t<range_value_t, CompatibleArrayType>>::value
// When range-view support is enabled, std::ranges::view types (e.g. std::string_view,
// filter_view) can match BOTH this iterator-based specialization AND the view-based one
// below, causing ambiguity. Exclude views here so the two specializations are mutually
// exclusive: this one handles plain iterable containers, the other handles views.
#if JSON_HAS_RANGE_VIEW_CONVERSION
&& !is_compatible_range_view<CompatibleArrayType>::value
#endif
            >>
{
    static constexpr bool value =
        is_constructible<BasicJsonType,
        range_value_t<CompatibleArrayType>>::value;
};

#if JSON_HAS_RANGE_VIEW_CONVERSION
template<typename BasicJsonType, typename CompatibleArrayType>
struct is_compatible_array_type_impl <
    BasicJsonType, CompatibleArrayType,
    enable_if_t < is_compatible_range_view<CompatibleArrayType>::value
    && !std::is_same<detected_t<range_value_t, CompatibleArrayType>, char>::value
    && !std::is_same<detected_t<range_value_t, CompatibleArrayType>, wchar_t>::value >>
{
    // CompatibleArrayType is a std::ranges::view here, so std::ranges::range_value_t
    // is safe and correctly handles C++20 iterators that may lack classic iterator_traits.
    static constexpr bool value =
        is_constructible<BasicJsonType,
        std::ranges::range_value_t<CompatibleArrayType>>::value;
};
#endif


template<typename BasicJsonType, typename CompatibleArrayType>
struct is_compatible_array_type
    : is_compatible_array_type_impl<BasicJsonType, CompatibleArrayType> {};

template<typename BasicJsonType, typename ConstructibleArrayType, typename = void>
struct is_constructible_array_type_impl : std::false_type {};

template<typename BasicJsonType, typename ConstructibleArrayType>
struct is_constructible_array_type_impl <
    BasicJsonType, ConstructibleArrayType,
    enable_if_t<std::is_same<ConstructibleArrayType,
    typename BasicJsonType::value_type>::value >>
            : std::true_type {};

template<typename BasicJsonType, typename ConstructibleArrayType>
struct is_constructible_array_type_impl <
    BasicJsonType, ConstructibleArrayType,
    enable_if_t < !std::is_same<ConstructibleArrayType,
    typename BasicJsonType::value_type>::value&&
    !is_compatible_string_type<BasicJsonType, ConstructibleArrayType>::value&&
    is_default_constructible<ConstructibleArrayType>::value&&
(std::is_move_assignable<ConstructibleArrayType>::value ||
 std::is_copy_assignable<ConstructibleArrayType>::value)&&
is_detected<iterator_t, ConstructibleArrayType>::value&&
is_iterator_traits<iterator_traits<detected_t<iterator_t, ConstructibleArrayType>>>::value&&
is_detected<range_value_t, ConstructibleArrayType>::value&&
// special case for types like std::filesystem::path whose iterator's value_type are themselves
// c.f. https://github.com/nlohmann/json/pull/3073
!std::is_same<ConstructibleArrayType, detected_t<range_value_t, ConstructibleArrayType>>::value&&
is_complete_type <
detected_t<range_value_t, ConstructibleArrayType >>::value >>
{
    using value_type = range_value_t<ConstructibleArrayType>;

    static constexpr bool value =
        std::is_same<value_type,
        typename BasicJsonType::array_t::value_type>::value ||
        has_from_json<BasicJsonType,
        value_type>::value ||
        has_non_default_from_json <
        BasicJsonType,
        value_type >::value;
};

template<typename BasicJsonType, typename ConstructibleArrayType>
struct is_constructible_array_type
    : is_constructible_array_type_impl<BasicJsonType, ConstructibleArrayType> {};

template<typename RealIntegerType, typename CompatibleNumberIntegerType,
         typename = void>
struct is_compatible_integer_type_impl : std::false_type {};

template<typename RealIntegerType, typename CompatibleNumberIntegerType>
struct is_compatible_integer_type_impl <
    RealIntegerType, CompatibleNumberIntegerType,
    enable_if_t < std::is_integral<RealIntegerType>::value&&
    std::is_integral<CompatibleNumberIntegerType>::value&&
    !std::is_same<bool, CompatibleNumberIntegerType>::value >>
{
    using RealLimits = std::numeric_limits<RealIntegerType>;
    using CompatibleLimits = std::numeric_limits<CompatibleNumberIntegerType>;

    static constexpr auto value =
        is_constructible<RealIntegerType,
        CompatibleNumberIntegerType>::value &&
        CompatibleLimits::is_integer &&
        RealLimits::is_signed == CompatibleLimits::is_signed;
};

template<typename RealIntegerType, typename CompatibleNumberIntegerType>
struct is_compatible_integer_type
    : is_compatible_integer_type_impl<RealIntegerType,
      CompatibleNumberIntegerType> {};

// whether to_json() stores an integer of type CompatibleNumberIntegerType as
// number_integer
template<typename BasicJsonType, typename CompatibleNumberIntegerType, typename = void>
struct is_compatible_number_integer_type
    : is_compatible_integer_type<typename BasicJsonType::number_integer_t, CompatibleNumberIntegerType> {};

// if number_unsigned_t is the same type as number_integer_t, unsigned integers
// are stored as number_integer as well (#2573)
template<typename BasicJsonType, typename CompatibleNumberIntegerType>
struct is_compatible_number_integer_type<BasicJsonType, CompatibleNumberIntegerType,
           enable_if_t<conjunction<std::is_same<typename BasicJsonType::number_integer_t, typename BasicJsonType::number_unsigned_t>,
           std::is_integral<CompatibleNumberIntegerType>,
           std::is_unsigned<CompatibleNumberIntegerType>,
           negation<std::is_same<bool, CompatibleNumberIntegerType>>>::value>>
           : std::is_constructible<typename BasicJsonType::number_integer_t, CompatibleNumberIntegerType> {};

template<typename BasicJsonType, typename CompatibleType, typename = void>
struct is_compatible_type_impl: std::false_type {};

template<typename BasicJsonType, typename CompatibleType>
struct is_compatible_type_impl <
    BasicJsonType, CompatibleType,
    enable_if_t<is_complete_type<CompatibleType>::value >>
{
    static constexpr bool value =
        has_to_json<BasicJsonType, CompatibleType>::value;
};

template<typename BasicJsonType, typename CompatibleType>
struct is_compatible_type
    : is_compatible_type_impl<BasicJsonType, CompatibleType> {};

// a one-element std::tuple holding a reference to BasicJsonType, as created by
// std::forward_as_tuple(j); see JSON_DISABLE_TUPLE_REFERENCE_CONVERSION
template<typename BasicJsonType, typename T>
struct is_basic_json_reference_tuple : std::false_type {};

template<typename BasicJsonType, typename T>
struct is_basic_json_reference_tuple<BasicJsonType, std::tuple<T>>
{
    static constexpr bool value =
        std::is_reference<T>::value && std::is_same<uncvref_t<T>, BasicJsonType>::value;
};

template<typename BasicJsonType, typename CompatibleArrayType>
struct is_compatible_binary_type
{
    static constexpr bool value =
        std::is_same<typename BasicJsonType::binary_t::container_type, CompatibleArrayType>::value &&
        !std::is_same<typename BasicJsonType::binary_t::container_type, std::vector<std::uint8_t>>::value;
};

template<typename BasicJsonType, typename CompatibleReferenceType>
struct is_compatible_reference_type_impl
{
    using JsonType = uncvref_t<BasicJsonType>;
    using CVType = typename std::remove_reference<CompatibleReferenceType>::type;
    using Type = typename std::remove_cv<CVType>::type;
    constexpr static bool value = std::is_reference<CompatibleReferenceType>::value &&
                                  (!std::is_const<typename std::remove_reference<BasicJsonType>::type>::value || std::is_const<CVType>::value) &&
                                  (std::is_same<typename JsonType::boolean_t, Type>::value ||
                                   std::is_same<typename JsonType::number_float_t, Type>::value ||
                                   std::is_same<typename JsonType::number_integer_t, Type>::value ||
                                   std::is_same<typename JsonType::number_unsigned_t, Type>::value ||
                                   std::is_same<typename JsonType::string_t, Type>::value ||
                                   std::is_same<typename JsonType::binary_t, Type>::value ||
                                   std::is_same<typename JsonType::object_t, Type>::value ||
                                   std::is_same<typename JsonType::array_t, Type>::value);
};

template<typename BasicJsonType, typename CompatibleReferenceType>
struct is_compatible_reference_type
    : is_compatible_reference_type_impl<BasicJsonType, CompatibleReferenceType> {};

template<typename T1, typename T2>
struct is_constructible_tuple : std::false_type {};

template<typename T1, typename... Args>
struct is_constructible_tuple<T1, std::tuple<Args...>> : conjunction<is_constructible<T1, Args>...> {};

template<typename BasicJsonType, typename T>
struct is_json_iterator_of : std::false_type {};

template<typename BasicJsonType>
struct is_json_iterator_of<BasicJsonType, typename BasicJsonType::iterator> : std::true_type {};

template<typename BasicJsonType>
struct is_json_iterator_of<BasicJsonType, typename BasicJsonType::const_iterator> : std::true_type
{};

// checks if a given type T is a template specialization of Primary
template<template <typename...> class Primary, typename T>
struct is_specialization_of : std::false_type {};

template<template <typename...> class Primary, typename... Args>
struct is_specialization_of<Primary, Primary<Args...>> : std::true_type {};

template<typename T>
using is_json_pointer = is_specialization_of<::nlohmann::json_pointer, uncvref_t<T>>;

// checks if B is a json_pointer<A>
template <typename A, typename B>
struct is_json_pointer_of : std::false_type {};

template <typename A>
struct is_json_pointer_of<A, ::nlohmann::json_pointer<A>> : std::true_type {};

template <typename A>
struct is_json_pointer_of<A, ::nlohmann::json_pointer<A>&> : std::true_type {};

// checks if A and B are comparable using Compare functor, assuming that
// neither A nor B is a json_pointer type (that case is handled by
// is_comparable below, which never instantiates this helper otherwise)
template<typename Compare, typename A, typename B, typename = void>
struct is_comparable_no_json_pointer : std::false_type {};

template<typename Compare, typename A, typename B>
struct is_comparable_no_json_pointer < Compare, A, B, enable_if_t <
std::is_constructible <decltype(std::declval<Compare>()(std::declval<A>(), std::declval<B>()))>::value
&& std::is_constructible <decltype(std::declval<Compare>()(std::declval<B>(), std::declval<A>()))>::value
>> : std::true_type {};

// checks if A and B are comparable using Compare functor
// We dispatch on is_json_pointer_of as a plain bool (rather than folding it
// into a single enable_if_t condition together with the checks below) so
// that the Compare(A, B) checks are only ever written - and thus only ever
// instantiated - when A/B are not a json_pointer/string pair. Those checks
// use json_pointer::operator string_t() (GCC, see #4621) resp. the
// deprecated json_pointer/string operator== (Clang, see #5288), and merely
// naming them as later operands of a plain && chain is not sufficient to
// avoid their instantiation on all compilers, even when the first operand
// is false. The dispatch on is_json_pointer_of can be removed once the
// deprecated json_pointer comparison operators have been removed.
template<typename Compare, typename A, typename B, bool = is_json_pointer_of<uncvref_t<A>, uncvref_t<B>>::value>
struct is_comparable : std::false_type {};

template<typename Compare, typename A, typename B>
struct is_comparable<Compare, A, B, false> : is_comparable_no_json_pointer<Compare, A, B> {};

template<typename T>
using detect_is_transparent = typename T::is_transparent;

// type trait to check if KeyType can be used as an object key (without a BasicJsonType)
// see is_usable_as_basic_json_key_type below
template<typename Comparator, typename ObjectKeyType, typename KeyTypeCVRef, bool RequireTransparentComparator = true,
         bool ExcludeObjectKeyType = RequireTransparentComparator, typename KeyType = uncvref_t<KeyTypeCVRef>>
using is_usable_as_key_type = typename std::conditional <
                              is_comparable<Comparator, ObjectKeyType, KeyTypeCVRef>::value
                              && !(ExcludeObjectKeyType && std::is_same<KeyType,
                                   ObjectKeyType>::value)
                              && (!RequireTransparentComparator
                                  || is_detected <detect_is_transparent, Comparator>::value)
                              && !is_json_pointer<KeyType>::value,
                              std::true_type,
                              std::false_type >::type;

#ifdef JSON_HAS_CPP_17
// type trait to check if KeyType can only be used as an object key after
// converting it to std::string_view: it is convertible to std::string_view, the
// object's comparator cannot compare it with object_t::key_type directly, but
// can compare a std::string_view. JSON pointers and JSON iterators are ruled out
// first, so that the conversion checks are never instantiated for them (a JSON
// pointer's deprecated conversion to string_t would be named otherwise).
template < typename BasicJsonType, typename KeyTypeCVRef, typename KeyType = uncvref_t<KeyTypeCVRef>,
           bool = is_json_pointer<KeyType>::value || is_json_iterator_of<BasicJsonType, KeyType>::value >
struct is_string_view_convertible_key_type : std::false_type {};

template<typename BasicJsonType, typename KeyTypeCVRef, typename KeyType>
struct is_string_view_convertible_key_type<BasicJsonType, KeyTypeCVRef, KeyType, false>
    : std::integral_constant < bool,
      std::is_convertible<KeyTypeCVRef, std::string_view>::value
      && !is_usable_as_key_type<typename BasicJsonType::object_comparator_t,
      typename BasicJsonType::object_t::key_type, KeyTypeCVRef, true, false>::value
      && is_usable_as_key_type<typename BasicJsonType::object_comparator_t,
      typename BasicJsonType::object_t::key_type, std::string_view, true, false>::value > {};
#else
template<typename BasicJsonType, typename KeyTypeCVRef>
struct is_string_view_convertible_key_type : std::false_type {};
#endif

// type trait to check if KeyType can be used as an object key
// true if:
//   - KeyType is comparable with BasicJsonType::object_t::key_type
//   - if ExcludeObjectKeyType is true, KeyType is not BasicJsonType::object_t::key_type
//   - the comparator is transparent or RequireTransparentComparator is false
//   - KeyType is not a JSON iterator or json_pointer
template<typename BasicJsonType, typename KeyTypeCVRef, bool RequireTransparentComparator = true,
         bool ExcludeObjectKeyType = RequireTransparentComparator, typename KeyType = uncvref_t<KeyTypeCVRef>>
using is_usable_as_basic_json_key_type = typename std::conditional <
    (is_usable_as_key_type<typename BasicJsonType::object_comparator_t,
     typename BasicJsonType::object_t::key_type, KeyTypeCVRef,
     RequireTransparentComparator, ExcludeObjectKeyType>::value
     && !is_json_iterator_of<BasicJsonType, KeyType>::value)
    || is_string_view_convertible_key_type<BasicJsonType, KeyTypeCVRef>::value
    , std::true_type,
    std::false_type >::type;

template<typename ObjectType, typename KeyType>
using detect_erase_with_key_type = decltype(std::declval<ObjectType&>().erase(std::declval<KeyType>()));

// type trait to check if object_t has an erase() member functions accepting KeyType
template<typename BasicJsonType, typename KeyType>
using has_erase_with_key_type = typename std::conditional <
                                is_detected <
                                detect_erase_with_key_type,
                                typename BasicJsonType::object_t, KeyType >::value,
                                std::true_type,
                                std::false_type >::type;

template<typename ObjectType, typename IteratorType>
using detect_erase_with_iterator = decltype(std::declval<ObjectType&>().erase(std::declval<IteratorType>()));

// type trait to check if erase(iterator) returns void instead of the following
// iterator, as the object types that do not compute a successor the caller may
// not need do
template<typename ObjectType, typename IteratorType>
using erase_returns_void = is_detected_exact<void, detect_erase_with_iterator, ObjectType, IteratorType>;

template<typename T>
using detect_capacity = decltype(std::declval<const T&>().capacity());

// type trait to check if a type has a capacity() member function
template<typename T>
struct has_capacity : std::integral_constant<bool, is_detected<detect_capacity, T>::value> {};

// a naive helper to check if a type is an ordered_map (exploits the fact that
// ordered_map inherits capacity() from std::vector)
template <typename T>
struct is_ordered_map : has_capacity<T> {};

// whether T is a specialization of nlohmann::ordered_map, which only ever
// appends members, so they can only move when its capacity changes
template<typename T>
struct is_nlohmann_ordered_map : std::false_type {};

template<class Key, class T, class IgnoredLess, class Allocator>
struct is_nlohmann_ordered_map<ordered_map<Key, T, IgnoredLess, Allocator>> : std::true_type {};

// whether adding or erasing elements never moves the other elements of the
// container T; only node-based standard containers are known to guarantee this
template<typename T>
struct has_stable_elements : std::false_type {};

template<class Key, class T, class Compare, class Allocator>
struct has_stable_elements<std::map<Key, T, Compare, Allocator>> : std::true_type {};

template<class Key, class T, class Compare, class Allocator>
struct has_stable_elements<std::multimap<Key, T, Compare, Allocator>> : std::true_type {};

template<class Key, class T, class Hash, class KeyEqual, class Allocator>
struct has_stable_elements<std::unordered_map<Key, T, Hash, KeyEqual, Allocator>> : std::true_type {};

template<class Key, class T, class Hash, class KeyEqual, class Allocator>
struct has_stable_elements<std::unordered_multimap<Key, T, Hash, KeyEqual, Allocator>> : std::true_type {};

// to avoid useless casts (see https://github.com/nlohmann/json/issues/2893#issuecomment-889152324)
template < typename T, typename U, enable_if_t < !std::is_same<T, U>::value, int > = 0 >
T conditional_static_cast(U value)
{
    return static_cast<T>(value);
}

template<typename T, typename U, enable_if_t<std::is_same<T, U>::value, int> = 0>
T conditional_static_cast(U value)
{
    return value;
}

// like conditional_static_cast, but converts to bool by comparing with zero,
// because MSVC 2015 warns about any conversion to bool (C4800), even with an
// explicit cast; used for enums whose underlying type is bool
template < typename T, typename U, enable_if_t < !std::is_same<T, bool>::value, int > = 0 >
T bool_aware_static_cast(U value)
{
    return conditional_static_cast<T>(value);
}

template<typename T, typename U, enable_if_t<std::is_same<T, bool>::value, int> = 0>
bool bool_aware_static_cast(U value)
{
    return value != U();
}

template<typename... Types>
using all_integral = conjunction<std::is_integral<Types>...>;

template<typename... Types>
using all_signed = conjunction<std::is_signed<Types>...>;

template<typename... Types>
using all_unsigned = conjunction<std::is_unsigned<Types>...>;

template<typename... Types>
using same_sign = disjunction<all_signed<Types...>, all_unsigned<Types...>>;

template<typename OfType, typename T>
using never_out_of_range = std::integral_constant < bool,
      (std::is_signed<OfType>::value && (sizeof(T) < sizeof(OfType)))
      || (same_sign<OfType, T>::value && sizeof(OfType) == sizeof(T)) >;

template<typename OfType, typename T,
         bool OfTypeSigned = std::is_signed<OfType>::value,
         bool TSigned = std::is_signed<T>::value>
struct value_in_range_of_impl2;

template<typename OfType, typename T>
struct value_in_range_of_impl2<OfType, T, false, false>
{
    static constexpr bool test(T val)
    {
        using CommonType = typename std::common_type<OfType, T>::type;
        return static_cast<CommonType>(val) <= static_cast<CommonType>((std::numeric_limits<OfType>::max)());
    }
};

template<typename OfType, typename T>
struct value_in_range_of_impl2<OfType, T, true, false>
{
    static constexpr bool test(T val)
    {
        using CommonType = typename std::common_type<OfType, T>::type;
        return static_cast<CommonType>(val) <= static_cast<CommonType>((std::numeric_limits<OfType>::max)());
    }
};

template<typename OfType, typename T>
struct value_in_range_of_impl2<OfType, T, false, true>
{
    static constexpr bool test(T val)
    {
        using CommonType = typename std::common_type<OfType, T>::type;
        return val >= 0 && static_cast<CommonType>(val) <= static_cast<CommonType>((std::numeric_limits<OfType>::max)());
    }
};

template<typename OfType, typename T>
struct value_in_range_of_impl2<OfType, T, true, true>
{
    static constexpr bool test(T val)
    {
        using CommonType = typename std::common_type<OfType, T>::type;
        return static_cast<CommonType>(val) >= static_cast<CommonType>((std::numeric_limits<OfType>::min)())
               && static_cast<CommonType>(val) <= static_cast<CommonType>((std::numeric_limits<OfType>::max)());
    }
};

template<typename OfType, typename T,
         bool NeverOutOfRange = never_out_of_range<OfType, T>::value,
         typename = detail::enable_if_t<all_integral<OfType, T>::value>>
struct value_in_range_of_impl1;

template<typename OfType, typename T>
struct value_in_range_of_impl1<OfType, T, false>
{
    static constexpr bool test(T val)
    {
        return value_in_range_of_impl2<OfType, T>::test(val);
    }
};

template<typename OfType, typename T>
struct value_in_range_of_impl1<OfType, T, true>
{
    static constexpr bool test(T /*val*/)
    {
        return true;
    }
};

template<typename OfType, typename T>
constexpr bool value_in_range_of(T val)
{
    return value_in_range_of_impl1<OfType, T>::test(val);
}

template<bool Value>
using bool_constant = std::integral_constant<bool, Value>;

// Stands in for number_unsigned_t in overload sets if it is the same type as
// number_integer_t, so that the unsigned overloads do not collide with the
// integer ones. Never constructed. Such a basic_json stores every integer as
// number_integer (#2573).
struct same_as_number_integer_type {};

// NumberUnsignedType, or same_as_number_integer_type if it is the same type as
// NumberIntegerType; basic_json uses this one, as it cannot name its own member
// types through an incomplete basic_json (MSVC reports a recursive alias, and
// old GCC versions crash)
template<typename NumberIntegerType, typename NumberUnsignedType>
using number_unsigned_overload_type = typename std::conditional<std::is_same<NumberIntegerType, NumberUnsignedType>::value,
      same_as_number_integer_type, NumberUnsignedType>::type;

// number_unsigned_t of BasicJsonType, or same_as_number_integer_type if it is
// the same type as number_integer_t
template<typename BasicJsonType>
using number_unsigned_overload_t = number_unsigned_overload_type<typename BasicJsonType::number_integer_t, typename BasicJsonType::number_unsigned_t>;

///////////////////////////////////////////////////////////////////////////////
// is_c_string
///////////////////////////////////////////////////////////////////////////////

namespace impl
{

template<typename T>
constexpr bool is_c_string()
{
    using TUnExt = typename std::remove_extent<T>::type;
    using TUnCVExt = typename std::remove_cv<TUnExt>::type;
    using TUnPtr = typename std::remove_pointer<T>::type;
    using TUnCVPtr = typename std::remove_cv<TUnPtr>::type;
    return
        (std::is_array<T>::value && std::is_same<TUnCVExt, char>::value)
        || (std::is_pointer<T>::value && std::is_same<TUnCVPtr, char>::value);
}

}  // namespace impl

// checks whether T is a [cv] char */[cv] char[] C string
template<typename T>
struct is_c_string : bool_constant<impl::is_c_string<T>()> {};

template<typename T>
using is_c_string_uncvref = is_c_string<uncvref_t<T>>;

///////////////////////////////////////////////////////////////////////////////
// is_transparent
///////////////////////////////////////////////////////////////////////////////

namespace impl
{

template<typename T>
constexpr bool is_transparent()
{
    return is_detected<detect_is_transparent, T>::value;
}

}  // namespace impl

// checks whether T has a member named is_transparent
template<typename T>
struct is_transparent : bool_constant<impl::is_transparent<T>()> {};

///////////////////////////////////////////////////////////////////////////////

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

// #include <nlohmann/detail/view/document_data.hpp>

// #include <nlohmann/detail/view/macro_scope.hpp>

// #include <nlohmann/detail/view/node.hpp>


// Hash indexes of the keys of large objects, so that a lookup does not compare thousands
// of keys (as Boost.JSON switches from a linear search to a hash table for
// large objects). An object with document_data::index_min_members members or
// more gets an open-addressing table after parsing; its node stores the
// number of the table (1-based) in `extra`. A slot holds the offset of a key
// node from its object node (0: empty). Of duplicate keys, the first is kept,
// as for the linear search.
//
// The hash is not seeded, so keys chosen to collide could make the build
// quadratic. A key therefore sits at most index_max_displacement slots away
// from its home slot; if a key would sit further away, the table is dropped
// and the object is searched linearly (like a small one). For the same
// reason, a lookup visits at most index_max_displacement + 1 slots.

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// the farthest a key may sit from its home slot (a table with at most half of
/// its slots in use gives random keys a distance of about 50 for millions of
/// members; and every member costs at most this many steps while building)
constexpr std::size_t index_max_displacement = 64;

// a table has at least 2 * len slots (len >= index_min_members), so the probe
// window of index_max_displacement + 1 slots stays far smaller than the table
// and a probe never wraps around onto its own start
static_assert(document_data::index_min_members >= 2 * index_max_displacement,
              "a table must be much larger than the probe window of a lookup");

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
    std::uint32_t* const table = d.index_slots.data() + start;
    const std::size_t mask = cap - 1;
    for (const node* k = document_data::first_child(obj), *end = document_data::child_end(obj); k != end; k = document_data::after(k + 1))
    {
        const char* const key = d.str(*k);
        std::size_t slot = conditional_static_cast<std::size_t>(key_hash(key, k->len)) & mask;
        bool duplicate = false;
        std::size_t distance = 0;
        while (table[slot] != 0)
        {
            const node* const other = obj + table[slot];
            if (other->len == k->len && (k->len == 0 || std::memcmp(d.str(*other), key, k->len) == 0))
            {
                duplicate = true; // keep the first
                break;
            }
            if (distance == index_max_displacement)
            {
                // too many keys share a home region
                d.index_slots.resize(start); // no table: the object is searched linearly
                return;
            }
            ++distance;
            slot = (slot + 1) & mask;
        }
        if (!duplicate)
        {
            table[slot] = static_cast<std::uint32_t>(k - obj);
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
        build_object_index(d, d.nodes + i);
    }
}

/// the key node of the first member with this key of an indexed object, or
/// nullptr
inline const node* find_indexed(const document_data& d, const node* obj, const char* key, std::size_t n) noexcept
{
    const document_data::object_index& ix = d.indexes[obj->extra - 1u];
    const std::uint32_t* const table = d.index_slots.data() + ix.start;
    std::size_t slot = conditional_static_cast<std::size_t>(key_hash(key, n)) & ix.mask;
    for (std::size_t distance = 0; distance <= index_max_displacement; ++distance)
    {
        const std::uint32_t s = table[slot];
        if (s == 0)
        {
            return nullptr;
        }
        const node* const k = obj + s;
        if (k->len == n && (n == 0 || std::memcmp(d.str(*k), key, n) == 0))
        {
            return k;
        }
        slot = (slot + 1) & ix.mask;
    }
    return nullptr; // (no key sits further from its home slot)
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
/// nullptr (the search stops at the first match; materialize() and parse()
/// keep the last value of a duplicate key instead); most keys are rejected by
/// their length, from the index alone
inline const node* find_member(const document_data& d, const node* object, const char* key, std::size_t n) noexcept
{
    if (NLOHMANN_VIEW_UNLIKELY(object->extra != 0))
    {
        return find_indexed(d, object, key, n); // a large object
    }
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
        if (d.key_equals(*m, key, n))
        {
            return m;
        }
    }
    return nullptr;
}

/// the number of members of an object with this key (duplicates included)
inline std::size_t count_members(const document_data& d, const node* object, const char* key, std::size_t n) noexcept
{
    std::size_t result = 0;
    const node* const end = document_data::child_end(object);
    for (const node* m = document_data::first_child(object); m != end; m = document_data::after(m + 1))
    {
        if (d.key_equals(*m, key, n))
        {
            ++result;
        }
    }
    return result;
}

/// whether an integer type is accepted as an array index by the view's
/// operator[] and at(): every integer type but bool and size_t, which has its
/// own overload
template<typename T>
struct is_index_type : std::integral_constant < bool,
    std::is_integral<T>::value && !std::is_same<T, bool>::value && !std::is_same<T, std::size_t>::value >
{};

/// an integer as an index: negative values, and values that do not fit a
/// size_t, map to the largest size_t (out of range for every array)
template<typename SizeType, typename IntegerType>
SizeType to_index(IntegerType idx) noexcept
{
    const IntegerType zero = 0;
    const auto result = static_cast<SizeType>(idx); // NOLINT(bugprone-signed-char-misuse,cert-str34-c): negative values are mapped below
    return (idx < zero || static_cast<IntegerType>(result) != idx) ? (std::numeric_limits<SizeType>::max)() : result;
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



#include <algorithm> // max
#include <cstddef> // size_t
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
#include <cstdint> // int64_t, uint64_t
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
        // [eE][+-]digits; huge exponents saturate (the parser rejected overflow)
        ++p;
        const bool exp_negative = *p == '-';
        p += (*p == '-' || *p == '+') ? 1 : 0;
        std::int64_t exp_value = 0;
        for (; p != e; ++p)
        {
            if (exp_value < 0x10000000)
            {
                exp_value = (exp_value * 10) + (*p - '0');
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

/// the value of the float token of a node, as parse() converts it; floats and
/// doubles with at most 19 digits are converted from the digit layout
template<typename FloatType>
FloatType float_value(const document_data& d, const node& n)
{
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
    // the ends of the open containers, and whether they are objects; sized
    // once from the document's deepest nesting (for a subtree an upper bound)
    struct open_container
    {
        const node* end;
        bool is_object;
    };
    std::vector<open_container> open((std::max)(d.max_depth, std::size_t{1}));
    std::size_t depth = 0;
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
                if (NLOHMANN_VIEW_UNLIKELY(depth == open.size()))
                {
                    open.resize(depth * 2); // (deeper than the document's recorded nesting)
                }
                open[depth++] = open_container{document_data::child_end(n), object};
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
                sax.number_float(float_value<typename BasicJsonType::number_float_t>(d, *n), no_token);
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
            if (depth == 0)
            {
                return result;
            }
            if (n != open[depth - 1].end)
            {
                break;
            }
            if (open[depth - 1].is_object)
            {
                sax.end_object();
            }
            else
            {
                sax.end_array();
            }
            --depth;
        }
        if (open[depth - 1].is_object)
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
    // as basic_json: the empty token and "-" (past the last element) are
    // unresolved rather than not a number
    if (s.empty() || (s.size() == 1 && s[0] == '-'))
    {
        return index_status::unresolved;
    }
    if (s[0] < '0' || s[0] > '9')
    {
        return index_status::not_number;
    }
    if (s.size() > 1 && s[0] == '0')
    {
        return index_status::leading_zero;
    }
    std::uint64_t v = 0;
    for (const auto c : s)
    {
        const auto d = static_cast<unsigned>(static_cast<unsigned char>(c)) - '0';
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
/// is resized ahead, and trimmed by finish()
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
        const auto size = static_cast<std::size_t>(m_pos - m_out.data());
        m_out.resize(size);
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

    /// a string literal, without its terminating NUL
    template<std::size_t N>
    NLOHMANN_VIEW_ALWAYS_INLINE void put(const char (&s)[N]) // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    {
        put(s, N - 1);
    }

    void put_repeated(char c, std::size_t n)
    {
        reserve(n);
        std::memset(m_pos, c, n);
        m_pos += n;
    }

  private:
    static StringType& sized(StringType& out, std::size_t estimate)
    {
        out.resize((std::max)(estimate, static_cast<std::size_t>(64)));
        return out;
    }

    NLOHMANN_VIEW_NOINLINE void grow(std::size_t n)
    {
        const auto used = static_cast<std::size_t>(m_pos - m_out.data());
        m_out.resize((std::max)(m_out.size() * 2, used + n + 256));
        m_pos = &m_out[0] + used;
        m_end = &m_out[0] + m_out.size();
    }

    StringType& m_out;
    char* m_pos;
    char* m_end;
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
template<typename BasicJsonType>
class view_serializer
{
    using string_t = typename BasicJsonType::string_t;
    using number_float_t = typename BasicJsonType::number_float_t;

  public:
    view_serializer(const document_data& d, string_t& out, std::size_t estimate, const dump_style& style)
        : m_doc(d), m_out(out, estimate), m_style(style)
    {}

    void dump(const node* root)
    {
        struct frame
        {
            const node* pos; ///< next element, or key of the next member
            const node* end;
            bool object;
            bool first;  ///< nothing written yet
        };
        std::vector<frame> stack;
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
                    stack.push_back(frame{document_data::first_child(n), document_data::child_end(n), object, true});
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
                if (stack.back().pos == stack.back().end)
                {
                    const bool object = stack.back().object;
                    stack.pop_back();
                    newline(stack.size());
                    m_out.put(object ? '}' : ']');
                    continue;
                }
                frame& f = stack.back();
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
                        m_out.put(": ");
                    }
                    else
                    {
                        m_out.put(':');
                    }
                    n = f.pos + 1;
                }
                else
                {
                    n = f.pos;
                }
                f.pos = document_data::after(n);
                break;
            }
        }
    }

  private:
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
                m_out.put("null");
                break;
            case value_t::boolean:
                if ((n.flags & node_flags::is_true) != 0)
                {
                    m_out.put("true");
                }
                else
                {
                    m_out.put("false");
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
                if (m_style.source_numbers)
                {
                    m_out.put(m_doc.str(n), n.len);
                }
                else
                {
                    write_float(float_value<number_float_t>(m_doc, n));
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

    /// as serializer::dump_float()
    void write_float(number_float_t x)
    {
        if (!std::isfinite(x))
        {
            m_out.put("null");
            return;
        }
        static constexpr bool is_ieee_single_or_double
            = std::numeric_limits<number_float_t>::is_iec559
              && ((std::numeric_limits<number_float_t>::digits == 24 && std::numeric_limits<number_float_t>::max_exponent == 128)
                  || (std::numeric_limits<number_float_t>::digits == 53 && std::numeric_limits<number_float_t>::max_exponent == 1024));
        write_float(x, std::integral_constant<bool, is_ieee_single_or_double>());
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
        if ((n.flags & node_flags::escaped) == 0 && !m_style.ensure_ascii)
        {
            // a string without escape sequences has nothing to escape
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

    /// as serializer::dump_escaped() for valid UTF-8 (the view has no other)
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
            if (codepoint >= 0xC0)
            {
                len = 2;
                if (codepoint >= 0xE0)
                {
                    len = codepoint >= 0xF0 ? 4 : 3;
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

    template<bool EnsureAscii>
    void write_codepoint(std::uint32_t codepoint, const unsigned char* bytes, std::size_t len)
    {
        switch (codepoint)
        {
            case 0x08:
                m_out.put("\\b");
                return;
            case 0x09:
                m_out.put("\\t");
                return;
            case 0x0A:
                m_out.put("\\n");
                return;
            case 0x0C:
                m_out.put("\\f");
                return;
            case 0x0D:
                m_out.put("\\r");
                return;
            case 0x22:
                m_out.put("\\\"");
                return;
            case 0x5C:
                m_out.put("\\\\");
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



#include <cstddef> // nullptr_t, size_t
#include <cstdint> // int64_t
#include <map> // map
#include <string> // basic_string
#include <type_traits> // decay, enable_if, is_arithmetic, is_constructible, is_integral, is_same
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

/// the arithmetic types arithmetic_value() converts to (bool has its own
/// conversion)
template<typename T>
struct is_non_bool_arithmetic : conjunction<std::is_arithmetic<T>, negation<std::is_same<T, bool>>> {};

/// the default values of value() other than C strings, which have their own
/// overload (returning string_t)
template<typename T>
struct is_non_c_string_default : negation<std::is_same<typename std::decay<T>::type, const char*>> {};

/// whether View::get<T>() converts to T without materialize(); get_to()
/// assigns these, and passes the others to from_json
template<typename T, typename BasicJsonType, typename View>
struct is_direct_value : std::integral_constant < bool,
    std::is_arithmetic<T>::value || std::is_same<T, std::nullptr_t>::value
    || std::is_same<T, typename View::string_view_t>::value
    || std::is_same<T, BasicJsonType>::value || std::is_same<T, View>::value >
{};

template<typename Traits, typename Alloc, typename BasicJsonType, typename View>
struct is_direct_value<std::basic_string<char, Traits, Alloc>, BasicJsonType, View> : std::true_type {};

template<typename U, typename A, typename BasicJsonType, typename View>
struct is_direct_value<std::vector<U, A>, BasicJsonType, View> : std::true_type {};

template<typename K, typename V, typename C, typename A, typename BasicJsonType, typename View>
struct is_direct_value<std::map<K, V, C, A>, BasicJsonType, View> : is_string_key<K> {};

template<typename K, typename V, typename H, typename E, typename A, typename BasicJsonType, typename View>
struct is_direct_value<std::unordered_map<K, V, H, E, A>, BasicJsonType, View> : is_string_key<K> {};

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END


NLOHMANN_JSON_NAMESPACE_BEGIN

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
    /// occur more than once); a discarded view if there is none, or if this
    /// is a discarded view (so that v["a"]["b"] is safe). Throws type_error.305
    /// if this is any other value but an object.
    NLOHMANN_VIEW_ALWAYS_INLINE basic_json_view operator[](string_view_t key) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_object()))
        {
            if (is_discarded())
            {
                return {};
            }
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
    /// range, or if this is a discarded view. Throws type_error.305 if this is
    /// any other value but an array.
    basic_json_view operator[](size_type idx) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_array()))
        {
            if (is_discarded())
            {
                return {};
            }
            detail::view::throw_type_error(305, "cannot use operator[] with a numeric argument with ", type_name());
        }
        return idx < m_node->len ? basic_json_view(m_doc, detail::view::element_at(m_node, idx)) : basic_json_view();
    }

    /// any other integer type (int, unsigned, long, std::int64_t, ...; a
    /// single overload for size_type alone would be ambiguous for all of them
    /// and for const char*); negative values are out of range
    template < typename IntegerType, typename std::enable_if < detail::view::is_index_type<IntegerType>::value, int >::type = 0 >
    basic_json_view operator[](IntegerType idx) const
    {
        return operator[](detail::view::to_index<size_type>(idx));
    }

    /// the value a JSON pointer refers to; a discarded view if a key is
    /// missing or an index is out of range, or if this is a discarded view.
    /// Other errors throw what const basic_json::operator[] throws.
    basic_json_view operator[](const json_pointer& ptr) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(is_discarded()))
        {
            return {};
        }
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
        if (NLOHMANN_VIEW_UNLIKELY(r.is_discarded()))
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

    /// any other integer type, see operator[]; negative values are out of
    /// range
    template < typename IntegerType, typename std::enable_if < detail::view::is_index_type<IntegerType>::value, int >::type = 0 >
    basic_json_view at(IntegerType idx) const
    {
        return at(detail::view::to_index<size_type>(idx));
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
    template<typename T, typename std::enable_if<detail::view::is_non_c_string_default<T>::value, int>::type = 0>
    T value(string_view_t key, const T& default_value) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_object()))
        {
            detail::view::throw_type_error(306, "cannot use value() with ", type_name());
        }
        const basic_json_view r = lookup(key);
        return r.is_discarded() ? default_value : r.template get<T>();
    }

    string_t value(string_view_t key, const char* default_value) const
    {
        return value(key, string_t(default_value));
    }

    /// the value a JSON pointer refers to converted to T, or the default
    /// value if the pointer cannot be resolved. Throws type_error.306 if this
    /// is neither an object nor an array.
    template<typename T, typename std::enable_if<detail::view::is_non_c_string_default<T>::value, int>::type = 0>
    T value(const json_pointer& ptr, const T& default_value) const
    {
        if (NLOHMANN_VIEW_UNLIKELY(!is_structured()))
        {
            detail::view::throw_type_error(306, "cannot use value() with ", type_name());
        }
        const basic_json_view r = detail::view::resolve_pointer(*this, detail::json_pointer_access::reference_tokens(ptr), detail::view::pointer_mode::value);
        return r.is_discarded() ? default_value : r.template get<T>();
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
        return !detail::view::resolve_pointer(*this, detail::json_pointer_access::reference_tokens(ptr), detail::view::pointer_mode::contains).is_discarded();
    }

    /// the number of members with this key (more than 1 if the key occurs
    /// more than once); 0 if this is not an object
    size_type count(string_view_t key) const
    {
        return is_object() ? detail::view::count_members(*m_doc, m_node, key.data(), key.size()) : 0;
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

    /// as BasicJsonType::get_to(): the types get<T>() converts directly are
    /// assigned, all others are passed to from_json with v as it is
    template<typename T>
    T& get_to(T& v) const
    {
        get_to_impl(v, detail::view::is_direct_value<T, BasicJsonType, basic_json_view> {});
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
        // the compact text is about as long as the source text of the value
        const std::size_t estimate = source_extent() + (style.pretty ? source_extent() / 2 : 0) + 64;
        detail::view::view_serializer<BasicJsonType>(*m_doc, out, estimate, style).dump(m_node);
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

    using json_side_t = detail::view::json_side<BasicJsonType, string_view_t>;

    static detail::view::view_side<BasicJsonType, basic_json_view> side(const basic_json_view& v) noexcept
    {
        return detail::view::view_side<BasicJsonType, basic_json_view>(v);
    }

    /// the number of source bytes of this value (estimated for values with
    /// decoded strings); the estimate sizes the output buffer of dump()
    std::size_t source_extent() const noexcept
    {
        const node* const end = m_doc->nodes + m_doc->node_count;
        if ((m_node->flags & detail::view::node_flags::storage) != 0)
        {
            return m_node->len;
        }
        // the value ends where the next node in the source begins; nodes
        // with decoded strings (their offset is in the arena) are skipped,
        // but only a few of them, to keep the walk short
        const node* next = document_data::after(m_node);
        for (int skipped = 0; next != end && skipped < 16; ++skipped, ++next)
        {
            if ((next->flags & detail::view::node_flags::storage) == 0)
            {
                return next->off >= m_node->off ? next->off - m_node->off : 0;
            }
        }
        if (next == end)
        {
            return m_doc->size - m_node->off;
        }
        // the end is unknown: assume a few bytes per node, the output buffer
        // grows should the value be larger
        const auto nodes = static_cast<std::size_t>(document_data::after(m_node) - m_node);
        return (std::min)(m_doc->size - m_node->off, static_cast<std::size_t>(1024) + (nodes * 16));
    }

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

    template<typename T, typename std::enable_if<detail::view::is_non_bool_arithmetic<T>::value, int>::type = 0>
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

    // --- get_to() dispatch ---

    template<typename T>
    void get_to_impl(T& v, std::true_type /*direct*/) const
    {
        v = get<T>();
    }

    /// from_json may keep parts of v (members a JSON object lacks, say)
    template<typename T>
    void get_to_impl(T& v, std::false_type /*direct*/) const
    {
        materialize().get_to(v);
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

    /// parse(ptr, len) does not compile: len would convert to allow_exceptions
    /// and ptr be read as a C string (as for the overloads of parse_copy,
    /// accept, and read below)
    template<typename InputType, typename IntegerType, typename... Flags>
    static typename std::enable_if<detail::view::is_integer_not_bool<IntegerType>::value, basic_json_document>::type
    parse(InputType&& input, IntegerType value, Flags&&... flags) = delete;

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
        std::string buf;
        append_input(buf, std::forward<InputType>(input));
        d.build_owned(std::move(buf), allow_exceptions, ignore_comments, ignore_trailing_commas);
        return d;
    }

    template<typename InputType, typename IntegerType, typename... Flags>
    static typename std::enable_if<detail::view::is_integer_not_bool<IntegerType>::value, basic_json_document>::type
    parse_copy(InputType&& input, IntegerType value, Flags&&... flags) = delete;

    /// check whether the input is valid JSON (the result of basic_json::accept)
    template<typename InputType>
    static bool accept(InputType&& input, const bool ignore_comments = false, const bool ignore_trailing_commas = false)
    {
        basic_json_document d;
        d.read(std::forward<InputType>(input), false, ignore_comments, ignore_trailing_commas);
        return !d.is_discarded();
    }

    template<typename InputType, typename IntegerType, typename... Flags>
    static typename std::enable_if<detail::view::is_integer_not_bool<IntegerType>::value, bool>::type
    accept(InputType&& input, IntegerType value, Flags&&... flags) = delete;

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

    template<typename InputType, typename IntegerType, typename... Flags>
    typename std::enable_if<detail::view::is_integer_not_bool<IntegerType>::value, void>::type
    // flawfinder: ignore (a member function, not POSIX read())
    read(InputType&& input, IntegerType value, Flags&&... flags) = delete;

    ////////////
    // access //
    ////////////

    /// the root value (discarded if parsing failed without exceptions)
    view_type root() const& noexcept
    {
        if (!m_data || m_data->discarded)
        {
            return view_type();
        }
        return view_type(m_data.get(), m_data->nodes);
    }

    /// deleted: the view of a temporary document would dangle
    view_type root() const&& = delete;

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
        return m_data ? m_data->node_count : 0;
    }

    /// bytes held by the document (index, decoded strings, owned text)
    std::size_t memory_usage() const noexcept
    {
        if (!m_data)
        {
            return 0;
        }
        return sizeof(document_data) + (m_data->inline_capacity * sizeof(detail::view::node))
               + (m_data->nodes != m_data->inline_nodes ? m_data->node_capacity * sizeof(detail::view::node) : 0)
               + m_data->arena.capacity() + m_data->owned.capacity()
               + (m_data->indexes.capacity() * sizeof(document_data::object_index)) + (m_data->index_slots.capacity() * sizeof(std::uint32_t))
               + (m_data->large_objects.capacity() * sizeof(std::uint32_t));
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
        std::vector<char> arena(shrink_arena ? d.arena : std::vector<char>());
        const bool shrink_nodes = d.nodes != d.inline_nodes && d.node_count != d.node_capacity;
        const bool into_header = d.node_count <= d.inline_capacity;
        std::vector<document_data::object_index> indexes(d.indexes.capacity() > d.indexes.size() ? d.indexes : std::vector<document_data::object_index>());
        std::vector<std::uint32_t> index_slots(d.index_slots.capacity() > d.index_slots.size() ? d.index_slots : std::vector<std::uint32_t>());
        node* fresh = (shrink_nodes && !into_header) ? static_cast<node*>(::operator new (d.node_count * sizeof(node))) : d.inline_nodes;

        if (shrink_nodes)
        {
            if (d.node_count != 0)
            {
                std::memcpy(fresh, d.nodes, d.node_count * sizeof(node));
            }
            ::operator delete (d.nodes);
            d.nodes = fresh;
            d.node_capacity = into_header ? d.inline_capacity : d.node_count;
        }
        if (shrink_arena)
        {
            d.arena.swap(arena);
            d.base[1] = d.arena.data();
        }
        if (d.indexes.capacity() > d.indexes.size())
        {
            d.indexes.swap(indexes);
        }
        if (d.index_slots.capacity() > d.index_slots.size())
        {
            d.index_slots.swap(index_slots);
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

    /// parse a buffer the document takes ownership of (it replaces the
    /// previous owned copy)
    void build_owned(std::string&& buf, bool allow_exceptions, bool comments, bool trailing_commas)
    {
        ensure_data(buf.data(), buf.size());
        m_data->owned = std::move(buf);
        build(m_data->owned.data(), m_data->owned.size(), allow_exceptions, comments, trailing_commas, true, true);
    }

    /// parse a copy of the input; the copy is appended to the cleared owned
    /// buffer, so that its capacity is reused
    template<typename T>
    void build_copy(T&& input, bool allow_exceptions, bool comments, bool trailing_commas)
    {
        if (!m_data)
        {
            std::string buf;
            append_input(buf, std::forward<T>(input));
            build_owned(std::move(buf), allow_exceptions, comments, trailing_commas);
            return;
        }
        document_data& d = *m_data;
        // (the previous text is gone from here on: should reading the input
        // throw, the document is discarded)
        d.discarded = true;
        d.src = "";
        d.size = 0;
        d.owned.clear();
        append_input(d.owned, std::forward<T>(input));
        build(d.owned.data(), d.owned.size(), allow_exceptions, comments, trailing_commas, true, true);
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
        d.node_count = 0;
        d.arena.clear();
        d.indexes.clear();
        d.index_slots.clear();
        d.large_objects.clear();
        d.discarded = true;
        detail::view::parse_failure failure;
        bool ok = false;
        if (NLOHMANN_VIEW_UNLIKELY(size > detail::view::max_input_size()))
        {
            failure.code = detail::view::error_code::input_too_large;
        }
        else
        {
            ok = detail::view::build < typename BasicJsonType::number_float_t, !detail::abi_config::strict_nul_handling > (d, src, size, comments, trailing_commas, sentinel, failure);
        }
        if (NLOHMANN_VIEW_LIKELY(ok))
        {
            d.base[0] = d.src;
            d.base[1] = d.arena.data();
            detail::view::build_object_indexes(d);
            std::vector<std::uint32_t>().swap(d.large_objects); // (only needed while parsing)
            d.discarded = false;
            return;
        }
        std::vector<std::uint32_t>().swap(d.large_objects);
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
        build_copy(s, ae, c, tc);
    }

    template<typename CharT>
    void read_kind(CharT* s, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::wide_c_string> /*unused*/)
    {
        if (s == nullptr)
        {
            build("", 0, ae, c, tc, false, true);
            return;
        }
        // NUL-terminated, as for the single-byte C strings
        build_copy(detail::view::make_adapter_input(detail::input_adapter(s, s + std::char_traits<typename std::remove_cv<CharT>::type>::length(s))), ae, c, tc);
    }

    template<typename T>
    void read_kind(T&& input, bool ae, bool c, bool tc, std::integral_constant<input_kind, input_kind::adapter> /*unused*/)
    {
        build_copy(std::forward<T>(input), ae, c, tc);
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
        build_copy(detail::view::make_adapter_input(detail::input_adapter(first, last)), ae, c, tc);
    }

    /// append the text of an input to buf: a contiguous byte input as one
    /// block, a stream in blocks, an input adapter (made here for any other
    /// input) character by character
    template<typename T>
    static void append_input(std::string& buf, T&& input)
    {
        using D = typename std::decay<T>::type;
        // NOLINTBEGIN(readability-avoid-nested-conditional-operator): a constant expression of C++11
        append_input_impl(buf, std::forward<T>(input), std::integral_constant < int, detail::is_contiguous_byte_container<D>::value ? 0
                          : std::is_base_of<std::istream, D>::value ? 1
                          : detail::view::is_adapter_input<D>::value ? 2 : 3 > {});
        // NOLINTEND(readability-avoid-nested-conditional-operator)
    }

    template<typename T>
    static void append_input_impl(std::string& buf, const T& s, std::integral_constant<int, 0> /*contiguous bytes*/)
    {
        buf.append(reinterpret_cast<const char*>(s.data()), static_cast<std::size_t>(s.size())); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    }

    template<typename Stream>
    static void append_input_impl(std::string& buf, Stream&& is, std::integral_constant<int, 1> /*stream*/) // NOLINT(cppcoreguidelines-missing-std-forward): read in place, as by the library's stream adapter
    {
        detail::view::append_stream(buf, is);
    }

    template<typename Adapter>
    static void append_input_impl(std::string& buf, detail::view::adapter_input<Adapter>&& input, std::integral_constant<int, 2> /*input adapter*/)
    {
        detail::view::append_adapter(buf, std::move(input.ia));
    }

    template<typename T>
    static void append_input_impl(std::string& buf, T&& input, std::integral_constant<int, 3> /*other*/)
    {
        detail::view::append_adapter(buf, detail::input_adapter(std::forward<T>(input)));
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
namespace std // NOLINT(cert-dcl58-cpp,bugprone-std-namespace-modification)
{

#if defined(__clang__)
    // Fix: https://github.com/nlohmann/json/issues/1401
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wmismatched-tags"
#endif
template<typename View>
class tuple_size<::nlohmann::detail::view::view_item<View>> // NOLINT(cert-dcl58-cpp,bugprone-std-namespace-modification)
    : public std::integral_constant<std::size_t, 2> {};

template<std::size_t N, typename View>
class tuple_element<N, ::nlohmann::detail::view::view_item<View>> // NOLINT(cert-dcl58-cpp,bugprone-std-namespace-modification)
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
#undef NLOHMANN_VIEW_REPEAT_SECOND_8
#undef NLOHMANN_VIEW_REPEAT_FIRST_8
#undef NLOHMANN_VIEW_NEON
#undef NLOHMANN_VIEW_SSE2
#undef NLOHMANN_VIEW_SSSE3
#undef NLOHMANN_VIEW_SSSE3_DISPATCH
#undef NLOHMANN_VIEW_SSSE3_TARGET
#undef NLOHMANN_VIEW_VECTOR
#undef NLOHMANN_VIEW_VECTOR_UTF8
// IWYU pragma: keep

#endif  // INCLUDE_NLOHMANN_JSON_VIEW_HPP_
