//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // max
#include <array> // array
#include <cmath> // isfinite
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t
#include <cstring> // memcpy, memset
#include <limits> // numeric_limits
#include <type_traits> // integral_constant
#include <vector> // vector

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>
#include <nlohmann/detail/view/number.hpp>
#include <nlohmann/detail/view/simd.hpp>

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
    /// the size of a growth step
    static constexpr std::size_t step = 0x10000;

    static StringType& sized(StringType& out, std::size_t estimate)
    {
        out.reserve(estimate);
        out.resize(detail::clamp(estimate, std::size_t{64}, step));
        return out;
    }

    NLOHMANN_VIEW_NOINLINE void grow(std::size_t n)
    {
        const auto used = static_cast<std::size_t>(m_pos - m_out.data());
        // (a step does not go beyond the reserved estimate, so that a good
        // estimate is never copied to a larger allocation; not a clamp: the
        // lower bound used + n + 256 can exceed capacity(), and then it must win)
        const std::size_t size = (std::max)((std::min)(m_out.size() + step, m_out.capacity()), used + n + 256);
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
    std::size_t i = 0;
#if NLOHMANN_VIEW_SSE2
    // (16 bytes per step; with NEON, the mask of a step costs more than it saves on the
    // short runs that are typical here)
    // NOLINTBEGIN(portability-simd-intrinsics)
    for (; i + 16 <= n; i += 16)
    {
        const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(s + i))); // NOLINT(bugprone-casting-through-void)
        // (a byte is below 0x20 if it is its own minimum with 0x1F)
        const __m128i special = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(in, _mm_set1_epi8('"')), _mm_cmpeq_epi8(in, _mm_set1_epi8('\\'))),
                                             _mm_cmpeq_epi8(_mm_min_epu8(in, _mm_set1_epi8(0x1F)), in));
        const auto mask = static_cast<std::uint64_t>(static_cast<unsigned>(_mm_movemask_epi8(special)));
        if (mask != 0)
        {
            return i + static_cast<std::size_t>(count_trailing_zeros(mask));
        }
    }
    // NOLINTEND(portability-simd-intrinsics)
#endif
    constexpr std::uint64_t ones = 0x0101010101010101ull;
    constexpr std::uint64_t high = 0x8080808080808080ull;
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

/// Whether dump() with ensure_ascii writes the string at s unchanged, for a
/// string of the source without escape sequences (which has no quote,
/// backslash, or control character): no byte is DEL (0x7F) or above. Adding 1
/// to each byte sets its high bit exactly for 0x7F, and a carry into the next
/// byte only comes from 0xFF, whose own high bit is set anyway.
inline bool is_ascii_without_delete(const char* s, std::size_t n) noexcept
{
    constexpr std::uint64_t ones = 0x0101010101010101ull;
    constexpr std::uint64_t high = 0x8080808080808080ull;
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8)
    {
        const std::uint64_t v = read_eight_bytes(s + i);
        if (((v | (v + ones)) & high) != 0)
        {
            return false;
        }
    }
    for (; i < n; ++i)
    {
        if (static_cast<unsigned char>(s[i]) >= 0x7F)
        {
            return false;
        }
    }
    return true;
}

#if NLOHMANN_VIEW_VECTOR
/// the bytes of the 16 at p that ensure_ascii cannot copy (a quote, a
/// backslash, a control character, DEL, or not ASCII; a signed compare with
/// 0x20 finds control characters and non-ASCII bytes at once), one bit per
/// byte (x86) or one nibble per byte (NEON)
NLOHMANN_VIEW_ALWAYS_INLINE std::uint64_t ascii_stop_mask(const unsigned char* p) noexcept
{
#if NLOHMANN_VIEW_NEON
    const uint8x16_t in = vld1q_u8(p);
    const uint8x16_t special = vorrq_u8(vorrq_u8(vceqq_u8(in, vdupq_n_u8('"')), vceqq_u8(in, vdupq_n_u8('\\'))),
                                        vorrq_u8(vceqq_u8(in, vdupq_n_u8(0x7F)), vcltq_s8(vreinterpretq_s8_u8(in), vdupq_n_s8(0x20))));
    return vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(vreinterpretq_u16_u8(special), 4)), 0);
#else
    const __m128i in = _mm_loadu_si128(static_cast<const __m128i*>(static_cast<const void*>(p))); // NOLINT(bugprone-casting-through-void)
    const __m128i special = _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(in, _mm_set1_epi8('"')), _mm_cmpeq_epi8(in, _mm_set1_epi8('\\'))),
                                         _mm_or_si128(_mm_cmpeq_epi8(in, _mm_set1_epi8(0x7F)), _mm_cmplt_epi8(in, _mm_set1_epi8(0x20))));
    return static_cast<std::uint64_t>(static_cast<unsigned>(_mm_movemask_epi8(special)));
#endif
}

/// the width in bits of a byte in the mask of ascii_stop_mask()
constexpr unsigned ascii_stop_bits() noexcept
{
    return NLOHMANN_VIEW_NEON ? 4u : 1u;
}
#endif

/// As find_ascii_copyable_run(), 16 bytes per step. end is the end of the
/// buffer that holds the n bytes at p (a short run is read as 16 bytes if
/// they are in the buffer).
inline std::size_t ascii_copyable_run(const unsigned char* p, std::size_t n, const unsigned char* end) noexcept
{
#if NLOHMANN_VIEW_VECTOR
    if (n >= 16)
    {
        std::size_t i = 0;
        for (; i + 16 <= n; i += 16)
        {
            const std::uint64_t mask = ascii_stop_mask(p + i);
            if (mask != 0)
            {
                return i + (static_cast<std::size_t>(count_trailing_zeros(mask)) / ascii_stop_bits());
            }
        }
        if (i == n)
        {
            return n;
        }
        // the last 16 bytes: those before i are known to be copyable
        const std::uint64_t mask = ascii_stop_mask(p + n - 16);
        return mask != 0 ? n - 16 + (static_cast<std::size_t>(count_trailing_zeros(mask)) / ascii_stop_bits()) : n;
    }
    if (end - p >= 16)
    {
        // (the bytes after the run are masked out)
        const std::uint64_t mask = ascii_stop_mask(p) & ((std::uint64_t{1} << (n * ascii_stop_bits())) - 1u);
        return mask != 0 ? static_cast<std::size_t>(count_trailing_zeros(mask)) / ascii_stop_bits() : n;
    }
#else
    static_cast<void>(end);
#endif
    return find_ascii_copyable_run(p, n);
}

/// A stack that starts in a buffer of the caller (a local array) and moves to
/// the heap (a vector of the caller) only when that is full, so that dumps of
/// shallow documents need no allocation. The top is a pointer, as in
/// std::vector. grow() is static and out of line: it gets the vector and the
/// used range and returns the new storage, so the address of the stack never
/// reaches a call. Otherwise the compiler would have to keep the three
/// pointers in memory and load and store them on every push_back() and
/// pop_back(), not just when growing.
template<typename T>
class small_stack
{
  public:
    small_stack(T* buffer, std::size_t capacity, std::vector<T>& heap) noexcept
        : m_begin(buffer), m_top(buffer), m_end(buffer + capacity), m_heap(heap)
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
            m_begin = grow(m_heap, m_begin, used, capacity);
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
    std::vector<T>& m_heap;
};

/// a string literal at w, without its terminating NUL (after room())
/// @return a pointer past it
template<std::size_t N>
NLOHMANN_VIEW_ALWAYS_INLINE char* put_literal(char* w, const char (&s)[N]) noexcept // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    std::memcpy(w, s, N - 1);
    return w + N - 1;
}

/// the depth of the innermost open container, counted only for indented output
template<bool Counted>
struct depth_counter
{
    std::size_t value = 0;
    void enter() noexcept
    {
        ++value;
    }
    std::size_t leave() noexcept
    {
        return --value;
    }
    std::size_t get() const noexcept
    {
        return value;
    }
};

template<>
struct depth_counter<false>
{
    void enter() noexcept {}
    std::size_t leave() noexcept // NOLINT(readability-convert-member-functions-to-static): same interface as depth_counter<true>
    {
        return 0;
    }
    std::size_t get() const noexcept // NOLINT(readability-convert-member-functions-to-static): same interface as depth_counter<true>
    {
        return 0;
    }
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
    /// doubles that are IEEE 754 binary64 are written from their bits (Zmij)
    using fast_double = std::integral_constant < bool, std::is_same<number_float_t, double>::value && ::nlohmann::detail::dtoa_impl::is_binary64<double>::value >;

  public:
    view_serializer(const document_data& d, string_t& out, std::size_t estimate, const dump_style& style)
        : m_doc(d), m_out(out, estimate), m_style(style)
    {}

    void dump(const node* root)
    {
        if (m_style.ensure_ascii)
        {
            dump_ascii(root);
        }
        else if (m_style.pretty)
        {
            dump_pretty(root);
        }
        else if (m_style.source_numbers)
        {
            dump_text<true, false, false>(root);
        }
        else
        {
            dump_text<false, false, false>(root);
        }
    }

  private:
    /// dump_text() with ensure_ascii, out of line: the walk without it is
    /// faster when it is not merged with this one into dump()
    NLOHMANN_VIEW_NOINLINE void dump_ascii(const node* root)
    {
        if (m_style.pretty)
        {
            if (m_style.source_numbers)
            {
                dump_text<true, true, true>(root);
            }
            else
            {
                dump_text<false, true, true>(root);
            }
        }
        else if (m_style.source_numbers)
        {
            dump_text<true, false, true>(root);
        }
        else
        {
            dump_text<false, false, true>(root);
        }
    }

    /// dump_text() with indentation, out of line: the compact walk is faster
    /// when it is not merged with the indented ones into dump()
    NLOHMANN_VIEW_NOINLINE void dump_pretty(const node* root)
    {
        if (m_style.source_numbers)
        {
            dump_text<true, true, false>(root);
        }
        else
        {
            dump_text<false, true, false>(root);
        }
    }

    /// a string that is not a plain string of the source (decoded, or written
    /// by an edit), without ensure_ascii: runs without characters to escape
    /// are copied. If validate is set, the string must be valid UTF-8: the
    /// runs are found by the lexer's scan, which validates the sequences, and
    /// invalid UTF-8 throws what basic_json::dump() throws. (The compact output
    /// writes the bytes of a damaged image unchanged, and scans without
    /// validating them.)
    NLOHMANN_VIEW_NOINLINE void write_decoded(const node& n, bool validate)
    {
        const auto* const s = reinterpret_cast<const unsigned char*>(m_doc.str(n)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        m_out.put('"');
        for (std::size_t i = 0; i < n.len;)
        {
            const std::size_t run = validate ? string_bulk_run(s + i, n.len - i) : plain_output_run(s + i, n.len - i);
            if (run != 0)
            {
                m_out.put(reinterpret_cast<const char*>(s + i), run); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
                i += run;
                continue;
            }
            if (validate && s[i] >= 0x80)
            {
                invalid_utf8(s, n.len); // (the scan stopped at ill-formed UTF-8)
            }
            write_codepoint<false>(s[i], s + i, 1); // a quote, a backslash, or a control character
            ++i;
        }
        m_out.put('"');
    }

    /// whether dump_text() copies a string or key from the source: one of
    /// the source, and with ensure_ascii one without bytes >= 0x7F (an overload
    /// each, so that the walk without ensure_ascii is compiled exactly as
    /// before: with GCC, a condition that only folds away later changed its
    /// block layout and made it 4-6% slower)
    static bool copied(const node& n, const char* /*src*/, std::false_type /*ensure_ascii*/) noexcept
    {
        return (n.flags & node_flags::storage) == 0;
    }

    static bool copied(const node& n, const char* src, std::true_type /*ensure_ascii*/) noexcept
    {
        return (n.flags & node_flags::storage) == 0 && is_ascii_without_delete(src + n.off, n.len);
    }

    /*!
    @brief a string with ensure_ascii: the characters that are not printable ASCII as \\uXXXX
    (a character beyond U+FFFF as a surrogate pair); strings of a document
    are valid UTF-8, except in a damaged image loaded with image_check::bounds,
    for which this throws what basic_json::dump() throws for the string
    */
    NLOHMANN_VIEW_NOINLINE void write_ascii(const node& n)
    {
        const auto* const s = reinterpret_cast<const unsigned char*>(m_doc.str(n)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        const std::size_t size = n.len;
        char* w = m_out.cursor();
        char* lim = m_out.limit();
        // room for k bytes
        const auto room = [&](std::size_t k)
        {
            const auto left = static_cast<std::size_t>(lim - w);
            if (NLOHMANN_VIEW_UNLIKELY(left < k))
            {
                m_out.set_cursor(w);
                m_out.reserve(k);
                w = m_out.cursor();
                lim = m_out.limit();
            }
        };
        static constexpr const char* hex = "0123456789abcdef";
        // \\uXXXX
        const auto u_escape = [&](std::uint32_t u)
        {
            w[0] = '\\';
            w[1] = 'u';
            w[2] = hex[(u >> 12u) & 0xFu];
            w[3] = hex[(u >> 8u) & 0xFu];
            w[4] = hex[(u >> 4u) & 0xFu];
            w[5] = hex[u & 0xFu];
            w += 6;
        };
        room(1);
        *w++ = '"';
        std::size_t i = 0;
        // (a string of the source starts with a run that has nothing to escape, 16 bytes per step)
        const std::size_t prefix = (n.flags & node_flags::storage) == 0 ? ascii_copyable_run(s, size, reinterpret_cast<const unsigned char*>(m_doc.src + m_doc.size)) : 0; // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        if (prefix != 0)
        {
            room(prefix);
            std::memcpy(w, s, prefix);
            w += prefix;
            i = prefix;
        }
        while (i < size)
        {
            // (a character that needs an escape sequence is not worth a call)
            const std::size_t run = is_ascii_copyable(s[i]) ? find_ascii_copyable_run(s + i, size - i) : 0;
            if (run != 0)
            {
                room(run);
                std::memcpy(w, s + i, run);
                w += run;
                i += run;
                continue;
            }
            room(12);
            if (s[i] >= 0x80)
            {
                const unsigned char lead = s[i];
                // (the two-byte sequences of Latin text and the three-byte sequences of most other
                // text, with continuation bytes of any value: the ranges that are restricted (E0,
                // ED, and the sequences of four bytes) go through validate_one_utf8())
                if (lead >= 0xE1 && lead <= 0xEF && lead != 0xED && size - i >= 3 && (s[i + 1] & 0xC0u) == 0x80 && (s[i + 2] & 0xC0u) == 0x80)
                {
                    u_escape(((lead & 0x0Fu) << 12u) | ((s[i + 1] & 0x3Fu) << 6u) | (s[i + 2] & 0x3Fu));
                    i += 3;
                    continue;
                }
                if (lead >= 0xC2 && lead <= 0xDF && size - i >= 2 && (s[i + 1] & 0xC0u) == 0x80)
                {
                    u_escape(((lead & 0x1Fu) << 6u) | (s[i + 1] & 0x3Fu));
                    i += 2;
                    continue;
                }
                const std::size_t len = validate_one_utf8(s + i, size - i);
                if (NLOHMANN_VIEW_UNLIKELY(len == 0))
                {
                    m_out.set_cursor(w);
                    invalid_utf8(s, size);
                    return; // LCOV_EXCL_LINE (invalid_utf8 throws)
                }
                std::uint32_t codepoint = s[i] & (0xFFu >> (len + 1));
                for (std::size_t k = 1; k < len; ++k)
                {
                    codepoint = (codepoint << 6u) | (s[i + k] & 0x3Fu);
                }
                i += len;
                if (codepoint <= 0xFFFF)
                {
                    u_escape(codepoint);
                }
                else
                {
                    u_escape(0xD7C0u + (codepoint >> 10u));
                    u_escape(0xDC00u + (codepoint & 0x3FFu));
                }
                continue;
            }
            // a quote, a backslash, or a control character (or DEL)
            const unsigned char c = s[i++];
            char escape = 0;
            switch (c)
            {
                case 0x08:
                    escape = 'b';
                    break;
                case 0x09:
                    escape = 't';
                    break;
                case 0x0A:
                    escape = 'n';
                    break;
                case 0x0C:
                    escape = 'f';
                    break;
                case 0x0D:
                    escape = 'r';
                    break;
                case 0x22:
                    escape = '"';
                    break;
                case 0x5C:
                    escape = '\\';
                    break;
                default:
                    break;
            }
            if (escape != 0)
            {
                w[0] = '\\';
                w[1] = escape;
                w += 2;
            }
            else
            {
                u_escape(c);
            }
        }
        room(1);
        *w++ = '"';
        m_out.set_cursor(w);
    }

    /// the copies of dump_text() that are not fixed-size moves (long
    /// strings, or near the end of the source); out of line, so that the
    /// compiler does not merge the fixed-size moves into this call
    NLOHMANN_VIEW_NOINLINE static void copy_long(char* to, const char* from, std::size_t n) noexcept
    {
        std::memcpy(to, from, n);
    }

    /// a compile-time option as a runtime condition: testing the template
    /// argument directly makes a condition like `Editable && c` constant when
    /// the option is off, which MSVC reports as C4127
    static NLOHMANN_VIEW_ALWAYS_INLINE bool enabled(bool option) noexcept
    {
        return option;
    }

    /*!
    @brief the output, compact (the default dump()) or indented, with or without ensure_ascii

    The same walk as dump(), with the write position in a local variable
    (stores through char pointers would otherwise force a reload of the
    buffer's members after each one), and with strings and number tokens of
    the source copied by fixed-size moves of 32 bytes where the source has
    that many bytes left, instead of a library call per token. The buffer
    keeps 64 bytes of slack for the overshoot. With ensure_ascii (Ascii), a
    string of the source is copied only if it has nothing to escape (see
    copied()); any other string is written by write_ascii().
    */
    template<bool SourceNumbers, bool Pretty, bool Ascii>
    void dump_text(const node* root)
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
        // (indented output) a line break and 63 indentation characters, from
        // which the line break of a level of up to 63 characters is a copy
        std::array<char, 64> ruler; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): filled below if used
        if (Pretty)
        {
            ruler.fill(m_style.indent_char);
            ruler[0] = '\n';
        }
        const std::size_t indent = m_style.indent;
        depth_counter<Pretty> level; // depth of the innermost open container (indented output)
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
        // (indented output) the line break and the indentation of a level
        const auto newline = [&](std::size_t depth)
        {
            const std::size_t count = 1 + (depth * indent);
            room(count);
            if (count <= ruler.size())
            {
                std::memcpy(w, ruler.data(), ruler.size());
            }
            else
            {
                *w = '\n';
                std::memset(w + 1, m_style.indent_char, count - 1);
            }
            w += count;
        };
        // a string that is not a plain string of the source (out of line, so
        // that the cursor stays in a register here)
        const auto escaped = [&](const node & n)
        {
            m_out.set_cursor(w);
            if (enabled(Ascii))
            {
                write_ascii(n);
            }
            else
            {
                write_decoded(n, Pretty);
            }
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
            // false positive: n comes from nav::value(), which never returns null for a valid index
            // @infer-ignore NULLPTR_DEREFERENCE
            switch (static_cast<value_t>(n->kind))
            {
                case value_t::string:
                    if (copied(*n, src, std::integral_constant<bool, Ascii>()))
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
                    if (enabled(Editable) && (n->flags & node_flags::storage) != 0)
                    {
                        copy_long(w, m_doc.str(*n), len); // a canonical token written by an edit
                        w += len;
                        break;
                    }
                    const char* const token = src + n->off;
                    if (!enabled(SourceNumbers) && NLOHMANN_VIEW_UNLIKELY(len == 2 && token[0] == '-' && token[1] == '0'))
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
                    if (enabled(SourceNumbers) && (n->flags & node_flags::storage) != node_flags::edited)
                    {
                        room(n->len);
                        copy(src + n->off, n->len);
                    }
                    else if (enabled(fast_double::value))
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
                        w = put_literal(w, "true");
                    }
                    else
                    {
                        w = put_literal(w, "false");
                    }
                    break;
                case value_t::object:
                case value_t::array:
                {
                    const bool object = n->kind == static_cast<std::uint8_t>(value_t::object);
                    room(8);
                    if (n->len == 0)
                    {
                        w = object ? put_literal(w, "{}") : put_literal(w, "[]");
                    }
                    else
                    {
                        *w++ = object ? '{' : '[';
                        stack.push_back(cur);
                        level.enter();
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
                    w = put_literal(w, "null");
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
                    if (Pretty)
                    {
                        newline(level.leave());
                    }
                    room(1);
                    *w++ = cur.object ? '}' : ']';
                    cur = stack.back();
                    stack.pop_back();
                }
                room(1);
                *w++ = ',';
            }
            if (Pretty)
            {
                newline(level.get());
            }
            const node* const at = Editable ? cur.pos : n;
            if (cur.object)
            {
                const node& key = *at;
                if (copied(key, src, std::integral_constant<bool, Ascii>()))
                {
                    room(key.len + (Pretty ? 4 : 3));
                    *w++ = '"';
                    copy(src + key.off, key.len);
                    w[0] = '"';
                    w[1] = ':';
                    w += 2;
                }
                else
                {
                    escaped(key);
                    room(Pretty ? 2 : 1);
                    *w++ = ':';
                }
                if (Pretty)
                {
                    *w++ = ' ';
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

    /// a float node as dump() writes it
    void write_float_node(const node& n)
    {
        write_float_node(n, fast_double {});
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
                // (without leading zeros, all digits of the token count; the
                // check also keeps an image that was only checked for bounds,
                // whose token may not be made of digits, from the counted
                // overload)
                const auto& powers = ::nlohmann::detail::dtoa_impl::powers_of_ten();
                const unsigned count = int_digits + frac_digits;
                return count - 1u < 15u && d.w >= powers[count - 1u] && d.w < powers[count]
                       ? ::nlohmann::detail::dtoa_impl::write_short_decimal(w, d.w, static_cast<int>(count), static_cast<int>(d.exponent))
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
        auto bits = bit_cast<std::uint64_t>(x);
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
            m_out.put("null");
            return;
        }
        write_float(x, std::integral_constant<bool, ::nlohmann::detail::has_native_float_format<number_float_t>::value>());
    }

    void write_float(number_float_t x, std::true_type /*has_native_float_format*/)
    {
        std::array<char, 64> buf{};
        const char* const end = ::nlohmann::detail::to_chars(buf.data(), buf.data() + buf.size(), x);
        m_out.put(buf.data(), static_cast<std::size_t>(end - buf.data()));
    }

    void write_float(number_float_t x, std::false_type /*has_native_float_format*/)
    {
        // other types (e.g. long double) are rare: the library writes them
        const string_t s = BasicJsonType(x).dump();
        m_out.put(s.data(), s.size());
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
        std::array<char, 6> e = {{'\\', 'u', 0, 0, 0, 0}};
        hex4_lower(static_cast<std::uint16_t>(u), &e[2]);
        m_out.put(e.data(), e.size());
    }

    const document_data& m_doc;
    output_buffer<string_t> m_out;
    const dump_style m_style;
};

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
