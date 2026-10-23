//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // count, find, max, min
#include <array> // array
#include <cstddef> // size_t
#include <cstdint> // uint32_t
#include <cstring> // strlen
#include <iterator> // begin, end, iterator_traits, random_access_iterator_tag, distance, next, reverse_iterator
#include <limits> // numeric_limits
#include <memory> // unique_ptr
#include <streambuf> // streambuf
#include <string> // string, char_traits
#include <type_traits> // enable_if, is_base_of, is_pointer, is_integral, remove_pointer
#include <utility> // declval, move, pair
#include <vector> // vector

#ifndef JSON_NO_IO
    #include <cstdio>   // FILE *
    #include <istream>  // istream
#endif                  // JSON_NO_IO

#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/iterators/iterator_traits.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>
#include <nlohmann/detail/string_utils.hpp>

#ifndef JSON_NO_IO
    // Which unlocked stdio functions file_input_adapter uses (see
    // JSON_DISABLE_UNLOCKED_FILE_IO): 1 = POSIX flockfile/getc_unlocked,
    // 2 = Microsoft CRT _lock_file/_fgetc_nolock, 0 = none (std::fgetc, which
    // locks the file for every character). Only C libraries known to declare
    // the functions are listed; the macros are tested after <cstdio>, which
    // defines __GLIBC__. MemorySanitizer builds always use std::fgetc: glibc's
    // inline getc_unlocked reads the stdio buffer directly, which glibc (not
    // instrumented) filled, so MemorySanitizer would report a false positive.
    #if defined(__has_feature)
        #if __has_feature(memory_sanitizer)
            #define JSON_UNLOCKED_FILE_IO_MSAN 1
        #endif
    #endif

    #if JSON_DISABLE_UNLOCKED_FILE_IO || defined(JSON_UNLOCKED_FILE_IO_MSAN)
        #define JSON_UNLOCKED_FILE_IO 0
    #elif defined(_MSC_VER)
        #define JSON_UNLOCKED_FILE_IO 2
    #elif defined(__GLIBC__) || defined(__APPLE__) || defined(__ANDROID__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
        #define JSON_UNLOCKED_FILE_IO 1
    #else
        #define JSON_UNLOCKED_FILE_IO 0
    #endif
    #undef JSON_UNLOCKED_FILE_IO_MSAN
#endif  // JSON_NO_IO

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/// the supported input formats
enum class input_format_t { json, cbor, msgpack, ubjson, bson, bjdata, bon8 };

/// @return the name of a binary input format, as used in exception messages
inline const char* input_format_name(const input_format_t format) noexcept
{
    switch (format)
    {
        case input_format_t::cbor:
            return "CBOR";
        case input_format_t::msgpack:
            return "MessagePack";
        case input_format_t::ubjson:
            return "UBJSON";
        case input_format_t::bson:
            return "BSON";
        case input_format_t::bjdata:
            return "BJData";
        case input_format_t::bon8:
            return "BON8";
        case input_format_t::json: // LCOV_EXCL_LINE
        default:            // LCOV_EXCL_LINE
            JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
            return ""; // LCOV_EXCL_LINE
    }
}

/// @return the message of the parse_error thrown or reported for an empty input
inline const char* empty_input_message() noexcept
{
    return "attempting to parse an empty input; check that your input string or stream contains the expected JSON";
}

////////////////////
// input adapters //
////////////////////

#ifndef JSON_NO_IO
/*!
A growable array of characters for the part of a token that an input adapter
copied out of its window: unlike std::vector<char>::push_back(), appending a
character takes no reference to a local, and is a few instructions when there
is room.
*/
class token_carry_buffer
{
  public:
    token_carry_buffer() = default;
    token_carry_buffer(const token_carry_buffer&) = delete;
    token_carry_buffer& operator=(const token_carry_buffer&) = delete;
    token_carry_buffer(token_carry_buffer&& rhs) noexcept
        : m_data(std::move(rhs.m_data)), m_end(rhs.m_end), m_capacity_end(rhs.m_capacity_end)
    {
        rhs.m_end = rhs.m_capacity_end = nullptr;
    }
    token_carry_buffer& operator=(token_carry_buffer&&) = delete;
    ~token_carry_buffer() = default;

    void clear() noexcept
    {
        m_end = m_data.get();
    }

    void push_back(char c)
    {
        if (JSON_HEDLEY_UNLIKELY(m_end == m_capacity_end))
        {
            grow(1);
        }
        *m_end++ = c;
    }

    void append(const char* first, const char* last)
    {
        const auto n = static_cast<std::size_t>(last - first);
        const auto room = static_cast<std::size_t>(m_capacity_end - m_end);
        if (n > room)
        {
            grow(n);
        }
        if (n != 0)
        {
            std::memcpy(m_end, first, n);
        }
        m_end += n;
    }

    /// replace the contents of @a out
    void copy_to(std::vector<char>& out) const
    {
        out.assign(m_data.get(), m_end);
    }

  private:
    /// make room for @a extra more characters
    JSON_HEDLEY_NEVER_INLINE void grow(std::size_t extra)
    {
        const auto size = static_cast<std::size_t>(m_end - m_data.get());
        const auto capacity = static_cast<std::size_t>(m_capacity_end - m_data.get());
        const std::size_t new_capacity = (std::max)(capacity < 32 ? static_cast<std::size_t>(32) : 2 * capacity, size + extra);
        std::unique_ptr<char[]> data(new char[new_capacity]); // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
        if (size != 0)
        {
            std::memcpy(data.get(), m_data.get(), size);
        }
        m_data = std::move(data);
        m_end = m_data.get() + size;
        m_capacity_end = m_data.get() + new_capacity;
    }

    std::unique_ptr<char[]> m_data{}; // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays,readability-redundant-member-init)
    char* m_end = nullptr;
    char* m_capacity_end = nullptr;
};
/*!
Input adapter for stdio file access. This adapter read only 1 byte and do not use any
 buffer. This adapter is a very low level adapter.
*/
class file_input_adapter
{
  public:
    using char_type = char;

    JSON_HEDLEY_NON_NULL(2)
    explicit file_input_adapter(std::FILE* f) noexcept
        : m_file(f)
    {
        JSON_ASSERT(m_file != nullptr);
        lock();
    }

    // make class move-only
    file_input_adapter(const file_input_adapter&) = delete;
    file_input_adapter(file_input_adapter&& rhs) noexcept
        : m_file(rhs.m_file)
    {
        // the lock is owned by the thread, not the adapter: hand it over
        rhs.m_file = nullptr;
    }
    file_input_adapter& operator=(const file_input_adapter&) = delete;
    file_input_adapter& operator=(file_input_adapter&&) = delete;
    ~file_input_adapter()
    {
        unlock();
    }

    std::char_traits<char>::int_type get_character() noexcept
    {
        // the file is locked for the lifetime of the adapter, so the
        // per-character lock of std::fgetc can be skipped
#if JSON_UNLOCKED_FILE_IO == 1
        return getc_unlocked(m_file);
#elif JSON_UNLOCKED_FILE_IO == 2
        return _fgetc_nolock(m_file);
#else
        return std::fgetc(m_file);
#endif
    }

    // returns the number of characters successfully read
    template<class T>
    std::size_t get_elements(T* dest, std::size_t count = 1)
    {
        return fread(dest, 1, sizeof(T) * count, m_file);
    }

  private:
    // Lock the file once for the whole parse instead of once per character.
    // The lock is recursive, so fread() and the user's own stdio calls on the
    // same thread keep working.
    void lock() noexcept
    {
#if JSON_UNLOCKED_FILE_IO == 1
        flockfile(m_file);
#elif JSON_UNLOCKED_FILE_IO == 2
        _lock_file(m_file);
#endif
    }

    void unlock() noexcept
    {
        // a moved-from adapter has no file and holds no lock
        if (m_file == nullptr)
        {
            return;
        }
#if JSON_UNLOCKED_FILE_IO == 1
        funlockfile(m_file);
#elif JSON_UNLOCKED_FILE_IO == 2
        _unlock_file(m_file);
#endif
    }

    /// the file pointer to read from
    std::FILE* m_file;
};

/*!
Input adapter for a (caching) istream. Does not skip a UTF Byte Order Mark
itself; that is done by the lexer's skip_bom(). Does not support changing
the underlying std::streambuf
in mid-input. Maintains underlying std::istream and std::streambuf to support
subsequent use of standard std::istream operations to process any input
characters following those used in parsing the JSON input.  Clears the
std::istream flags; any input errors (e.g., EOF) will be detected by the first
subsequent call for input from the std::istream.
*/
class input_stream_adapter
{
  public:
    using char_type = char;

    ~input_stream_adapter()
    {
        // clear stream flags; we use underlying streambuf I/O, do not
        // maintain ifstream flags, except eof
        if (is != nullptr)
        {
#if JSON_PRECISE_STREAM_POSITION
            // consume the character last returned by get_character() unless it
            // was given back with release_lookahead()
            commit_lookahead();
#endif
            // only call clear() if there is something to clear: it throws
            // std::ios_base::failure if the stream has exceptions() enabled
            // for a state bit that remains set, and a destructor must not throw
            if ((is->rdstate() & ~std::ios::eofbit) != 0)
            {
                is->clear(is->rdstate() & std::ios::eofbit);
            }
        }
    }

    explicit input_stream_adapter(std::istream& i)
        : is(&i), sb(i.rdbuf())
    {}

    // deleted because of pointer members
    input_stream_adapter(const input_stream_adapter&) = delete;
    input_stream_adapter& operator=(input_stream_adapter&) = delete;
    input_stream_adapter& operator=(input_stream_adapter&&) = delete;

    input_stream_adapter(input_stream_adapter&& rhs) noexcept
        : is(rhs.is), sb(rhs.sb)
#if JSON_PRECISE_STREAM_POSITION
        , lookahead(rhs.lookahead)
#endif
#if !JSON_DISABLE_STREAM_BULK_SCAN
        , token_carry(std::move(rhs.token_carry))
        , token_segment(rhs.token_segment)
        , current_in_get_area(rhs.current_in_get_area)
        , tracking_token(rhs.tracking_token)
        , no_get_area(rhs.no_get_area)
#endif
    {
        rhs.is = nullptr;
        rhs.sb = nullptr;
#if JSON_PRECISE_STREAM_POSITION
        rhs.lookahead = false;
#endif
    }

#if JSON_PRECISE_STREAM_POSITION
    // Whether the character last returned by get_character() can be given back
    // to the input with release_lookahead().
    static constexpr bool supports_lookahead = true;

    // std::istream/std::streambuf use std::char_traits<char>::to_int_type, to
    // ensure that std::char_traits<char>::eof() and the character 0xFF do not
    // end up as the same value, e.g., 0xFFFFFFFF.
    //
    // The character is peeked rather than consumed: it is only stepped over
    // once the next character is requested, or when the adapter is destroyed.
    // Until then, release_lookahead() can leave it in the input.
    std::char_traits<char>::int_type get_character()
    {
        if (lookahead)
        {
            // step over the character returned by the previous call
            sb->sbumpc();
        }

#if !JSON_DISABLE_STREAM_BULK_SCAN
        // sgetc() refills the get area if it is exhausted
        const bool refill = streambuf_access::get_ptr(sb) == streambuf_access::get_end(sb);
        if (JSON_HEDLEY_UNLIKELY(refill))
        {
            save_token_segment();
        }
#endif

        auto res = sb->sgetc();
        // set eof manually, as we don't use the istream interface.
        if (JSON_HEDLEY_UNLIKELY(res == std::char_traits<char>::eof()))
        {
            // there is nothing to step over next time
            lookahead = false;
#if !JSON_DISABLE_STREAM_BULK_SCAN
            current_in_get_area = false;
#endif
            is->clear(is->rdstate() | std::ios::eofbit);
        }
        else
        {
            lookahead = true;
#if !JSON_DISABLE_STREAM_BULK_SCAN
            if (JSON_HEDLEY_UNLIKELY(refill))
            {
                // the peeked character is at gptr(), unless the streambuf has
                // no get area
                after_refill(res, streambuf_access::get_ptr(sb) != streambuf_access::get_end(sb));
            }
            else
            {
                current_in_get_area = true;
            }
#endif
        }
        return res;
    }

    // Leave the character last returned by get_character() in the input, so
    // that the next read from the stream - by this adapter or by the caller
    // once parsing is done - sees it again. Unlike putting a consumed
    // character back, this cannot fail.
    void release_lookahead() noexcept
    {
        lookahead = false;
    }
#else
    // std::istream/std::streambuf use std::char_traits<char>::to_int_type, to
    // ensure that std::char_traits<char>::eof() and the character 0xFF do not
    // end up as the same value, e.g., 0xFFFFFFFF.
    //
    // The character is consumed, so the character that terminates a number
    // stays consumed after parsing; see JSON_PRECISE_STREAM_POSITION.
    std::char_traits<char>::int_type get_character()
    {
#if !JSON_DISABLE_STREAM_BULK_SCAN
        // the character is in the get area: step over it, as sbumpc() does
        const char* const next = streambuf_access::get_ptr(sb);
        if (JSON_HEDLEY_LIKELY(next != streambuf_access::get_end(sb)))
        {
            current_in_get_area = true;
            streambuf_access::bump(sb, 1);
            return std::char_traits<char>::to_int_type(*next);
        }
        if (no_get_area)
        {
            return get_character_no_get_area();
        }
#endif
        return get_character_slow();
    }
#endif

    template<class T>
    std::size_t get_elements(T* dest, std::size_t count = 1)
    {
#if JSON_PRECISE_STREAM_POSITION
        commit_lookahead();
#endif
#if !JSON_DISABLE_STREAM_BULK_SCAN
        // the elements are in the get area: copy them, as sgetn() does, but
        // without the virtual call
        const char* const first = streambuf_access::get_ptr(sb);
        const auto available = static_cast<std::size_t>(streambuf_access::get_end(sb) - first);
        if (JSON_HEDLEY_LIKELY(count * sizeof(T) <= available && count * sizeof(T) <= static_cast<std::size_t>((std::numeric_limits<int>::max)())))
        {
            std::memcpy(dest, first, count * sizeof(T));
            streambuf_access::bump(sb, static_cast<int>(count * sizeof(T)));
            return count * sizeof(T);
        }
#endif
        auto res = static_cast<std::size_t>(sb->sgetn(reinterpret_cast<char*>(dest), static_cast<std::streamsize>(count * sizeof(T))));
        if (JSON_HEDLEY_UNLIKELY(res < count * sizeof(T)))
        {
            is->clear(is->rdstate() | std::ios::eofbit);
        }
        return res;
    }

#if !JSON_DISABLE_STREAM_BULK_SCAN
    // The lexer may scan the characters in the get area of the streambuf
    // directly (SWAR fast paths). The get area is only a window into the
    // input: it ends wherever the streambuf's buffer ends, and is refilled by
    // the next get_character(). The lexer therefore keeps counting the
    // position itself and treats the end of the window as "unknown", not as
    // the end of the input.
    static constexpr bool supports_bulk_scan = true;
    static constexpr bool bulk_window = true;

    // Pointer to the next unread character; only valid when
    // bulk_remaining() > 0. The character before it is the one last returned
    // by get_character().
    const char* bulk_data() const
    {
        return current_end();
    }

    // Number of unread characters in the get area.
    std::size_t bulk_remaining() const
    {
        if (!current_in_get_area)
        {
            return 0;
        }
        return static_cast<std::size_t>(streambuf_access::get_end(sb) - current_end());
    }

    // Consume @a n characters previously inspected via bulk_data(); the last
    // of them becomes the character last returned by get_character().
    void bulk_skip(std::size_t n)
    {
        JSON_ASSERT(n <= bulk_remaining());
        // gbump() takes an int, but a get area (e.g., of a std::stringbuf) can
        // be larger
        constexpr auto max_bump = static_cast<std::size_t>((std::numeric_limits<int>::max)());
        for (; n > max_bump; n -= max_bump)
        {
            streambuf_access::bump(sb, static_cast<int>(max_bump));
        }
        streambuf_access::bump(sb, static_cast<int>(n));
    }

    // The adapter keeps the current token for the lexer's error messages: the
    // part in the get area is only remembered as a pointer, and copied out
    // when the get area is about to be refilled.
    static constexpr bool supports_token_tracking = true;

    // Start a token with the characters read from now on. Until this is
    // called, nothing is tracked (the binary readers never call it).
    void begin_token() noexcept
    {
        tracking_token = true;
        token_carry.clear();
        token_segment = current_end();
    }

    // Start a new token with the character @a c last returned by
    // get_character().
    void mark_token_start(std::char_traits<char>::int_type c)
    {
        tracking_token = true;
        token_carry.clear();
        if (current_in_get_area)
        {
            token_segment = current_end() - 1;
        }
        else
        {
            token_segment = nullptr;
            token_carry.push_back(std::char_traits<char>::to_char_type(c));
        }
    }

    // Copy the characters read since mark_token_start() to @a out, without the
    // last one if @a drop_last.
    void copy_token(std::vector<char>& out, bool drop_last) const
    {
        token_carry.copy_to(out);
        if (token_segment != nullptr)
        {
            out.insert(out.end(), token_segment, current_end());
        }
        if (drop_last && !out.empty())
        {
            out.pop_back();
        }
    }
#endif

  private:
#if !JSON_PRECISE_STREAM_POSITION
    // the get area is exhausted, or there is none
#if !JSON_DISABLE_STREAM_BULK_SCAN
    JSON_HEDLEY_NEVER_INLINE
#endif
    std::char_traits<char>::int_type get_character_slow()
    {
#if !JSON_DISABLE_STREAM_BULK_SCAN
        // sbumpc() refills the get area if it is exhausted
        const bool refill = streambuf_access::get_ptr(sb) == streambuf_access::get_end(sb);
        if (JSON_HEDLEY_UNLIKELY(refill))
        {
            save_token_segment();
        }
#endif

        auto res = sb->sbumpc();
        // set eof manually, as we don't use the istream interface.
        if (JSON_HEDLEY_UNLIKELY(res == std::char_traits<char>::eof()))
        {
#if !JSON_DISABLE_STREAM_BULK_SCAN
            current_in_get_area = false;
#endif
            is->clear(is->rdstate() | std::ios::eofbit);
        }
#if !JSON_DISABLE_STREAM_BULK_SCAN
        else if (JSON_HEDLEY_UNLIKELY(refill))
        {
            // the consumed character is at gptr() - 1, unless the streambuf
            // has no get area and returned it from uflow()
            const char* const next = streambuf_access::get_ptr(sb);
            after_refill(res, next != nullptr && next != streambuf_access::get_begin(sb));
        }
        else
        {
            current_in_get_area = true;
        }
#endif
        return res;
    }
#endif
#if !JSON_DISABLE_STREAM_BULK_SCAN
    // Reads the protected get-area pointers of any std::streambuf. Naming the
    // members through a derived class makes forming the member pointers
    // accessible; calling them on another streambuf object is then ordinary
    // member access through a pointer to member.
    struct streambuf_access : std::streambuf
    {
        static const char* get_ptr(std::streambuf* s)
        {
            return (s->*(&streambuf_access::gptr))();
        }
        static const char* get_end(std::streambuf* s)
        {
            return (s->*(&streambuf_access::egptr))();
        }
        static const char* get_begin(std::streambuf* s)
        {
            return (s->*(&streambuf_access::eback))();
        }
        static void bump(std::streambuf* s, int n)
        {
            (s->*(&streambuf_access::gbump))(n);
        }
        // sbumpc() for an exhausted get area
        static std::streambuf::int_type next_character(std::streambuf* s)
        {
            return (s->*(&streambuf_access::uflow))();
        }
    };

    // one past the character last returned by get_character(), if that is in
    // the get area
    const char* current_end() const
    {
#if JSON_PRECISE_STREAM_POSITION
        // the character is peeked at gptr() and not stepped over yet, unless
        // it was given back with release_lookahead()
        return streambuf_access::get_ptr(sb) + (lookahead ? 1 : 0);
#else
        return streambuf_access::get_ptr(sb);
#endif
    }

    // the get area is about to be replaced: copy the token's part in it
    void save_token_segment()
    {
        if (token_segment != nullptr)
        {
            token_carry.append(token_segment, streambuf_access::get_end(sb));
            token_segment = nullptr;
        }
    }

#if !JSON_PRECISE_STREAM_POSITION
    // The streambuf has no get area (e.g., std::cin synchronized with stdio):
    // every character comes from uflow(), and the token is kept by value.
    JSON_HEDLEY_NEVER_INLINE std::char_traits<char>::int_type get_character_no_get_area()
    {
        // the get area is exhausted, so this is what sbumpc() does
        const auto res = streambuf_access::next_character(sb);
        if (JSON_HEDLEY_UNLIKELY(res == std::char_traits<char>::eof() || streambuf_access::get_end(sb) != nullptr))
        {
            return get_character_no_get_area_other(res);
        }
        // current_in_get_area is false: only the first character of a get
        // area, or the end of the input, is read here
        if (tracking_token)
        {
            token_carry.push_back(std::char_traits<char>::to_char_type(res));
        }
        return res;
    }

    // @a res came from uflow() of a streambuf without a get area: it is the
    // end of the input, or the streambuf has a get area now
    JSON_HEDLEY_NEVER_INLINE std::char_traits<char>::int_type get_character_no_get_area_other(std::char_traits<char>::int_type res)
    {
        if (res == std::char_traits<char>::eof())
        {
            current_in_get_area = false;
            is->clear(is->rdstate() | std::ios::eofbit);
            return res;
        }
        // the consumed character is at gptr() - 1
        after_refill(res, streambuf_access::get_ptr(sb) != streambuf_access::get_begin(sb));
        return res;
    }
#endif

    // character @a c was just read into a new get area (@a in_get_area) or
    // returned without one
    void after_refill(std::char_traits<char>::int_type c, bool in_get_area)
    {
        current_in_get_area = in_get_area;
        no_get_area = !in_get_area;
        if (!tracking_token)
        {
            return;
        }
        if (in_get_area)
        {
            token_segment = current_end() - 1;
        }
        else
        {
            token_carry.push_back(std::char_traits<char>::to_char_type(c));
        }
    }
#endif

#if JSON_PRECISE_STREAM_POSITION
    // Step over the character last returned by get_character(). The character
    // has already been peeked successfully, so for every streambuf with a get
    // area this is a pointer increment that cannot fail.
    void commit_lookahead()
    {
        if (lookahead)
        {
            lookahead = false;
            sb->sbumpc();
        }
    }
#endif

    /// the associated input stream
    std::istream* is = nullptr;
    std::streambuf* sb = nullptr;
#if JSON_PRECISE_STREAM_POSITION
    /// whether get_character() peeked a character that is not consumed yet
    bool lookahead = false;
#endif
#if !JSON_DISABLE_STREAM_BULK_SCAN
    /// the part of the current token that was in earlier get areas
    token_carry_buffer token_carry{}; // NOLINT(readability-redundant-member-init)
    /// start of the current token's part in the get area, or nullptr
    const char* token_segment = nullptr;
    /// whether the character last returned by get_character() is in the get area
    bool current_in_get_area = false;
    /// whether a token is tracked at all; the binary readers never start one
    bool tracking_token = false;
    /// whether the streambuf had no get area when it was last asked for a
    /// character
    bool no_get_area = false;
#endif
};
#endif  // JSON_NO_IO

// General-purpose iterator-based adapter. It might not be as fast as
// theoretically possible for some containers, but it is extremely versatile.
// SentinelType defaults to IteratorType for backward compatibility, but may be
// a different type, e.g. a C++20 sentinel such as std::default_sentinel_t when
// IteratorType is a std::counted_iterator.
template<typename IteratorType, typename SentinelType = IteratorType>
class iterator_input_adapter
{
    // Whether the number of elements between two positions can be computed in
    // O(1): either the iterator and the sentinel have the same type (plain
    // std::distance) or, in C++20, the sentinel is a sized sentinel for the
    // iterator (std::ranges::distance), e.g. std::default_sentinel_t paired
    // with std::counted_iterator.
    //
    // JSON_HAS_RANGES gates the C++20 branch: on standard libraries with an
    // incomplete <ranges> (libstdc++ < 11, see #4440) evaluating
    // std::contiguous_iterator on a std::counted_iterator is a hard error
    // instead of yielding false, and these traits are instantiated for every
    // adapter. Such toolchains fall back to the pointer-only test and simply
    // use the byte-at-a-time scanner.
    static constexpr bool sentinel_is_sized =
#if JSON_HAS_RANGES && defined(__cpp_lib_concepts) && defined(JSON_HAS_CPP_20)
        std::is_same<IteratorType, SentinelType>::value || std::sized_sentinel_for<SentinelType, IteratorType>;
#else
        std::is_same<IteratorType, SentinelType>::value;
#endif

  public:
    using char_type = typename std::iterator_traits<IteratorType>::value_type;

    // Whether the lexer may reconstruct already-consumed input on demand (for
    // diagnostics) instead of copying every scanned character eagerly. This is
    // only sound for multi-pass, randomly-addressable byte input: the iterator
    // must be random-access (so the consumed prefix can be revisited in O(1))
    // and each element must map 1:1 to an input byte (wide inputs are wrapped
    // in wide_string_input_adapter, which does not expose this).
    static constexpr bool supports_seek =
        std::is_same<typename std::iterator_traits<IteratorType>::iterator_category, std::random_access_iterator_tag>::value
        && sentinel_is_sized
        && sizeof(char_type) == 1;

    iterator_input_adapter(IteratorType first, SentinelType last)
        : begin(first), current(std::move(first)), end(std::move(last))
    {}

    typename char_traits<char_type>::int_type get_character()
    {
        if (JSON_HEDLEY_LIKELY(current != end))
        {
            auto result = char_traits<char_type>::to_int_type(*current);
            std::advance(current, 1);
            return result;
        }

        ++eof_reads;
        return char_traits<char_type>::eof();
    }

    // number of characters consumed from the input so far
    std::size_t get_consumed_count() const
    {
        return static_cast<std::size_t>(std::distance(begin, current));
    }

    // number of get_character() calls so far, including those that returned
    // EOF; the lexer derives its position from it (see lexer::lazy_position)
    std::size_t get_read_count() const
    {
        return get_consumed_count() + eof_reads;
    }

    // number of newlines in the consumed range [0, last_index); @a line_start
    // is set to the index after the last of them (0 if there is none); only
    // valid when supports_seek
    std::size_t count_consumed_lines(std::size_t last_index, std::size_t& line_start) const
    {
        const auto to = std::next(begin, static_cast<typename std::iterator_traits<IteratorType>::difference_type>(last_index));
        const auto newline = char_traits<char_type>::to_char_type('\n');
        using reverse_it = std::reverse_iterator<IteratorType>;
        const auto last_newline = std::find(reverse_it(to), reverse_it(begin), newline);
        line_start = static_cast<std::size_t>(std::distance(begin, last_newline.base()));
        return static_cast<std::size_t>(std::count(begin, last_newline.base(), newline));
    }

    // append the already-consumed characters in the half-open range
    // [first_index, last_index) to @a out; only valid when supports_seek
    template<typename ContainerType>
    void copy_consumed_range(std::size_t first_index, std::size_t last_index, ContainerType& out) const
    {
        const auto from = std::next(begin, static_cast<typename std::iterator_traits<IteratorType>::difference_type>(first_index));
        const auto to = std::next(begin, static_cast<typename std::iterator_traits<IteratorType>::difference_type>(last_index));
        out.insert(out.end(), from, to);
    }

    // Copy up to count * sizeof(T) bytes into dest, returning the number of
    // bytes actually read. For contiguous iterators (e.g. pointers) this is a
    // single std::memcpy; for general iterators we fall back to processing the
    // range one-by-one.
    template<class T>
    std::size_t get_elements(T* dest, std::size_t count = 1)
    {
        return get_elements_impl(dest, count, std::integral_constant<bool, iterator_is_contiguous> {});
    }

  private:
    // whether IteratorType refers to a contiguous range and therefore supports
    // a std::memcpy fast path (pointers always do; in C++20 we can also detect
    // library iterators such as those of std::vector and std::string). The
    // available element count must also be computable in O(1), hence
    // sentinel_is_sized.
    static constexpr bool iterator_is_contiguous = sentinel_is_sized &&
#if JSON_HAS_RANGES && defined(__cpp_lib_concepts) && defined(JSON_HAS_CPP_20)
        (std::contiguous_iterator<IteratorType> || std::is_pointer<IteratorType>::value);
#else
        std::is_pointer<IteratorType>::value;
#endif

    // number of unread elements in [current, end)
    std::size_t remaining_count() const
    {
#if JSON_HAS_RANGES && defined(__cpp_lib_concepts) && defined(JSON_HAS_CPP_20)
        // std::ranges::distance also supports sized sentinels of a different
        // type (e.g. std::counted_iterator + std::default_sentinel_t)
        return static_cast<std::size_t>(std::ranges::distance(current, end));
#else
        return static_cast<std::size_t>(std::distance(current, end));
#endif
    }

  public:
    // Whether the remaining input is a single contiguous block of 1-byte
    // elements that the lexer can inspect directly (used for the SWAR string
    // fast path).
    static constexpr bool supports_bulk_scan =
        iterator_is_contiguous && sizeof(char_type) == 1;

    // Pointer to the next unread element; only valid when bulk_remaining() > 0.
    const char_type* bulk_data() const
    {
        return &*current;
    }

    // Number of unread elements available as one contiguous block.
    std::size_t bulk_remaining() const
    {
        return remaining_count();
    }

    // Consume @a n elements previously inspected via bulk_data().
    void bulk_skip(std::size_t n)
    {
        std::advance(current, static_cast<typename std::iterator_traits<IteratorType>::difference_type>(n));
    }

  private:
    // contiguous fast path: bulk copy the remaining range with std::memcpy
    template<class T>
    std::size_t get_elements_impl(T* dest, std::size_t count, std::true_type /*contiguous*/)
    {
        const std::size_t wanted = count * sizeof(T);
        const std::size_t available = remaining_count() * sizeof(char_type);
        const std::size_t copied = (std::min)(wanted, available);
        if (JSON_HEDLEY_LIKELY(copied != 0))
        {
            // the copy must stay within both buffers: the caller-provided
            // destination holds `wanted` bytes and the remaining input range
            // holds `available` bytes, and `copied` is the minimum of the two
            JSON_ASSERT(copied <= wanted);    // does not overrun the destination
            JSON_ASSERT(copied <= available); // does not read past the input end
            // &*current yields the raw address for both raw pointers and
            // non-pointer contiguous iterators (e.g. std::vector's iterator)
            std::memcpy(dest, &*current, copied);
            std::advance(current, static_cast<typename std::iterator_traits<IteratorType>::difference_type>(copied / sizeof(char_type)));
        }
        return copied;
    }

    // general fallback: copy the range one element at a time
    template<class T>
    std::size_t get_elements_impl(T* dest, std::size_t count, std::false_type /*contiguous*/)
    {
        auto* ptr = reinterpret_cast<char*>(dest);
        for (std::size_t read_index = 0; read_index < count * sizeof(T); ++read_index)
        {
            if (JSON_HEDLEY_LIKELY(current != end))
            {
                ptr[read_index] = static_cast<char>(*current);
                std::advance(current, 1);
            }
            else
            {
                return read_index;
            }
        }
        return count * sizeof(T);
    }

    IteratorType begin;
    IteratorType current;
    SentinelType end;
    /// number of get_character() calls that returned EOF
    std::size_t eof_reads = 0;

    template<typename BaseInputAdapter, size_t T>
    friend struct wide_string_input_helper;

    bool empty() const
    {
        return current == end;
    }
};

template<typename BaseInputAdapter, size_t T>
struct wide_string_input_helper;

template<typename BaseInputAdapter>
struct wide_string_input_helper<BaseInputAdapter, 4>
{
    // UTF-32
    static void fill_buffer(BaseInputAdapter& input,
                            std::array<std::char_traits<char>::int_type, 4>& utf8_bytes,
                            size_t& utf8_bytes_index,
                            size_t& utf8_bytes_filled)
    {
        utf8_bytes_index = 0;

        if (JSON_HEDLEY_UNLIKELY(input.empty()))
        {
            utf8_bytes[0] = std::char_traits<char>::eof();
            utf8_bytes_filled = 1;
        }
        else
        {
            // get the current character; converted to an unsigned type so that
            // a negative unit (wint_t is signed on some platforms) is not
            // mistaken for an ASCII character or for EOF
            const auto wc = static_cast<std::uint32_t>(input.get_character());

            if (wc <= 0x10FFFF)
            {
                // UTF-32 to UTF-8 encoding
                utf8_bytes_filled = 0;
                encode_utf8(static_cast<std::uint32_t>(wc), [&utf8_bytes, &utf8_bytes_filled](std::uint32_t byte)
                {
                    utf8_bytes[utf8_bytes_filled++] = static_cast<std::char_traits<char>::int_type>(byte);
                });
            }
            else
            {
                // A code point above U+10FFFF has no UTF-8 encoding. Passing the
                // unit through would narrow it to int, where 0xFFFFFFFF becomes
                // char_traits<char>::eof() and would end the input silently, so
                // emit a byte that is never valid UTF-8 and let the decoder
                // reject it.
                utf8_bytes[0] = 0xFF;
                utf8_bytes_filled = 1;
            }
        }
    }
};

template<typename BaseInputAdapter>
struct wide_string_input_helper<BaseInputAdapter, 2>
{
    // UTF-16
    static void fill_buffer(BaseInputAdapter& input,
                            std::array<std::char_traits<char>::int_type, 4>& utf8_bytes,
                            size_t& utf8_bytes_index,
                            size_t& utf8_bytes_filled)
    {
        utf8_bytes_index = 0;

        if (JSON_HEDLEY_UNLIKELY(input.empty()))
        {
            utf8_bytes[0] = std::char_traits<char>::eof();
            utf8_bytes_filled = 1;
        }
        else
        {
            // get the current character
            const auto wc = input.get_character();

            if (0xD800 > wc || wc >= 0xE000)
            {
                // a UTF-16 code unit outside the surrogate range is a valid
                // code point (at most U+FFFF) on its own
                utf8_bytes_filled = 0;
                encode_utf8(static_cast<std::uint32_t>(wc), [&utf8_bytes, &utf8_bytes_filled](std::uint32_t byte)
                {
                    utf8_bytes[utf8_bytes_filled++] = static_cast<std::char_traits<char>::int_type>(byte);
                });
            }
            else
            {
                // A supplementary code point is a high surrogate (0xD800..0xDBFF)
                // followed by a low surrogate (0xDC00..0xDFFF). A lone low
                // surrogate, a high surrogate at the end of the input, or a high
                // surrogate followed by any other unit is malformed UTF-16. In
                // that case the offending unit is passed through unchanged so the
                // UTF-8 decoder rejects it, matching how \uXXXX surrogate escapes
                // are handled in the lexer.
                bool valid_pair = false;
                if (wc <= 0xDBFF && JSON_HEDLEY_UNLIKELY(!input.empty()))
                {
                    // only consume the next unit if it completes the pair
                    const auto wc2 = static_cast<unsigned int>(*input.current);
                    if (0xDC00 <= wc2 && wc2 <= 0xDFFF)
                    {
                        input.get_character();
                        const auto charcode = 0x10000u + (((static_cast<unsigned int>(wc) & 0x3FFu) << 10u) | (wc2 & 0x3FFu));
                        utf8_bytes_filled = 0;
                        encode_utf8(charcode, [&utf8_bytes, &utf8_bytes_filled](std::uint32_t byte)
                        {
                            utf8_bytes[utf8_bytes_filled++] = static_cast<std::char_traits<char>::int_type>(byte);
                        });
                        valid_pair = true;
                    }
                }

                if (!valid_pair)
                {
                    // emit a byte that is never valid UTF-8 (see the UTF-32 case)
                    utf8_bytes[0] = 0xFF;
                    utf8_bytes_filled = 1;
                }
            }
        }
    }
};

// Wraps another input adapter to convert wide character types into individual bytes.
template<typename BaseInputAdapter, typename WideCharType>
class wide_string_input_adapter
{
  public:
    using char_type = char;

    wide_string_input_adapter(BaseInputAdapter base)
        : base_adapter(base) {}

    typename std::char_traits<char>::int_type get_character() noexcept
    {
        // check if the buffer needs to be filled
        if (utf8_bytes_index == utf8_bytes_filled)
        {
            fill_buffer<sizeof(WideCharType)>();

            JSON_ASSERT(utf8_bytes_filled > 0);
            JSON_ASSERT(utf8_bytes_index == 0);
        }

        // use buffer
        JSON_ASSERT(utf8_bytes_filled > 0);
        JSON_ASSERT(utf8_bytes_index < utf8_bytes_filled);
        return utf8_bytes[utf8_bytes_index++];
    }

    // parsing binary with wchar doesn't make sense, but since the parsing mode can be runtime, we need something here
    template<class T>
    JSON_HEDLEY_NO_RETURN std::size_t get_elements(T* /*dest*/, std::size_t /*count*/ = 1)
    {
        JSON_THROW(parse_error::create(exception_id::unexpected_byte, 1, "wide string type cannot be interpreted as binary data", nullptr));
    }

  private:
    BaseInputAdapter base_adapter;

    template<size_t T>
    void fill_buffer()
    {
        wide_string_input_helper<BaseInputAdapter, T>::fill_buffer(base_adapter, utf8_bytes, utf8_bytes_index, utf8_bytes_filled);
    }

    /// a buffer for UTF-8 bytes
    std::array<std::char_traits<char>::int_type, 4> utf8_bytes = {{0, 0, 0, 0}};

    /// index to the utf8_codes array for the next valid byte
    std::size_t utf8_bytes_index = 0;
    /// number of valid bytes in the utf8_codes array
    std::size_t utf8_bytes_filled = 0;
};

template<typename IteratorType, typename SentinelType = IteratorType, typename Enable = void>
struct iterator_input_adapter_factory
{
    using iterator_type = IteratorType;
    using sentinel_type = SentinelType;
    using char_type = typename std::iterator_traits<iterator_type>::value_type;
    using adapter_type = iterator_input_adapter<iterator_type, sentinel_type>;

    static adapter_type create(IteratorType first, SentinelType last)
    {
        return adapter_type(std::move(first), std::move(last));
    }
};

// Detection: whether IteratorType and SentinelType can be compared with !=
template<typename IteratorType, typename SentinelType, typename = void>
struct can_compare_ne_impl : std::false_type {};

template<typename IteratorType, typename SentinelType>
struct can_compare_ne_impl < IteratorType, SentinelType,
       void_t < decltype(std::declval<IteratorType>() != std::declval<SentinelType>()) >>
           : std::true_type {};

// Workaround for reversed operator order
template<typename IteratorType, typename SentinelType, typename = void>
struct can_compare_ne_reversed : std::false_type {};

template<typename IteratorType, typename SentinelType>
struct can_compare_ne_reversed < IteratorType, SentinelType,
       void_t < decltype(std::declval<SentinelType>() != std::declval<IteratorType>()) >>
           : std::true_type {};

template<typename IteratorType, typename SentinelType>
struct can_compare_ne_either_order : std::integral_constant < bool,
    can_compare_ne_impl<IteratorType, SentinelType>::value ||
    can_compare_ne_reversed<IteratorType, SentinelType>::value > {};

// std::nullptr_t is excluded explicitly: a literal `nullptr` passed as a
// trailing default argument (e.g. parse(s, nullptr, ...)) must never be
// mistaken for a sentinel, and some compilers (e.g. GCC 4.8) unreliably
// SFINAE the `operator!=` detection above for std::nullptr_t against
// container/string types, which would otherwise make such calls ambiguous
// with the compatible-input overload.
template<typename IteratorType, typename SentinelType>
struct can_compare_ne : std::integral_constant < bool,
    !std::is_same<SentinelType, std::nullptr_t>::value &&
    can_compare_ne_either_order<IteratorType, SentinelType>::value > {};

template<typename T>
struct is_iterator_of_multibyte
{
    using value_type = typename std::iterator_traits<T>::value_type;
    enum // NOLINT(cppcoreguidelines-use-enum-class)
    {
        value = sizeof(value_type) > 1
    };
};

template<typename IteratorType, typename SentinelType>
struct iterator_input_adapter_factory<IteratorType, SentinelType, enable_if_t<is_iterator_of_multibyte<IteratorType>::value>>
{
    using iterator_type = IteratorType;
    using sentinel_type = SentinelType;
    using char_type = typename std::iterator_traits<iterator_type>::value_type;
    using base_adapter_type = iterator_input_adapter<iterator_type, sentinel_type>;
    using adapter_type = wide_string_input_adapter<base_adapter_type, char_type>;

    static adapter_type create(IteratorType first, SentinelType last)
    {
        return adapter_type(base_adapter_type(std::move(first), std::move(last)));
    }
};

// General purpose iterator-based input (iterator+sentinel pair; SentinelType
// defaults to IteratorType for the common same-type case, but may differ for
// C++20 ranges-style iterator+sentinel pairs). Only enable for types that can
// be compared with !=.
template < typename IteratorType, typename SentinelType = IteratorType,
           typename = typename std::enable_if <
               can_compare_ne<IteratorType, SentinelType>::value >::type >
typename iterator_input_adapter_factory<IteratorType, SentinelType>::adapter_type input_adapter(IteratorType first, SentinelType last)
{
    using factory_type = iterator_input_adapter_factory<IteratorType, SentinelType>;
    return factory_type::create(first, last);
}

// The element type a container's data() points at, cv-qualifiers removed.
// Ill-formed - and therefore SFINAE-friendly - for types without data().
template<typename ContainerType>
using container_data_t = typename std::remove_cv<typename std::remove_pointer <
                         decltype(std::declval<const ContainerType&>().data()) >::type >::type;

// The container's own element type, cv-qualifiers removed. It is looked up on
// the bare type so it is also found when ContainerType is deduced as a
// reference by the forwarding-reference overload below.
template<typename ContainerType>
using container_value_t = typename std::remove_cv <
                          typename std::remove_cv<typename std::remove_reference<ContainerType>::type>::type::value_type >::type;

// Detect a container that stores its elements contiguously as single bytes
// (std::string, std::vector<char/unsigned char>, std::array<char, N>,
// std::string_view, ...). Such inputs are wrapped in a pointer-based adapter so
// they benefit from the contiguous fast paths (bulk string scanning, memcpy for
// binary formats) in every C++ standard - not only in C++20, where the standard
// library iterators model std::contiguous_iterator and are detected directly.
//
// data() and size() on their own would be duck typing: they say nothing about
// size() counting the units data() points at, and reading [data(), data() +
// size()) as bytes would be wrong for a type where it does not. Requiring the
// container's own value_type to be that same single-byte element ties the two
// together; every contiguous standard container satisfies it. Anything else
// keeps the iterator-based adapter, which is always correct - only slower.
template<typename ContainerType, typename = void>
struct is_contiguous_byte_container : std::false_type {};

template<typename ContainerType>
struct is_contiguous_byte_container < ContainerType, void_t <
    container_data_t<ContainerType>,
    container_value_t<ContainerType>,
decltype(std::declval<const ContainerType&>().size()) >>
            : std::integral_constant < bool,
        std::is_pointer<decltype(std::declval<const ContainerType&>().data())>::value&&
        std::is_integral<container_data_t<ContainerType>>::value&&
        sizeof(container_data_t<ContainerType>) == 1 &&
        std::is_same<container_data_t<ContainerType>, container_value_t<ContainerType>>::value > {};

// Convenience shorthand from container to iterator
// Enables ADL on begin(container) and end(container)
// Encloses the using declarations in namespace for not to leak them to outside scope

namespace container_input_adapter_factory_impl
{

using std::begin;
using std::end;

template<typename ContainerType, typename Enable = void>
struct container_input_adapter_factory {};

template<typename ContainerType>
struct container_input_adapter_factory< ContainerType,
       void_t<decltype(begin(std::declval<ContainerType>()), end(std::declval<ContainerType>()))>>
       {
           using adapter_type = decltype(input_adapter(begin(std::declval<ContainerType>()), end(std::declval<ContainerType>())));

           static adapter_type create(ContainerType&& container)
{
    // container is forwarded twice on purpose: the resulting begin/end
    // iterator types must match adapter_type, computed the same way
    // NOLINTNEXTLINE(bugprone-use-after-move,hicpp-invalid-access-moved)
    return input_adapter(begin(std::forward<ContainerType>(container)), end(std::forward<ContainerType>(container)));
}
       };

}  // namespace container_input_adapter_factory_impl

// General container path (iterator-based). Contiguous single-byte containers
// are excluded here and routed through the pointer-based overload below.
template < typename ContainerType,
           enable_if_t < !is_contiguous_byte_container<ContainerType>::value, int > = 0 >
typename container_input_adapter_factory_impl::container_input_adapter_factory<ContainerType>::adapter_type input_adapter(ContainerType && container)
{
    return container_input_adapter_factory_impl::container_input_adapter_factory<ContainerType>::create(std::forward<ContainerType>(container));
}

// Contiguous single-byte containers (std::string, std::vector<char>, ...) are
// wrapped in a pointer-based adapter so the contiguous fast paths apply in every
// standard. The pointer keeps the container's own element type (const char* for
// std::string, const std::uint8_t* for std::vector<std::uint8_t>, ...), so the
// resulting char_type - and therefore the parsing behavior - is byte-for-byte
// identical to the iterator-based path; only the raw pointer additionally
// enables the bulk fast paths. The container outlives the adapter for the whole
// parse (temporaries live until the end of the full expression), exactly as the
// iterators it replaces did.
template < typename ContainerType,
           enable_if_t < is_contiguous_byte_container<ContainerType>::value, int > = 0 >
auto input_adapter(const ContainerType& container)
-> decltype(input_adapter(container.data(), container.data() + container.size()))
{
    return input_adapter(container.data(), container.data() + container.size());
}

// specialization for std::string
using string_input_adapter_type = decltype(input_adapter(std::declval<std::string>()));

#ifndef JSON_NO_IO
// Special cases with fast paths
inline file_input_adapter input_adapter(std::FILE* file)
{
    if (file == nullptr)
    {
        JSON_THROW(parse_error::create(exception_id::syntax_error, 0, empty_input_message(), nullptr));
    }
    return file_input_adapter(file);
}

inline input_stream_adapter input_adapter(std::istream& stream)
{
    if (stream.rdbuf() == nullptr)
    {
        JSON_THROW(parse_error::create(exception_id::syntax_error, 0, empty_input_message(), nullptr));
    }
    return input_stream_adapter(stream);
}

inline input_stream_adapter input_adapter(std::istream&& stream)
{
    return input_adapter(stream);
}
#endif  // JSON_NO_IO

using contiguous_bytes_input_adapter = decltype(input_adapter(std::declval<const char*>(), std::declval<const char*>()));

// Null-delimited strings, and the like.
template < typename CharT,
           typename std::enable_if <
               std::is_pointer<CharT>::value&&
               !std::is_array<CharT>::value&&
               std::is_integral<typename std::remove_pointer<CharT>::type>::value&&
               sizeof(typename std::remove_pointer<CharT>::type) == 1,
               int >::type = 0 >
contiguous_bytes_input_adapter input_adapter(CharT b)
{
    if (b == nullptr)
    {
        JSON_THROW(parse_error::create(exception_id::syntax_error, 0, empty_input_message(), nullptr));
    }
    auto length = std::strlen(reinterpret_cast<const char*>(b));
    const auto* ptr = reinterpret_cast<const char*>(b);
    return input_adapter(ptr, ptr + length); // cppcheck-suppress[nullPointerArithmeticRedundantCheck]
}

template<typename T, std::size_t N>
auto input_adapter(T (&array)[N]) -> decltype(input_adapter(array, array + N)) // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
#if JSON_STRICT_NUL_HANDLING
    // A text-literal array from string-literal initialization (e.g.
    // json::parse("123") or json::parse(L"123")) carries a trailing '\0'
    // contributed by the compiler, not by the source text; drop exactly that
    // one byte so it is not mistaken for real trailing data. This covers all
    // character types that string literals can use: char, wchar_t, char16_t,
    // char32_t, and (C++20) char8_t. Every other element type (unsigned char,
    // std::uint8_t, ...) keeps the full extent unconditionally, since a
    // trailing zero byte there is genuine data (e.g. CBOR/MessagePack). This
    // intentionally does not strlen()-scan the array (as the pointer overload
    // above does for a null-delimited string): for an array that is not
    // NUL-terminated within its bounds, that would read past the end of the
    // array.
    using char_t = typename std::remove_cv<T>::type;
    constexpr bool is_text_literal_type = std::is_same<char_t, char>::value
                                          || std::is_same<char_t, wchar_t>::value
                                          || std::is_same<char_t, char16_t>::value
                                          || std::is_same<char_t, char32_t>::value
#if defined(__cpp_char8_t)
                                          || std::is_same<char_t, char8_t>::value
#endif
                                          ;
    if (is_text_literal_type && N > 0 && array[N - 1] == 0)
    {
        return input_adapter(array, array + N - 1);
    }
#endif
    return input_adapter(array, array + N);
}

// This class only handles inputs that construct a contiguous_bytes_input_adapter
// (e.g. span_input_adapter). It's required so that expressions like {ptr, len}
// can be implicitly cast to the correct adapter.
class span_input_adapter
{
  public:
    template < typename CharT,
               typename std::enable_if <
                   std::is_pointer<CharT>::value&&
                   std::is_integral<typename std::remove_pointer<CharT>::type>::value&&
                   sizeof(typename std::remove_pointer<CharT>::type) == 1,
                   int >::type = 0 >
    span_input_adapter(CharT b, std::size_t l)
        : ia(reinterpret_cast<const char*>(b), reinterpret_cast<const char*>(b) + l) {}

    template<class IteratorType,
             typename std::enable_if<
                 std::is_same<typename iterator_traits<IteratorType>::iterator_category, std::random_access_iterator_tag>::value,
                 int>::type = 0>
    span_input_adapter(IteratorType first, IteratorType last)
        : ia(input_adapter(first, last)) {}

    contiguous_bytes_input_adapter&& get()
    {
        return std::move(ia); // NOLINT(hicpp-move-const-arg,performance-move-const-arg)
    }

  private:
    contiguous_bytes_input_adapter ia;
};

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
