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
#include <cstddef> // size_t
#include <cstring> // memcpy
#include <memory> // shared_ptr, make_shared
#include <string> // basic_string
#include <type_traits> // conditional, integral_constant, is_same
#include <utility> // move
#include <vector> // vector

#ifndef JSON_NO_IO
    #include <ios>      // streamsize
    #include <ostream>  // basic_ostream
#endif  // JSON_NO_IO

#include <nlohmann/detail/macro_scope.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/// abstract output adapter interface
template<typename CharType> struct output_adapter_protocol
{
    virtual void write_character(CharType c) = 0;
    /// @param[in] s      pointer to the characters to write; binary_writer legitimately
    ///                   passes a null pointer together with length 0 for an empty
    ///                   string or binary value, so implementations must tolerate that
    /// @param[in] length number of characters at @a s
    virtual void write_characters(const CharType* s, std::size_t length) = 0;
    virtual ~output_adapter_protocol() = default;

    output_adapter_protocol() = default;
    output_adapter_protocol(const output_adapter_protocol&) = default;
    output_adapter_protocol(output_adapter_protocol&&) noexcept = default;
    output_adapter_protocol& operator=(const output_adapter_protocol&) = default;
    output_adapter_protocol& operator=(output_adapter_protocol&&) noexcept = default;
};

/// a type to simplify interfaces
template<typename CharType>
using output_adapter_t = std::shared_ptr<output_adapter_protocol<CharType>>;

/// the largest number of characters a writer may reserve() from a sink at once;
/// output_vector_sink also appends writes of at least this size with insert()
constexpr std::size_t max_reserve_size = 256;

/// @brief copy @a length characters, at most 32, without a call of memcpy()
///
/// Short strings are the typical payload of a binary value, and a call of
/// memcpy() costs more than copying them. A copy of 16 to 32 characters is two
/// possibly overlapping 16-byte copies, one of 8 to 15 two 8-byte copies, and
/// so on down to a single character; each is a fixed-size load and store.
/// Nothing outside of [src, src + length) is read or written.
template<typename CharType>
inline void copy_short(CharType* dst, const CharType* src, const std::size_t length, std::true_type /*is_byte*/) noexcept
{
    JSON_ASSERT(length <= 32);
    if (length >= 16)
    {
        std::array<char, 16> first; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
        std::array<char, 16> last; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
        std::memcpy(first.data(), src, 16);
        std::memcpy(last.data(), src + (length - 16), 16);
        std::memcpy(dst, first.data(), 16);
        std::memcpy(dst + (length - 16), last.data(), 16);
    }
    else if (length >= 8)
    {
        std::array<char, 8> first; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
        std::array<char, 8> last; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
        std::memcpy(first.data(), src, 8);
        std::memcpy(last.data(), src + (length - 8), 8);
        std::memcpy(dst, first.data(), 8);
        std::memcpy(dst + (length - 8), last.data(), 8);
    }
    else if (length >= 4)
    {
        std::array<char, 4> first; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
        std::array<char, 4> last; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): written before read
        std::memcpy(first.data(), src, 4);
        std::memcpy(last.data(), src + (length - 4), 4);
        std::memcpy(dst, first.data(), 4);
        std::memcpy(dst + (length - 4), last.data(), 4);
    }
    else if (length != 0)
    {
        // 1 to 3: the first, the middle, and the last character
        const CharType a = src[0];
        const CharType b = src[length >> 1];
        const CharType c = src[length - 1];
        dst[0] = a;
        dst[length >> 1] = b;
        dst[length - 1] = c;
    }
}

/// @brief copy @a length characters, of a character type wider than a byte
template<typename CharType>
inline void copy_short(CharType* dst, const CharType* src, const std::size_t length, std::false_type /*is_byte*/) noexcept
{
    std::memcpy(dst, src, length * sizeof(CharType));
}

/// the number of characters an empty vector is grown to by output_vector_sink
constexpr std::size_t min_vector_sink_capacity = 64;

/// @brief non-virtual output sink writing into a std::vector
///
/// This sink is not part of the virtual output_adapter_protocol hierarchy: it is
/// passed to binary_writer by value as a template parameter, so
/// write_character()/write_characters() are ordinary (inlinable) calls with no
/// vtable lookup and no shared_ptr. It is used for the common
/// `to_cbor`/`to_msgpack`/... into a std::vector.
///
/// Most writes are a few bytes - a type marker, or a number of 1, 2, 4, or 8
/// bytes - and appending those with push_back() or insert() cost more than
/// encoding them: insert() is an out-of-line call into a routine that can insert
/// anywhere, and resize() is one as well with libstdc++. The sink therefore keeps
/// its own write position: it grows the vector geometrically ahead of the
/// position and copies each write to it, so a write is a capacity check and a
/// short copy. The destructor shrinks the vector to the bytes actually written,
/// also when a write throws; shrinking a vector never allocates. The sink owns
/// that trim, so it can be moved but not copied, and the vector must not be used
/// while the sink is alive.
template<typename CharType, typename AllocatorType = std::allocator<CharType>>
class output_vector_sink
{
  public:
    explicit output_vector_sink(std::vector<CharType, AllocatorType>& vec) noexcept
        : v(&vec), cursor(vec.data() + vec.size()), limit(cursor)
    {}

    output_vector_sink(const output_vector_sink&) = delete;
    output_vector_sink& operator=(const output_vector_sink&) = delete;
    output_vector_sink& operator=(output_vector_sink&&) = delete;

    output_vector_sink(output_vector_sink&& other) noexcept
        : v(other.v), cursor(other.cursor), limit(other.limit)
    {
        other.v = nullptr;
    }

    ~output_vector_sink()
    {
        if (v != nullptr)
        {
            v->resize(position());
        }
    }

    // always inlined: GCC otherwise keeps these out of line in a large
    // translation unit, and a call per byte or number costs more than the write
    JSON_HEDLEY_ALWAYS_INLINE
    void write_character(CharType c)
    {
        if (JSON_HEDLEY_UNLIKELY(cursor == limit))
        {
            grow(1);
        }
        *cursor++ = c;
    }

    // no JSON_HEDLEY_NON_NULL here: binary_writer legitimately passes a null
    // pointer with length 0 for empty strings/binary values; memcpy must not
    // see it.
    JSON_HEDLEY_ALWAYS_INLINE
    void write_characters(const CharType* s, std::size_t length)
    {
        if (JSON_HEDLEY_UNLIKELY(space() < length))
        {
            if (length >= max_reserve_size)
            {
                append(s, length);
                return;
            }
            grow(length);
        }
        if (length <= 32)
        {
            copy_short(cursor, s, length, std::integral_constant<bool, sizeof(CharType) == 1>());
            cursor += length;
        }
        else
        {
            std::memcpy(cursor, s, length * sizeof(CharType));
            cursor += length;
        }
    }

    /// @brief space for writing up to @a length characters directly
    ///
    /// Returns a pointer to at least @a length (at most @ref max_reserve_size)
    /// writable characters at the write position; @ref commit then keeps the
    /// first ones of them. A writer can store whole words there and keep only
    /// the bytes it needs, and keep its write pointer in a register across many
    /// values instead of updating the sink after each.
    JSON_HEDLEY_ALWAYS_INLINE
    CharType* reserve(const std::size_t length)
    {
        JSON_ASSERT(length <= max_reserve_size);
        if (JSON_HEDLEY_UNLIKELY(space() < length))
        {
            grow(length);
        }
        return cursor;
    }

    /// keep the first @a length characters written to the space from reserve()
    JSON_HEDLEY_ALWAYS_INLINE
    void commit(const std::size_t length) noexcept
    {
        cursor += length;
    }

    /// nothing to pass on: the characters are in the vector (see output_adapter_sink)
    void flush() noexcept
    {}

  private:
    /// number of characters of *v written so far
    std::size_t position() const noexcept
    {
        return static_cast<std::size_t>(cursor - v->data());
    }

    /// number of characters that fit the vector behind the write position
    std::size_t space() const noexcept
    {
        return static_cast<std::size_t>(limit - cursor);
    }

    /// make room for at least @a length more characters after the position;
    /// kept out of line so that the write functions stay small enough for
    /// GCC to inline them into the writer
    JSON_HEDLEY_NEVER_INLINE
    void grow(const std::size_t length)
    {
        // use the capacity the vector already has, else at least double it;
        // never less than min_vector_sink_capacity, so that a small value does not
        // reallocate for every few bytes
        const std::size_t written = position();
        const std::size_t needed = written + length;
        v->resize((std::max)(min_vector_sink_capacity, needed <= v->capacity()
                             ? v->capacity()
                             : (std::max)(needed, v->capacity() * 2)));
        cursor = v->data() + written;
        limit = v->data() + v->size();
    }

    /// append @a length (at least max_reserve_size) characters that do not fit
    /// the space ahead of the position: insert() copies them once into the
    /// grown vector, where grow() would first zero the new space and then copy
    /// over it - noticeable for a large string or binary value
    JSON_HEDLEY_NEVER_INLINE
    void append(const CharType* s, const std::size_t length)
    {
        const std::size_t written = position();
        v->resize(written);
        if (v->capacity() - written < length)
        {
            // grow geometrically, with room for the writes that follow, so
            // that the next grow() need not reallocate right away
            v->reserve((std::max)(v->capacity() * 2, written + length + max_reserve_size));
        }
        v->insert(v->end(), s, s + length);
        cursor = v->data() + v->size();
        limit = cursor;
    }

    std::vector<CharType, AllocatorType>* v;
    /// the write position: in *v, at the number of characters written so far
    CharType* cursor;
    /// the end of *v
    CharType* limit;
};

/// output adapter for byte vectors
template<typename CharType, typename AllocatorType = std::allocator<CharType>>
class output_vector_adapter : public output_adapter_protocol<CharType>
{
  public:
    explicit output_vector_adapter(std::vector<CharType, AllocatorType>& vec) noexcept
        : v(vec)
    {}

    void write_character(CharType c) override
    {
        v.push_back(c);
    }

    // no JSON_HEDLEY_NON_NULL here: binary_writer legitimately passes a null
    // pointer with length 0 for empty strings/binary values; appending an empty
    // range is a no-op
    void write_characters(const CharType* s, std::size_t length) override
    {
        v.insert(v.end(), s, s + length);
    }

  private:
    std::vector<CharType, AllocatorType>& v;
};

#ifndef JSON_NO_IO
/// output adapter for output streams
template<typename CharType>
class output_stream_adapter : public output_adapter_protocol<CharType>
{
  public:
    explicit output_stream_adapter(std::basic_ostream<CharType>& s) noexcept
        : stream(s)
    {}

    // NOLINTNEXTLINE(portability-template-virtual-member-function)
    void write_character(CharType c) override
    {
        stream.put(c);
    }

    // NOLINTNEXTLINE(portability-template-virtual-member-function)
    void write_characters(const CharType* s, std::size_t length) override
    {
        stream.write(s, static_cast<std::streamsize>(length));
    }

  private:
    std::basic_ostream<CharType>& stream;
};
#endif  // JSON_NO_IO

/// output adapter for basic_string
template<typename CharType, typename StringType = std::basic_string<CharType>>
class output_string_adapter : public output_adapter_protocol<CharType>
{
  public:
    explicit output_string_adapter(StringType& s) noexcept
        : str(s)
    {}

    void write_character(CharType c) override
    {
        str.push_back(c);
    }

    void write_characters(const CharType* s, std::size_t length) override
    {
        str.append(s, length);
    }

  private:
    StringType& str;
};

/// @brief output sink forwarding to a type-erased output adapter
///
/// Wraps the polymorphic output_adapter_t so the same binary_writer template can
/// also target arbitrary adapters (output streams, strings, user-provided
/// adapters) via the `output_adapter`-based overloads.
///
/// A write through the adapter is a virtual call, and for a stream a call with
/// a sentry on top, which costs more than encoding the few bytes of most values.
/// The sink therefore collects what is written in a buffer and passes it on in
/// one piece when it is full, a write is too large for it, or @ref flush is
/// called. Everything written reaches the adapter in the same order and with
/// the same bytes; the destructor passes on what is left, so that a write that
/// throws leaves the adapter with exactly the bytes written before it. Only
/// @ref flush can report an error of the adapter (the destructor must not
/// throw), so it has to be called once the value is written.
template<typename CharType>
class output_adapter_sink
{
  public:
    explicit output_adapter_sink(output_adapter_t<CharType> adapter)
        : oa(std::move(adapter))
    {
        JSON_ASSERT(oa);
    }

    output_adapter_sink(const output_adapter_sink&) = delete;
    output_adapter_sink& operator=(const output_adapter_sink&) = delete;
    output_adapter_sink& operator=(output_adapter_sink&&) = delete;

    output_adapter_sink(output_adapter_sink&& other) noexcept
        : oa(std::move(other.oa)), used(other.used)
    {
        std::memcpy(buffer.data(), other.buffer.data(), other.used * sizeof(CharType));
        other.used = 0;
    }

    ~output_adapter_sink()
    {
        // a normal return has flushed already, so this is for a write that threw
        if (used != 0)
        {
            JSON_TRY
            {
                flush();
            }
            JSON_CATCH(...)
            {
                // nothing can be done about an adapter that throws here
            }
        }
    }

    JSON_HEDLEY_ALWAYS_INLINE
    void write_character(CharType c)
    {
        if (JSON_HEDLEY_UNLIKELY(used == buffer_size))
        {
            flush();
        }
        buffer[used++] = c;
    }

    // no JSON_HEDLEY_NON_NULL: forwards (null, 0) for empty payloads, exactly as
    // the type-erased path already did before this sink existed
    JSON_HEDLEY_ALWAYS_INLINE
    void write_characters(const CharType* s, std::size_t length)
    {
        if (JSON_HEDLEY_UNLIKELY(buffer_size - used < length))
        {
            write_large(s, length);
            return;
        }
        if (length <= 32)
        {
            copy_short(buffer.data() + used, s, length, std::integral_constant<bool, sizeof(CharType) == 1>());
            used += length;
        }
        else
        {
            std::memcpy(buffer.data() + used, s, length * sizeof(CharType));
            used += length;
        }
    }

    /// space for writing up to @a length characters (see
    /// output_vector_sink::reserve)
    JSON_HEDLEY_ALWAYS_INLINE
    CharType* reserve(const std::size_t length)
    {
        JSON_ASSERT(length <= max_reserve_size);
        if (JSON_HEDLEY_UNLIKELY(buffer_size - used < length))
        {
            flush();
        }
        return buffer.data() + used;
    }

    /// keep the first @a length characters written to the space from reserve()
    JSON_HEDLEY_ALWAYS_INLINE
    void commit(const std::size_t length) noexcept
    {
        used += length;
    }

    /// pass everything written so far on to the adapter
    void flush()
    {
        if (used != 0)
        {
            // reset first: the characters count as written even if the adapter throws
            const std::size_t length = used;
            used = 0;
            oa->write_characters(buffer.data(), length);
        }
    }

  private:
    /// a write that does not fit the space left in the buffer
    JSON_HEDLEY_NEVER_INLINE
    void write_large(const CharType* s, const std::size_t length)
    {
        flush();
        if (length >= buffer_size)
        {
            oa->write_characters(s, length);
        }
        else
        {
            std::memcpy(buffer.data(), s, length * sizeof(CharType));
            used = length;
        }
    }

    /// large enough for reserve() at any time
    static constexpr std::size_t buffer_size = 4 * max_reserve_size;

    output_adapter_t<CharType> oa;
    /// number of characters of @ref buffer not yet passed on
    std::size_t used = 0;
    std::array<CharType, buffer_size> buffer{};
};

/// @brief whether std::basic_string<CharType> has a non-deprecated std::char_traits
///        specialization, and is therefore usable as output_adapter's default StringType
///
/// std::char_traits is only guaranteed (and, on some standard libraries, only
/// implemented without a deprecation warning) for the character types listed
/// below; std::char_traits<T> for any other T (e.g. std::uint8_t, as used by the
/// binary writers) is a non-standard extension some standard libraries deprecate.
/// See https://github.com/nlohmann/json/issues/5725 item 2.
template<typename CharType>
struct is_output_adapter_string_char_type : std::integral_constant < bool,
    std::is_same<CharType, char>::value ||
    std::is_same<CharType, wchar_t>::value ||
    std::is_same<CharType, char16_t>::value ||
    std::is_same<CharType, char32_t>::value
#if defined(__cpp_lib_char8_t) && (__cpp_lib_char8_t >= 201907L)
    || std::is_same<CharType, char8_t>::value
#endif
    > {};

/// @brief placeholder type for output_adapter's StringType and (with JSON_NO_IO
///        undefined) its std::basic_ostream constructor parameter, for CharType
///        with no non-deprecated std::char_traits specialization
///
/// Never actually used: the StringType- and std::basic_ostream-based
/// output_adapter constructors are neither documented nor tested for such
/// CharType (only the std::vector-based constructor is used for them, by the
/// binary writers). Naming std::basic_string<CharType> or
/// std::basic_ostream<CharType> anywhere such a constructor would otherwise be
/// declared - even as an unused default template argument or an unused,
/// never-called overload - instantiates std::char_traits<CharType> merely to
/// name the type, which is exactly what triggers the deprecation warning this
/// placeholder avoids.
template<typename CharType>
struct output_adapter_no_string_type {};

// Select output_adapter's default StringType (and, below, its ostream
// constructor's parameter type) via partial specialization, not
// std::conditional: std::conditional<B, T, F> requires both T and F to be named
// as template arguments up front, which would still instantiate (and thus name)
// std::basic_string<CharType> / std::basic_ostream<CharType> for every CharType,
// defeating the point. A bool non-type parameter with two specializations only
// ever names the type that is actually selected.
template<typename CharType, bool = is_output_adapter_string_char_type<CharType>::value>
struct output_adapter_default_string_type
{
    using type = output_adapter_no_string_type<CharType>;
};

template<typename CharType>
struct output_adapter_default_string_type<CharType, true>
{
    using type = std::basic_string<CharType>;
};

#ifndef JSON_NO_IO
/// distinct from output_adapter_no_string_type, so the placeholder overloads of
/// output_adapter's constructor (used when CharType is not a character type)
/// stay distinct overloads instead of colliding into a single redeclaration
template<typename CharType>
struct output_adapter_no_ostream_type {};

template<typename CharType, bool = is_output_adapter_string_char_type<CharType>::value>
struct output_adapter_ostream_type
{
    using type = output_adapter_no_ostream_type<CharType>;
};

template<typename CharType>
struct output_adapter_ostream_type<CharType, true>
{
    using type = std::basic_ostream<CharType>;
};
#endif  // JSON_NO_IO

template < typename CharType, typename StringType =
           typename output_adapter_default_string_type<CharType>::type >
class output_adapter
{
  public:
    template<typename AllocatorType = std::allocator<CharType>>
    output_adapter(std::vector<CharType, AllocatorType>& vec)
        : oa(std::make_shared<output_vector_adapter<CharType, AllocatorType>>(vec)) {}

#ifndef JSON_NO_IO
    output_adapter(typename output_adapter_ostream_type<CharType>::type& s)
        : oa(std::make_shared<output_stream_adapter<CharType>>(s)) {}
#endif  // JSON_NO_IO

    output_adapter(StringType& s)
        : oa(std::make_shared<output_string_adapter<CharType, StringType>>(s)) {}

    operator output_adapter_t<CharType>()
    {
        return oa;
    }

  private:
    output_adapter_t<CharType> oa = nullptr;
};

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
