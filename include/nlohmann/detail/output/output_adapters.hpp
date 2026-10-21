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
        : v(&vec), position(vec.size())
    {}

    output_vector_sink(const output_vector_sink&) = delete;
    output_vector_sink& operator=(const output_vector_sink&) = delete;
    output_vector_sink& operator=(output_vector_sink&&) = delete;

    output_vector_sink(output_vector_sink&& other) noexcept
        : v(other.v), position(other.position)
    {
        other.v = nullptr;
    }

    ~output_vector_sink()
    {
        if (v != nullptr)
        {
            v->resize(position);
        }
    }

    // always inlined: GCC otherwise keeps these out of line in a large
    // translation unit, and a call per byte or number costs more than the write
    JSON_HEDLEY_ALWAYS_INLINE
    void write_character(CharType c)
    {
        if (JSON_HEDLEY_UNLIKELY(position == v->size()))
        {
            grow(1);
        }
        (*v)[position++] = c;
    }

    // no JSON_HEDLEY_NON_NULL here: binary_writer legitimately passes a null
    // pointer with length 0 for empty strings/binary values; memcpy must not
    // see it.
    JSON_HEDLEY_ALWAYS_INLINE
    void write_characters(const CharType* s, std::size_t length)
    {
        if (JSON_HEDLEY_UNLIKELY(v->size() - position < length))
        {
            if (length >= max_reserve_size)
            {
                append(s, length);
                return;
            }
            grow(length);
        }
        if (length != 0)
        {
            std::memcpy(v->data() + position, s, length * sizeof(CharType));
            position += length;
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
        if (JSON_HEDLEY_UNLIKELY(v->size() - position < length))
        {
            grow(length);
        }
        return v->data() + position;
    }

    /// keep the first @a length characters written to the space from reserve()
    JSON_HEDLEY_ALWAYS_INLINE
    void commit(const std::size_t length) noexcept
    {
        position += length;
    }

  private:
    /// make room for at least @a length more characters after the position;
    /// kept out of line so that the write functions stay small enough for
    /// GCC to inline them into the writer
    JSON_HEDLEY_NEVER_INLINE
    void grow(const std::size_t length)
    {
        // use the capacity the vector already has, else at least double it;
        // never less than 64 characters, so that a small value does not
        // reallocate for every few bytes
        const std::size_t needed = position + length;
        v->resize((std::max)(std::size_t{64}, needed <= v->capacity()
                             ? v->capacity()
                             : (std::max)(needed, v->capacity() * 2)));
    }

    /// append @a length (at least max_reserve_size) characters that do not fit
    /// the space ahead of the position: insert() copies them once into the
    /// grown vector, where grow() would first zero the new space and then copy
    /// over it - noticeable for a large string or binary value
    JSON_HEDLEY_NEVER_INLINE
    void append(const CharType* s, const std::size_t length)
    {
        v->resize(position);
        if (v->capacity() - position < length)
        {
            // grow geometrically, with room for the writes that follow, so
            // that the next grow() need not reallocate right away
            v->reserve((std::max)(v->capacity() * 2, position + length + max_reserve_size));
        }
        v->insert(v->end(), s, s + length);
        position = v->size();
    }

    std::vector<CharType, AllocatorType>* v;
    /// number of characters of *v written so far
    std::size_t position;
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
/// adapters) via the `output_adapter`-based overloads. Each write still goes
/// through one virtual call, exactly as before; only the concrete sinks above
/// avoid it.
template<typename CharType>
class output_adapter_sink
{
  public:
    explicit output_adapter_sink(output_adapter_t<CharType> adapter)
        : oa(std::move(adapter))
    {
        JSON_ASSERT(oa);
    }

    void write_character(CharType c)
    {
        oa->write_character(c);
    }

    // no JSON_HEDLEY_NON_NULL: forwards (null, 0) for empty payloads, exactly as
    // the type-erased path already did before this sink existed
    void write_characters(const CharType* s, std::size_t length)
    {
        oa->write_characters(s, length);
    }

    /// space for writing up to @a length characters (see
    /// output_vector_sink::reserve)
    CharType* reserve(const std::size_t length) noexcept
    {
        JSON_ASSERT(length <= max_reserve_size);
        static_cast<void>(length);
        return reserved.data();
    }

    /// write the first @a length characters written to the space from reserve()
    void commit(const std::size_t length)
    {
        oa->write_characters(reserved.data(), length);
    }

  private:
    output_adapter_t<CharType> oa;
    std::array<CharType, max_reserve_size> reserved{};
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
