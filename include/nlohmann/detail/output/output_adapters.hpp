//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t
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

/// @brief non-virtual output sink writing into a std::vector
///
/// This sink is not part of the virtual output_adapter_protocol hierarchy: it is
/// passed to binary_writer by value as a template parameter, so
/// write_character()/write_characters() are ordinary (inlinable) calls with no
/// vtable lookup and no shared_ptr. It is used for the common
/// `to_cbor`/`to_msgpack`/... into a std::vector. output_vector_adapter below
/// wraps this same sink to provide the virtual interface.
template<typename CharType, typename AllocatorType = std::allocator<CharType>>
class output_vector_sink
{
  public:
    explicit output_vector_sink(std::vector<CharType, AllocatorType>& vec) noexcept
        : v(vec)
    {}

    void write_character(CharType c)
    {
        v.push_back(c);
    }

    // no JSON_HEDLEY_NON_NULL here: binary_writer legitimately passes a null
    // pointer with length 0 for empty strings/binary values. Appending an empty
    // range is a no-op; the type-erased path tolerates this via the (unattributed)
    // virtual base, and the concrete sink must do the same.
    void write_characters(const CharType* s, std::size_t length)
    {
        v.insert(v.end(), s, s + length);
    }

  private:
    std::vector<CharType, AllocatorType>& v;
};

/// output adapter for byte vectors
///
/// The appending itself lives in output_vector_sink; this class only adds the
/// virtual output_adapter_protocol interface on top of it, so both the
/// type-erased and the templated path share one implementation.
template<typename CharType, typename AllocatorType = std::allocator<CharType>>
class output_vector_adapter : public output_adapter_protocol<CharType>
{
  public:
    explicit output_vector_adapter(std::vector<CharType, AllocatorType>& vec) noexcept
        : sink(vec)
    {}

    void write_character(CharType c) override
    {
        sink.write_character(c);
    }

    void write_characters(const CharType* s, std::size_t length) override
    {
        sink.write_characters(s, length);
    }

  private:
    output_vector_sink<CharType, AllocatorType> sink;
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

  private:
    output_adapter_t<CharType> oa;
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
