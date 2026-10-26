//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // max
#include <cstddef> // size_t
#ifndef JSON_NO_IO
    #include <cstdio> // FILE, fread
#endif
#include <istream> // istream, streambuf
#include <string> // basic_string, char_traits, string
#include <type_traits> // decay, integral_constant, is_array, is_const, is_integral, is_lvalue_reference, is_pointer, is_same, remove_cv, remove_extent, remove_pointer, remove_reference
#include <utility> // forward

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>

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

/// a pointer to a C stream (never with JSON_NO_IO, which leaves out <cstdio>)
template<typename T>
struct is_c_stream
#ifndef JSON_NO_IO
    : std::is_same<T, std::FILE*>
#else
    : std::false_type
#endif
{};

#ifndef JSON_NO_IO
/// append the rest of a C stream: in blocks with fread, not character by
/// character (the library's file adapter reads with fgetc);
/// f is not null
inline void append_file(std::string& buf, std::FILE* f)
{
    for (;;)
    {
        const std::size_t used = buf.size();
        const std::size_t room = (std::max)(buf.capacity() - used, std::size_t{4096});
        buf.resize(used + room);
        const std::size_t got = std::fread(&buf[used], 1, room, f);
        buf.resize(used + got);
        if (got < room)
        {
            break; // end of file, or an error (as fgetc, which returns EOF for both)
        }
    }
}
#endif

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
