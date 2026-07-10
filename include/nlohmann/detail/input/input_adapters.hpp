//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cstddef> // size_t
#include <cstring> // strlen
#include <iterator> // begin, end, iterator_traits, random_access_iterator_tag, distance, next
#include <memory> // shared_ptr, make_shared, addressof
#include <numeric> // accumulate
#include <streambuf> // streambuf
#include <string> // string, char_traits
#include <type_traits> // enable_if, is_base_of, is_pointer, is_integral, remove_pointer
#include <utility> // pair, declval

#ifndef JSON_NO_IO
    #include <cstdio>   // FILE *
    #include <istream>  // istream
#endif                  // JSON_NO_IO

#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/iterators/iterator_traits.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/// the supported input formats
enum class input_format_t { json, cbor, msgpack, ubjson, bson, bjdata };

////////////////////
// input adapters //
////////////////////

#ifndef JSON_NO_IO
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
    }

    // make class move-only
    file_input_adapter(const file_input_adapter&) = delete;
    file_input_adapter(file_input_adapter&&) noexcept = default;
    file_input_adapter& operator=(const file_input_adapter&) = delete;
    file_input_adapter& operator=(file_input_adapter&&) = delete;
    ~file_input_adapter() = default;

    std::char_traits<char>::int_type get_character() noexcept
    {
        return std::fgetc(m_file);
    }

    // returns the number of characters successfully read
    template<class T>
    std::size_t get_elements(T* dest, std::size_t count = 1)
    {
        return fread(dest, 1, sizeof(T) * count, m_file);
    }

  private:
    /// the file pointer to read from
    std::FILE* m_file;
};

/*!
Input adapter for a (caching) istream. Ignores a UFT Byte Order Mark at
beginning of input. Does not support changing the underlying std::streambuf
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
            is->clear(is->rdstate() & std::ios::eofbit);
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
    {
        rhs.is = nullptr;
        rhs.sb = nullptr;
    }

    // std::istream/std::streambuf use std::char_traits<char>::to_int_type, to
    // ensure that std::char_traits<char>::eof() and the character 0xFF do not
    // end up as the same value, e.g., 0xFFFFFFFF.
    std::char_traits<char>::int_type get_character()
    {
        auto res = sb->sbumpc();
        // set eof manually, as we don't use the istream interface.
        if (JSON_HEDLEY_UNLIKELY(res == std::char_traits<char>::eof()))
        {
            is->clear(is->rdstate() | std::ios::eofbit);
        }
        return res;
    }

    template<class T>
    std::size_t get_elements(T* dest, std::size_t count = 1)
    {
        auto res = static_cast<std::size_t>(sb->sgetn(reinterpret_cast<char*>(dest), static_cast<std::streamsize>(count * sizeof(T))));
        if (JSON_HEDLEY_UNLIKELY(res < count * sizeof(T)))
        {
            is->clear(is->rdstate() | std::ios::eofbit);
        }
        return res;
    }

  private:
    /// the associated input stream
    std::istream* is = nullptr;
    std::streambuf* sb = nullptr;
};
#endif  // JSON_NO_IO

// General-purpose iterator-based adapter. It might not be as fast as
// theoretically possible for some containers, but it is extremely versatile.
// SentinelType defaults to IteratorType for backward compatibility, but may
// be a different type (e.g., a C++20 sentinel or counted_iterator).
template<typename IteratorType, typename SentinelType = IteratorType>
class iterator_input_adapter
{
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
        && std::is_same<IteratorType, SentinelType>::value
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

        return char_traits<char_type>::eof();
    }

    // number of characters consumed from the input so far
    std::size_t get_consumed_count() const
    {
        return static_cast<std::size_t>(std::distance(begin, current));
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
    // library iterators such as those of std::vector and std::string).
    // The fast path also requires SentinelType == IteratorType so std::distance works.
    static constexpr bool iterator_is_contiguous =
        std::is_same<IteratorType, SentinelType>::value && (
#if defined(__cpp_lib_concepts) && defined(JSON_HAS_CPP_20)
            std::contiguous_iterator<IteratorType> ||
#endif
            std::is_pointer<IteratorType>::value);

    // contiguous fast path: bulk copy the remaining range with std::memcpy
    template<class T>
    std::size_t get_elements_impl(T* dest, std::size_t count, std::true_type /*contiguous*/)
    {
        const std::size_t wanted = count * sizeof(T);
        const std::size_t available = static_cast<std::size_t>(std::distance(current, end)) * sizeof(char_type);
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
            // get the current character
            const auto wc = input.get_character();

            // UTF-32 to UTF-8 encoding
            if (wc < 0x80)
            {
                utf8_bytes[0] = static_cast<std::char_traits<char>::int_type>(wc);
                utf8_bytes_filled = 1;
            }
            else if (wc <= 0x7FF)
            {
                utf8_bytes[0] = static_cast<std::char_traits<char>::int_type>(0xC0u | ((static_cast<unsigned int>(wc) >> 6u) & 0x1Fu));
                utf8_bytes[1] = static_cast<std::char_traits<char>::int_type>(0x80u | (static_cast<unsigned int>(wc) & 0x3Fu));
                utf8_bytes_filled = 2;
            }
            else if (wc <= 0xFFFF)
            {
                utf8_bytes[0] = static_cast<std::char_traits<char>::int_type>(0xE0u | ((static_cast<unsigned int>(wc) >> 12u) & 0x0Fu));
                utf8_bytes[1] = static_cast<std::char_traits<char>::int_type>(0x80u | ((static_cast<unsigned int>(wc) >> 6u) & 0x3Fu));
                utf8_bytes[2] = static_cast<std::char_traits<char>::int_type>(0x80u | (static_cast<unsigned int>(wc) & 0x3Fu));
                utf8_bytes_filled = 3;
            }
            else if (wc <= 0x10FFFF)
            {
                utf8_bytes[0] = static_cast<std::char_traits<char>::int_type>(0xF0u | ((static_cast<unsigned int>(wc) >> 18u) & 0x07u));
                utf8_bytes[1] = static_cast<std::char_traits<char>::int_type>(0x80u | ((static_cast<unsigned int>(wc) >> 12u) & 0x3Fu));
                utf8_bytes[2] = static_cast<std::char_traits<char>::int_type>(0x80u | ((static_cast<unsigned int>(wc) >> 6u) & 0x3Fu));
                utf8_bytes[3] = static_cast<std::char_traits<char>::int_type>(0x80u | (static_cast<unsigned int>(wc) & 0x3Fu));
                utf8_bytes_filled = 4;
            }
            else
            {
                // unknown character
                utf8_bytes[0] = static_cast<std::char_traits<char>::int_type>(wc);
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

            // UTF-16 to UTF-8 encoding
            if (wc < 0x80)
            {
                utf8_bytes[0] = static_cast<std::char_traits<char>::int_type>(wc);
                utf8_bytes_filled = 1;
            }
            else if (wc <= 0x7FF)
            {
                utf8_bytes[0] = static_cast<std::char_traits<char>::int_type>(0xC0u | ((static_cast<unsigned int>(wc) >> 6u)));
                utf8_bytes[1] = static_cast<std::char_traits<char>::int_type>(0x80u | (static_cast<unsigned int>(wc) & 0x3Fu));
                utf8_bytes_filled = 2;
            }
            else if (0xD800 > wc || wc >= 0xE000)
            {
                utf8_bytes[0] = static_cast<std::char_traits<char>::int_type>(0xE0u | ((static_cast<unsigned int>(wc) >> 12u)));
                utf8_bytes[1] = static_cast<std::char_traits<char>::int_type>(0x80u | ((static_cast<unsigned int>(wc) >> 6u) & 0x3Fu));
                utf8_bytes[2] = static_cast<std::char_traits<char>::int_type>(0x80u | (static_cast<unsigned int>(wc) & 0x3Fu));
                utf8_bytes_filled = 3;
            }
            else
            {
                if (JSON_HEDLEY_UNLIKELY(!input.empty()))
                {
                    const auto wc2 = static_cast<unsigned int>(input.get_character());
                    const auto charcode = 0x10000u + (((static_cast<unsigned int>(wc) & 0x3FFu) << 10u) | (wc2 & 0x3FFu));
                    utf8_bytes[0] = static_cast<std::char_traits<char>::int_type>(0xF0u | (charcode >> 18u));
                    utf8_bytes[1] = static_cast<std::char_traits<char>::int_type>(0x80u | ((charcode >> 12u) & 0x3Fu));
                    utf8_bytes[2] = static_cast<std::char_traits<char>::int_type>(0x80u | ((charcode >> 6u) & 0x3Fu));
                    utf8_bytes[3] = static_cast<std::char_traits<char>::int_type>(0x80u | (charcode & 0x3Fu));
                    utf8_bytes_filled = 4;
                }
                else
                {
                    utf8_bytes[0] = static_cast<std::char_traits<char>::int_type>(wc);
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
        JSON_THROW(parse_error::create(112, 1, "wide string type cannot be interpreted as binary data", nullptr));
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
    return input_adapter(begin(std::forward<ContainerType>(container)), end(std::forward<ContainerType>(container)));
}
       };

}  // namespace container_input_adapter_factory_impl

template<typename ContainerType>
typename container_input_adapter_factory_impl::container_input_adapter_factory<ContainerType>::adapter_type input_adapter(ContainerType&& container)
{
    return container_input_adapter_factory_impl::container_input_adapter_factory<ContainerType>::create(std::forward<ContainerType>(container));
}

// specialization for std::string
using string_input_adapter_type = decltype(input_adapter(std::declval<std::string>()));

#ifndef JSON_NO_IO
// Special cases with fast paths
inline file_input_adapter input_adapter(std::FILE* file)
{
    if (file == nullptr)
    {
        JSON_THROW(parse_error::create(101, 0, "attempting to parse an empty input; check that your input string or stream contains the expected JSON", nullptr));
    }
    return file_input_adapter(file);
}

inline input_stream_adapter input_adapter(std::istream& stream)
{
    return input_stream_adapter(stream);
}

inline input_stream_adapter input_adapter(std::istream&& stream)
{
    return input_stream_adapter(stream);
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
        JSON_THROW(parse_error::create(101, 0, "attempting to parse an empty input; check that your input string or stream contains the expected JSON", nullptr));
    }
    auto length = std::strlen(reinterpret_cast<const char*>(b));
    const auto* ptr = reinterpret_cast<const char*>(b);
    return input_adapter(ptr, ptr + length); // cppcheck-suppress[nullPointerArithmeticRedundantCheck]
}

template<typename T, std::size_t N>
auto input_adapter(T (&array)[N]) -> decltype(input_adapter(array, array + N)) // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    return input_adapter(array, array + N);
}

// This class only handles inputs of input_buffer_adapter type.
// It's required so that expressions like {ptr, len} can be implicitly cast
// to the correct adapter.
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
