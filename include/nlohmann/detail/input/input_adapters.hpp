#pragma once

#include <cassert> // assert
#include <cstddef> // size_t
#include <cstring> // strlen
#include <istream> // istream
#include <iterator> // begin, end, iterator_traits, random_access_iterator_tag, distance, next
#include <memory> // shared_ptr, make_shared, addressof
#include <numeric> // accumulate
#include <string> // string, char_traits
#include <type_traits> // enable_if, is_base_of, is_pointer, is_integral, remove_pointer
#include <utility> // pair, declval

#include <nlohmann/detail/macro_scope.hpp>

namespace nlohmann
{
namespace detail
{
/// the supported input formats
enum class input_format_t { json, cbor, msgpack, ubjson, bson };

////////////////////
// input adapters //
////////////////////

/*!
@brief abstract input adapter interface

Produces a stream of std::char_traits<char>::int_type characters from a
std::istream, a buffer, or some other input type. Accepts the return of
exactly one non-EOF character for future input. The int_type characters
returned consist of all valid char values as positive values (typically
unsigned char), plus an EOF value outside that range, specified by the value
of the function std::char_traits<char>::eof(). This value is typically -1, but
could be any arbitrary value which is not a valid char value.
*/
struct input_adapter_protocol
{
    /// get a character [0,255] or std::char_traits<char>::eof().
    virtual std::char_traits<char>::int_type get_character() = 0;
    virtual ~input_adapter_protocol() = default;
};

/// a type to simplify interfaces
using input_adapter_t = std::shared_ptr<input_adapter_protocol>;

/*!
Input adapter for a (caching) istream. Ignores a UFT Byte Order Mark at
beginning of input. Does not support changing the underlying std::streambuf
in mid-input. Maintains underlying std::istream and std::streambuf to support
subsequent use of standard std::istream operations to process any input
characters following those used in parsing the JSON input.  Clears the
std::istream flags; any input errors (e.g., EOF) will be detected by the first
subsequent call for input from the std::istream.
*/
class input_stream_adapter : public input_adapter_protocol
{
  public:
    ~input_stream_adapter() override
    {
        // clear stream flags; we use underlying streambuf I/O, do not
        // maintain ifstream flags, except eof
        is.clear(is.rdstate() & std::ios::eofbit);
    }

    explicit input_stream_adapter(std::istream& i)
        : is(i), sb(*i.rdbuf())
    {}

    // delete because of pointer members
    input_stream_adapter(const input_stream_adapter&) = delete;
    input_stream_adapter& operator=(input_stream_adapter&) = delete;
    input_stream_adapter(input_stream_adapter&&) = delete;
    input_stream_adapter& operator=(input_stream_adapter&&) = delete;

    // std::istream/std::streambuf use std::char_traits<char>::to_int_type, to
    // ensure that std::char_traits<char>::eof() and the character 0xFF do not
    // end up as the same value, eg. 0xFFFFFFFF.
    std::char_traits<char>::int_type get_character() override
    {
        auto res = sb.sbumpc();
        // set eof manually, as we don't use the istream interface.
        if (res == EOF)
        {
            is.clear(is.rdstate() | std::ios::eofbit);
        }
        return res;
    }

  private:
    /// the associated input stream
    std::istream& is;
    std::streambuf& sb;
};

/// input adapter for buffer input
class input_buffer_adapter : public input_adapter_protocol
{
  public:
    input_buffer_adapter(const char* b, const std::size_t l) noexcept
        : cursor(b), limit(b + l)
    {}

    // delete because of pointer members
    input_buffer_adapter(const input_buffer_adapter&) = delete;
    input_buffer_adapter& operator=(input_buffer_adapter&) = delete;
    input_buffer_adapter(input_buffer_adapter&&) = delete;
    input_buffer_adapter& operator=(input_buffer_adapter&&) = delete;
    ~input_buffer_adapter() override = default;

    std::char_traits<char>::int_type get_character() noexcept override
    {
        if (JSON_LIKELY(cursor < limit))
        {
            return std::char_traits<char>::to_int_type(*(cursor++));
        }

        return std::char_traits<char>::eof();
    }

  private:
    /// pointer to the current character
    const char* cursor;
    /// pointer past the last character
    const char* const limit;
};

template<typename WideStringType, size_t T>
struct wide_string_input_helper
{
    // UTF-32
    static void fill_buffer(const WideStringType& str, size_t& current_wchar, std::array<std::char_traits<char>::int_type, 4>& utf8_bytes, size_t& utf8_bytes_index, size_t& utf8_bytes_filled)
    {
        utf8_bytes_index = 0;

        if (current_wchar == str.size())
        {
            utf8_bytes[0] = std::char_traits<char>::eof();
            utf8_bytes_filled = 1;
        }
        else
        {
            // get the current character
            const auto wc = static_cast<int>(str[current_wchar++]);

            // UTF-32 to UTF-8 encoding
            if (wc < 0x80)
            {
                utf8_bytes[0] = wc;
                utf8_bytes_filled = 1;
            }
            else if (wc <= 0x7FF)
            {
                utf8_bytes[0] = 0xC0 | ((wc >> 6) & 0x1F);
                utf8_bytes[1] = 0x80 | (wc & 0x3F);
                utf8_bytes_filled = 2;
            }
            else if (wc <= 0xFFFF)
            {
                utf8_bytes[0] = 0xE0 | ((wc >> 12) & 0x0F);
                utf8_bytes[1] = 0x80 | ((wc >> 6) & 0x3F);
                utf8_bytes[2] = 0x80 | (wc & 0x3F);
                utf8_bytes_filled = 3;
            }
            else if (wc <= 0x10FFFF)
            {
                utf8_bytes[0] = 0xF0 | ((wc >> 18) & 0x07);
                utf8_bytes[1] = 0x80 | ((wc >> 12) & 0x3F);
                utf8_bytes[2] = 0x80 | ((wc >> 6) & 0x3F);
                utf8_bytes[3] = 0x80 | (wc & 0x3F);
                utf8_bytes_filled = 4;
            }
            else
            {
                // unknown character
                utf8_bytes[0] = wc;
                utf8_bytes_filled = 1;
            }
        }
    }
};

template<typename WideStringType>
struct wide_string_input_helper<WideStringType, 2>
{
    // UTF-16
    static void fill_buffer(const WideStringType& str, size_t& current_wchar, std::array<std::char_traits<char>::int_type, 4>& utf8_bytes, size_t& utf8_bytes_index, size_t& utf8_bytes_filled)
    {
        utf8_bytes_index = 0;

        if (current_wchar == str.size())
        {
            utf8_bytes[0] = std::char_traits<char>::eof();
            utf8_bytes_filled = 1;
        }
        else
        {
            // get the current character
            const auto wc = static_cast<int>(str[current_wchar++]);

            // UTF-16 to UTF-8 encoding
            if (wc < 0x80)
            {
                utf8_bytes[0] = wc;
                utf8_bytes_filled = 1;
            }
            else if (wc <= 0x7FF)
            {
                utf8_bytes[0] = 0xC0 | ((wc >> 6));
                utf8_bytes[1] = 0x80 | (wc & 0x3F);
                utf8_bytes_filled = 2;
            }
            else if (0xD800 > wc or wc >= 0xE000)
            {
                utf8_bytes[0] = 0xE0 | ((wc >> 12));
                utf8_bytes[1] = 0x80 | ((wc >> 6) & 0x3F);
                utf8_bytes[2] = 0x80 | (wc & 0x3F);
                utf8_bytes_filled = 3;
            }
            else
            {
                if (current_wchar < str.size())
                {
                    const auto wc2 = static_cast<int>(str[current_wchar++]);
                    const int charcode = 0x10000 + (((wc & 0x3FF) << 10) | (wc2 & 0x3FF));
                    utf8_bytes[0] = 0xf0 | (charcode >> 18);
                    utf8_bytes[1] = 0x80 | ((charcode >> 12) & 0x3F);
                    utf8_bytes[2] = 0x80 | ((charcode >> 6) & 0x3F);
                    utf8_bytes[3] = 0x80 | (charcode & 0x3F);
                    utf8_bytes_filled = 4;
                }
                else
                {
                    // unknown character
                    ++current_wchar;
                    utf8_bytes[0] = wc;
                    utf8_bytes_filled = 1;
                }
            }
        }
    }
};

template<typename WideStringType>
class wide_string_input_adapter : public input_adapter_protocol
{
  public:
    explicit wide_string_input_adapter(const WideStringType& w)  noexcept
        : str(w)
    {}

    std::char_traits<char>::int_type get_character() noexcept override
    {
        // check if buffer needs to be filled
        if (utf8_bytes_index == utf8_bytes_filled)
        {
            fill_buffer<sizeof(typename WideStringType::value_type)>();

            assert(utf8_bytes_filled > 0);
            assert(utf8_bytes_index == 0);
        }

        // use buffer
        assert(utf8_bytes_filled > 0);
        assert(utf8_bytes_index < utf8_bytes_filled);
        return utf8_bytes[utf8_bytes_index++];
    }

  private:
    template<size_t T>
    void fill_buffer()
    {
        wide_string_input_helper<WideStringType, T>::fill_buffer(str, current_wchar, utf8_bytes, utf8_bytes_index, utf8_bytes_filled);
    }

    /// the wstring to process
    const WideStringType& str;

    /// index of the current wchar in str
    std::size_t current_wchar = 0;

    /// a buffer for UTF-8 bytes
    std::array<std::char_traits<char>::int_type, 4> utf8_bytes = {{0, 0, 0, 0}};

    /// index to the utf8_codes array for the next valid byte
    std::size_t utf8_bytes_index = 0;
    /// number of valid bytes in the utf8_codes array
    std::size_t utf8_bytes_filled = 0;
};

class input_adapter
{
  public:
    // native support

    /// input adapter for input stream
    input_adapter(std::istream& i)
        : ia(std::make_shared<input_stream_adapter>(i)) {}

    /// input adapter for input stream
    input_adapter(std::istream&& i)
        : ia(std::make_shared<input_stream_adapter>(i)) {}

    input_adapter(const std::wstring& ws)
        : ia(std::make_shared<wide_string_input_adapter<std::wstring>>(ws)) {}

    input_adapter(const std::u16string& ws)
        : ia(std::make_shared<wide_string_input_adapter<std::u16string>>(ws)) {}

    input_adapter(const std::u32string& ws)
        : ia(std::make_shared<wide_string_input_adapter<std::u32string>>(ws)) {}

    /// input adapter for buffer
    template<typename CharT,
             typename std::enable_if<
                 std::is_pointer<CharT>::value and
                 std::is_integral<typename std::remove_pointer<CharT>::type>::value and
                 sizeof(typename std::remove_pointer<CharT>::type) == 1,
                 int>::type = 0>
    input_adapter(CharT b, std::size_t l)
        : ia(std::make_shared<input_buffer_adapter>(reinterpret_cast<const char*>(b), l)) {}

    // derived support

    /// input adapter for string literal
    template<typename CharT,
             typename std::enable_if<
                 std::is_pointer<CharT>::value and
                 std::is_integral<typename std::remove_pointer<CharT>::type>::value and
                 sizeof(typename std::remove_pointer<CharT>::type) == 1,
                 int>::type = 0>
    input_adapter(CharT b)
        : input_adapter(reinterpret_cast<const char*>(b),
                        std::strlen(reinterpret_cast<const char*>(b))) {}

    /// input adapter for iterator range with contiguous storage
    template<class IteratorType,
             typename std::enable_if<
                 std::is_same<typename std::iterator_traits<IteratorType>::iterator_category, std::random_access_iterator_tag>::value,
                 int>::type = 0>
    input_adapter(IteratorType first, IteratorType last)
    {
#ifndef NDEBUG
        // assertion to check that the iterator range is indeed contiguous,
        // see http://stackoverflow.com/a/35008842/266378 for more discussion
        const auto is_contiguous = std::accumulate(
                                       first, last, std::pair<bool, int>(true, 0),
                                       [&first](std::pair<bool, int> res, decltype(*first) val)
        {
            res.first &= (val == *(std::next(std::addressof(*first), res.second++)));
            return res;
        }).first;
        assert(is_contiguous);
#endif

        // assertion to check that each element is 1 byte long
        static_assert(
            sizeof(typename std::iterator_traits<IteratorType>::value_type) == 1,
            "each element in the iterator range must have the size of 1 byte");

        const auto len = static_cast<size_t>(std::distance(first, last));
        if (JSON_LIKELY(len > 0))
        {
            // there is at least one element: use the address of first
            ia = std::make_shared<input_buffer_adapter>(reinterpret_cast<const char*>(&(*first)), len);
        }
        else
        {
            // the address of first cannot be used: use nullptr
            ia = std::make_shared<input_buffer_adapter>(nullptr, len);
        }
    }

    /// input adapter for array
    template<class T, std::size_t N>
    input_adapter(T (&array)[N])
        : input_adapter(std::begin(array), std::end(array)) {}

    /// input adapter for contiguous container
    template<class ContiguousContainer, typename
             std::enable_if<not std::is_pointer<ContiguousContainer>::value and
                            std::is_base_of<std::random_access_iterator_tag, typename std::iterator_traits<decltype(std::begin(std::declval<ContiguousContainer const>()))>::iterator_category>::value,
                            int>::type = 0>
    input_adapter(const ContiguousContainer& c)
        : input_adapter(std::begin(c), std::end(c)) {}

    operator input_adapter_t()
    {
        return ia;
    }

  private:
    /// the actual adapter
    input_adapter_t ia = nullptr;
};
}  // namespace detail
}  // namespace nlohmann
