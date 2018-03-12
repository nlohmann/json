#pragma once

#include <algorithm> // min
#include <array> // array
#include <cassert> // assert
#include <cstddef> // size_t
#include <cstring> // strlen
#include <ios> // streamsize, streamoff, streampos
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
////////////////////
// input adapters //
////////////////////

/*!
@brief abstract input adapter interface

Produces a stream of std::char_traits<char>::int_type characters from a
std::istream, a buffer, or some other input type.  Accepts the return of exactly
one non-EOF character for future input.  The int_type characters returned
consist of all valid char values as positive values (typically unsigned char),
plus an EOF value outside that range, specified by the value of the function
std::char_traits<char>::eof().  This value is typically -1, but could be any
arbitrary value which is not a valid char value.
*/
struct input_adapter_protocol
{
    /// get a character [0,255] or std::char_traits<char>::eof().
    virtual std::char_traits<char>::int_type get_character() = 0;
    /// restore the last non-eof() character to input
    virtual void unget_character() = 0;
    virtual ~input_adapter_protocol() = default;
};

/// a type to simplify interfaces
using input_adapter_t = std::shared_ptr<input_adapter_protocol>;

/*!
A helper function to skip the UTF-8 byte order mark.

If a complete BOM has been skipped, or if an incomplete BOM has been detected
and the stream has been successfully rewind to the start of the BOM, returns
goodbit.
If an internal operation fails, returns badbit, and the streambuf should no
longer be used.

Note: Doesn't handle the eofbit. Before doing anything else is.unget() clears
the eofbit. However, some implementations keep the eofbit if is.unget() fails,
others do not.

Note: The streambuf must be non-null.
*/
inline std::ios_base::iostate skip_byte_order_mark(std::streambuf* sb)
{
    using traits_type = std::char_traits<char>;

    assert(sb != nullptr);

    if (sb->sgetc() == 0xEF)
    {
        sb->sbumpc();
        if (sb->sgetc() == 0xBB)
        {
            sb->sbumpc();
            if (sb->sgetc() == 0xBF)
            {
                sb->sbumpc();
                return std::ios_base::goodbit;
            }

            if (sb->sungetc() == traits_type::eof())
            {
                return std::ios_base::badbit;
            }
        }

        if (sb->sungetc() == traits_type::eof())
        {
            return std::ios_base::badbit;
        }
    }

    return std::ios_base::goodbit;
}

/*!
Input adapter for a (caching) istream.
Ignores a UTF Byte Order Mark at beginning of input.

Does not support changing the underlying std::streambuf in mid-input.
*/
#if 0
class input_stream_adapter : public input_adapter_protocol
{
  public:
    using traits_type = std::char_traits<char>;

    explicit input_stream_adapter(std::istream& i)
        : is(i)
    {
        // Skip byte order mark
        if (is.peek() == 0xEF)
        {
            is.ignore();
            if (is.peek() == 0xBB)
            {
                is.ignore();
                if (is.peek() == 0xBF)
                {
                    is.ignore();
                    return; // Found a complete BOM.
                }

                is.unget();
            }

            is.unget();
        }
    }

    input_stream_adapter(const input_stream_adapter&) = delete;
    input_stream_adapter& operator=(const input_stream_adapter&) = delete;

    traits_type::int_type get_character() override
    {
        // Only try to get a character if the stream is good!
        if (is.good())
        {
            const auto ch = is.peek();
            // If peek() returns EOF, the following call to ignore() will set
            // the failbit, but we do not want to set the failbit here.
            if (ch != traits_type::eof())
            {
                is.ignore();
                return ch;
            }
        }

        return traits_type::eof();
    }

    void unget_character() override
    {
        is.unget();
    }

  private:
    std::istream& is;
};
#else
class input_stream_adapter : public input_adapter_protocol
{
    //
    // NOTE:
    //
    // This implementation differs slightly from the reference implementation
    // (using the std::istream interface):
    //
    //      From N4659:
    //      30.7.4.3 Unformatted input functions
    //
    //      [...]
    //      If an exception is thrown during input then `ios::badbit` is turned
    //      on[310] in `*this`'s error state. (Exceptions thrown from
    //      `basic_ios<>::clear()` are not caught or rethrown.)
    //      If `(exceptions() & badbit) != 0` then the exception is rethrown.
    //
    //      [310] This is done without causing an `ios::failure` to be thrown.
    //
    // However, there is no (portable) way to turn on the `badbit` in `is`
    // without throwing an exception, so here we don't catch (and possibly)
    // rethrow exceptions from streambuf operations.
    // If an internal operation throws an exception, the behavior of this
    // implementation is therefore slightly different from the reference
    // implementation:
    //
    // If an exception is thrown during input and
    //
    // - badbit is turned ON in `is.exceptions()`:
    //      The badbit will **not** be set in `is`'s error state.
    //
    // - badbit is turned OFF in `is.exceptions()`:
    //      The badbit will **not** be set in `is`'s error state and the
    //      exception is **not** swallowed.
    //

  public:
    using traits_type = std::char_traits<char>;

    explicit input_stream_adapter(std::istream& i)
        : is(i)
        , ok(i, /* noskipws */ true)
    {
        std::ios_base::iostate state = std::ios_base::goodbit;
        if (ok)
        {
            state |= nlohmann::detail::skip_byte_order_mark(is.rdbuf());
        }
        else
        {
            state |= std::ios_base::failbit;
        }

        // Update the stream state. In case skip_byte_order_mark() failed (but
        // did not throw an exception), `state` now has the badbit set and the
        // call to setstate might throw an ios::failure. Likewise, if the stream
        // is "not ok" then the failbit will be set, which might throw an
        // exception, too.
        is.setstate(state);
    }

    input_stream_adapter(const input_stream_adapter&) = delete;
    input_stream_adapter& operator=(const input_stream_adapter&) = delete;

    traits_type::int_type get_character() override
    {
        // Only try to get a character if the stream is good!
        if (is.good())
        {
            const auto ch = is.rdbuf()->sbumpc();
            if (ch != traits_type::eof())
            {
                return ch;
            }

            // sbumpc failed.
            // No more characters are available. Set eofbit.
            is.setstate(std::ios_base::eofbit);
        }

        return traits_type::eof();
    }

    void unget_character() override
    {
        // This method is only ever called if the last call to get_character was
        // successful (i.e. not EOF). This implies that the stream is good and
        // that the call to sungetc below is guaranteed to succeed.
        is.rdbuf()->sungetc();
    }

  private:
    std::istream& is;
    std::istream::sentry const ok;
};
#endif

/// input adapter for buffer input
class input_buffer_adapter : public input_adapter_protocol
{
  public:
    input_buffer_adapter(const char* b, const std::size_t l)
        : cursor(b), limit(b + l), start(b)
    {
        // skip byte order mark
        if (l >= 3 and b[0] == '\xEF' and b[1] == '\xBB' and b[2] == '\xBF')
        {
            cursor += 3;
        }
    }

    // delete because of pointer members
    input_buffer_adapter(const input_buffer_adapter&) = delete;
    input_buffer_adapter& operator=(input_buffer_adapter&) = delete;

    std::char_traits<char>::int_type get_character() noexcept override
    {
        if (JSON_LIKELY(cursor < limit))
        {
            return std::char_traits<char>::to_int_type(*(cursor++));
        }

        return std::char_traits<char>::eof();
    }

    void unget_character() noexcept override
    {
        if (JSON_LIKELY(cursor > start))
        {
            --cursor;
        }
    }

  private:
    /// pointer to the current character
    const char* cursor;
    /// pointer past the last character
    const char* limit;
    /// pointer to the first character
    const char* start;
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
        // assertion to check that the iterator range is indeed contiguous,
        // see http://stackoverflow.com/a/35008842/266378 for more discussion
        assert(std::accumulate(
                   first, last, std::pair<bool, int>(true, 0),
                   [&first](std::pair<bool, int> res, decltype(*first) val)
        {
            res.first &= (val == *(std::next(std::addressof(*first), res.second++)));
            return res;
        }).first);

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
}
}
