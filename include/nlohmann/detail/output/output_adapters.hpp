#pragma once

#include <algorithm> // copy
#include <cstddef> // size_t
#include <ios> // streamsize
#include <iterator> // back_inserter
#include <memory> // shared_ptr, make_shared
#include <ostream> // basic_ostream
#include <string> // basic_string
#include <vector> // vector
#include <nlohmann/detail/macro_scope.hpp>

namespace nlohmann
{
namespace detail
{


template<typename T>
struct output_adapter_impl;

// Output to a string, append() is faster than insert(str.end(),...) on some compilers,
// so it's worth having a special override for it.
template<typename StringType>
struct string_output_adapter
{
    using char_type = typename StringType::value_type;

    string_output_adapter(StringType& dst) : dst_(dst) {}

    void write_character(char_type c)
    {
        dst_.push_back(c);
    }

    void write_characters(const char_type* str, std::size_t len)
    {
        dst_.append(str, len);
    }

  private:
    StringType& dst_;
};

// Output to an iterator-like object
template<class IteratorType>
struct iterator_output_adapter
{
    using char_type = char; //?????????????????????????

    iterator_output_adapter(IteratorType dst) : dst_(dst) {}

    void write_character(char_type c)
    {
        *dst_++ = c;
    }

    void write_characters(const char_type* str, std::size_t len)
    {
        std::copy(str, str + len, dst_);
    }

  private:
    IteratorType dst_;
};

// Output to a stream-like object
template<class StreamType>
struct stream_output_adapter
{
    using char_type = typename StreamType::char_type;

    stream_output_adapter(StreamType& dst) : dst_(dst) {}

    void write_character(char_type c)
    {
        dst_.put(c);
    }

    void write_characters(const char_type* str, std::size_t len)
    {
        dst_.write(str, len);
    }

  private:
    StreamType& dst_;
};

template<typename T, typename = void>
struct is_output_iterator : public std::false_type {};

template<typename T>
struct is_output_iterator<T,
           typename std::enable_if<
           std::is_same<
           typename std::iterator_traits<T>::iterator_category,
           std::output_iterator_tag>::value
           >::type> : public std::true_type {};

template <typename T>
constexpr auto has_push_back (int)
-> decltype( std::declval<T>().push_back('a'),
             std::true_type() );

template <typename>
constexpr std::false_type has_push_back (long);

// If the parameter is a basic_string
template<typename CharT, typename Traits, typename Allocator>
string_output_adapter<std::basic_string<CharT, Traits, Allocator>> output_adapter(std::basic_string<CharT, Traits, Allocator>& dst)
{
    return string_output_adapter<std::basic_string<CharT, Traits, Allocator>>(dst);
}

// If the parameter is an output iterator
template<typename IteratorType,
         typename std::enable_if<
             is_output_iterator<IteratorType>::value,
             int>::type = 0>
auto output_adapter(IteratorType dst) -> iterator_output_adapter<IteratorType>
{
    return iterator_output_adapter<IteratorType>(std::move(dst));
}

// Try to extract an output iterator from the parameter
template<typename ContainerType,
         typename std::enable_if<
             decltype(has_push_back<ContainerType>(0))::value,
             int>::type = 0>
auto output_adapter(ContainerType& dst) -> decltype(output_adapter(std::back_inserter(dst)))
{
    return output_adapter(std::back_inserter(dst));
}


// If all else fails, treat it as a stream
template<typename StreamType, typename std::enable_if<
             not is_output_iterator<StreamType>::value and
             not decltype(has_push_back<StreamType>(0))::value,
             int>::type = 0>
stream_output_adapter<StreamType> output_adapter(StreamType& dst)
{
    return stream_output_adapter<StreamType>(dst);
}

}  // namespace detail
}  // namespace nlohmann
