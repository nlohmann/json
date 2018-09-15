#pragma once

#include <algorithm> // copy
#include <cstddef> // size_t
#include <ios> // streamsize
#include <iterator> // back_inserter
#include <memory> // shared_ptr, make_shared
#include <ostream> // basic_ostream
#include <string> // basic_string
#include <vector> // vector

namespace nlohmann
{
namespace detail
{
/// abstract output adapter interface
template<typename CharType> struct output_adapter_protocol
{
    virtual void write_character(CharType c) = 0;
    virtual void write_characters(const CharType* s, std::size_t length) = 0;
    virtual void write_characters_at(std::size_t position, const CharType* s, std::size_t length) = 0;
    virtual std::size_t reserve_characters(std::size_t length) = 0;
    virtual ~output_adapter_protocol() = default;
};

/// a type to simplify interfaces
template<typename CharType>
using output_adapter_t = std::shared_ptr<output_adapter_protocol<CharType>>;

/// output adapter for byte vectors
template<typename CharType>
class output_vector_adapter : public output_adapter_protocol<CharType>
{
  public:
    explicit output_vector_adapter(std::vector<CharType>& vec) : v(vec) {}

    void write_character(CharType c) override
    {
        v.push_back(c);
    }

    void write_characters(const CharType* s, std::size_t length) override
    {
        std::copy(s, s + length, std::back_inserter(v));
    }

    void write_characters_at(std::size_t position, const CharType* s, std::size_t length) override
    {
        std::copy(s, s + length, std::begin(v) + position);
    }

    std::size_t reserve_characters(std::size_t length) override
    {
        const auto position = v.size();
        std::fill_n(std::back_inserter(v), length, static_cast<CharType>(0x00));
        return position;
    }

  private:
    std::vector<CharType>& v;
};

/// output adapter for output streams
template<typename CharType>
class output_stream_adapter : public output_adapter_protocol<CharType>
{
  public:
    explicit output_stream_adapter(std::basic_ostream<CharType>& s) : stream(s) {}

    void write_character(CharType c) override
    {
        stream.put(c);
    }

    void write_characters(const CharType* s, std::size_t length) override
    {
        stream.write(s, static_cast<std::streamsize>(length));
    }

    void write_characters_at(std::size_t position, const CharType* s, std::size_t length) override
    {
        const auto orig_offset = stream.tellp();
        stream.seekp(static_cast<typename std::basic_ostream<CharType>::pos_type>(position));
        stream.write(s, static_cast<std::streamsize>(length));
        stream.seekp(orig_offset);
    }

    std::size_t reserve_characters(std::size_t length) override
    {
        const auto position = stream.tellp();
        std::vector<CharType> empty(length, static_cast<CharType>(0));
        stream.write(empty.data(), length);
        return static_cast<std::size_t>(position);
    }

  private:
    std::basic_ostream<CharType>& stream;
};

/// output adapter for basic_string
template<typename CharType, typename StringType = std::basic_string<CharType>>
class output_string_adapter : public output_adapter_protocol<CharType>
{
  public:
    explicit output_string_adapter(StringType& s) : str(s) {}

    void write_character(CharType c) override
    {
        str.push_back(c);
    }

    void write_characters(const CharType* s, std::size_t length) override
    {
        str.append(s, length);
    }

    void write_characters_at(std::size_t position, const CharType* s, std::size_t length) override
    {
        std::copy(s, s + length, std::begin(str) + position);
    }

    std::size_t reserve_characters(std::size_t length) override
    {
        const auto position = str.size();
        std::fill_n(std::back_inserter(str), length, static_cast<CharType>(0x00));
        return position;
    }


  private:
    StringType& str;
};

template<typename CharType, typename StringType = std::basic_string<CharType>>
class output_adapter
{
  public:
    output_adapter(std::vector<CharType>& vec)
        : oa(std::make_shared<output_vector_adapter<CharType>>(vec)) {}

    output_adapter(std::basic_ostream<CharType>& s)
        : oa(std::make_shared<output_stream_adapter<CharType>>(s)) {}

    output_adapter(StringType& s)
        : oa(std::make_shared<output_string_adapter<CharType, StringType>>(s)) {}

    operator output_adapter_t<CharType>()
    {
        return oa;
    }

  private:
    output_adapter_t<CharType> oa = nullptr;
};
}
}
