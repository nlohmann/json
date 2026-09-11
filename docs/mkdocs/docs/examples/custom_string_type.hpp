#pragma once

#include <ostream>
#include <string>

// A minimal, self-contained StringType built around a private std::string.
// Wraps rather than inherits, so it exposes exactly what the library needs
// and nothing more of std::string's interface.
//
// Covers the "Always required" members, the extras needed for the binary
// formats, and the extras needed for JSON Pointer / flatten / unflatten /
// diff. Extending it further (e.g. for std::hash<basic_json> or to_bson) is
// a matter of adding the extra members listed in the "Required for other
// functionality" table.
//
// See https://json.nlohmann.me/features/types/template_parameters/#stringtype
class custom_string_type
{
    std::string data_;

  public:
    using value_type = char;
    using size_type = std::string::size_type;
    using iterator = std::string::iterator;
    using const_iterator = std::string::const_iterator;

    static constexpr size_type npos = std::string::npos;

    custom_string_type() = default;
    custom_string_type(const custom_string_type&) = default;
    custom_string_type(custom_string_type&&) = default;
    custom_string_type& operator=(const custom_string_type&) = default;
    custom_string_type& operator=(custom_string_type&&) = default;

    // not explicit: the library relies on being able to hand it a string literal
    custom_string_type(const char* s) : data_(s) {}
    custom_string_type(const char* s, size_type count) : data_(s, count) {}
    custom_string_type(size_type count, char ch) : data_(count, ch) {}

    size_type size() const
    {
        return data_.size();
    }
    bool empty() const
    {
        return data_.empty();
    }
    void clear()
    {
        data_.clear();
    }
    void resize(size_type n)
    {
        data_.resize(n);
    }
    void resize(size_type n, char c)
    {
        data_.resize(n, c);
    }
    void reserve(size_type n)
    {
        data_.reserve(n);
    }

    // must stay null-terminated -- the parser hands this to std::strtoull &
    // friends; std::string::data() has guaranteed that since C++11
    const char* data() const
    {
        return data_.data();
    }

    void push_back(char c)
    {
        data_.push_back(c);
    }

    char& operator[](size_type pos)
    {
        return data_[pos];
    }
    char operator[](size_type pos) const
    {
        return data_[pos];
    }

    custom_string_type& append(const char* s, size_type count)
    {
        data_.append(s, count);
        return *this;
    }
    custom_string_type& append(const custom_string_type& other)
    {
        data_.append(other.data_);
        return *this;
    }

    size_type find_first_of(char c, size_type pos = 0) const
    {
        return data_.find_first_of(c, pos);
    }

    iterator begin()
    {
        return data_.begin();
    }
    iterator end()
    {
        return data_.end();
    }
    const_iterator begin() const
    {
        return data_.begin();
    }
    const_iterator end() const
    {
        return data_.end();
    }

    friend bool operator==(const custom_string_type& lhs, const custom_string_type& rhs)
    {
        return lhs.data_ == rhs.data_;
    }
    friend bool operator<(const custom_string_type& lhs, const custom_string_type& rhs)
    {
        return lhs.data_ < rhs.data_;
    }

    // not required by the library itself, but dump() returns a custom_string_type
    // and this makes `std::cout << j.dump()` work as expected
    friend std::ostream& operator<<(std::ostream& os, const custom_string_type& s)
    {
        return os << s.data_;
    }
};
