#pragma once

#include <cstdint>
#include <initializer_list>
#include <vector>

// A minimal, self-contained BinaryType built around a private std::vector.
// See https://json.nlohmann.me/features/types/template_parameters/#binarytype
class custom_binary_type
{
    using vector_t = std::vector<std::uint8_t>;
    vector_t data_;

  public:
    using value_type = vector_t::value_type;
    using size_type = vector_t::size_type;
    using iterator = vector_t::iterator;
    using const_iterator = vector_t::const_iterator;

    custom_binary_type() = default;
    custom_binary_type(const custom_binary_type&) = default;
    custom_binary_type(custom_binary_type&&) = default;
    custom_binary_type& operator=(const custom_binary_type&) = default;
    custom_binary_type& operator=(custom_binary_type&&) = default;

    template<class InputIt>
    custom_binary_type(InputIt first, InputIt last) : data_(first, last) {}

    // so basic_json::binary({0x01, 0x02}) can build one directly
    custom_binary_type(std::initializer_list<std::uint8_t> init) : data_(init) {}

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

    // read-only is enough: the writers only ever read from a binary value
    const std::uint8_t* data() const
    {
        return data_.data();
    }

    std::uint8_t& operator[](size_type pos)
    {
        return data_[pos];
    }
    std::uint8_t operator[](size_type pos) const
    {
        return data_[pos];
    }

    std::uint8_t& back()
    {
        return data_.back();
    }
    std::uint8_t back() const
    {
        return data_.back();
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
    const_iterator cbegin() const
    {
        return data_.cbegin();
    }
    const_iterator cend() const
    {
        return data_.cend();
    }

    template<class InputIt>
    iterator insert(const_iterator pos, InputIt first, InputIt last)
    {
        return data_.insert(pos, first, last);
    }

    friend bool operator==(const custom_binary_type& lhs, const custom_binary_type& rhs)
    {
        return lhs.data_ == rhs.data_;
    }
    friend bool operator<(const custom_binary_type& lhs, const custom_binary_type& rhs)
    {
        return lhs.data_ < rhs.data_;
    }
};
