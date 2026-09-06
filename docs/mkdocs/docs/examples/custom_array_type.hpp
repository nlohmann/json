#pragma once

#include <memory>
#include <utility>
#include <vector>

// A minimal, self-contained ArrayType built around a private std::vector.
// See https://json.nlohmann.me/features/types/template_parameters/#arraytype
template<class T, class Allocator = std::allocator<T>>
class custom_array_type
{
    using vector_t = std::vector<T, Allocator>;
    vector_t data_;

  public:
    using value_type = typename vector_t::value_type;
    using size_type = typename vector_t::size_type;
    using iterator = typename vector_t::iterator;
    using const_iterator = typename vector_t::const_iterator;

    custom_array_type() = default;
    custom_array_type(const custom_array_type&) = default;
    custom_array_type(custom_array_type&&) = default;
    custom_array_type& operator=(const custom_array_type&) = default;
    custom_array_type& operator=(custom_array_type&&) = default;

    template<class InputIt>
    custom_array_type(InputIt first, InputIt last) : data_(first, last) {}

    custom_array_type(size_type count, const T& value) : data_(count, value) {}

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

    bool empty() const
    {
        return data_.empty();
    }
    size_type size() const
    {
        return data_.size();
    }
    size_type max_size() const
    {
        return data_.max_size();
    }
    void clear()
    {
        data_.clear();
    }
    void resize(size_type n)
    {
        data_.resize(n);
    }

    T& operator[](size_type pos)
    {
        return data_[pos];
    }
    const T& operator[](size_type pos) const
    {
        return data_[pos];
    }

    T& back()
    {
        return data_.back();
    }
    const T& back() const
    {
        return data_.back();
    }

    void push_back(const T& value)
    {
        data_.push_back(value);
    }
    void push_back(T&& value)
    {
        data_.push_back(std::move(value));
    }

    template<class... Args>
    void emplace_back(Args&& ... args)
    {
        data_.emplace_back(std::forward<Args>(args)...);
    }

    void pop_back()
    {
        data_.pop_back();
    }

    iterator insert(const_iterator pos, const T& value)
    {
        return data_.insert(pos, value);
    }
    iterator insert(const_iterator pos, size_type count, const T& value)
    {
        return data_.insert(pos, count, value);
    }
    template<class InputIt>
    iterator insert(const_iterator pos, InputIt first, InputIt last)
    {
        return data_.insert(pos, first, last);
    }

    iterator erase(const_iterator pos)
    {
        return data_.erase(pos);
    }
    iterator erase(const_iterator first, const_iterator last)
    {
        return data_.erase(first, last);
    }

    void swap(custom_array_type& other)
    {
        data_.swap(other.data_);
    }

    friend bool operator==(const custom_array_type& lhs, const custom_array_type& rhs)
    {
        return lhs.data_ == rhs.data_;
    }
    friend bool operator<(const custom_array_type& lhs, const custom_array_type& rhs)
    {
        return lhs.data_ < rhs.data_;
    }
};
