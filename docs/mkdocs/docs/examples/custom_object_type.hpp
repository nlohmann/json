#pragma once

#include <map>
#include <utility>

// A minimal, self-contained ObjectType built around a private std::map.
// key_compare is deliberately not exposed: when an ObjectType has no
// key_compare member, the library falls back to its own default comparator.
// See https://json.nlohmann.me/features/types/template_parameters/#objecttype
template<class Key, class T, class Compare, class Allocator>
class custom_object_type
{
    using map_t = std::map<Key, T, Compare, Allocator>;
    map_t data_;

  public:
    using key_type = typename map_t::key_type;
    using mapped_type = typename map_t::mapped_type;
    using value_type = typename map_t::value_type;
    using size_type = typename map_t::size_type;
    using iterator = typename map_t::iterator;
    using const_iterator = typename map_t::const_iterator;

    custom_object_type() = default;
    custom_object_type(const custom_object_type&) = default;
    custom_object_type(custom_object_type&&) = default;
    custom_object_type& operator=(const custom_object_type&) = default;
    custom_object_type& operator=(custom_object_type&&) = default;

    template<class InputIt>
    custom_object_type(InputIt first, InputIt last) : data_(first, last) {}

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

    iterator find(const key_type& key)
    {
        return data_.find(key);
    }
    const_iterator find(const key_type& key) const
    {
        return data_.find(key);
    }
    size_type count(const key_type& key) const
    {
        return data_.count(key);
    }

    std::pair<iterator, bool> emplace(const key_type& key, const mapped_type& value)
    {
        return data_.emplace(key, value);
    }

    std::pair<iterator, bool> insert(const value_type& value)
    {
        return data_.insert(value);
    }

    template<class InputIt>
    void insert(InputIt first, InputIt last)
    {
        data_.insert(first, last);
    }

    mapped_type& operator[](const key_type& key)
    {
        return data_[key];
    }

    mapped_type& at(const key_type& key)
    {
        return data_.at(key);
    }
    const mapped_type& at(const key_type& key) const
    {
        return data_.at(key);
    }

    iterator erase(iterator pos)
    {
        return data_.erase(pos);
    }
    iterator erase(iterator first, iterator last)
    {
        return data_.erase(first, last);
    }
    size_type erase(const key_type& key)
    {
        return data_.erase(key);
    }

    void swap(custom_object_type& other)
    {
        data_.swap(other.data_);
    }

    friend bool operator==(const custom_object_type& lhs, const custom_object_type& rhs)
    {
        return lhs.data_ == rhs.data_;
    }
    friend bool operator<(const custom_object_type& lhs, const custom_object_type& rhs)
    {
        return lhs.data_ < rhs.data_;
    }
};
