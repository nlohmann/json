#pragma once

#include <functional> // less
#include <initializer_list> // initializer_list
#include <iterator> // input_iterator_tag, iterator_traits
#include <memory> // allocator
#include <stdexcept> // for out_of_range
#include <type_traits> // enable_if, is_convertible
#include <utility> // pair
#include <vector> // vector

#include <nlohmann/detail/macro_scope.hpp>

namespace nlohmann
{

/// ordered_map: a minimal map-like container that preserves insertion order
/// for use within nlohmann::basic_json<ordered_map>
template <class Key, class T, class IgnoredLess = std::less<Key>,
          class Allocator = std::allocator<std::pair<const Key, T>>>
                  struct ordered_map : std::vector<std::pair<const Key, T>, Allocator>
{
    using key_type = Key;
    using mapped_type = T;
    using Container = std::vector<std::pair<const Key, T>, Allocator>;
    using typename Container::iterator;
    using typename Container::const_iterator;
    using typename Container::size_type;
    using typename Container::value_type;

    // Explicit constructors instead of `using Container::Container`
    // otherwise older compilers choke on it (GCC <= 5.5, xcode <= 9.4)
    ordered_map(const Allocator& alloc = Allocator()) : Container{alloc} {}
    template <class It>
    ordered_map(It first, It last, const Allocator& alloc = Allocator())
        : Container{first, last, alloc} {}
    ordered_map(std::initializer_list<T> init, const Allocator& alloc = Allocator() )
        : Container{init, alloc} {}

    std::pair<iterator, bool> emplace(const key_type& key, T&& t)
    {
        for (auto it = this->begin(); it != this->end(); ++it)
        {
            if (it->first == key)
            {
                return {it, false};
            }
        }
        Container::emplace_back(key, t);
        return {--this->end(), true};
    }

    T& operator[](const Key& key)
    {
        return emplace(key, T{}).first->second;
    }

    const T& operator[](const Key& key) const
    {
        return at(key);
    }

    T& at(const Key& key)
    {
        for (auto it = this->begin(); it != this->end(); ++it)
        {
            if (it->first == key)
            {
                return it->second;
            }
        }

        JSON_THROW(std::out_of_range("key not found"));
    }

    const T& at(const Key& key) const
    {
        for (auto it = this->begin(); it != this->end(); ++it)
        {
            if (it->first == key)
            {
                return it->second;
            }
        }

        JSON_THROW(std::out_of_range("key not found"));
    }

    size_type erase(const Key& key)
    {
        for (auto it = this->begin(); it != this->end(); ++it)
        {
            if (it->first == key)
            {
                // Since we cannot move const Keys, re-construct them in place
                for (auto next = it; ++next != this->end(); ++it)
                {
                    it->~value_type(); // Destroy but keep allocation
                    new (&*it) value_type{std::move(*next)};
                }
                Container::pop_back();
                return 1;
            }
        }
        return 0;
    }

    iterator erase(iterator pos)
    {
        auto it = pos;

        // Since we cannot move const Keys, re-construct them in place
        for (auto next = it; ++next != this->end(); ++it)
        {
            it->~value_type(); // Destroy but keep allocation
            new (&*it) value_type{std::move(*next)};
        }
        Container::pop_back();
        return pos;
    }

    size_type count(const Key& key) const
    {
        for (auto it = this->begin(); it != this->end(); ++it)
        {
            if (it->first == key)
            {
                return 1;
            }
        }
        return 0;
    }

    iterator find(const Key& key)
    {
        for (auto it = this->begin(); it != this->end(); ++it)
        {
            if (it->first == key)
            {
                return it;
            }
        }
        return Container::end();
    }

    const_iterator find(const Key& key) const
    {
        for (auto it = this->begin(); it != this->end(); ++it)
        {
            if (it->first == key)
            {
                return it;
            }
        }
        return Container::end();
    }

    std::pair<iterator, bool> insert( value_type&& value )
    {
        return emplace(value.first, std::move(value.second));
    }

    std::pair<iterator, bool> insert( const value_type& value )
    {
        for (auto it = this->begin(); it != this->end(); ++it)
        {
            if (it->first == value.first)
            {
                return {it, false};
            }
        }
        Container::push_back(value);
        return {--this->end(), true};
    }

    template<typename InputIt>
    using require_input_iter = typename std::enable_if<std::is_convertible<typename std::iterator_traits<InputIt>::iterator_category,
            std::input_iterator_tag>::value>::type;

    template<typename InputIt, typename = require_input_iter<InputIt>>
    void insert(InputIt first, InputIt last)
    {
        for (auto it = first; it != last; ++it)
        {
            insert(*it);
        }
    }
};

}  // namespace nlohmann
