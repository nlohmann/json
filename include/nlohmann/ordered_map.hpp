//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // max, min
#include <functional> // equal_to, less
#include <initializer_list> // initializer_list
#include <iterator> // input_iterator_tag, iterator_traits
#include <memory> // allocator // IWYU pragma: keep
#include <new> // for operator new (placement new)
#include <stdexcept> // for out_of_range
#include <tuple> // forward_as_tuple
#include <type_traits> // enable_if, integral_constant, is_convertible, is_nothrow_move_constructible
#include <utility> // forward, move, pair, piecewise_construct
#include <vector> // vector

#include <nlohmann/detail/abi_macros.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN

/// ordered_map: a minimal map-like container that preserves insertion order
/// for use within nlohmann::basic_json<ordered_map>
template <class Key, class T, class IgnoredLess = std::less<Key>,
          class Allocator = std::allocator<std::pair<const Key, T>>>
              struct ordered_map : std::vector<std::pair<const Key, T>, Allocator>
{
    using key_type = Key;
    using mapped_type = T;
    using Container = std::vector<std::pair<const Key, T>, Allocator>;
    using iterator = typename Container::iterator;
    using const_iterator = typename Container::const_iterator;
    using size_type = typename Container::size_type;
    using value_type = typename Container::value_type;
#ifdef JSON_HAS_CPP_14
    using key_compare = std::equal_to<>;
#else
    using key_compare = std::equal_to<Key>;
#endif

    // Explicit constructors instead of `using Container::Container`
    // otherwise older compilers choke on it (GCC <= 5.5, xcode <= 9.4)
    ordered_map() noexcept(noexcept(Container())) : Container{} {}
    explicit ordered_map(const Allocator& alloc) noexcept(noexcept(Container(alloc))) : Container{alloc} {}
    template <class It>
    ordered_map(It first, It last, const Allocator& alloc = Allocator())
        : Container{first, last, alloc} {}
    ordered_map(std::initializer_list<value_type> init, const Allocator& alloc = Allocator() )
        : Container{init, alloc} {}
    ordered_map(const ordered_map&) = default;
    ordered_map(ordered_map&&) noexcept(std::is_nothrow_move_constructible<Container>::value) = default;
    ~ordered_map() = default;

    ordered_map& operator=(const ordered_map& other)
    {
        if (this != &other)
        {
            ordered_map tmp(other);
            Container::operator=(std::move(static_cast<Container&>(tmp)));
        }
        return *this;
    }

    ordered_map& operator=(ordered_map&& other) noexcept(std::is_nothrow_move_assignable<Container>::value)
    {
        Container::operator=(std::move(static_cast<Container&>(other)));
        return *this;
    }

private:
    /// @brief find the entry for @a key, for either constness of @a self
    /// @note the single place that performs the linear key search
    template<typename Self, typename KeyType>
    static auto find_impl(Self& self, const KeyType& key) -> decltype(self.begin())
    {
        for (auto it = self.begin(); it != self.end(); ++it)
        {
            if (self.m_compare(it->first, key))
            {
                return it;
            }
        }
        return self.end();
    }

    /// @brief remove the entry @a it points to, preserving order
    /// @note keys are not movable, so the tail is destroyed and re-constructed in place
    void erase_at(iterator it)
    {
        for (auto next = it; ++next != this->end(); ++it)
        {
            it->~value_type(); // Destroy but keep allocation
            new (&*it) value_type{std::move(*next)};
        }
        Container::pop_back();
    }

public:
    template<class V, detail::enable_if_t<
                 detail::is_constructible<T, V>::value, int> = 0>
    std::pair<iterator, bool> emplace(const key_type& key, V && t)
    {
        const auto it = find_impl(*this, key);
        if (it != this->end())
        {
            return {it, false};
        }
        append(key, std::forward<V>(t));
        return {std::prev(this->end()), true};
    }

    template<class KeyType, class V, detail::enable_if_t<
                 detail::conjunction<detail::is_usable_as_key_type<key_compare, key_type, KeyType>,
                                     detail::is_constructible<T, V>>::value, int> = 0>
    std::pair<iterator, bool> emplace(KeyType && key, V && t)
    {
        const auto it = find_impl(*this, key);
        if (it != this->end())
        {
            return {it, false};
        }
        append(std::forward<KeyType>(key), std::forward<V>(t));
        return {std::prev(this->end()), true};
    }

    T& operator[](const key_type& key)
    {
        return emplace(key, T{}).first->second;
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    T & operator[](KeyType && key)
    {
        return emplace(std::forward<KeyType>(key), T{}).first->second;
    }

    const T& operator[](const key_type& key) const
    {
        return at(key);
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    const T & operator[](KeyType && key) const
    {
        return at(std::forward<KeyType>(key));
    }

    T& at(const key_type& key)
    {
        const auto it = find_impl(*this, key);
        if (it == this->end())
        {
            JSON_THROW(std::out_of_range("key not found"));
        }
        return it->second;
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    T & at(KeyType && key) // NOLINT(cppcoreguidelines-missing-std-forward)
    {
        const auto it = find_impl(*this, key);
        if (it == this->end())
        {
            JSON_THROW(std::out_of_range("key not found"));
        }
        return it->second;
    }

    const T& at(const key_type& key) const
    {
        const auto it = find_impl(*this, key);
        if (it == this->end())
        {
            JSON_THROW(std::out_of_range("key not found"));
        }
        return it->second;
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    const T & at(KeyType && key) const // NOLINT(cppcoreguidelines-missing-std-forward)
    {
        const auto it = find_impl(*this, key);
        if (it == this->end())
        {
            JSON_THROW(std::out_of_range("key not found"));
        }
        return it->second;
    }

    size_type erase(const key_type& key)
    {
        const auto it = find_impl(*this, key);
        if (it != this->end())
        {
            erase_at(it);
            return 1;
        }
        return 0;
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    size_type erase(KeyType && key) // NOLINT(cppcoreguidelines-missing-std-forward)
    {
        const auto it = find_impl(*this, key);
        if (it != this->end())
        {
            erase_at(it);
            return 1;
        }
        return 0;
    }

    iterator erase(iterator pos)
    {
        return erase(pos, std::next(pos));
    }

    iterator erase(iterator first, iterator last)
    {
        if (first == last)
        {
            return first;
        }

        const auto elements_affected = std::distance(first, last);
        const auto offset = std::distance(Container::begin(), first);

        // This is the start situation. We need to delete elements_affected
        // elements (3 in this example: e, f, g), and need to return an
        // iterator past the last deleted element (h in this example).
        // Note that offset is the distance from the start of the vector
        // to first. We will need this later.

        // [ a, b, c, d, e, f, g, h, i, j ]
        //               ^        ^
        //             first    last

        // Since we cannot move const Keys, we re-construct them in place.
        // We start at first and re-construct (viz. copy) the elements from
        // the back of the vector. Example for the first iteration:

        //               ,--------.
        //               v        |   destroy e and re-construct with h
        // [ a, b, c, d, e, f, g, h, i, j ]
        //               ^        ^
        //               it       it + elements_affected

        for (auto it = first; std::next(it, elements_affected) != Container::end(); ++it)
        {
            // false positive: Infer's model of std::string keeps the buffer of a
            // moved-from string, so it assumes a buffer is destroyed twice
            // @infer-ignore USE_AFTER_DELETE
            it->~value_type(); // destroy but keep allocation
            new (&*it) value_type{std::move(*std::next(it, elements_affected))}; // "move" next element to it
        }

        // [ a, b, c, d, h, i, j, h, i, j ]
        //               ^        ^
        //             first    last

        // remove the unneeded elements at the end of the vector
        Container::resize(this->size() - static_cast<size_type>(elements_affected));

        // [ a, b, c, d, h, i, j ]
        //               ^        ^
        //             first    last

        // first is now pointing past the last deleted element, but we cannot
        // use this iterator, because it may have been invalidated by the
        // resize call. Instead, we can return begin() + offset.
        return Container::begin() + offset;
    }

    size_type count(const key_type& key) const
    {
        return find_impl(*this, key) != this->end() ? 1 : 0;
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    size_type count(KeyType && key) const // NOLINT(cppcoreguidelines-missing-std-forward)
    {
        return find_impl(*this, key) != this->end() ? 1 : 0;
    }

    iterator find(const key_type& key)
    {
        return find_impl(*this, key);
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    iterator find(KeyType && key) // NOLINT(cppcoreguidelines-missing-std-forward)
    {
        return find_impl(*this, key);
    }

    const_iterator find(const key_type& key) const
    {
        return find_impl(*this, key);
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    const_iterator find(KeyType && key) const // NOLINT(cppcoreguidelines-missing-std-forward)
    {
        return find_impl(*this, key);
    }

    std::pair<iterator, bool> insert( value_type&& value )
    {
        return emplace(value.first, std::move(value.second));
    }

    std::pair<iterator, bool> insert( const value_type& value )
    {
        const auto it = find_impl(*this, value.first);
        if (it != this->end())
        {
            return {it, false};
        }
        append(value);
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

private:
    /*!
    @brief add an element whose key is not yet contained at the end

    A std::vector copies all elements when it grows, because their const keys
    make them not nothrow move constructible. For ordered_json, this is a deep
    copy of every value. Where the strong exception guarantee can be kept, grow
    the storage here instead, copying only the keys and moving the values.
    */
    template<typename... Args>
    void append(Args&& ... args)
    {
        // evaluated here rather than at class scope, because T is still
        // incomplete when basic_json instantiates its object_t
        using move_values = std::integral_constant<bool, detail::conjunction<
                detail::negation<std::is_nothrow_move_constructible<value_type>>,
                std::is_copy_constructible<key_type>,
                detail::is_default_constructible<mapped_type>,
                std::is_nothrow_move_assignable<mapped_type>>::value>;
        append_impl(move_values{}, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void append_impl(std::true_type /*unused*/, Args&& ... args)
    {
        if (this->size() < this->capacity())
        {
            Container::emplace_back(std::forward<Args>(args)...);
            return;
        }

        // 1. May throw, but only changes tmp: copy the keys, value-initialize
        //    the values, and add the new element. The arguments may refer to
        //    elements of this container, so they are used before any value is
        //    moved out of it.
        Container tmp(this->get_allocator()); // equal allocators, so swap() is valid
        tmp.reserve((std::min)(this->max_size(), (std::max)(size_type{1}, 2 * this->size())));
        for (const auto& element : *this)
        {
            tmp.emplace_back(std::piecewise_construct, std::forward_as_tuple(element.first), std::forward_as_tuple());
        }
        tmp.emplace_back(std::forward<Args>(args)...);

        // 2. Cannot throw: move the values over and adopt the new storage.
        auto it = tmp.begin();
        for (auto& element : *this)
        {
            it->second = std::move(element.second);
            ++it;
        }
        Container::swap(tmp);
    }

    template<typename... Args>
    void append_impl(std::false_type /*unused*/, Args&& ... args)
    {
        Container::emplace_back(std::forward<Args>(args)...);
    }

    JSON_NO_UNIQUE_ADDRESS key_compare m_compare = key_compare();
};

NLOHMANN_JSON_NAMESPACE_END
