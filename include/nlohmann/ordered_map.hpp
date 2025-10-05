//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm>
#include <functional>
#include <initializer_list>
#include <iterator>
#include <list>
#include <memory>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
/*!
@brief Insertion-order-preserving map with O(1) average lookup

Internally uses a std::list to contain the <key,value> pairs, plus
an index (effectively keyed by a pointer-to-key) for O(1) lookups.

This implements all the methods of std::map except:
- Ordering-dependent operations (lower_bound, upper_bound, equal_range,
  key_comp and value_comp, etc.); these simply make no sense without
  lexicographic ordering.
- Extensions added after C++11 (try_emplace, insert_or_assign, contains,
  erase_if, etc.).

It also has iterator arithmetic (it+n), which is not used by the library
but needed by some unit tests of the original implementation.

Stable iterators guarantee: insertion and value updates do not invalidate
iterators (except for the iterator to an element that is erased).

Size complexity is linear to the size of contained data; time complexity
is on average O(1) for all access methods and all methods that change a
single element, O(N) when N elements are affected.
*/
template<class Key,
         class T,
         class IgnoredCompare = std::less<Key>, // Unused
         class Allocator = std::allocator<std::pair<const Key, T>>>
             struct ordered_map
{
    private:
    using value_pair    = std::pair<const Key, T>;
    using list_type     = std::list<value_pair, Allocator>;
    using list_iterator = typename list_type::iterator;
    using list_const_iterator = typename list_type::const_iterator;

    // --- pointer-to-key index machinery ---
    struct key_ref
    {
        const Key* p;
        key_ref() : p(nullptr) {}
        explicit key_ref(const Key& k) : p(std::addressof(k)) {}
        explicit key_ref(const Key* pk) : p(pk) {}
    };
    struct key_ref_hash
    {
        std::size_t operator()(const key_ref& kr) const
        {
            return std::hash<Key> {}(*kr.p);
        }
    };
    struct key_ref_equal
    {
        bool operator()(const key_ref& a, const key_ref& b) const noexcept
        {
            return std::equal_to<Key> {}(*a.p, *b.p);
        }
    };

    using index_type = std::unordered_map<key_ref, list_iterator, key_ref_hash, key_ref_equal>;

    list_type  m_list;
    index_type m_index;

    // iterator wrapper that supports it+n for tests which do om.begin()+k
    template <typename ListIter, typename Self, typename Ref, typename Ptr>
    struct iter_base
    {
        using iterator_category = std::bidirectional_iterator_tag;
        using value_type        = value_pair;
        using difference_type   = typename list_type::difference_type;
        using reference         = Ref;
        using pointer           = Ptr;

    iter_base() : it_() {}
    explicit iter_base(ListIter it) : it_(it) {}

    reference operator*()  const
    {
        return *it_;
    }
    pointer   operator->() const
    {
        return std::addressof(*it_);
    }

    Self& operator++()
    {
        ++it_;
        return self();
    }
    Self  operator++(int)
    {
        Self tmp = self();
        ++(*this);
        return tmp;
    }
    Self& operator--()
    {
        --it_;
        return self();
    }
    Self  operator--(int)
    {
        Self tmp = self();
        --(*this);
        return tmp;
    }

    // This is O(n), but used only by unit tests
    Self operator+(difference_type n) const
    {
        Self tmp = self();
        if (n >= 0)    // NOLINT(*-braces-around-statements)
            while (n--)
            {
                ++tmp.it_;
            }
        else            // NOLINT(*-braces-around-statements)
            while (n++)
            {
                --tmp.it_;
            }
        return tmp;
    }
    Self& operator+=(difference_type n)
    {
        *this = *this + n;
        return self();
    }

    bool operator==(const Self& o) const
    {
        return it_ == o.it_;
    }
    bool operator!=(const Self& o) const
    {
        return it_ != o.it_;
    }

    ListIter base() const
    {
        return it_;
    }

    private:
    ListIter it_;
    Self& self()
    {
        return static_cast<Self&>(*this);
    }
    const Self& self() const
    {
        return static_cast<const Self&>(*this);
    }
    };

    // Strong-safety rebuild: build a temporary index, then swap.
    void rebuild_index()
    {
#ifndef JSON_NOEXCEPTION
        index_type tmp;
        tmp.reserve(m_index.size());
        for (list_iterator it = m_list.begin(); it != m_list.end(); ++it)
        {
            tmp.emplace(key_ref(std::addressof(it->first)), it);
        }
        m_index.swap(tmp);
#else
        m_index.clear();
        for (list_iterator it = m_list.begin(); it != m_list.end(); ++it)
        {
            m_index.emplace(key_ref(std::addressof(it->first)), it);
        }
#endif
    }

    // ---- C++11-safe helper: reserve index only when the iterator is at least forward ----
    template<typename It>
    static void reserve_index_for_range(index_type& idx, It first, It last)
    {
        using cat_t = typename std::iterator_traits<It>::iterator_category;
        reserve_index_for_range_impl(idx, first, last, cat_t{});
    }

    template<typename It>
    static void reserve_index_for_range_impl(index_type& idx, It first, It last, std::input_iterator_tag tag)
    {
        // single-pass; no pre-reserve possible
    }

    template<typename It>
    static void reserve_index_for_range_impl(index_type& idx, It first, It last, std::forward_iterator_tag tag)
    {
        (void)tag;
        using size_type2 = typename index_type::size_type;
        const auto add = static_cast<size_type2>(std::distance(first, last));
        idx.reserve(idx.size() + add);
    }

    // Also reserve for bidirectional iterators
    template<typename It>
    static void reserve_index_for_range_impl(index_type& idx, It first, It last, std::bidirectional_iterator_tag tag)
    {
        (void)tag;
        using size_type2 = typename index_type::size_type;
        const auto add = static_cast<size_type2>(std::distance(first, last));
        idx.reserve(idx.size() + add);
    }

    // And for random-access iterators
    template<typename It>
    static void reserve_index_for_range_impl(index_type& idx, It first, It last, std::random_access_iterator_tag tag)
    {
        (void) tag;
        using size_type2 = typename index_type::size_type;
        const auto add = static_cast<size_type2>(std::distance(first, last));
        idx.reserve(idx.size() + add);
    }

public:
    // types (match original)
    using key_type             = Key;
    using mapped_type          = T;
    using value_type           = value_pair;
    using allocator_type       = Allocator;
    using size_type            = typename list_type::size_type;
    using difference_type      = typename list_type::difference_type;
    using reference            = value_type&;
    using const_reference      = const value_type&;
    using pointer              = typename std::allocator_traits<Allocator>::pointer;
    using const_pointer        = typename std::allocator_traits<Allocator>::const_pointer;

#if defined(JSON_HAS_CPP_14)
    using key_compare          = std::equal_to<>;
#else
    using key_compare          = std::equal_to<Key>;
#endif

    // compatibility alias (original inherited std::vector<value_type>)
    using Container            = std::vector<value_type, Allocator>;

    struct iterator : iter_base<list_iterator, iterator, value_type&, value_type*>
    {
        iterator() : iter_base<list_iterator, iterator, value_type &, value_type*>() {}
        explicit iterator(list_iterator it) : iter_base<list_iterator, iterator, value_type &, value_type*>(it) {}
    };

    struct const_iterator : iter_base<list_const_iterator, const_iterator, const value_type&, const value_type*>
    {
        const_iterator() : iter_base<list_const_iterator, const_iterator, const value_type &, const value_type*>() {}
        explicit const_iterator(list_const_iterator it) : iter_base<list_const_iterator, const_iterator, const value_type &, const value_type*>(it) {}
        const_iterator(iterator it) : iter_base<list_const_iterator, const_iterator, const value_type &, const value_type*>(it.base()) {}
    };

    using reverse_iterator       = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    // constructors
    ordered_map() noexcept
        : m_list(), m_index() {}

    explicit ordered_map(const Allocator& alloc) noexcept
        : m_list(alloc), m_index() {}

    template<class InputIt>
    ordered_map(InputIt first, InputIt last, const Allocator& alloc = Allocator())
        : m_list(alloc), m_index()
    {
        insert(first, last);
    }

    ordered_map(std::initializer_list<value_type> init, const Allocator& alloc = Allocator())
        : m_list(alloc), m_index()
    {
        insert(init.begin(), init.end());
    }

    ordered_map(const ordered_map& other)
        : m_list(other.m_list), m_index()
    {
        rebuild_index();
    }

    ordered_map(ordered_map&& other) noexcept
        : m_list(std::move(other.m_list)), m_index()
    {
        rebuild_index();
    }

    ordered_map& operator=(const ordered_map& other)
    {
        if (this != &other)
        {
            list_type tmp(other.m_list);  // may throw; strong guarantee
            m_list.swap(tmp);
            rebuild_index();
        }
        return *this;
    }

    ordered_map& operator=(ordered_map&& other) noexcept
    {
        if (this != &other)
        {
            list_type tmp(std::move(other.m_list)); // noexcept move-construct
            m_list.swap(tmp);
            rebuild_index();
        }
        return *this;
    }

    ~ordered_map() noexcept = default;

    allocator_type get_allocator() const noexcept
    {
        return m_list.get_allocator();
    }

    // element access
    T& at(const Key& key)
    {
        auto it = m_index.find(key_ref(key));
        if (it == m_index.end())
        {
            JSON_THROW(std::out_of_range("key not found"));
        }
        return it->second->second;
    }

    const T& at(const Key& key) const
    {
        auto it = m_index.find(key_ref(key));
        if (it == m_index.end())
        {
            JSON_THROW(std::out_of_range("key not found"));
        }
        return it->second->second;
    }

    T& operator[](const Key& key)
    {
        auto it = m_index.find(key_ref(key));
        if (it != m_index.end())
        {
            return it->second->second;
        }
        m_list.emplace_back(key, T{});
        list_iterator lit = --m_list.end();

#ifndef JSON_NOEXCEPTION
        JSON_TRY
        {
            m_index.emplace(key_ref(std::addressof(lit->first)), lit);
        }
        JSON_CATCH(...)
        {
            m_list.pop_back();
            JSON_THROW(std::bad_alloc());
        }
#else
        m_index.emplace(key_ref(std::addressof(lit->first)), lit);
#endif
        return lit->second;
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    T & operator[](KeyType && key)
    {
        key_type k(std::forward<KeyType>(key));
        auto it = m_index.find(key_ref(k));
        if (it != m_index.end())
        {
            return it->second->second;
        }
        m_list.emplace_back(k, T{});
        list_iterator lit = --m_list.end();

#ifndef JSON_NOEXCEPTION
        JSON_TRY
        {
            m_index.emplace(key_ref(std::addressof(lit->first)), lit);
        }
        JSON_CATCH(...)
        {
            m_list.pop_back();
            JSON_THROW(std::bad_alloc());
        }
#else
        m_index.emplace(key_ref(std::addressof(lit->first)), lit);
#endif
        return lit->second;
    }

    const T& operator[](const key_type& key) const
    {
        return at(key);
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    const T & operator[](KeyType && key) const
    {
        return at(key_type(std::forward<KeyType>(key)));
    }

    // iterators
    iterator       begin()        noexcept
    {
        return iterator(m_list.begin());
    }
    iterator       end()          noexcept
    {
        return iterator(m_list.end());
    }
    const_iterator begin()  const noexcept
    {
        return const_iterator(m_list.begin());
    }
    const_iterator end()    const noexcept
    {
        return const_iterator(m_list.end());
    }
    const_iterator cbegin() const noexcept
    {
        return const_iterator(m_list.begin());
    }
    const_iterator cend()   const noexcept
    {
        return const_iterator(m_list.end());
    }

    reverse_iterator       rbegin()        noexcept
    {
        return reverse_iterator(end());
    }
    reverse_iterator       rend()          noexcept
    {
        return reverse_iterator(begin());
    }
    const_reverse_iterator rbegin()  const noexcept
    {
        return const_reverse_iterator(end());
    }
    const_reverse_iterator rend()    const noexcept
    {
        return const_reverse_iterator(begin());
    }
    const_reverse_iterator crbegin() const noexcept
    {
        return const_reverse_iterator(cend());
    }
    const_reverse_iterator crend()   const noexcept
    {
        return const_reverse_iterator(cbegin());
    }

    // capacity
    bool empty() const noexcept
    {
        return m_list.empty();
    }
    size_type size() const noexcept
    {
        return m_index.size();
    }
    size_type max_size() const noexcept
    {
        return m_list.max_size();
    }

    // modifiers
    void clear() noexcept
    {
        m_list.clear();
        m_index.clear();
    }

    std::pair<iterator, bool> insert(const value_type& value)
    {
        auto it = m_index.find(key_ref(value.first));
        if (it != m_index.end())
        {
            return std::make_pair(iterator(it->second), false);
        }
        m_list.push_back(value);
        list_iterator lit = --m_list.end();

#ifndef JSON_NOEXCEPTION
        JSON_TRY
        {
            m_index.emplace(key_ref(std::addressof(lit->first)), lit);
        }
        JSON_CATCH(...)
        {
            m_list.pop_back();
            JSON_THROW(std::bad_alloc());
        }
#else
        m_index.emplace(key_ref(std::addressof(lit->first)), lit);
#endif
        return std::make_pair(iterator(lit), true);
    }

    std::pair<iterator, bool> insert(value_type&& value)
    {
        auto it = m_index.find(key_ref(value.first));
        if (it != m_index.end())
        {
            return std::make_pair(iterator(it->second), false);
        }
        m_list.push_back(std::move(value));
        list_iterator lit = --m_list.end();

#ifndef JSON_NOEXCEPTION
        JSON_TRY
        {
            m_index.emplace(key_ref(std::addressof(lit->first)), lit);
        }
        JSON_CATCH(...)
        {
            m_list.pop_back();
            JSON_THROW(std::bad_alloc());
        }
#else
        m_index.emplace(key_ref(std::addressof(lit->first)), lit);
#endif
        return std::make_pair(iterator(lit), true);
    }

    // hint overloads (the hint is ignored)
    iterator insert(const_iterator /*hint*/, const value_type& value)
    {
        return insert(value).first;
    }
    iterator insert(const_iterator /*hint*/, value_type&& value)
    {
        return insert(std::move(value)).first;
    }

    // keep SFINAE’d range-insert like the original
    template<typename InputIt>
    using require_input_iter = typename std::enable_if <
        std::is_base_of<std::input_iterator_tag,
                        typename std::iterator_traits<InputIt>::iterator_category>::value
        // ReSharper disable once CppUseTypeTraitAlias
        >::type;

    template<typename InputIt, typename = require_input_iter<InputIt>>
    void insert(InputIt first, InputIt last)
    {
        // Optional micro-optimization: reserve only when the iterator is at least forward
        reserve_index_for_range(m_index, first, last);

        for (; first != last; ++first)
        {
            insert(*first);
        }
    }

    // vector-compat helpers (used by tests)
    void push_back(const value_type& v)
    {
        (void)insert(v);
    }
    void push_back(value_type&& v)
    {
        (void)insert(std::move(v));
    }

    // emplace
    std::pair<iterator, bool> emplace(const key_type& key, T&& t)
    {
        auto it = m_index.find(key_ref(key));
        if (it != m_index.end())
        {
            return std::make_pair(iterator(it->second), false);
        }
        m_list.emplace_back(key, std::forward<T>(t));
        list_iterator lit = --m_list.end();

#ifndef JSON_NOEXCEPTION
        JSON_TRY
        {
            m_index.emplace(key_ref(std::addressof(lit->first)), lit);
        }
        JSON_CATCH(...)
        {
            m_list.pop_back();
            JSON_THROW(std::bad_alloc());
        }
#else
        m_index.emplace(key_ref(std::addressof(lit->first)), lit);
#endif
        return std::make_pair(iterator(lit), true);
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    std::pair<iterator, bool> emplace(KeyType && key, T && t)
    {
        key_type k(std::forward<KeyType>(key));
        auto it = m_index.find(key_ref(k));
        if (it != m_index.end())
        {
            return std::make_pair(iterator(it->second), false);
        }
        m_list.emplace_back(k, std::forward<T>(t));
        list_iterator lit = --m_list.end();

#ifndef JSON_NOEXCEPTION
        JSON_TRY
        {
            m_index.emplace(key_ref(std::addressof(lit->first)), lit);
        }
        JSON_CATCH(...)
        {
            m_list.pop_back();
            JSON_THROW(std::bad_alloc());
        }
#else
        m_index.emplace(key_ref(std::addressof(lit->first)), lit);
#endif
        return std::make_pair(iterator(lit), true);
    }

    // emplace_hint (hint ignored)
    iterator emplace_hint(const_iterator /*hint*/, const key_type& key, T&& t)
    {
        return emplace(key, std::forward<T>(t)).first;
    }
    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    iterator emplace_hint(const_iterator /*hint*/, KeyType && key, T && t)
    {
        return emplace(std::forward<KeyType>(key), std::forward<T>(t)).first;
    }

    // erase
    size_type erase(const Key& key)
    {
        auto it = m_index.find(key_ref(key));
        if (it == m_index.end())
        {
            return 0;
        }
        m_list.erase(it->second);
        m_index.erase(it);
        return 1;
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    size_type erase(KeyType && key)
    {
        key_type k(std::forward<KeyType>(key));
        auto it = m_index.find(key_ref(k));
        if (it == m_index.end())
        {
            return 0;
        }
        m_list.erase(it->second);
        m_index.erase(it);
        return 1;
    }

    iterator erase(iterator pos)
    {
        auto hit = m_index.find(key_ref(pos->first));
        if (hit != m_index.end())
        {
            m_index.erase(hit);
        }
        list_iterator next = m_list.erase(pos.base());
        return iterator(next);
    }

    iterator erase(const_iterator pos)
    {
        auto hit = m_index.find(key_ref(pos->first));
        if (hit != m_index.end())
        {
            m_index.erase(hit);
        }
        list_iterator next = m_list.erase(pos.base());
        return iterator(next);
    }

    iterator erase(iterator first, iterator last)
    {
        for (iterator it = first; it != last; ++it)
        {
            auto hit = m_index.find(key_ref(it->first));
            if (hit != m_index.end())
            {
                m_index.erase(hit);
            }
        }
        list_iterator ret = m_list.erase(first.base(), last.base());
        return iterator(ret);
    }

    iterator erase(const_iterator first, const_iterator last)
    {
        for (const_iterator it = first; it != last; ++it)
        {
            auto hit = m_index.find(key_ref(it->first));
            if (hit != m_index.end())
            {
                m_index.erase(hit);
            }
        }
        list_iterator ret = m_list.erase(first.base(), last.base());
        return iterator(ret);
    }

    // lookup
    size_type count(const Key& key) const
    {
        return static_cast<size_type>(m_index.count(key_ref(key)));
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    size_type count(KeyType && key) const
    {
        key_type k(std::forward<KeyType>(key));
        return static_cast<size_type>(m_index.count(key_ref(k)));
    }

    iterator find(const Key& key)
    {
        auto it = m_index.find(key_ref(key));
        return (it == m_index.end()) ? iterator(m_list.end()) : iterator(it->second);
    }

    const_iterator find(const Key& key) const
    {
        auto it = m_index.find(key_ref(key));
        return (it == m_index.end()) ? const_iterator(m_list.end()) : const_iterator(it->second);
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    iterator find(KeyType && key)
    {
        key_type k(std::forward<KeyType>(key));
        auto it = m_index.find(key_ref(k));
        return (it == m_index.end()) ? iterator(m_list.end()) : iterator(it->second);
    }

    template<class KeyType, detail::enable_if_t<
                 detail::is_usable_as_key_type<key_compare, key_type, KeyType>::value, int> = 0>
    const_iterator find(KeyType && key) const
    {
        key_type k(std::forward<KeyType>(key));
        auto it = m_index.find(key_ref(k));
        return (it == m_index.end()) ? const_iterator(m_list.end()) : const_iterator(it->second);
    }

    // comparison (preserve vector-like sequence comparison)
    friend bool operator==(const ordered_map& lhs, const ordered_map& rhs)
    {
        return lhs.m_list == rhs.m_list;
    }
    friend bool operator!=(const ordered_map& lhs, const ordered_map& rhs)
    {
        return !(lhs == rhs);
    }
    friend bool operator<(const ordered_map& lhs, const ordered_map& rhs)
    {
        return std::lexicographical_compare(lhs.m_list.begin(), lhs.m_list.end(),
                                            rhs.m_list.begin(), rhs.m_list.end());
    }
    friend bool operator>(const ordered_map& lhs, const ordered_map& rhs)
    {
        return rhs < lhs;
    }
    friend bool operator<=(const ordered_map& lhs, const ordered_map& rhs)
    {
        return !(rhs < lhs);
    }
    friend bool operator>=(const ordered_map& lhs, const ordered_map& rhs)
    {
        return !(lhs < rhs);
    }

    // swap
    void swap(ordered_map& other) noexcept
    {
        m_list.swap(other.m_list);
        m_index.swap(other.m_index);
    }
    friend void swap(ordered_map& a, ordered_map& b) noexcept
    {
        a.swap(b);
    }
};

NLOHMANN_JSON_NAMESPACE_END
