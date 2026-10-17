//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // ptrdiff_t, size_t
#include <iterator> // forward_iterator_tag
#include <string> // string, to_string
#include <type_traits> // enable_if

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/document_data.hpp>
#include <nlohmann/detail/view/errors.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>
#include <nlohmann/detail/view/node.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// the result of view_iterator::operator->: keeps the view alive for the
/// duration of the member access
template<typename View>
class arrow_proxy
{
  public:
    explicit arrow_proxy(const View& v) noexcept
        : m_view(v)
    {}

    const View* operator->() const noexcept
    {
        return &m_view;
    }

  private:
    View m_view;
};

/*!
@brief forward iterator over the elements of a basic_json_view

Iterates over the elements of an array or the member values of an object, in
document order; key() gives the key of an object member. As for basic_json, a
primitive value iterates as a range of one element (itself), and null as an
empty range.
*/
template<typename View>
class view_iterator
{
  public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = View;
    using difference_type = std::ptrdiff_t;
    using pointer = arrow_proxy<View>;
    using reference = View;
    using string_view_t = typename View::string_view_t;

    view_iterator() noexcept = default;

    /// @param[in] pos  the element, or the key of the member
    /// @param[in] object  whether pos is a key (its value is the next node)
    view_iterator(const document_data* d, const node* pos, bool object) noexcept
        : m_doc(d), m_pos(pos), m_value_offset(object ? 1 : 0)
    {}

    NLOHMANN_VIEW_ALWAYS_INLINE View operator*() const noexcept
    {
        return View(m_doc, View::navigation::value(m_pos + m_value_offset));
    }

    pointer operator->() const noexcept
    {
        return pointer(**this);
    }

    NLOHMANN_VIEW_ALWAYS_INLINE view_iterator& operator++() noexcept
    {
        m_pos = document_data::after(m_pos + m_value_offset);
        return *this;
    }

    view_iterator operator++(int) noexcept
    {
        const view_iterator r = *this;
        ++*this;
        return r;
    }

    friend bool operator==(const view_iterator& a, const view_iterator& b) noexcept
    {
        return a.m_pos == b.m_pos;
    }

    friend bool operator!=(const view_iterator& a, const view_iterator& b) noexcept
    {
        return a.m_pos != b.m_pos;
    }

    /// the key of the current object member; throws invalid_iterator.207 for
    /// other iterators, like basic_json's iterators
    string_view_t key() const
    {
        if (NLOHMANN_VIEW_UNLIKELY(m_value_offset == 0))
        {
            throw_invalid_iterator(207, "cannot use key() for non-object iterators");
        }
        return string_view_t(m_doc->str(*m_pos), m_pos->len);
    }

    View value() const noexcept
    {
        return **this;
    }

    /// whether the iterator runs over the members of an object
    bool is_object_iterator() const noexcept
    {
        return m_value_offset != 0;
    }

  private:
    const document_data* m_doc = nullptr;
    const node* m_pos = nullptr;
    std::size_t m_value_offset = 0; ///< 1 for objects: the value follows its key
};

/*!
@brief a (key, value) item of basic_json_view::items()

The key of an array element is its index, as for basic_json::items().
Supports structured bindings: for (const auto [key, value] : view.items())
*/
template<typename View>
class view_item
{
  public:
    using string_view_t = typename View::string_view_t;
    using iterator = view_iterator<View>;

    view_item(const iterator& it, std::size_t index)
        : m_it(it)
    {
        if (!it.is_object_iterator())
        {
            m_index = std::to_string(index);
        }
    }

    /// the member key, or the element index for arrays
    string_view_t key() const
    {
        if (m_it.is_object_iterator())
        {
            return m_it.key();
        }
        return string_view_t(m_index.data(), m_index.size());
    }

    View value() const noexcept
    {
        return *m_it;
    }

    template<std::size_t N, typename std::enable_if<N == 0, int>::type = 0>
    string_view_t get() const
    {
        return key();
    }

    template<std::size_t N, typename std::enable_if<N == 1, int>::type = 0>
    View get() const noexcept
    {
        return value();
    }

  private:
    iterator m_it;
    std::string m_index{}; // NOLINT(readability-redundant-member-init)
};

/// the range returned by basic_json_view::items()
template<typename View>
class view_items
{
  public:
    using item = view_item<View>;

    class iterator
    {
      public:
        using iterator_category = std::forward_iterator_tag;
        using value_type = item;
        using difference_type = std::ptrdiff_t;
        using pointer = void;
        using reference = item;

        explicit iterator(const view_iterator<View>& it) noexcept
            : m_it(it)
        {}

        item operator*() const
        {
            return item(m_it, m_index);
        }

        iterator& operator++() noexcept
        {
            ++m_it;
            ++m_index;
            return *this;
        }

        iterator operator++(int) noexcept
        {
            const iterator r = *this;
            ++*this;
            return r;
        }

        friend bool operator==(const iterator& a, const iterator& b) noexcept
        {
            return a.m_it == b.m_it;
        }

        friend bool operator!=(const iterator& a, const iterator& b) noexcept
        {
            return a.m_it != b.m_it;
        }

      private:
        view_iterator<View> m_it;
        std::size_t m_index = 0;
    };

    explicit view_items(const View& v) noexcept
        : m_view(v)
    {}

    iterator begin() const noexcept
    {
        return iterator(m_view.begin());
    }

    iterator end() const noexcept
    {
        return iterator(m_view.end());
    }

  private:
    View m_view;
};

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
