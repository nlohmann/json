//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // sort, stable_sort
#include <cstddef> // size_t
#include <string> // string
#include <utility> // move, pair
#include <vector> // vector

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

// Equality of views, and of views with basic_json values, with the semantics
// of basic_json's operator== applied to the values parse() would produce:
// numbers compare by value across their types, an object is compared by its
// members with duplicate keys resolved as parse() resolves them (the last
// value, at the position of the first occurrence), and in document order if
// the object type keeps an order (ordered_json), by key otherwise.

/// one side of a comparison: a view
template<typename BasicJsonType, typename View>
class view_side
{
  public:
    using string_view_t = typename View::string_view_t;

    explicit view_side(const View& v) noexcept
        : m_view(v)
    {}

    value_t type() const noexcept
    {
        return m_view.type();
    }

    std::size_t size() const noexcept
    {
        return m_view.size();
    }

    string_view_t string() const
    {
        return m_view.get_string();
    }

    /// a number, boolean, or null as a basic_json value (no allocation)
    BasicJsonType scalar() const
    {
        switch (m_view.type())
        {
            case value_t::number_integer:
                return BasicJsonType(m_view.template get<typename BasicJsonType::number_integer_t>());
            case value_t::number_unsigned:
                return BasicJsonType(m_view.template get<typename BasicJsonType::number_unsigned_t>());
            case value_t::number_float:
                return BasicJsonType(m_view.template get<typename BasicJsonType::number_float_t>());
            case value_t::boolean:
                return BasicJsonType(m_view.template get<bool>());
            case value_t::null:
            case value_t::object:
            case value_t::array:
            case value_t::string:
            case value_t::binary:
            case value_t::discarded:
            default:
                return BasicJsonType(nullptr);
        }
    }

    void elements(std::vector<view_side>& out) const
    {
        out.reserve(m_view.size());
        for (const View e : m_view)
        {
            out.emplace_back(e);
        }
    }

    /// the members as parse() keeps them: one per key, the last value at the
    /// position of the first occurrence; in that order, or sorted by key
    void members(std::vector<std::pair<string_view_t, view_side>>& out, bool ordered) const
    {
        struct member
        {
            string_view_t key;
            View value;
            std::size_t position;
        };
        std::vector<member> all;
        all.reserve(m_view.size());
        std::size_t position = 0;
        for (auto it = m_view.begin(); it != m_view.end(); ++it)
        {
            all.push_back(member{it.key(), it.value(), position++});
        }
        std::stable_sort(all.begin(), all.end(), [](const member & a, const member & b)
        {
            return a.key < b.key;
        });
        std::vector<member> unique;
        unique.reserve(all.size());
        for (std::size_t i = 0; i < all.size();)
        {
            std::size_t last = i;
            while (last + 1 < all.size() && all[last + 1].key == all[i].key)
            {
                ++last;
            }
            unique.push_back(member{all[i].key, all[last].value, all[i].position});
            i = last + 1;
        }
        if (ordered)
        {
            std::sort(unique.begin(), unique.end(), [](const member & a, const member & b)
            {
                return a.position < b.position;
            });
        }
        out.reserve(unique.size());
        for (const member& m : unique)
        {
            out.emplace_back(m.key, view_side(m.value));
        }
    }

  private:
    View m_view;
};

/// the other side of a comparison: a basic_json value
template<typename BasicJsonType, typename StringView>
class json_side
{
  public:
    using string_view_t = StringView;

    explicit json_side(const BasicJsonType& j) noexcept
        : m_json(&j)
    {}

    value_t type() const noexcept
    {
        return m_json->type();
    }

    std::size_t size() const noexcept
    {
        return m_json->size();
    }

    string_view_t string() const
    {
        const auto& s = m_json->template get_ref<const typename BasicJsonType::string_t&>();
        return string_view_t(s.data(), s.size());
    }

    BasicJsonType scalar() const
    {
        return *m_json;
    }

    void elements(std::vector<json_side>& out) const
    {
        out.reserve(m_json->size());
        for (const auto& e : *m_json)
        {
            out.emplace_back(e);
        }
    }

    void members(std::vector<std::pair<string_view_t, json_side>>& out, bool ordered) const
    {
        out.reserve(m_json->size());
        for (auto it = m_json->cbegin(); it != m_json->cend(); ++it)
        {
            out.emplace_back(string_view_t(it.key().data(), it.key().size()), json_side(it.value()));
        }
        if (!ordered)
        {
            std::sort(out.begin(), out.end(), [](const std::pair<string_view_t, json_side>& a, const std::pair<string_view_t, json_side>& b)
            {
                return a.first < b.first;
            });
        }
    }

  private:
    const BasicJsonType* m_json;
};

/// whether two sides are equal; iterative, so that the nesting depth is
/// limited by memory only
template<typename BasicJsonType, typename A, typename B>
bool equal(const A& a0, const B& b0)
{
    using string_view_t = typename A::string_view_t;
    const bool ordered = is_ordered_map<typename BasicJsonType::object_t>::value;

    struct frame
    {
        std::vector<A> elements_a{};
        std::vector<B> elements_b{};
        std::vector<std::pair<string_view_t, A>> members_a{};
        std::vector<std::pair<string_view_t, B>> members_b{};
        bool object = false;
        std::size_t next = 0;
    };
    std::vector<frame> stack;
    A a = a0;
    B b = b0;
    for (;;)
    {
        const value_t ta = a.type();
        const value_t tb = b.type();
        const bool numbers = (ta == value_t::number_integer || ta == value_t::number_unsigned || ta == value_t::number_float)
                             && (tb == value_t::number_integer || tb == value_t::number_unsigned || tb == value_t::number_float);
        if (ta == value_t::discarded || tb == value_t::discarded)
        {
            // basic_json decides (JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON)
            if (ta != tb || !(BasicJsonType(value_t::discarded) == BasicJsonType(value_t::discarded)))
            {
                return false;
            }
        }
        else
        {
            if (!numbers && ta != tb)
            {
                return false;
            }
            if (ta == value_t::string)
            {
                if (!(a.string() == b.string()))
                {
                    return false;
                }
            }
            else if (ta == value_t::array || ta == value_t::object)
            {
                if (a.size() != b.size() && ta == value_t::array)
                {
                    return false;
                }
                frame f;
                f.object = ta == value_t::object;
                if (f.object)
                {
                    a.members(f.members_a, ordered);
                    b.members(f.members_b, ordered);
                    if (f.members_a.size() != f.members_b.size())
                    {
                        return false;
                    }
                }
                else
                {
                    a.elements(f.elements_a);
                    b.elements(f.elements_b);
                }
                stack.push_back(std::move(f));
            }
            else if (!(a.scalar() == b.scalar())) // numbers (also of different types), null, boolean
            {
                return false;
            }
        }

        // the next pair of values
        for (;;)
        {
            if (stack.empty())
            {
                return true;
            }
            frame& f = stack.back();
            const std::size_t count = f.object ? f.members_a.size() : f.elements_a.size();
            if (f.next == count)
            {
                stack.pop_back();
                continue;
            }
            if (f.object)
            {
                if (!(f.members_a[f.next].first == f.members_b[f.next].first))
                {
                    return false;
                }
                a = f.members_a[f.next].second;
                b = f.members_b[f.next].second;
            }
            else
            {
                a = f.elements_a[f.next];
                b = f.elements_b[f.next];
            }
            ++f.next;
            break;
        }
    }
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
