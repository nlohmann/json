//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <nlohmann/json.hpp>

namespace custom_object_key_test
{
class key
{
  public:
    key() = default;

    key(const char* value)
        : m_value(value)
    {}

    key(std::string value)
        : m_value(std::move(value))
    {}

    operator std::string() const
    {
        return m_value;
    }

    friend bool operator<(const key& lhs, const key& rhs)
    {
        return lhs.m_value < rhs.m_value;
    }

  private:
    std::string m_value;
};

template<typename Key, typename Value, typename Compare, typename Allocator>
class object
    : public std::map <
      key,
      Value,
      std::less<key>, // NOLINT(modernize-use-transparent-functors)
      typename std::allocator_traits<Allocator>::template rebind_alloc <
          std::pair<const key, Value >>>
{
  private:
    using allocator_type =
    typename std::allocator_traits<Allocator>::template rebind_alloc <
        std::pair<const key, Value >>;

    using base_type =
        std::map<key, Value, std::less<key>, allocator_type>; // NOLINT(modernize-use-transparent-functors)

  public:
    using base_type::base_type;
};

using json = nlohmann::basic_json<object>;
} // namespace custom_object_key_test
