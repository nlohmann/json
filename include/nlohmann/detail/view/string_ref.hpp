//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // min
#include <cstddef> // size_t
#include <cstring> // memcmp, strlen
#include <string> // basic_string

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>

#if NLOHMANN_VIEW_HAS_CPP_17
    #include <string_view> // string_view
#endif
#ifndef JSON_NO_IO
    #include <ostream> // ostream
#endif

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

#if NLOHMANN_VIEW_HAS_CPP_17
using string_ref = std::string_view;
#else
/// minimal C++11 stand-in for std::string_view
class string_ref
{
  public:
    using size_type = std::size_t;
    using const_iterator = const char*;

    string_ref() noexcept = default;
    // s must be null-terminated, as for std::string_view(const char*)
    // flawfinder: ignore
    string_ref(const char* s) : m_data(s), m_size(std::strlen(s)) {} // NOLINT(google-explicit-constructor,hicpp-explicit-conversions)
    string_ref(const char* s, std::size_t n) noexcept : m_data(s), m_size(n) {}
    template<typename Traits, typename Alloc>
    string_ref(const std::basic_string<char, Traits, Alloc>& s) noexcept : m_data(s.data()), m_size(s.size()) {} // NOLINT(google-explicit-constructor,hicpp-explicit-conversions)

    const char* data() const noexcept
    {
        return m_data;
    }
    std::size_t size() const noexcept
    {
        return m_size;
    }
    std::size_t length() const noexcept
    {
        return m_size;
    }
    bool empty() const noexcept
    {
        return m_size == 0;
    }
    const char* begin() const noexcept
    {
        return m_data;
    }
    const char* end() const noexcept
    {
        return m_data + m_size;
    }
    char operator[](std::size_t i) const noexcept
    {
        return m_data[i];
    }

    template<typename Traits, typename Alloc>
    explicit operator std::basic_string<char, Traits, Alloc>() const
    {
        return std::basic_string<char, Traits, Alloc>(m_data, m_size);
    }

    friend bool operator==(string_ref a, string_ref b) noexcept
    {
        return a.m_size == b.m_size && (a.m_size == 0 || std::memcmp(a.m_data, b.m_data, a.m_size) == 0);
    }
    friend bool operator!=(string_ref a, string_ref b) noexcept
    {
        return !(a == b);
    }
    friend bool operator<(string_ref a, string_ref b) noexcept
    {
        const int c = std::memcmp(a.m_data, b.m_data, (std::min)(a.m_size, b.m_size));
        return c != 0 ? c < 0 : a.m_size < b.m_size;
    }
#ifndef JSON_NO_IO
    friend std::ostream& operator<<(std::ostream& o, string_ref s)
    {
        return o.write(s.m_data, static_cast<std::streamsize>(s.m_size));
    }
#endif

  private:
    const char* m_data = "";
    std::size_t m_size = 0;
};
#endif

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
