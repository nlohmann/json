//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <string> // basic_string, char_traits, string
#include <type_traits> // decay, integral_constant, is_array, is_lvalue_reference, is_pointer, is_same, remove_reference
#include <utility> // forward

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>

#if NLOHMANN_VIEW_HAS_CPP_17
    #include <string_view> // string_view
#endif

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

/// how a document takes its input
enum class input_kind
{
    move_string,  ///< rvalue std::string: owned without a copy
    c_string,     ///< const char* (NUL-terminated): borrowed
    char_array,   ///< char array (e.g. a string literal): borrowed
    borrow_range, ///< lvalue contiguous byte container, or std::string_view: borrowed
    copy_range,   ///< rvalue contiguous byte container: copied
    adapter,      ///< anything else parse() accepts (streams, wide strings, ...): read into a buffer
};

template<typename InputType>
struct classify_input
{
    using R = typename std::remove_reference<InputType>::type;
    using D = typename std::decay<InputType>::type;
    static constexpr bool is_rvalue = !std::is_lvalue_reference<InputType>::value;
    static constexpr bool is_bytes = is_contiguous_byte_container<D>::value;
#if NLOHMANN_VIEW_HAS_CPP_17
    static constexpr bool is_string_view = std::is_same<D, std::string_view>::value;
#else
    static constexpr bool is_string_view = false;
#endif
    // NOLINTBEGIN(readability-avoid-nested-conditional-operator): a constant expression of C++11
    static constexpr input_kind value =
        std::is_array<R>::value ? input_kind::char_array
        : std::is_pointer<D>::value ? input_kind::c_string
        : (is_rvalue && std::is_same<D, std::string>::value) ? input_kind::move_string
        : (is_bytes && (!is_rvalue || is_string_view)) ? input_kind::borrow_range
        : is_bytes ? input_kind::copy_range
        : input_kind::adapter;
    // NOLINTEND(readability-avoid-nested-conditional-operator)
};

/// std::basic_string guarantees a NUL at data()[size()] (the parser's sentinel)
template<typename T>
struct is_std_string : std::false_type {};

template<typename Traits, typename Alloc>
struct is_std_string<std::basic_string<char, Traits, Alloc>> : std::true_type {};

/// drain a json input adapter (UTF-16/32 inputs arrive as UTF-8)
template<typename Adapter>
std::string collect_adapter(Adapter ia)
{
    std::string buf;
    for (;;)
    {
        const auto ch = ia.get_character();
        if (ch == std::char_traits<char>::eof())
        {
            break;
        }
        buf.push_back(static_cast<char>(ch));
    }
    return buf;
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
