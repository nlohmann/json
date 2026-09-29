//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#ifndef INCLUDE_NLOHMANN_JSON_LITERALS_HPP_
#define INCLUDE_NLOHMANN_JSON_LITERALS_HPP_

#include <cstddef> // size_t
#include <string> // string

// NOLINTNEXTLINE(misc-header-include-cycle): json.hpp includes this header at its end
#include <nlohmann/json.hpp>

// This header is included at the end of <nlohmann/json.hpp> unless
// JSON_NO_AUTOMATIC_UDLS is defined, and can be included on its own after that.
// Either way, the library's internal macros are no longer defined here (and the
// amalgamation inlines macro_scope.hpp only once), so only standard and public
// macros may be used below.

// declares the literal operator for the given suffix; GCC 4.8 requires a space
// between "" and the suffix, which newer compilers deprecate (CWG 2521)
#if !defined(__GNUC__) || defined(__clang__) || __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)
    #define NLOHMANN_JSON_LITERAL_OPERATOR(suffix) operator""##suffix
#else
    #define NLOHMANN_JSON_LITERAL_OPERATOR(suffix) operator"" suffix
#endif

NLOHMANN_JSON_NAMESPACE_BEGIN
inline namespace literals
{
inline namespace json_literals
{

/// @brief user-defined string literal for JSON values
/// @sa https://json.nlohmann.me/api/operator_literal_json/
inline nlohmann::json NLOHMANN_JSON_LITERAL_OPERATOR(_json)(const char* s, std::size_t n)
{
    return nlohmann::json::parse(s, s + n);
}

#if defined(__cpp_char8_t)
inline nlohmann::json operator""_json(const char8_t* s, std::size_t n)
{
    return nlohmann::json::parse(reinterpret_cast<const char*>(s),
                                 reinterpret_cast<const char*>(s) + n);
}
#endif

/// @brief user-defined string literal for JSON pointer
/// @sa https://json.nlohmann.me/api/operator_literal_json_pointer/
inline nlohmann::json::json_pointer NLOHMANN_JSON_LITERAL_OPERATOR(_json_pointer)(const char* s, std::size_t n)
{
    return nlohmann::json::json_pointer(std::string(s, n));
}

#if defined(__cpp_char8_t)
inline nlohmann::json::json_pointer operator""_json_pointer(const char8_t* s, std::size_t n)
{
    return nlohmann::json::json_pointer(std::string(reinterpret_cast<const char*>(s), n));
}
#endif

}  // namespace json_literals
}  // namespace literals
NLOHMANN_JSON_NAMESPACE_END

#if !defined(JSON_USE_GLOBAL_UDLS) || JSON_USE_GLOBAL_UDLS
    using nlohmann::literals::json_literals::NLOHMANN_JSON_LITERAL_OPERATOR(_json); // NOLINT(misc-unused-using-decls,google-global-names-in-headers)
    using nlohmann::literals::json_literals::NLOHMANN_JSON_LITERAL_OPERATOR(_json_pointer); //NOLINT(misc-unused-using-decls,google-global-names-in-headers)
#endif

#undef NLOHMANN_JSON_LITERAL_OPERATOR

#endif  // INCLUDE_NLOHMANN_JSON_LITERALS_HPP_
