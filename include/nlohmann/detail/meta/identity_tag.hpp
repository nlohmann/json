//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.11.2
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#ifndef INCLUDE_NLOHMANN_DETAIL_META_IDENTITY_TAG_HPP
#define INCLUDE_NLOHMANN_DETAIL_META_IDENTITY_TAG_HPP

#include <nlohmann/detail/abi_macros.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

// dispatching helper struct
template <class T> struct identity_tag {};

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END

#endif  // INCLUDE_NLOHMANN_DETAIL_META_IDENTITY_TAG_HPP
