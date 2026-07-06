//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <type_traits> // conditional, is_same

#include <nlohmann/detail/abi_macros.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN

/*!
@brief Default base class of the @ref basic_json class.

So that the correct implementations of the copy / move ctors / assign operators
of @ref basic_json do not require complex case distinctions
(no base class / custom base class used as customization point),
@ref basic_json always has a base class.
By default, this class is used because it is empty and thus has no effect
on the behavior of @ref basic_json.

@note This class intentionally lives in namespace @ref nlohmann rather than
      @ref nlohmann::detail. Every @ref basic_json specialization derives from
      it (via @ref detail::json_base_class) unless a custom base class is
      supplied, which makes its namespace an associated namespace of
      @ref basic_json for the purpose of argument-dependent lookup (ADL). If
      it lived in `nlohmann::detail`, that namespace - and with it the
      library's internal `to_json`/`from_json` overloads - would leak into
      ADL for any unqualified `to_json`/`from_json` call a user makes
      involving a @ref basic_json argument, silently shadowing the user's own
      overloads in some cases.
*/
struct json_default_base {};

namespace detail
{

template<class T>
using json_base_class = typename std::conditional <
                        std::is_same<T, void>::value,
                        ::nlohmann::json_default_base,
                        T
                        >::type;

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
