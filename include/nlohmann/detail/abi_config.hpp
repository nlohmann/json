//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <nlohmann/detail/abi_macros.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/*!
@brief the configuration macros that change the library's behavior

json.hpp undefines these macros at its end (see macro_unscope.hpp), so code
that builds on the library after it (json_view.hpp) reads them here. Like the
macros, they are part of the ABI namespace, so they always match the
basic_json they are used with.
*/
struct abi_config
{
    /// JSON_STRICT_NUL_HANDLING: a null byte is an error, not the end of input
    static constexpr bool strict_nul_handling = JSON_STRICT_NUL_HANDLING != 0;
    /// JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON
    static constexpr bool legacy_discarded_value_comparison = JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON != 0;
};

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
