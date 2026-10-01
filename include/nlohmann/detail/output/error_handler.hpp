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

/// how to treat decoding errors
///
/// @ref basic_json::dump uses this to decide what to do with ill-formed
/// UTF-8 while escaping a string, and the binary writers (@ref
/// basic_json::to_cbor, @ref basic_json::to_ubjson, @ref
/// basic_json::to_bjdata, @ref basic_json::to_bson) use it the same way for
/// string values and object keys. The binary readers (@ref
/// basic_json::from_cbor, @ref basic_json::from_msgpack, @ref
/// basic_json::from_ubjson, @ref basic_json::from_bjdata, @ref
/// basic_json::from_bson) use it to decide whether to check text strings
/// and object keys for well-formed UTF-8 at all, since none of those
/// formats requires a decoder to do so.
enum class error_handler_t
{
    strict,  ///< throw a type_error/parse_error exception in case of invalid UTF-8
    replace, ///< replace invalid UTF-8 sequences with U+FFFD
    ignore,  ///< ignore invalid UTF-8 sequences
    keep     ///< keep invalid UTF-8 sequences unchanged
};

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
