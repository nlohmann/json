//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t
#include <string> // string, to_string

#include <nlohmann/detail/abi_macros.hpp>
#include <nlohmann/detail/macro_scope.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

template<typename StringType>
void int_to_string(StringType& target, std::size_t value)
{
    // For ADL
    using std::to_string;
    target = to_string(value);
}

template<typename StringType>
StringType to_string(std::size_t value)
{
    StringType result;
    int_to_string(result, value);
    return result;
}

///////////////////
// UTF-8 decoding //
///////////////////

// UTF-8 decoder states used by decode() below
static constexpr std::uint8_t UTF8_ACCEPT = 0;
static constexpr std::uint8_t UTF8_REJECT = 1;

/*!
@brief process a byte of a UTF-8 sequence

This is a single-byte step of a "shift-based" UTF-8 decoder originally
written by Björn Hoehrmann. See
http://bjoern.hoehrmann.de/utf-8/decoder/dfa/ for details.

This decoder is the single source of truth for UTF-8 validation in this
library: it is used both by the serializer (to escape and, in strict mode,
reject ill-formed UTF-8 when dumping a string) and by the binary readers
(to reject ill-formed UTF-8 in CBOR/MessagePack/BSON/UBJSON text strings at
decode time; see @ref is_valid_utf8 below).

@param[in,out] state  the current decoder state
@param[in,out] codep  codepoint (valid only if resulting state is UTF8_ACCEPT)
@param[in] byte       next byte to decode
@return               new state

@note Original source: http://bjoern.hoehrmann.de/utf-8/decoder/dfa/
@sa http://bjoern.hoehrmann.de/utf-8/decoder/dfa/
*/
inline std::uint8_t decode(std::uint8_t& state, std::uint32_t& codep, const std::uint8_t byte) noexcept
{
    static const std::array<std::uint8_t, 400> utf8d =
    {
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 00..1F
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20..3F
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 40..5F
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 60..7F
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, // 80..9F
            7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, // A0..BF
            8, 8, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // C0..DF
            0xA, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x4, 0x3, 0x3, // E0..EF
            0xB, 0x6, 0x6, 0x6, 0x5, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, 0x8, // F0..FF
            0x0, 0x1, 0x2, 0x3, 0x5, 0x8, 0x7, 0x1, 0x1, 0x1, 0x4, 0x6, 0x1, 0x1, 0x1, 0x1, // s0..s0
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, // s1..s2
            1, 2, 1, 1, 1, 1, 1, 2, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, // s3..s4
            1, 2, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 1, 3, 1, 1, 1, 1, 1, 1, // s5..s6
            1, 3, 1, 1, 1, 1, 1, 3, 1, 3, 1, 1, 1, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 // s7..s8
        }
    };

    JSON_ASSERT(static_cast<std::size_t>(byte) < utf8d.size());
    const std::uint8_t type = utf8d[byte];

    codep = (state != UTF8_ACCEPT)
            ? (byte & 0x3fu) | (codep << 6u)
            : (0xFFu >> type) & (byte);

    const std::size_t index = 256u + (static_cast<std::size_t>(state) * 16u) + static_cast<std::size_t>(type);
    JSON_ASSERT(index < utf8d.size());
    state = utf8d[index];
    return state;
}

/*!
@brief check whether a string consists solely of valid UTF-8

Used by the CBOR/MessagePack/BSON/UBJSON binary readers to reject text
strings that are not valid UTF-8 at decode time (RFC 8949 §3.1 and the
MessagePack/BSON specifications all require text strings to be UTF-8), so
that malformed input is caught immediately instead of only surfacing later
as a type_error.316 when the resulting value is dumped.

@param[in] s  the string to check
@return whether @a s is valid UTF-8
*/
template<typename StringType>
inline bool is_valid_utf8(const StringType& s) noexcept
{
    std::uint8_t state = UTF8_ACCEPT;
    std::uint32_t codepoint = 0;

    for (std::size_t i = 0; i < s.size(); ++i)
    {
        decode(state, codepoint, static_cast<std::uint8_t>(s[i]));
        if (state == UTF8_REJECT)
        {
            return false;
        }
    }

    return state == UTF8_ACCEPT;
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
