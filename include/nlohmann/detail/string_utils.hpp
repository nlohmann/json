//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2008, 2009 Björn Hoehrmann <bjoern@hoehrmann.de>
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <array> // array
#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint32_t
#include <string> // string, to_string

#include <nlohmann/detail/abi_macros.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/output/error_handler.hpp>

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

/// @return a byte as two uppercase hexadecimal digits
inline std::string hex_byte(const std::uint8_t byte)
{
    std::string result = "00";
    constexpr const char* nibble_to_hex = "0123456789ABCDEF";
    result[0] = nibble_to_hex[byte / 16];
    result[1] = nibble_to_hex[byte % 16];
    return result;
}

///////////////////
// UTF-8 encoding //
///////////////////

/*!
@brief encode a Unicode code point as UTF-8

Used to turn a decoded code point back into bytes: by the wide-string input
adapters in input_adapters.hpp (one code point per UTF-32 unit, per UTF-16
unit outside the surrogate range, and per valid UTF-16 surrogate pair), and
by the lexer's handling of u-escapes and surrogate pairs in lexer.hpp. Passing a
code point above U+10FFFF, or one in the surrogate range U+D800..U+DFFF, is
undefined behavior; callers are expected to have rejected those already
(the wide-string adapters pass malformed units through unencoded instead of
calling this function, and the lexer rejects unpaired surrogates before
reaching it).

@tparam Out    a callable invoked with one byte (as std::uint32_t, 0x00..0xFF)
               at a time, most significant byte first
@param[in] cp   the code point to encode (at most U+10FFFF)
@param[in] out  called once for each byte of the UTF-8 encoding of @a cp
*/
template<typename Out>
void encode_utf8(std::uint32_t cp, const Out& out)
{
    JSON_ASSERT(cp <= 0x10FFFF);

    if (cp < 0x80)
    {
        // 1-byte characters: 0xxxxxxx (ASCII)
        out(cp);
    }
    else if (cp <= 0x7FF)
    {
        // 2-byte characters: 110xxxxx 10xxxxxx
        out(0xC0u | (cp >> 6u));
        out(0x80u | (cp & 0x3Fu));
    }
    else if (cp <= 0xFFFF)
    {
        // 3-byte characters: 1110xxxx 10xxxxxx 10xxxxxx
        out(0xE0u | (cp >> 12u));
        out(0x80u | ((cp >> 6u) & 0x3Fu));
        out(0x80u | (cp & 0x3Fu));
    }
    else
    {
        // 4-byte characters: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
        out(0xF0u | (cp >> 18u));
        out(0x80u | ((cp >> 12u) & 0x3Fu));
        out(0x80u | ((cp >> 6u) & 0x3Fu));
        out(0x80u | (cp & 0x3Fu));
    }
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

The library checks UTF-8 well-formedness (RFC 3629, section 4) in three
places, which differ in speed, diagnostics, and how they read the input:

- decode() below: the serializer, to escape and, in strict mode, reject
  ill-formed UTF-8 when dumping a string. The CBOR, MessagePack, BSON,
  UBJSON and BJData readers do not use it: none of those specs requires a
  decoder to reject ill-formed UTF-8 in text strings, so the readers keep
  the bytes as is and leave the check to dump() and the binary writers.
- the per-lead-byte switch in lexer::scan_string(): JSON text, with a
  diagnostic for each kind of error.
- validate_one_utf8() and valid_utf8_prefix() in string_scan.hpp: the lexer's
  bulk string scan, the bulk path of the BON8 reader, and the BON8 writer.
  They must accept exactly what the lexer's switch accepts.
- the byte path of binary_reader::get_bon8_string(): BON8 input without bulk
  access, and the bytes the bulk path leaves to it.

All four must accept the same set of sequences, so a change to one needs a
matching change to the others.

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
@brief check a string for well-formed UTF-8 (RFC 3629, section 4)

Used by the binary readers (CBOR, MessagePack, UBJSON, BJData, BSON) when an
@ref error_handler_t other than `keep` is requested for a text string value
or object key: none of those formats requires a decoder to reject ill-formed
UTF-8 on its own, so the check is opt-in there, unlike the JSON lexer and the
serializer's @ref decode -based escaping, which always run it.

@param[in] s      the string to check
@param[in] first  the index to start checking at
@return whether `s.substr(first)` is well-formed UTF-8

@sa @ref decode
*/
template<typename StringType>
inline bool is_valid_utf8(const StringType& s, const std::size_t first = 0) noexcept
{
    std::uint8_t state = UTF8_ACCEPT;
    std::uint32_t codepoint = 0;

    for (std::size_t i = first; i < s.size(); ++i)
    {
        decode(state, codepoint, static_cast<std::uint8_t>(s[i]));
        if (state == UTF8_REJECT)
        {
            return false;
        }
    }

    return state == UTF8_ACCEPT;
}

/*!
@brief sanitize a string with ill-formed UTF-8 for @ref error_handler_t::replace or @ref error_handler_t::ignore

Replaces every maximal ill-formed subsequence with U+FFFD (`replace`) or
drops it (`ignore`), using exactly the same boundaries @ref
serializer::dump_escaped_impl uses while escaping a string: a byte that does
not extend the sequence started by the previous byte(s) is reread as the
start of a new one, instead of being swallowed along with them.

@pre @a error_handler is @ref error_handler_t::replace or @ref error_handler_t::ignore
@note Well-formed input is copied through unchanged, including bytes (e.g.
      control characters or quotes) that @ref serializer::dump_escaped_impl
      would itself escape; this function only concerns itself with
      well-formedness, not with producing valid JSON text.

@param[in] s              the string to sanitize
@param[in] error_handler  @ref error_handler_t::replace or @ref error_handler_t::ignore

@return @a s with every ill-formed subsequence replaced or removed

@sa @ref decode
*/
template<typename StringType>
inline StringType sanitize_utf8(const StringType& s, const error_handler_t error_handler)
{
    JSON_ASSERT(error_handler == error_handler_t::replace || error_handler == error_handler_t::ignore);

    StringType result;
    result.reserve(s.size());

    std::uint32_t codepoint = 0;
    std::uint8_t state = UTF8_ACCEPT;
    // length of result after the last accepted code point
    std::size_t result_len_after_last_accept = 0;
    // whether bytes of an as yet unresolved sequence were already appended
    bool pending = false;

    for (std::size_t i = 0; i < s.size(); ++i)
    {
        switch (decode(state, codepoint, static_cast<std::uint8_t>(s[i])))
        {
            case UTF8_ACCEPT: // decode found a well-formed code point
            {
                result.push_back(s[i]);
                result_len_after_last_accept = result.size();
                pending = false;
                break;
            }

            case UTF8_REJECT: // decode found an ill-formed byte
            {
                // in case we saw this byte for the first time, read it again,
                // because it may be fine for itself, just not for the
                // sequence that came before it
                if (pending)
                {
                    --i;
                }

                // drop the bytes of the ill-formed sequence buffered below
                result.resize(result_len_after_last_accept);

                if (error_handler == error_handler_t::replace)
                {
                    result.append("\xEF\xBF\xBD");
                    result_len_after_last_accept = result.size();
                }

                pending = false;
                state = UTF8_ACCEPT;
                break;
            }

            default: // decode found yet incomplete multibyte code point
            {
                result.push_back(s[i]);
                pending = true;
                break;
            }
        }
    }

    // the string ended with an incomplete sequence
    if (state != UTF8_ACCEPT)
    {
        result.resize(result_len_after_last_accept);

        if (error_handler == error_handler_t::replace)
        {
            result.append("\xEF\xBF\xBD");
        }
    }

    return result;
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
