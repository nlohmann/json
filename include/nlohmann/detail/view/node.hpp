//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t
#include <cstdint> // uint8_t, uint16_t, uint32_t, uint64_t
#include <cstring> // memcpy

#include <nlohmann/json.hpp>
#include <nlohmann/detail/view/macro_scope.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
namespace view
{

// the node kinds are value_t values; the tests of is_container() and of the
// number kinds depend on this numbering
static_assert(static_cast<std::uint8_t>(value_t::null) == 0 && static_cast<std::uint8_t>(value_t::object) == 1
              && static_cast<std::uint8_t>(value_t::array) == 2 && static_cast<std::uint8_t>(value_t::string) == 3
              && static_cast<std::uint8_t>(value_t::boolean) == 4 && static_cast<std::uint8_t>(value_t::number_integer) == 5
              && static_cast<std::uint8_t>(value_t::number_unsigned) == 6 && static_cast<std::uint8_t>(value_t::number_float) == 7,
              "the node format depends on the numbering of value_t");

/// node flags
struct node_flags
{
    static constexpr std::uint8_t escaped = 1; ///< string payload lives in the decode arena, not the source
    static constexpr std::uint8_t storage = 3; ///< mask: where a string or number token lives (index into document_data::base)
    static constexpr std::uint8_t is_true = 4; ///< boolean value
};

/// One entry of the flat index, in document order. An object's members are
/// stored as key node followed by the value's subtree. Integers keep their
/// converted 64-bit value in the len/next bytes (the node after a scalar is
/// always the next one, and the token length follows from `extra`).
struct node
{
    std::uint8_t kind;   ///< value_t
    std::uint8_t flags;  ///< node_flags
    std::uint16_t extra; ///< numbers: integer digits (low byte) and fraction digits (high byte), 255 = "many"; otherwise 0
    std::uint32_t off;   ///< source offset (string content, number token, literal, bracket); arena offset if node_flags::escaped
    std::uint32_t len;   ///< string: decoded bytes; float: token bytes; array/object: element count
    std::uint32_t next;  ///< array/object: number of nodes of the subtree (its extent in the enclosing sequence)
};
static_assert(sizeof(node) == 16, "node must stay 16 bytes");

NLOHMANN_VIEW_ALWAYS_INLINE bool is_container(const node& n) noexcept
{
    return static_cast<unsigned>(n.kind) - 1u <= 1u;
}

/// the converted value of an integer node (stored in len/next)
NLOHMANN_VIEW_ALWAYS_INLINE std::uint64_t integer_bits(const node& n) noexcept
{
    std::uint64_t v = 0;
    std::memcpy(&v, reinterpret_cast<const unsigned char*>(&n) + 8, 8); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    return v;
}

NLOHMANN_VIEW_ALWAYS_INLINE void set_integer_bits(node& n, std::uint64_t v) noexcept
{
    std::memcpy(reinterpret_cast<unsigned char*>(&n) + 8, &v, 8); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
}

/// token length of a number node
NLOHMANN_VIEW_ALWAYS_INLINE std::uint32_t number_length(const node& n) noexcept
{
    return n.kind == static_cast<std::uint8_t>(value_t::number_float) ? n.len
           : (n.extra & 0xFFu) + (n.kind == static_cast<std::uint8_t>(value_t::number_integer) ? 1u : 0u);
}

/// estimated number of nodes for an input of `size` bytes (one node per ~12
/// bytes covers typical documents without regrowth)
inline std::size_t estimate_nodes(std::size_t size) noexcept
{
    return (size / 12) + 16;
}

/// estimated number of nodes for the input [src, src + size): pretty-printed
/// input (whitespace after the first byte) needs about a node per 12 bytes,
/// minified input up to one per 4 (yyjson tells the two apart the same way)
inline std::size_t estimate_nodes(const char* src, std::size_t size) noexcept
{
    return size >= 2 && (src[1] == ' ' || src[1] == '\n' || src[1] == '\r' || src[1] == '\t') ? estimate_nodes(size) : (size / 4) + 16;
}

}  // namespace view
}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
