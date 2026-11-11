//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstddef> // size_t
#include <type_traits> // false_type, is_integral, remove_cv, true_type

#include <nlohmann/detail/abi_macros.hpp>

// JSON_RECURSION_DEPTH_LIMIT: the number of nesting levels the operations that
// walk a value recurse into on the call stack before they continue with an
// explicit stack (see detail::recursion_depth_limit() below).
//
// May be defined by the user before the first include of the library; it has
// to be the same in every translation unit of a program (it is not part of the
// ABI tag, see https://json.nlohmann.me/api/macros/json_recursion_depth_limit/).
// Allowed: an integer constant expression from 0 to 254. The default is 128.
#ifndef JSON_RECURSION_DEPTH_LIMIT
    #define JSON_RECURSION_DEPTH_LIMIT 128
#endif

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

/*!
@brief the number of nesting levels an operation recurses into

Operations that walk a value (copying, comparing, serializing, hashing, merging,
diffing, converting, destroying, and writing the binary formats CBOR,
MessagePack, UBJSON, BJData, and BON8) recurse once per nesting level, which is
fastest, but a value nested deeply enough would exhaust the call stack. So they
recurse only this many levels deep and finish whatever lies below with an
explicit stack that lives on the heap. All of them share this limit and none has
a constant of its own. It is the value of the macro JSON_RECURSION_DEPTH_LIMIT,
128 by default. (Parsing, the binary readers, flatten(), unflatten(), and
to_bson() always use an explicit stack and do not read it, and the lockstep
comparison of json_view documents has a fixed bound of its own, 48 levels.)

Most of the operations pass the depth down as an argument. The copy constructor
and the comparison operators cannot, as their signatures are fixed, so they
count it in basic_json::nesting_depth() instead, a byte per thread. Only the
levels that are descended into are counted, so the count never exceeds the limit.
The limit must fit in the byte with some headroom, so that the count cannot wrap
around: it must be below 255, and 254 is the largest value allowed. (More levels
would hardly be useful: 254 levels need up to 576 KiB of stack in an unoptimized
build already, twice the stack of the default.)

The smallest value is 0: every operation then uses its explicit stack from the
first level on and no operation recurses over the nesting of a value at all.
That is slower, but needs a constant amount of call stack. It works because
every use of the limit compares a depth with it (`depth >= limit`, or `<` for
the opposite), which holds for 0 as for any other value; nothing computes
`limit - 1` or `limit + 1`, so nothing wraps around. Each operation's explicit
stack handles any nesting level, including the first, so none of them relies on
having recursed first.

The call stack that an operation needs is roughly a few KiB plus a cost per level
times the limit. At the default of 128 levels, an unoptimized build needs up to
about 290 KiB (`dump()` with Clang at -O0: about 2.3 KiB per level) and an
optimized build up to about 48 KiB; with 254 levels it is up to 576 KiB and
112 KiB, and with 0 it is 16 KiB or less. Lower the limit for threads with small
stacks (RTOS tasks, fibers, musl threads), raise it to trade stack for speed on
deeply nested values. All of this, with the measurements, is in the
documentation of the macro.

@sa https://json.nlohmann.me/api/macros/json_recursion_depth_limit/
@sa https://github.com/nlohmann/json/issues/5387
*/
/// the type of the value of JSON_RECURSION_DEPTH_LIMIT is bool or a character type
template<typename T> struct recursion_depth_limit_is_char_or_bool : std::false_type {};
template<> struct recursion_depth_limit_is_char_or_bool<bool> : std::true_type {};
template<> struct recursion_depth_limit_is_char_or_bool<char> : std::true_type {};
template<> struct recursion_depth_limit_is_char_or_bool<signed char> : std::true_type {};
template<> struct recursion_depth_limit_is_char_or_bool<unsigned char> : std::true_type {};
template<> struct recursion_depth_limit_is_char_or_bool<wchar_t> : std::true_type {};
template<> struct recursion_depth_limit_is_char_or_bool<char16_t> : std::true_type {};
template<> struct recursion_depth_limit_is_char_or_bool<char32_t> : std::true_type {};
#if defined(__cpp_char8_t)
template<> struct recursion_depth_limit_is_char_or_bool<char8_t> : std::true_type {};
#endif

constexpr std::size_t recursion_depth_limit() noexcept
{
    // an integer: not a floating-point number, whose range check would pass for 1.5 or 254.0
    // (bool and the character types are integer types, too, but true, false or 'a' are
    // no way to say a limit; JSON_UBJSON_VALUELESS_ELEMENTS_PER_BYTE refuses them as well)
    static_assert(std::is_integral<decltype(JSON_RECURSION_DEPTH_LIMIT)>::value
                  && !recursion_depth_limit_is_char_or_bool<typename std::remove_cv<decltype(JSON_RECURSION_DEPTH_LIMIT)>::type>::value,
                  "JSON_RECURSION_DEPTH_LIMIT must be an integer constant (not bool or a character type)");
    static_assert(JSON_RECURSION_DEPTH_LIMIT >= 0 && JSON_RECURSION_DEPTH_LIMIT <= 254,
                  "JSON_RECURSION_DEPTH_LIMIT must be between 0 and 254: the nesting depth is counted in a byte per thread "
                  "and may exceed the limit by one (see https://json.nlohmann.me/api/macros/json_recursion_depth_limit/)");
    return static_cast<std::size_t>(JSON_RECURSION_DEPTH_LIMIT);
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
