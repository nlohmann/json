//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.11.2
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint> // size_t
#include <utility> // declval
#include <string> // string

#include <nlohmann/detail/abi_macros.hpp>
#include <nlohmann/detail/meta/detected.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{
// helper struct to call sax->next_token_start
//(we want this functionality as a type to ease passing it as template argument)
struct sax_call_next_token_start_pos_direct
{
    template<typename SAX, typename...Ts>
    static auto call(SAX* sax, Ts&& ...ts)
    -> decltype(sax->next_token_start(std::forward<Ts>(ts)...))
    {
        sax->next_token_start(std::forward<Ts>(ts)...);
    }
};
// helper struct to call sax->next_token_end
// (we want this functionality as a type to ease passing it as template argument)
struct sax_call_next_token_end_pos_direct
{
    template<typename SAX, typename...Ts>
    static auto call(SAX* sax, Ts&& ...ts)
    -> decltype(sax->next_token_end(std::forward<Ts>(ts)...))
    {
        sax->next_token_end(std::forward<Ts>(ts)...);
    }
};

// dispatch the calls to next_token_start next_token_end
// and drop the calls if the sax parser does not support these methods.
//
// DirectCaller can be set to one of sax_call_next_token_{start,end}_pos_direct to
// determine which method is called
template <typename DirectCaller, typename SAX, typename LexOrPos>
struct sax_call_function
{
    // is the parameter a lexer or a byte position
    static constexpr bool called_with_byte_pos = std::is_same<LexOrPos, std::size_t>::value;

    template<typename SAX2, typename...Ts2>
    using call_t = decltype(DirectCaller::call(std::declval<SAX2*>(), std::declval<Ts2>()...));

    //the sax parser supports calls with a position
    static constexpr bool detected_call_with_byte_pos =
        is_detected_exact<void, call_t, SAX, std::size_t>::value;

    //the sax parser supports calls with a lexer
    static constexpr bool detected_call_with_lex_pos =
        !called_with_byte_pos &&
        is_detected_exact<void, call_t, SAX, const position_t >::value;

    //there either has to be a version accepting a lexer or a position
    static constexpr bool valid = detected_call_with_byte_pos || detected_call_with_lex_pos;

    //called with byte pos and byte pos is method supported -> pass data on
    template<typename SaxT = SAX>
    static typename std::enable_if <
    std::is_same<SaxT, SAX>::value &&
    valid &&
    detected_call_with_byte_pos
    >::type
    call(SaxT* sax, std::size_t pos)
    {
        DirectCaller::call(sax, pos);
    }

    //the sax parser has no version of the method -> drop call
    template<typename SaxT = SAX>
    static typename std::enable_if <
    std::is_same<SaxT, SAX>::value &&
    !valid
    >::type
    call(SaxT* /*unused*/, const LexOrPos& /*unused*/) {}

    //called with lex and lex pos method is supported -> call with position from lexer
    // the start pos in the lexer is last read char -> chars_read_total-1
    template<typename SaxT = SAX>
    static typename std::enable_if <
    std::is_same<SaxT, SAX>::value &&
    valid &&
    !called_with_byte_pos &&
    detected_call_with_lex_pos &&
    std::is_same<DirectCaller, sax_call_next_token_start_pos_direct>::value
    >::type
    call(SaxT* sax, const LexOrPos& lex)
    {
        JSON_ASSERT(lex.get_position().chars_read_total > 0);
        JSON_ASSERT(lex.get_position().chars_read_current_line > 0);
        //the lexer has already read the first char of the current element -> fix this
        auto pos_copy = lex.get_position();
        --pos_copy.chars_read_total;
        --pos_copy.chars_read_current_line;
        DirectCaller::call(sax, pos_copy);
    }

    //called with lex and lex pos method is supported -> pass data on
    // the one past end pos in the lexer is the current index -> chars_read_total
    template<typename SaxT = SAX>
    static typename std::enable_if <
    std::is_same<SaxT, SAX>::value &&
    valid &&
    !called_with_byte_pos &&
    detected_call_with_lex_pos &&
    std::is_same<DirectCaller, sax_call_next_token_end_pos_direct>::value
    >::type
    call(SaxT* sax, const LexOrPos& lex)
    {
        DirectCaller::call(sax, lex.get_position());
    }

    // called with lex and only byte pos method is supported -> call with byte position from lexer
    // the start pos in the lexer is last read char -> chars_read_total-1
    template<typename SaxT = SAX>
    static typename std::enable_if <
    std::is_same<SaxT, SAX>::value &&
    valid &&
    !called_with_byte_pos &&
    !detected_call_with_lex_pos &&
    std::is_same<DirectCaller, sax_call_next_token_start_pos_direct>::value
    >::type
    call(SaxT* sax, const LexOrPos& lex)
    {
        JSON_ASSERT(lex.get_position().chars_read_total > 0);
        DirectCaller::call(sax, lex.get_position().chars_read_total - 1);
    }

    // called with lex and only byte pos method is supported -> call with byte position from lexer
    // the one past end pos in the lexer is the current index -> chars_read_total
    template<typename SaxT = SAX>
    static typename std::enable_if <
    std::is_same<SaxT, SAX>::value &&
    valid &&
    !called_with_byte_pos &&
    !detected_call_with_lex_pos &&
    std::is_same<DirectCaller, sax_call_next_token_end_pos_direct>::value
    >::type
    call(SaxT* sax, const LexOrPos& lex)
    {
        DirectCaller::call(sax, lex.get_position().chars_read_total);
    }
};

//set the element start pos of a sax parser by calling any version of sax->next_token_start (if available)
template<class SAX, class LexOrPos>
void sax_call_next_token_start_pos(SAX* sax, const LexOrPos& lexOrPos)
{
    using call_t = sax_call_function<sax_call_next_token_start_pos_direct, SAX, LexOrPos>;
    call_t::call(sax, lexOrPos);
}
//set the element end pos of a sax parser by calling any version of sax->next_token_end (if available)
template<class SAX, class LexOrPos>
void sax_call_next_token_end_pos(SAX* sax, const LexOrPos& lexOrPos)
{
    using call_t = sax_call_function<sax_call_next_token_end_pos_direct, SAX, LexOrPos>;
    call_t::call(sax, lexOrPos);
}
//set the element start end pos of a sax parser by calling any version of
// sax->next_token_start and sax->next_token_end (if available)
template<class SAX, class LexOrPos1, class LexOrPos2>
void sax_call_next_token_start_end_pos(SAX* sax, const LexOrPos1& lexOrPos1, const LexOrPos2& lexOrPos2)
{
    sax_call_next_token_start_pos(sax, lexOrPos1);
    sax_call_next_token_end_pos(sax, lexOrPos2);
}
//set the element start end pos of a sax parser by calling any version of
// sax->next_token_start and sax->next_token_end (if available)
template<class SAX, class LexOrPos>
void sax_call_next_token_start_end_pos(SAX* sax, const LexOrPos& lexOrPos)
{
    sax_call_next_token_start_pos(sax, lexOrPos);
    sax_call_next_token_end_pos(sax, lexOrPos);
}



template<typename T>
using null_function_t = decltype(std::declval<T&>().null());

template<typename T>
using boolean_function_t =
    decltype(std::declval<T&>().boolean(std::declval<bool>()));

template<typename T, typename Integer>
using number_integer_function_t =
    decltype(std::declval<T&>().number_integer(std::declval<Integer>()));

template<typename T, typename Unsigned>
using number_unsigned_function_t =
    decltype(std::declval<T&>().number_unsigned(std::declval<Unsigned>()));

template<typename T, typename Float, typename String>
using number_float_function_t = decltype(std::declval<T&>().number_float(
                                    std::declval<Float>(), std::declval<const String&>()));

template<typename T, typename String>
using string_function_t =
    decltype(std::declval<T&>().string(std::declval<String&>()));

template<typename T, typename Binary>
using binary_function_t =
    decltype(std::declval<T&>().binary(std::declval<Binary&>()));

template<typename T>
using start_object_function_t =
    decltype(std::declval<T&>().start_object(std::declval<std::size_t>()));

template<typename T, typename String>
using key_function_t =
    decltype(std::declval<T&>().key(std::declval<String&>()));

template<typename T>
using end_object_function_t = decltype(std::declval<T&>().end_object());

template<typename T>
using start_array_function_t =
    decltype(std::declval<T&>().start_array(std::declval<std::size_t>()));

template<typename T>
using end_array_function_t = decltype(std::declval<T&>().end_array());

template<typename T, typename Exception>
using parse_error_function_t = decltype(std::declval<T&>().parse_error(
        std::declval<std::size_t>(), std::declval<const std::string&>(),
        std::declval<const Exception&>()));

template<typename SAX, typename BasicJsonType>
struct is_sax
{
  private:
    static_assert(is_basic_json<BasicJsonType>::value,
                  "BasicJsonType must be of type basic_json<...>");

    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using binary_t = typename BasicJsonType::binary_t;
    using exception_t = typename BasicJsonType::exception;

  public:
    static constexpr bool value =
        is_detected_exact<bool, null_function_t, SAX>::value &&
        is_detected_exact<bool, boolean_function_t, SAX>::value &&
        is_detected_exact<bool, number_integer_function_t, SAX, number_integer_t>::value &&
        is_detected_exact<bool, number_unsigned_function_t, SAX, number_unsigned_t>::value &&
        is_detected_exact<bool, number_float_function_t, SAX, number_float_t, string_t>::value &&
        is_detected_exact<bool, string_function_t, SAX, string_t>::value &&
        is_detected_exact<bool, binary_function_t, SAX, binary_t>::value &&
        is_detected_exact<bool, start_object_function_t, SAX>::value &&
        is_detected_exact<bool, key_function_t, SAX, string_t>::value &&
        is_detected_exact<bool, end_object_function_t, SAX>::value &&
        is_detected_exact<bool, start_array_function_t, SAX>::value &&
        is_detected_exact<bool, end_array_function_t, SAX>::value &&
        is_detected_exact<bool, parse_error_function_t, SAX, exception_t>::value;
};

template<typename SAX, typename BasicJsonType>
struct is_sax_static_asserts
{
  private:
    static_assert(is_basic_json<BasicJsonType>::value,
                  "BasicJsonType must be of type basic_json<...>");

    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;
    using string_t = typename BasicJsonType::string_t;
    using binary_t = typename BasicJsonType::binary_t;
    using exception_t = typename BasicJsonType::exception;

  public:
    static_assert(is_detected_exact<bool, null_function_t, SAX>::value,
                  "Missing/invalid function: bool null()");
    static_assert(is_detected_exact<bool, boolean_function_t, SAX>::value,
                  "Missing/invalid function: bool boolean(bool)");
    static_assert(is_detected_exact<bool, boolean_function_t, SAX>::value,
                  "Missing/invalid function: bool boolean(bool)");
    static_assert(
        is_detected_exact<bool, number_integer_function_t, SAX,
        number_integer_t>::value,
        "Missing/invalid function: bool number_integer(number_integer_t)");
    static_assert(
        is_detected_exact<bool, number_unsigned_function_t, SAX,
        number_unsigned_t>::value,
        "Missing/invalid function: bool number_unsigned(number_unsigned_t)");
    static_assert(is_detected_exact<bool, number_float_function_t, SAX,
                  number_float_t, string_t>::value,
                  "Missing/invalid function: bool number_float(number_float_t, const string_t&)");
    static_assert(
        is_detected_exact<bool, string_function_t, SAX, string_t>::value,
        "Missing/invalid function: bool string(string_t&)");
    static_assert(
        is_detected_exact<bool, binary_function_t, SAX, binary_t>::value,
        "Missing/invalid function: bool binary(binary_t&)");
    static_assert(is_detected_exact<bool, start_object_function_t, SAX>::value,
                  "Missing/invalid function: bool start_object(std::size_t)");
    static_assert(is_detected_exact<bool, key_function_t, SAX, string_t>::value,
                  "Missing/invalid function: bool key(string_t&)");
    static_assert(is_detected_exact<bool, end_object_function_t, SAX>::value,
                  "Missing/invalid function: bool end_object()");
    static_assert(is_detected_exact<bool, start_array_function_t, SAX>::value,
                  "Missing/invalid function: bool start_array(std::size_t)");
    static_assert(is_detected_exact<bool, end_array_function_t, SAX>::value,
                  "Missing/invalid function: bool end_array()");
    static_assert(
        is_detected_exact<bool, parse_error_function_t, SAX, exception_t>::value,
        "Missing/invalid function: bool parse_error(std::size_t, const "
        "std::string&, const exception&)");
};

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
