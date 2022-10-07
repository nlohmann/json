#pragma once

#include <cstdint> // size_t
#include <utility> // declval
#include <string> // string
#include <type_traits>

#include <nlohmann/detail/meta/detected.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>

namespace nlohmann
{
namespace detail
{
template<typename T>
using null_function_t = decltype(std::declval<T&>().null());

template<typename T>
using key_null_function_t = decltype(std::declval<T&>().key_null());


template<typename T>
using boolean_function_t =
    decltype(std::declval<T&>().boolean(std::declval<bool>()));

template<typename T>
using key_boolean_function_t =
    decltype(std::declval<T&>().key_boolean(std::declval<bool>()));


template<typename T, typename Integer>
using number_integer_function_t =
    decltype(std::declval<T&>().number_integer(std::declval<Integer>()));

template<typename T, typename Integer>
using key_number_integer_function_t =
    decltype(std::declval<T&>().key_number_integer(std::declval<Integer>()));


template<typename T, typename Unsigned>
using number_unsigned_function_t =
    decltype(std::declval<T&>().number_unsigned(std::declval<Unsigned>()));

template<typename T, typename Unsigned>
using key_number_unsigned_function_t =
    decltype(std::declval<T&>().key_number_unsigned(std::declval<Unsigned>()));


template<typename T, typename Float, typename String>
using number_float_function_t = decltype(std::declval<T&>().number_float(
                                    std::declval<Float>(), std::declval<const String&>()));

template<typename T, typename Float, typename String>
using key_number_float_function_t = decltype(std::declval<T&>().key_number_float(
                                        std::declval<Float>(), std::declval<const String&>()));


template<typename T, typename String>
using string_function_t =
    decltype(std::declval<T&>().string(std::declval<String&>()));

template<typename T, typename String>
using key_function_t =
    decltype(std::declval<T&>().key(std::declval<String&>()));


template<typename T, typename Binary>
using binary_function_t =
    decltype(std::declval<T&>().binary(std::declval<Binary&>()));

template<typename T, typename Binary>
using key_binary_function_t =
    decltype(std::declval<T&>().key_binary(std::declval<Binary&>()));


template<typename T>
using start_array_function_t =
    decltype(std::declval<T&>().start_array(std::declval<std::size_t>()));

template<typename T>
using start_key_array_function_t =
    decltype(std::declval<T&>().start_key_array(std::declval<std::size_t>()));


template<typename T>
using end_array_function_t = decltype(std::declval<T&>().end_array());

template<typename T>
using end_key_array_function_t = decltype(std::declval<T&>().end_key_array());


template<typename T>
using start_object_function_t =
    decltype(std::declval<T&>().start_object(std::declval<std::size_t>()));

template<typename T>
using start_key_object_function_t =
    decltype(std::declval<T&>().start_key_object(std::declval<std::size_t>()));


template<typename T>
using end_object_function_t = decltype(std::declval<T&>().end_object());

template<typename T>
using end_key_object_function_t = decltype(std::declval<T&>().end_key_object());





template<typename T, typename Exception>
using parse_error_function_t = decltype(std::declval<T&>().parse_error(
        std::declval<std::size_t>(), std::declval<const std::string&>(),
        std::declval<const Exception&>()));

template<typename SAX, typename BasicJsonType, typename IsTrue = conjunction<
             is_detected_exact<bool, null_function_t, SAX>,
             is_detected_exact<bool, boolean_function_t, SAX>,
             is_detected_exact<bool, number_integer_function_t, SAX, typename BasicJsonType::number_integer_t>,
             is_detected_exact<bool, number_unsigned_function_t, SAX, typename BasicJsonType::number_unsigned_t>,
             is_detected_exact<bool, number_float_function_t, SAX, typename BasicJsonType::number_float_t, typename BasicJsonType::string_t>,
             is_detected_exact<bool, string_function_t, SAX, typename BasicJsonType::string_t>,
             is_detected_exact<bool, binary_function_t, SAX, typename BasicJsonType::binary_t>,
             is_detected_exact<bool, key_function_t, SAX, typename BasicJsonType::string_t>,
             is_detected_exact<bool, start_array_function_t, SAX>,
             is_detected_exact<bool, end_array_function_t, SAX>,
             is_detected_exact<bool, start_object_function_t, SAX>,
             is_detected_exact<bool, end_object_function_t, SAX>,
             is_detected_exact<bool, parse_error_function_t, SAX, typename BasicJsonType::exception>
             >
         >
struct is_sax : IsTrue
{
  private:
    static_assert(is_basic_json<BasicJsonType>::value,
                  "BasicJsonType must be of type basic_json<...>");
};


template<typename SAX, typename BasicJsonType, typename IsTrue = conjunction<
             is_sax<SAX, BasicJsonType>,
             is_detected_exact<bool, key_null_function_t, SAX>,
             is_detected_exact<bool, key_boolean_function_t, SAX>,
             is_detected_exact<bool, key_number_integer_function_t, SAX, typename BasicJsonType::number_integer_t>,
             is_detected_exact<bool, key_number_unsigned_function_t, SAX, typename BasicJsonType::number_unsigned_t>,
             is_detected_exact<bool, key_number_float_function_t, SAX, typename BasicJsonType::number_float_t, typename BasicJsonType::string_t>,
             is_detected_exact<bool, key_binary_function_t, SAX, typename BasicJsonType::binary_t>,
             is_detected_exact<bool, start_array_function_t, SAX>,
             is_detected_exact<bool, end_array_function_t, SAX>,
             is_detected_exact<bool, start_key_object_function_t, SAX>,
             is_detected_exact<bool, end_key_object_function_t, SAX>
             >
         >
struct is_sax_msgpack : IsTrue
{
  private:
    static_assert(is_basic_json<BasicJsonType>::value,
                  "BasicJsonType must be of type basic_json<...>");
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
}  // namespace nlohmann
