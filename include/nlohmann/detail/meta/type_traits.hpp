#pragma once

#include <ciso646> // not
#include <limits> // numeric_limits
#include <type_traits> // false_type, is_constructible, is_integral, is_same, true_type
#include <utility> // declval

#include <nlohmann/json_fwd.hpp>
#include <nlohmann/detail/meta/cpp_future.hpp>
#include <nlohmann/detail/meta/detected.hpp>
#include <nlohmann/detail/macro_scope.hpp>

namespace nlohmann
{
/*!
@brief detail namespace with internal helper functions

This namespace collects functions that should not be exposed,
implementations of some @ref basic_json methods, and meta-programming helpers.

@since version 2.1.0
*/
namespace detail
{
/////////////
// helpers //
/////////////

template<typename> struct is_basic_json : std::false_type {};

NLOHMANN_BASIC_JSON_TPL_DECLARATION
struct is_basic_json<NLOHMANN_BASIC_JSON_TPL> : std::true_type {};

//////////////////////////
// aliases for detected //
//////////////////////////

template <typename T>
using mapped_type_t = typename T::mapped_type;

template <typename T>
using key_type_t = typename T::key_type;

template <typename T>
using value_type_t = typename T::value_type;

template <typename T>
using iterator_t = typename T::iterator;

template <typename T, typename... Args>
using to_json_function = decltype(T::to_json(std::declval<Args>()...));

template <typename T, typename... Args>
using from_json_function = decltype(T::from_json(std::declval<Args>()...));

///////////////////
// is_ functions //
///////////////////

// source: https://stackoverflow.com/a/37193089/4116453

template <typename T, typename = void>
struct is_complete_type : std::false_type {};

template <typename T>
struct is_complete_type<T, decltype(void(sizeof(T)))> : std::true_type {};

template <typename BasicJsonType, typename CompatibleObjectType,
          typename = void>
struct is_compatible_object_type_impl : std::false_type {};

template <typename BasicJsonType, typename CompatibleObjectType>
struct is_compatible_object_type_impl <
    BasicJsonType, CompatibleObjectType,
    enable_if_t<is_detected<mapped_type_t, CompatibleObjectType>::value and
    is_detected<key_type_t, CompatibleObjectType>::value >>
{

    using object_t = typename BasicJsonType::object_t;

    // macOS's is_constructible does not play well with nonesuch...
    static constexpr bool value =
        std::is_constructible<typename object_t::key_type,
        typename CompatibleObjectType::key_type>::value and
        std::is_constructible<typename object_t::mapped_type,
        typename CompatibleObjectType::mapped_type>::value;
};

template <typename BasicJsonType, typename CompatibleObjectType>
struct is_compatible_object_type
    : is_compatible_object_type_impl<BasicJsonType, CompatibleObjectType> {};

template <typename BasicJsonType, typename CompatibleStringType,
          typename = void>
struct is_compatible_string_type_impl : std::false_type {};

template <typename BasicJsonType, typename CompatibleStringType>
struct is_compatible_string_type_impl <
    BasicJsonType, CompatibleStringType,
    enable_if_t<is_detected_exact<typename BasicJsonType::string_t::value_type,
    value_type_t, CompatibleStringType>::value >>
{
    static constexpr auto value =
        std::is_constructible<typename BasicJsonType::string_t, CompatibleStringType>::value;
};

template <typename BasicJsonType, typename CompatibleStringType>
struct is_compatible_string_type
    : is_compatible_string_type_impl<BasicJsonType, CompatibleStringType> {};

template<typename BasicJsonType, typename T>
struct is_basic_json_nested_type
{
    static auto constexpr value = std::is_same<T, typename BasicJsonType::iterator>::value or
                                  std::is_same<T, typename BasicJsonType::const_iterator>::value or
                                  std::is_same<T, typename BasicJsonType::reverse_iterator>::value or
                                  std::is_same<T, typename BasicJsonType::const_reverse_iterator>::value;
};

template <typename BasicJsonType, typename CompatibleArrayType, typename = void>
struct is_compatible_array_type_impl : std::false_type {};

template <typename BasicJsonType, typename CompatibleArrayType>
struct is_compatible_array_type_impl <
    BasicJsonType, CompatibleArrayType,
    enable_if_t<is_detected<value_type_t, CompatibleArrayType>::value and
    is_detected<iterator_t, CompatibleArrayType>::value >>
{
    static constexpr auto value = not(
                                      is_compatible_object_type<BasicJsonType, CompatibleArrayType>::value or
                                      std::is_constructible<typename BasicJsonType::string_t,
                                      CompatibleArrayType>::value or
                                      is_basic_json_nested_type<BasicJsonType, CompatibleArrayType>::value);
};

template <typename BasicJsonType, typename CompatibleArrayType>
struct is_compatible_array_type
    : is_compatible_array_type_impl<BasicJsonType, CompatibleArrayType> {};

template <typename RealIntegerType, typename CompatibleNumberIntegerType,
          typename = void>
struct is_compatible_integer_type_impl : std::false_type {};

template <typename RealIntegerType, typename CompatibleNumberIntegerType>
struct is_compatible_integer_type_impl <
    RealIntegerType, CompatibleNumberIntegerType,
    enable_if_t<std::is_integral<RealIntegerType>::value and
    std::is_integral<CompatibleNumberIntegerType>::value and
    not std::is_same<bool, CompatibleNumberIntegerType>::value >>
{
    // is there an assert somewhere on overflows?
    using RealLimits = std::numeric_limits<RealIntegerType>;
    using CompatibleLimits = std::numeric_limits<CompatibleNumberIntegerType>;

    static constexpr auto value =
        std::is_constructible<RealIntegerType,
        CompatibleNumberIntegerType>::value and
        CompatibleLimits::is_integer and
        RealLimits::is_signed == CompatibleLimits::is_signed;
};

template <typename RealIntegerType, typename CompatibleNumberIntegerType>
struct is_compatible_integer_type
    : is_compatible_integer_type_impl<RealIntegerType,
      CompatibleNumberIntegerType> {};

// trait checking if JSONSerializer<T>::from_json(json const&, udt&) exists
template<typename BasicJsonType, typename T>
struct has_from_json
{
    using serializer = typename BasicJsonType::template json_serializer<T, void>;

    static constexpr bool value =
        is_detected_exact<void, from_json_function, serializer,
        const BasicJsonType&, T&>::value;
};

// This trait checks if JSONSerializer<T>::from_json(json const&) exists
// this overload is used for non-default-constructible user-defined-types
template<typename BasicJsonType, typename T>
struct has_non_default_from_json
{
    using serializer = typename BasicJsonType::template json_serializer<T, void>;

    static constexpr bool value =
        is_detected_exact<T, from_json_function, serializer,
        const BasicJsonType&>::value;
};

// This trait checks if BasicJsonType::json_serializer<T>::to_json exists
template<typename BasicJsonType, typename T>
struct has_to_json
{
    using serializer = typename BasicJsonType::template json_serializer<T, void>;

    static constexpr bool value =
        is_detected_exact<void, to_json_function, serializer, BasicJsonType&,
        T>::value;
};

template <typename BasicJsonType, typename CompatibleCompleteType>
struct is_compatible_complete_type
{
    static constexpr bool value =
        not std::is_base_of<std::istream, CompatibleCompleteType>::value and
        not is_basic_json<CompatibleCompleteType>::value and
        not is_basic_json_nested_type<BasicJsonType, CompatibleCompleteType>::value and
        has_to_json<BasicJsonType, CompatibleCompleteType>::value;
};

template <typename BasicJsonType, typename CompatibleType>
struct is_compatible_type
    : conjunction<is_complete_type<CompatibleType>,
      is_compatible_complete_type<BasicJsonType, CompatibleType>>
{
};
}
}
