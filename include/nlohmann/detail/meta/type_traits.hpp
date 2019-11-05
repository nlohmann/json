#pragma once

#include <ciso646> // not
#include <limits> // numeric_limits
#include <type_traits> // false_type, is_constructible, is_integral, is_same, true_type
#include <utility> // declval

#include <nlohmann/detail/iterators/iterator_traits.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/cpp_future.hpp>
#include <nlohmann/detail/meta/detected.hpp>
#include <nlohmann/json_fwd.hpp>

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

// Note to maintainers:
//
// Every trait in this file expects a non CV-qualified type.
// The only exceptions are in the 'aliases for detected' section
// (i.e. those of the form: decltype(T::member_function(std::declval<T>())))
//
// In this case, T has to be properly CV-qualified to constraint the function arguments
// (e.g. to_json(BasicJsonType&, const T&))

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
using difference_type_t = typename T::difference_type;

template <typename T>
using pointer_t = typename T::pointer;

template <typename T>
using reference_t = typename T::reference;

template <typename T>
using iterator_category_t = typename T::iterator_category;

template <typename T>
using iterator_t = typename T::iterator;

template <typename T, typename... Args>
using to_json_function = decltype(T::to_json(std::declval<Args>()...));

template <typename T, typename... Args>
using from_json_function = decltype(T::from_json(std::declval<Args>()...));

template <typename T, typename U>
using get_template_function = decltype(std::declval<T>().template get<U>());

// trait checking if JSONSerializer<T>::from_json(json const&, udt&) exists
template <typename BasicJsonType, typename T, typename = void>
struct has_from_json : std::false_type {};

template <typename BasicJsonType, typename T>
struct has_from_json<BasicJsonType, T,
           enable_if_t<not is_basic_json<T>::value>>
{
    using serializer = typename BasicJsonType::template json_serializer<T, void>;

    static constexpr bool value =
        is_detected_exact<void, from_json_function, serializer,
        const BasicJsonType&, T&>::value;
};

// This trait checks if JSONSerializer<T>::from_json(json const&) exists
// this overload is used for non-default-constructible user-defined-types
template <typename BasicJsonType, typename T, typename = void>
struct has_non_default_from_json : std::false_type {};

template<typename BasicJsonType, typename T>
struct has_non_default_from_json<BasicJsonType, T, enable_if_t<not is_basic_json<T>::value>>
{
    using serializer = typename BasicJsonType::template json_serializer<T, void>;

    static constexpr bool value =
        is_detected_exact<T, from_json_function, serializer,
        const BasicJsonType&>::value;
};

// This trait checks if BasicJsonType::json_serializer<T>::to_json exists
// Do not evaluate the trait when T is a basic_json type, to avoid template instantiation infinite recursion.
template <typename BasicJsonType, typename T, typename = void>
struct has_to_json : std::false_type {};

template <typename BasicJsonType, typename T>
struct has_to_json<BasicJsonType, T, enable_if_t<not is_basic_json<T>::value>>
{
    using serializer = typename BasicJsonType::template json_serializer<T, void>;

    static constexpr bool value =
        is_detected_exact<void, to_json_function, serializer, BasicJsonType&,
        T>::value;
};


///////////////////
// is_ functions //
///////////////////

template <typename T, typename = void>
struct is_iterator_traits : std::false_type {};

template <typename T>
struct is_iterator_traits<iterator_traits<T>>
{
  private:
    using traits = iterator_traits<T>;

  public:
    static constexpr auto value =
        is_detected<value_type_t, traits>::value &&
        is_detected<difference_type_t, traits>::value &&
        is_detected<pointer_t, traits>::value &&
        is_detected<iterator_category_t, traits>::value &&
        is_detected<reference_t, traits>::value;
};

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

template <typename BasicJsonType, typename ConstructibleObjectType,
          typename = void>
struct is_constructible_object_type_impl : std::false_type {};

template <typename BasicJsonType, typename ConstructibleObjectType>
struct is_constructible_object_type_impl <
    BasicJsonType, ConstructibleObjectType,
    enable_if_t<is_detected<mapped_type_t, ConstructibleObjectType>::value and
    is_detected<key_type_t, ConstructibleObjectType>::value >>
{
    using object_t = typename BasicJsonType::object_t;

    static constexpr bool value =
        (std::is_default_constructible<ConstructibleObjectType>::value and
         (std::is_move_assignable<ConstructibleObjectType>::value or
          std::is_copy_assignable<ConstructibleObjectType>::value) and
         (std::is_constructible<typename ConstructibleObjectType::key_type,
          typename object_t::key_type>::value and
          std::is_same <
          typename object_t::mapped_type,
          typename ConstructibleObjectType::mapped_type >::value)) or
        (has_from_json<BasicJsonType,
         typename ConstructibleObjectType::mapped_type>::value or
         has_non_default_from_json <
         BasicJsonType,
         typename ConstructibleObjectType::mapped_type >::value);
};

template <typename BasicJsonType, typename ConstructibleObjectType>
struct is_constructible_object_type
    : is_constructible_object_type_impl<BasicJsonType,
      ConstructibleObjectType> {};

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

template <typename BasicJsonType, typename ConstructibleStringType>
struct is_compatible_string_type
    : is_compatible_string_type_impl<BasicJsonType, ConstructibleStringType> {};

template <typename BasicJsonType, typename ConstructibleStringType,
          typename = void>
struct is_constructible_string_type_impl : std::false_type {};

template <typename BasicJsonType, typename ConstructibleStringType>
struct is_constructible_string_type_impl <
    BasicJsonType, ConstructibleStringType,
    enable_if_t<is_detected_exact<typename BasicJsonType::string_t::value_type,
    value_type_t, ConstructibleStringType>::value >>
{
    static constexpr auto value =
        std::is_constructible<ConstructibleStringType,
        typename BasicJsonType::string_t>::value;
};

template <typename BasicJsonType, typename ConstructibleStringType>
struct is_constructible_string_type
    : is_constructible_string_type_impl<BasicJsonType, ConstructibleStringType> {};

template <typename BasicJsonType, typename CompatibleArrayType, typename = void>
struct is_compatible_array_type_impl : std::false_type {};

template <typename BasicJsonType, typename CompatibleArrayType>
struct is_compatible_array_type_impl <
    BasicJsonType, CompatibleArrayType,
    enable_if_t<is_detected<value_type_t, CompatibleArrayType>::value and
    is_detected<iterator_t, CompatibleArrayType>::value and
// This is needed because json_reverse_iterator has a ::iterator type...
// Therefore it is detected as a CompatibleArrayType.
// The real fix would be to have an Iterable concept.
    not is_iterator_traits<
    iterator_traits<CompatibleArrayType>>::value >>
{
    static constexpr bool value =
        std::is_constructible<BasicJsonType,
        typename CompatibleArrayType::value_type>::value;
};

template <typename BasicJsonType, typename CompatibleArrayType>
struct is_compatible_array_type
    : is_compatible_array_type_impl<BasicJsonType, CompatibleArrayType> {};

template <typename BasicJsonType, typename ConstructibleArrayType, typename = void>
struct is_constructible_array_type_impl : std::false_type {};

template <typename BasicJsonType, typename ConstructibleArrayType>
struct is_constructible_array_type_impl <
    BasicJsonType, ConstructibleArrayType,
    enable_if_t<std::is_same<ConstructibleArrayType,
    typename BasicJsonType::value_type>::value >>
            : std::true_type {};

template <typename BasicJsonType, typename ConstructibleArrayType>
struct is_constructible_array_type_impl <
    BasicJsonType, ConstructibleArrayType,
    enable_if_t<not std::is_same<ConstructibleArrayType,
    typename BasicJsonType::value_type>::value and
    std::is_default_constructible<ConstructibleArrayType>::value and
(std::is_move_assignable<ConstructibleArrayType>::value or
 std::is_copy_assignable<ConstructibleArrayType>::value) and
is_detected<value_type_t, ConstructibleArrayType>::value and
is_detected<iterator_t, ConstructibleArrayType>::value and
is_complete_type<
detected_t<value_type_t, ConstructibleArrayType>>::value >>
{
    static constexpr bool value =
        // This is needed because json_reverse_iterator has a ::iterator type,
        // furthermore, std::back_insert_iterator (and other iterators) have a
        // base class `iterator`... Therefore it is detected as a
        // ConstructibleArrayType. The real fix would be to have an Iterable
        // concept.
        not is_iterator_traits<iterator_traits<ConstructibleArrayType>>::value and

        (std::is_same<typename ConstructibleArrayType::value_type,
         typename BasicJsonType::array_t::value_type>::value or
         has_from_json<BasicJsonType,
         typename ConstructibleArrayType::value_type>::value or
         has_non_default_from_json <
         BasicJsonType, typename ConstructibleArrayType::value_type >::value);
};

template <typename BasicJsonType, typename ConstructibleArrayType>
struct is_constructible_array_type
    : is_constructible_array_type_impl<BasicJsonType, ConstructibleArrayType> {};

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

template <typename BasicJsonType, typename CompatibleType, typename = void>
struct is_compatible_type_impl: std::false_type {};

template <typename BasicJsonType, typename CompatibleType>
struct is_compatible_type_impl <
    BasicJsonType, CompatibleType,
    enable_if_t<is_complete_type<CompatibleType>::value >>
{
    static constexpr bool value =
        has_to_json<BasicJsonType, CompatibleType>::value;
};

template <typename BasicJsonType, typename CompatibleType>
struct is_compatible_type
    : is_compatible_type_impl<BasicJsonType, CompatibleType> {};

// https://en.cppreference.com/w/cpp/types/conjunction
template<class...> struct conjunction : std::true_type { };
template<class B1> struct conjunction<B1> : B1 { };
template<class B1, class... Bn>
struct conjunction<B1, Bn...>
: std::conditional<bool(B1::value), conjunction<Bn...>, B1>::type {};

template <typename T1, typename T2>
struct is_constructible_tuple : std::false_type {};

template <typename T1, typename... Args>
struct is_constructible_tuple<T1, std::tuple<Args...>> : conjunction<std::is_constructible<T1, Args>...> {};
}  // namespace detail
}  // namespace nlohmann
