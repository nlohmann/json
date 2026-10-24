//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <algorithm> // min, transform
#include <array> // array
#include <forward_list> // forward_list
#include <iterator> // inserter, front_inserter, end
#include <map> // map
#include <string> // string
#include <tuple> // tuple, make_tuple
#include <type_traits> // is_arithmetic, is_same, is_enum, underlying_type, is_convertible
#include <unordered_map> // unordered_map
#include <utility> // pair, declval
#include <valarray> // valarray
#include <vector> // vector

#include <nlohmann/detail/exceptions.hpp>
#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/cpp_future.hpp>
#include <nlohmann/detail/meta/identity_tag.hpp>
#include <nlohmann/detail/meta/std_fs.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>
#include <nlohmann/detail/string_concat.hpp>
#include <nlohmann/detail/value_t.hpp>

// include after macro_scope.hpp
#ifdef JSON_HAS_CPP_17
    #include <optional> // optional
#endif

#if JSON_HAS_FILESYSTEM || JSON_HAS_EXPERIMENTAL_FILESYSTEM
    #include <string_view> // u8string_view
#endif

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

template<typename BasicJsonType>
inline void from_json(const BasicJsonType& j, typename std::nullptr_t& n)
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_null()))
    {
        throw_type_must_be("null", j);
    }
    n = nullptr;
}

#ifdef JSON_HAS_CPP_17
template < typename BasicJsonType, typename T,
           typename std::enable_if < !nlohmann::detail::is_basic_json<T>::value, int >::type = 0 >
void from_json(const BasicJsonType& j, std::optional<T>& opt)
{
    if (j.is_null())
    {
        opt = std::nullopt;
    }
    else
    {
        opt.emplace(j.template get<T>());
    }
}
#endif // JSON_HAS_CPP_17

// read a number value of any of the three number types into val;
// returns false (leaving val untouched) if j is not a number
template<typename BasicJsonType, typename ArithmeticType>
bool get_number_value(const BasicJsonType& j, ArithmeticType& val)
{
    switch (static_cast<value_t>(j))
    {
        case value_t::number_unsigned:
        {
            // never null: a basic_json whose number_unsigned_t is number_integer_t
            // stores no number_unsigned values (#2573)
            const auto* ptr = j.template get_ptr<const typename BasicJsonType::number_unsigned_t*>();
            JSON_ASSERT(ptr != nullptr);
            val = static_cast<ArithmeticType>(*ptr);
            return true;
        }
        case value_t::number_integer:
        {
            val = static_cast<ArithmeticType>(*j.template get_ptr<const typename BasicJsonType::number_integer_t*>());
            return true;
        }
        case value_t::number_float:
        {
            val = static_cast<ArithmeticType>(*j.template get_ptr<const typename BasicJsonType::number_float_t*>());
            return true;
        }

        case value_t::null:
        case value_t::object:
        case value_t::array:
        case value_t::string:
        case value_t::boolean:
        case value_t::binary:
        case value_t::discarded:
        default:
            return false;
    }
}

// overloads for basic_json template parameters
template < typename BasicJsonType, typename ArithmeticType,
           enable_if_t < std::is_arithmetic<ArithmeticType>::value&&
                         !std::is_same<ArithmeticType, typename BasicJsonType::boolean_t>::value,
                         int > = 0 >
void get_arithmetic_value(const BasicJsonType& j, ArithmeticType& val)
{
    if (JSON_HEDLEY_UNLIKELY(!get_number_value(j, val)))
    {
        throw_type_must_be("number", j);
    }
}

template<typename BasicJsonType>
inline void from_json(const BasicJsonType& j, typename BasicJsonType::boolean_t& b)
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_boolean()))
    {
        throw_type_must_be("boolean", j);
    }
    b = *j.template get_ptr<const typename BasicJsonType::boolean_t*>();
}

template<typename BasicJsonType>
inline void from_json(const BasicJsonType& j, typename BasicJsonType::string_t& s)
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_string()))
    {
        throw_type_must_be("string", j);
    }
    s = *j.template get_ptr<const typename BasicJsonType::string_t*>();
}

template <
    typename BasicJsonType, typename StringType,
    enable_if_t <
        std::is_assignable<StringType&, const typename BasicJsonType::string_t>::value
        && is_detected_exact<typename BasicJsonType::string_t::value_type, value_type_t, StringType>::value
        && !std::is_same<typename BasicJsonType::string_t, StringType>::value
        && !is_json_ref<StringType>::value, int > = 0 >
inline void from_json(const BasicJsonType& j, StringType& s)
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_string()))
    {
        throw_type_must_be("string", j);
    }

    s = *j.template get_ptr<const typename BasicJsonType::string_t*>();
}

template<typename BasicJsonType>
inline void from_json(const BasicJsonType& j, typename BasicJsonType::number_float_t& val)
{
    get_arithmetic_value(j, val);
}

template<typename BasicJsonType>
inline void from_json(const BasicJsonType& j, number_unsigned_overload_t<BasicJsonType>& val)
{
    get_arithmetic_value(j, val);
}

template<typename BasicJsonType>
inline void from_json(const BasicJsonType& j, typename BasicJsonType::number_integer_t& val)
{
    get_arithmetic_value(j, val);
}

#if !JSON_DISABLE_ENUM_SERIALIZATION
template<typename BasicJsonType, typename EnumType,
         enable_if_t<std::is_enum<EnumType>::value, int> = 0>
inline void from_json(const BasicJsonType& j, EnumType& e)
{
    using underlying_type = typename std::underlying_type<EnumType>::type;
    // get_arithmetic_value() does not accept boolean_t; read the number that to_json() wrote instead
    using value_type = typename std::conditional<std::is_same<underlying_type, typename BasicJsonType::boolean_t>::value,
          typename BasicJsonType::number_unsigned_t, underlying_type>::type;
    value_type val;
    get_arithmetic_value(j, val);
    e = static_cast<EnumType>(bool_aware_static_cast<underlying_type>(val));
}
#endif  // JSON_DISABLE_ENUM_SERIALIZATION

// forward_list doesn't have an insert method
template<typename BasicJsonType, typename T, typename Allocator,
         enable_if_t<is_getable<BasicJsonType, T>::value, int> = 0>
inline void from_json(const BasicJsonType& j, std::forward_list<T, Allocator>& l)
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_array()))
    {
        throw_type_must_be("array", j);
    }
    l.clear();
    std::transform(j.rbegin(), j.rend(),
                   std::front_inserter(l), [](const BasicJsonType & i)
    {
        return i.template get<T>();
    });
}

// valarray doesn't have an insert method
template<typename BasicJsonType, typename T,
         enable_if_t<is_getable<BasicJsonType, T>::value, int> = 0>
inline void from_json(const BasicJsonType& j, std::valarray<T>& l)
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_array()))
    {
        throw_type_must_be("array", j);
    }
    l.resize(j.size());
    std::transform(j.begin(), j.end(), std::begin(l),
                   [](const BasicJsonType & elem)
    {
        return elem.template get<T>();
    });
}

// element is not itself a C array: read it directly
template<typename BasicJsonType, typename T>
auto from_json_c_array_element(const BasicJsonType& j, T& e)
-> decltype(e = j.template get<T>(), void())
{
    e = j.template get<T>();
}

// element is itself a C array: recurse one dimension at a time, so any rank is supported
template<typename BasicJsonType, typename T, std::size_t N>
void from_json_c_array_element(const BasicJsonType& j, T (&arr)[N])  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
{
    for (std::size_t i = 0; i < N; ++i)
    {
        from_json_c_array_element(j.at(i), arr[i]);
    }
}

template<typename BasicJsonType, typename T, std::size_t N>
auto from_json(const BasicJsonType& j, T (&arr)[N])  // NOLINT(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
-> decltype(j.template get<typename std::remove_all_extents<T>::type>(), void())
{
    from_json_c_array_element(j, arr);
}

template<typename BasicJsonType>
inline void from_json_array_impl(const BasicJsonType& j, typename BasicJsonType::array_t& arr, priority_tag<3> /*unused*/)
{
    arr = *j.template get_ptr<const typename BasicJsonType::array_t*>();
}

// fill a std::array from the JSON array j: the size is checked once and the
// elements are read in order, so a short array converts the elements it has and
// then throws the out_of_range error at() would throw for the first missing one
template<typename BasicJsonType, typename T, std::size_t N>
void from_json_std_array(const BasicJsonType& j, std::array<T, N>& arr)
{
    const auto& inner_array = *j.template get_ptr<const typename BasicJsonType::array_t*>();
    const std::size_t size = (std::min)(N, inner_array.size());
    for (std::size_t i = 0; i < size; ++i)
    {
        arr[i] = inner_array[i].template get<T>();
    }
    if (JSON_HEDLEY_UNLIKELY(size < N))
    {
        static_cast<void>(j.at(size));
    }
}

template<typename BasicJsonType, typename T, std::size_t N>
auto from_json_array_impl(const BasicJsonType& j, std::array<T, N>& arr,
                          priority_tag<2> /*unused*/)
-> decltype(j.template get<T>(), void())
{
    from_json_std_array(j, arr);
}

// reserve() is called through this pair (used for arrays and objects alike)
// so from_json_array_impl and the object from_json have a single body for both
// containers that support reserve() and those that don't.
template<typename ConstructibleContainerType>
auto reserve_if_possible(ConstructibleContainerType& c, typename ConstructibleContainerType::size_type size, priority_tag<1> /*unused*/)
-> decltype(c.reserve(size), void())
{
    c.reserve(size);
}

template<typename ConstructibleContainerType>
void reserve_if_possible(ConstructibleContainerType& /*c*/, std::size_t /*size*/, priority_tag<0> /*unused*/)
{}

// append through push_back() where available; containers without it (such as
// std::set) fall back to insert(end(), ...), which is what std::inserter did
template<typename ConstructibleArrayType, typename ValueType>
auto from_json_array_append(ConstructibleArrayType& arr, ValueType&& value, priority_tag<1> /*unused*/)
-> decltype(arr.push_back(std::forward<ValueType>(value)), void())
{
    arr.push_back(std::forward<ValueType>(value));
}

template<typename ConstructibleArrayType, typename ValueType>
void from_json_array_append(ConstructibleArrayType& arr, ValueType&& value, priority_tag<0> /*unused*/)
{
    using std::end;
    arr.insert(end(arr), std::forward<ValueType>(value));
}

template<typename BasicJsonType, typename ConstructibleArrayType,
         enable_if_t<
             std::is_assignable<ConstructibleArrayType&, ConstructibleArrayType>::value,
             int> = 0>
auto from_json_array_impl(const BasicJsonType& j, ConstructibleArrayType& arr, priority_tag<1> /*unused*/)
-> decltype(
    j.template get<typename ConstructibleArrayType::value_type>(),
    void())
{
    ConstructibleArrayType ret;
    const auto* inner_array = j.template get_ptr<const typename BasicJsonType::array_t*>();
    reserve_if_possible(ret, inner_array->size(), priority_tag<1> {});
    for (const auto& elem : *inner_array)
    {
        // get<BasicJsonType>() returns *this, this won't call a from_json
        // method when value_type is BasicJsonType
        from_json_array_append(ret, elem.template get<typename ConstructibleArrayType::value_type>(), priority_tag<1> {});
    }
    arr = std::move(ret);
}

template < typename BasicJsonType, typename ConstructibleArrayType,
           enable_if_t <
               is_constructible_array_type<BasicJsonType, ConstructibleArrayType>::value&&
               !is_constructible_object_type<BasicJsonType, ConstructibleArrayType>::value&&
               !is_constructible_string_type<BasicJsonType, ConstructibleArrayType>::value&&
               !std::is_same<ConstructibleArrayType, typename BasicJsonType::binary_t>::value&&
               !is_compatible_binary_type<BasicJsonType, ConstructibleArrayType>::value&&
               !is_basic_json<ConstructibleArrayType>::value,
               int > = 0 >
auto from_json(const BasicJsonType& j, ConstructibleArrayType& arr)
-> decltype(from_json_array_impl(j, arr, priority_tag<3> {}),
j.template get<typename ConstructibleArrayType::value_type>(),
void())
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_array()))
    {
        throw_type_must_be("array", j);
    }

    from_json_array_impl(j, arr, priority_tag<3> {});
}

template < typename BasicJsonType, typename T, std::size_t... Idx >
std::array<T, sizeof...(Idx)> from_json_inplace_array_impl(const BasicJsonType& j,
                     identity_tag<std::array<T, sizeof...(Idx)>> /*unused*/, index_sequence<Idx...> /*unused*/)
{
    return { { j.at(Idx).template get<T>()... } };
}

// std::is_trivial is deprecated in C++26 (see binary_writer::to_char_type);
// a struct rather than an alias, as astyle indents an #ifdef block of aliases
template<typename T>
struct is_trivial_element
#ifdef JSON_HAS_CPP_26
    : conjunction<std::is_trivially_copyable<T>, std::is_trivially_default_constructible<T>>
#else
    : std::is_trivial<T>
#endif
{};

// the element type may not be default constructible: construct every element
// in place (a pack expansion that is unrolled N times)
template<typename BasicJsonType, typename T, std::size_t N>
std::array<T, N> from_json_make_array(const BasicJsonType& j, identity_tag<std::array<T, N>> tag,
                                      std::false_type /*is_trivial_element*/)
{
    return from_json_inplace_array_impl(j, tag, make_index_sequence<N> {});
}

// a trivial element type cannot tell default construction plus assignment from
// construction in place, so use a loop instead of unrolling N conversions
template<typename BasicJsonType, typename T, std::size_t N>
std::array<T, N> from_json_make_array(const BasicJsonType& j, identity_tag<std::array<T, N>> /*unused*/,
                                      std::true_type /*is_trivial_element*/)
{
    std::array<T, N> arr; // NOLINT(cppcoreguidelines-pro-type-member-init,hicpp-member-init): every element is assigned or an exception is thrown
    from_json_std_array(j, arr);
    return arr;
}

template < typename BasicJsonType, typename T, std::size_t N >
auto from_json(const BasicJsonType& j, identity_tag<std::array<T, N>> tag)
-> decltype(from_json_inplace_array_impl(j, tag, make_index_sequence<N> {}))
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_array()))
    {
        throw_type_must_be("array", j);
    }

    return from_json_make_array(j, tag, is_trivial_element<T> {});
}

template<typename BasicJsonType>
inline void from_json(const BasicJsonType& j, typename BasicJsonType::binary_t& bin)
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_binary()))
    {
        throw_type_must_be("binary", j);
    }

    bin = *j.template get_ptr<const typename BasicJsonType::binary_t*>();
}

template < typename BasicJsonType, typename CompatibleArrayType,
           enable_if_t < is_compatible_binary_type<BasicJsonType, CompatibleArrayType>::value,
                         int > = 0 >
inline void from_json(const BasicJsonType& j, CompatibleArrayType& bin)
{
    if (j.is_binary())
    {
        bin = static_cast<CompatibleArrayType>(*j.template get_ptr<const typename BasicJsonType::binary_t*>());
    }
    else if (j.is_array())
    {
        from_json_array_impl(j, bin, priority_tag<3> {});
    }
    else
    {
        throw_type_must_be("binary or array", j);
    }
}

// the keys of the source are sorted for the usual object types, so hinting the
// end makes every insertion constant-time (for containers that order their keys
// the same way); containers without emplace_hint() (such as ordered_map) fall
// back to emplace()
template<typename ConstructibleObjectType, typename Key, typename Value>
auto from_json_object_emplace(ConstructibleObjectType& obj, Key&& key, Value&& value, priority_tag<1> /*unused*/)
-> decltype(obj.emplace_hint(obj.end(), std::forward<Key>(key), std::forward<Value>(value)), void())
{
    obj.emplace_hint(obj.end(), std::forward<Key>(key), std::forward<Value>(value));
}

template<typename ConstructibleObjectType, typename Key, typename Value>
void from_json_object_emplace(ConstructibleObjectType& obj, Key&& key, Value&& value, priority_tag<0> /*unused*/)
{
    obj.emplace(std::forward<Key>(key), std::forward<Value>(value));
}

template<typename BasicJsonType, typename ConstructibleObjectType,
         enable_if_t<is_constructible_object_type<BasicJsonType, ConstructibleObjectType>::value, int> = 0>
inline void from_json(const BasicJsonType& j, ConstructibleObjectType& obj)
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_object()))
    {
        throw_type_must_be("object", j);
    }

    ConstructibleObjectType ret;
    const auto* inner_object = j.template get_ptr<const typename BasicJsonType::object_t*>();
    reserve_if_possible(ret, inner_object->size(), priority_tag<1> {});
    for (const auto& p : *inner_object)
    {
        from_json_object_emplace(ret, p.first, p.second.template get<typename ConstructibleObjectType::mapped_type>(), priority_tag<1> {});
    }
    obj = std::move(ret);
}

// overload for arithmetic types, not chosen for basic_json template arguments
// (BooleanType, etc.)
template < typename BasicJsonType, typename ArithmeticType,
           enable_if_t <
               std::is_arithmetic<ArithmeticType>::value&&
               !std::is_same<ArithmeticType, typename BasicJsonType::number_unsigned_t>::value&&
               !std::is_same<ArithmeticType, typename BasicJsonType::number_integer_t>::value&&
               !std::is_same<ArithmeticType, typename BasicJsonType::number_float_t>::value&&
               !std::is_same<ArithmeticType, typename BasicJsonType::boolean_t>::value,
               int > = 0 >
inline void from_json(const BasicJsonType& j, ArithmeticType& val)
{
    if (get_number_value(j, val))
    {
        return;
    }

    // unlike get_arithmetic_value(), a boolean is accepted here
    if (JSON_HEDLEY_UNLIKELY(!j.is_boolean()))
    {
        throw_type_must_be("number", j);
    }
    val = static_cast<ArithmeticType>(*j.template get_ptr<const typename BasicJsonType::boolean_t*>());
}

template<typename BasicJsonType, typename Type>
detail::uncvref_t<Type> from_json_tuple_get_impl(BasicJsonType&& j, detail::identity_tag<Type> /*unused*/, detail::priority_tag<0> /*unused*/)
{
    return std::forward<BasicJsonType>(j).template get<detail::uncvref_t<Type>>();
}

template<typename BasicJsonType, typename Type,
         detail::enable_if_t<detail::is_compatible_reference_type<BasicJsonType, Type>::value, int> = 0>
Type from_json_tuple_get_impl(BasicJsonType && j, detail::identity_tag<Type> /*unused*/, detail::priority_tag<1> /*unused*/)
{
    return std::forward<BasicJsonType>(j).template get_ref<Type>();
}

template<typename BasicJsonType, typename Type,
         detail::enable_if_t<std::is_arithmetic<uncvref_t<Type>>::value, int> = 0>
detail::uncvref_t<Type> from_json_tuple_get_impl(BasicJsonType && j, detail::identity_tag<Type> /*unused*/, detail::priority_tag<2> /*unused*/)
{
    return std::forward<BasicJsonType>(j).template get<detail::uncvref_t<Type>>();
}

template<std::size_t PTagValue, typename BasicJsonType, typename... Types>
using tuple_type = std::tuple < decltype(from_json_tuple_get_impl(std::declval<BasicJsonType>(), detail::identity_tag<Types> {}, detail::priority_tag<PTagValue> {}))... >;

template<std::size_t PTagValue, typename... Args, typename BasicJsonType, std::size_t... Idx>
tuple_type<PTagValue, const BasicJsonType&, Args...> from_json_tuple_impl_base(const BasicJsonType& j, index_sequence<Idx...> /*unused*/)
{
    return tuple_type<PTagValue, const BasicJsonType&, Args...>(from_json_tuple_get_impl(j.at(Idx), detail::identity_tag<Args> {}, detail::priority_tag<PTagValue> {})...);
}

template<std::size_t PTagValue, typename BasicJsonType>
std::tuple<> from_json_tuple_impl_base(const BasicJsonType& /*unused*/, index_sequence<> /*unused*/)
{
    return {};
}

template < typename BasicJsonType, class A1, class A2 >
std::pair<A1, A2> from_json_tuple_impl(const BasicJsonType& j, identity_tag<std::pair<A1, A2>> /*unused*/, priority_tag<0> /*unused*/)
{
    return {j.at(0).template get<A1>(),
            j.at(1).template get<A2>()};
}

template<typename BasicJsonType, typename A1, typename A2>
inline void from_json_tuple_impl(const BasicJsonType& j, std::pair<A1, A2>& p, priority_tag<1> /*unused*/)
{
    p = from_json_tuple_impl(j, identity_tag<std::pair<A1, A2>> {}, priority_tag<0> {});
}

template<typename BasicJsonType, typename... Args>
std::tuple<Args...> from_json_tuple_impl(const BasicJsonType& j, identity_tag<std::tuple<Args...>> /*unused*/, priority_tag<2> /*unused*/)
{
    static_assert(conjunction<disjunction<negation<std::is_reference<Args>>, is_compatible_reference_type<const BasicJsonType&, Args>>...>::value,
                  "Can not return a tuple containing references to types not contained in a Json, try Json::get_to()");
    return from_json_tuple_impl_base<1, Args...>(j, index_sequence_for<Args...> {});
}

template<typename BasicJsonType, typename... Args>
inline void from_json_tuple_impl(const BasicJsonType& j, std::tuple<Args...>& t, priority_tag<3> /*unused*/)
{
    t = from_json_tuple_impl_base<2, Args...>(j, index_sequence_for<Args...> {});
}

template<typename BasicJsonType, typename TupleRelated>
auto from_json(const BasicJsonType& j, TupleRelated&& t)
-> decltype(from_json_tuple_impl(j, std::forward<TupleRelated>(t), priority_tag<3> {}))
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_array()))
    {
        throw_type_must_be("array", j);
    }

    return from_json_tuple_impl(j, std::forward<TupleRelated>(t), priority_tag<3> {});
}

// shared body for std::map/std::unordered_map with a non-string Key: both
// containers are read from an array of [key, value] pairs the same way
template<typename BasicJsonType, typename MapType>
void from_json_pair_array_to_map(const BasicJsonType& j, MapType& m)
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_array()))
    {
        throw_type_must_be("array", j);
    }
    m.clear();
    for (const auto& p : j)
    {
        if (JSON_HEDLEY_UNLIKELY(!p.is_array()))
        {
            throw_type_must_be("array", p);
        }
        m.emplace(p.at(0).template get<typename MapType::key_type>(), p.at(1).template get<typename MapType::mapped_type>());
    }
}

// read a map with enum keys from an object, using the enum's own from_json for
// the keys (e.g., from NLOHMANN_JSON_SERIALIZE_ENUM); this is the form written
// with JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS
template<typename BasicJsonType, typename Map>
inline bool from_json_enum_keyed_object(const BasicJsonType& j, Map& m, std::true_type /*key is enum*/)
{
    if (!j.is_object())
    {
        return false;
    }
    m.clear();
    for (const auto& p : *j.template get_ptr<const typename BasicJsonType::object_t*>())
    {
        m.emplace(BasicJsonType(p.first).template get<typename Map::key_type>(), p.second.template get<typename Map::mapped_type>());
    }
    return true;
}

template<typename BasicJsonType, typename Map>
inline bool from_json_enum_keyed_object(const BasicJsonType& /*j*/, Map& /*m*/, std::false_type /*key is enum*/)
{
    return false;
}

template < typename BasicJsonType, typename Key, typename Value, typename Compare, typename Allocator,
           typename = enable_if_t < !std::is_constructible <
                                        typename BasicJsonType::string_t, Key >::value >>
void from_json(const BasicJsonType& j, std::map<Key, Value, Compare, Allocator>& m)
{
    // NOLINTNEXTLINE(modernize-type-traits) we use C++11
    if (from_json_enum_keyed_object(j, m, std::is_enum<Key> {}))
    {
        return;
    }
    from_json_pair_array_to_map(j, m);
}

template < typename BasicJsonType, typename Key, typename Value, typename Hash, typename KeyEqual, typename Allocator,
           typename = enable_if_t < !std::is_constructible <
                                        typename BasicJsonType::string_t, Key >::value >>
void from_json(const BasicJsonType& j, std::unordered_map<Key, Value, Hash, KeyEqual, Allocator>& m)
{
    // NOLINTNEXTLINE(modernize-type-traits) we use C++11
    if (from_json_enum_keyed_object(j, m, std::is_enum<Key> {}))
    {
        return;
    }
    from_json_pair_array_to_map(j, m);
}

#if JSON_HAS_FILESYSTEM || JSON_HAS_EXPERIMENTAL_FILESYSTEM

// Workaround for MSVC 19.51 (and possibly later): in large cpp files, the compiler may fail to resolve with generic has_from_json (issue #4996)
template<typename BasicJsonType>
struct has_from_json<BasicJsonType, std_fs::path, void> : std::true_type {};

template<typename BasicJsonType>
inline void from_json(const BasicJsonType& j, std_fs::path& p)
{
    if (JSON_HEDLEY_UNLIKELY(!j.is_string()))
    {
        throw_type_must_be("string", j);
    }
    const auto& s = *j.template get_ptr<const typename BasicJsonType::string_t*>();
    // Checking for C++20 standard or later can be insufficient in case the
    // library support for char8_t is either incomplete or was disabled
    // altogether. Use the __cpp_lib_char8_t feature test instead.
#if defined(__cpp_lib_char8_t) && (__cpp_lib_char8_t >= 201907L)
    p = std_fs::path(std::u8string_view(reinterpret_cast<const char8_t*>(s.data()), s.size()));
#else
    p = std_fs::u8path(s); // accepts UTF-8 encoded std::string in C++17, deprecated in C++20
#endif
}
#endif

struct from_json_fn
{
    template<typename BasicJsonType, typename T>
    auto operator()(const BasicJsonType& j, T&& val) const
    noexcept(noexcept(from_json(j, std::forward<T>(val))))
    -> decltype(from_json(j, std::forward<T>(val)))
    {
        return from_json(j, std::forward<T>(val));
    }
};

}  // namespace detail

#ifndef JSON_HAS_CPP_17
/// namespace to hold default `from_json` function
/// to see why this is required:
/// http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2015/n4381.html
namespace // NOLINT(cert-dcl59-cpp,fuchsia-header-anon-namespaces,google-build-namespaces,misc-anonymous-namespace-in-header)
{
#endif
JSON_INLINE_VARIABLE constexpr const auto& from_json = // NOLINT(misc-definitions-in-headers)
    detail::static_const<detail::from_json_fn>::value;
#ifndef JSON_HAS_CPP_17
}  // namespace
#endif

NLOHMANN_JSON_NAMESPACE_END
