#pragma once

#ifdef JSON_HAS_CPP_17
    #include <functional> // invoke
#endif
#include <type_traits> // invoke_result, is_base_of, is_function, is_invocable, is_object, is_same, remove_reference
#include <utility> // declval, forward

#include <nlohmann/detail/macro_scope.hpp>
#include <nlohmann/detail/meta/detected.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>

namespace nlohmann
{
namespace detail
{

#ifdef JSON_HAS_CPP_17

// the following utilities are natively available in C++17
using std::invoke;
using std::invoke_result;
using std::is_invocable;

#else

// invoke_impl derived from the C++ standard draft [func.require] for qslib (proprietary)
// modified to use standard library type traits and utilities where possible

namespace internal
{

template<typename Fn, typename... Args,
         typename = decltype(std::declval<Fn>()(std::forward<Args>(std::declval<Args>())...))>
auto invoke_impl(Fn && f, Args && ...args) -> decltype(f(std::forward<Args>(args)...))
{
    return f(std::forward<Args>(args)...);
};

template < typename T, typename U, typename V, typename... Args, enable_if_t <
               std::is_function<T>::value
               && std::is_base_of<U, typename std::remove_reference<V>::type>::value, int > = 0 >
auto invoke_impl(T U::*f, V && v, Args && ...args) -> decltype((v.*f)(std::forward<Args>(args)...))
{
    return (v.*f)(std::forward<Args>(args)...);
}

template < typename T, typename U, typename V, typename... Args, enable_if_t <
               std::is_function<T>::value
               && !std::is_base_of<U, typename std::remove_reference<V>::type>::value, int > = 0 >
auto invoke_impl(T U::*f, V && v, Args && ...args) -> decltype(((*v).*f)(std::forward<Args>(args)...))
{
    return ((*v).*f)(std::forward<Args>(args)...);
}

template < typename T, typename U, typename V, typename... Args, enable_if_t <
               std::is_object<T>::value
               && sizeof...(Args) == 0, int > = 0 >
auto invoke_impl(T U::*f, V && v, Args && ... /*unused*/) -> decltype((*v).*f)
{
    return (*v).*f;
}

template <typename Fn, typename... Args>
using detect_invocable = decltype(invoke_impl(std::declval<Fn>(), std::declval<Args>()...));

// https://en.cppreference.com/w/cpp/types/result_of
template <typename AlwaysVoid, typename, typename...>
struct invoke_result {};

template <typename Fn, typename...Args>
struct invoke_result<decltype(void(invoke_impl(std::declval<Fn>(), std::declval<Args>()...))), Fn, Args...>
{
    using type = decltype(invoke_impl(std::declval<Fn>(), std::declval<Args>()...));
};

} // namespace internal

template <typename Fn, typename... Args>
auto invoke(Fn&& f, Args&& ... args) -> decltype(internal::invoke_impl(std::forward<Fn>(f), std::forward<Args>(args)...))
{
    return internal::invoke_impl(std::forward<Fn>(f), std::forward<Args>(args)...);
}

template <typename Fn, typename... Args>
using invoke_result = internal::invoke_result<void, Fn, Args...>;

template <typename Fn, typename... Args>
using is_invocable = typename is_detected<internal::detect_invocable, Fn, Args...>::type;

#endif

// used as a dummy argument
struct null_arg_t
{
    explicit null_arg_t() = default;
};

static constexpr null_arg_t null_arg{};

template<typename T>
using is_null_arg = typename std::is_same<uncvref_t<T>, null_arg_t>::type;

template<typename Value, typename Tuple, std::size_t I>
struct apply_value_or_arg
{
    using element_type = typename std::tuple_element<I, Tuple>::type;
    using type = typename std::conditional<detail::is_basic_json_value_placeholder<element_type>::value, Value, element_type>::type;
};

template<typename Value, typename Fn, typename Tuple, std::size_t... I>
using apply_invoke_result_t = typename detail::invoke_result<Fn,
      typename apply_value_or_arg<Value, Tuple, I>::type...>::type;

template<typename Value, typename Fn, typename Tuple, std::size_t... I>
using apply_is_invocable = typename detail::is_invocable<Fn,
      typename apply_value_or_arg<Value, Tuple, I>::type...>::type;

}  // namespace detail
}  // namespace nlohmann
