#pragma once

#include <nlohmann/detail/macro_scope.hpp>

#ifdef JSON_HAS_CPP_17

#include <optional>
#include <utility>

NLOHMANN_JSON_NAMESPACE_BEGIN

template <typename T>
class optional
{
    // *INDENT-OFF*

    using base_type = std::optional<T>;
    using value_type = T;

    template <typename U, typename = optional>
    struct has_conversion_operator : std::false_type { };

    template <typename U>
    struct has_conversion_operator<U,
        decltype(std::declval<U>().operator optional())> : std::true_type { };

    template <typename... U>
    using is_base_constructible_from = std::is_constructible<base_type, U...>;

    template <typename U>
    using is_convertible_to_base = std::is_convertible<U, base_type>;

    template <typename U>
    using enable_int_if = std::enable_if_t<U::value, int>;

    template <typename U>
    using use_conversion_operator =
        enable_int_if<
            has_conversion_operator<U>
        >;

    template <typename U>
    using use_implicit_forwarding =
        enable_int_if<
            std::conjunction<
                std::negation<has_conversion_operator<U>>,
                is_base_constructible_from<U>,
                is_convertible_to_base<U>
            >
        >;

    template <typename U>
    using use_explicit_forwarding =
        enable_int_if<
            std::conjunction<
                std::negation<has_conversion_operator<U>>,
                is_base_constructible_from<U>,
                std::negation<is_convertible_to_base<U>>
            >
        >;

    template <typename... U>
    using can_construct_in_place_from =
        enable_int_if<
            is_base_constructible_from<std::in_place_t, U...>
        >;

    struct noexcept_fix_t {}; // trick for GCC8.1 (see default constructor)

    base_type base_value;

  public:

    base_type& base() & noexcept
    {
        return base_value;
    }

    const base_type& base() const & noexcept
    {
        return base_value;
    }

    base_type&& base() && noexcept
    {
        return std::move(base_value);
    }

    constexpr optional() noexcept(noexcept(std::optional<noexcept_fix_t>()))
        : base_value() // explicitly initialized to mitigate -Werror=effc++
    {
    }

    constexpr optional(std::nullopt_t /* unused */) noexcept
        : base_value(std::nullopt)
    {
    }

    template <typename U, use_conversion_operator<U> = 0>
    constexpr optional(U&& value)
        noexcept(noexcept(
            base_type(std::forward<U>(value).operator optional())
         )) :
            base_value(std::forward<U>(value).operator optional())
    {
    }

    template <typename U = T, use_implicit_forwarding<U> = 0>
    constexpr optional(U&& value)
        noexcept(noexcept(
            base_type(std::forward<U>(value))
        )) :
            base_value(std::forward<U>(value))
    {
    }

    template <typename U, use_explicit_forwarding<U> = 0>
    explicit
    constexpr optional(U&& value)
        noexcept(noexcept(
            base_type(std::forward<U>(value))
        )) :
            base_value(std::forward<U>(value))
    {
    }

    template <typename U, typename... Args, can_construct_in_place_from<U, Args...> = 0>
    explicit
    constexpr optional(std::in_place_t /* unused */, U&& u, Args&&... args)
        noexcept(noexcept(
            base_type(std::in_place, std::forward<U>(u), std::forward<Args>(args)...)
        )) :
            base_value(std::in_place, std::forward<U>(u), std::forward<Args>(args)...)
    {
    }

    template <typename U, typename... Args, can_construct_in_place_from<std::initializer_list<U>&, Args...> = 0>
    explicit
    constexpr optional(std::in_place_t /* unused */, std::initializer_list<U> u, Args&&... args)
        noexcept(noexcept(
            base_type(std::in_place, u, std::forward<Args>(args)...)
        )) :
            base_value(std::in_place, u, std::forward<Args>(args)...)
    {
    }

    constexpr T& operator *() & noexcept { return *base_value; }
    constexpr const T& operator *() const& noexcept { return *base_value; }

    constexpr T&& operator *() && noexcept { return static_cast<T&&>(*base_value); }
    constexpr const T&& operator *() const&& noexcept { return static_cast<const T&&>(*base_value); }

    constexpr T* operator ->() noexcept { return base_value.operator ->(); }
    constexpr const T* operator ->() const noexcept { return base_value.operator ->(); }

    operator base_type& () & noexcept { return base_value; }
    operator base_type&& () && noexcept { return std::move(base_value); }

    // *INDENT-ON*
};

namespace detail::opt
{

template <typename T> const T& cmp_val(const T& v)
{
    return v;
}
template <typename T> const std::optional<T>& cmp_val(const optional<T>& v)
{
    return v.base();
}

}  // namespace detail::opt

#define JSON_OPTIONAL_COMPARISON_EXPR(OP) \
    detail::opt::cmp_val(lhs) OP detail::opt::cmp_val(rhs)

#define JSON_OPTIONAL_COMPARISON(OP, LHS, RHS) \
    template <typename A, typename B> \
    auto operator OP (const LHS& lhs, const RHS& rhs) \
    -> decltype(JSON_OPTIONAL_COMPARISON_EXPR(OP)) \
    { \
        return JSON_OPTIONAL_COMPARISON_EXPR(OP); \
    }

#ifdef JSON_HAS_CPP_20

// *INDENT-OFF*

JSON_OPTIONAL_COMPARISON( <=>, optional<A>, B)

// *INDENT-ON*

JSON_OPTIONAL_COMPARISON( ==, optional<A>, B)
JSON_OPTIONAL_COMPARISON( ==, optional<A>, std::optional<B>)
JSON_OPTIONAL_COMPARISON( ==, std::optional<A>, optional<B>)

#else // JSON_HAS_CPP_20

#define JSON_OPTIONAL_COMPARISON_OP(OP) \
    JSON_OPTIONAL_COMPARISON(OP, optional<A>, optional<B>) \
    JSON_OPTIONAL_COMPARISON(OP, optional<A>, std::optional<B>) \
    JSON_OPTIONAL_COMPARISON(OP, std::optional<A>, optional<B>) \
    JSON_OPTIONAL_COMPARISON(OP, optional<A>, B) \
    JSON_OPTIONAL_COMPARISON(OP, A, optional<B>)

JSON_OPTIONAL_COMPARISON_OP( == )
JSON_OPTIONAL_COMPARISON_OP( != )
JSON_OPTIONAL_COMPARISON_OP( < )
JSON_OPTIONAL_COMPARISON_OP( <= )
JSON_OPTIONAL_COMPARISON_OP( > )
JSON_OPTIONAL_COMPARISON_OP( >= )

#undef JSON_OPTIONAL_COMPARISON_OP

#endif // JSON_HAS_CPP_20

#undef JSON_OPTIONAL_COMPARISON
#undef JSON_OPTIONAL_COMPARISON_EXPR

NLOHMANN_JSON_NAMESPACE_END

#endif // JSON_HAS_CPP_17
