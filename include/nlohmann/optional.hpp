#pragma once

#include <nlohmann/detail/macro_scope.hpp>

#ifdef JSON_HAS_CPP_17

#include <optional>
#include <utility>

namespace nlohmann
{

template <typename T>
class optional : public std::optional<T>
{
    // *INDENT-OFF*

    using base_type = std::optional<T>;

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

    struct noexcept_fix_t {};

  public:

    const base_type& base() const
    {
        return *this;
    }

    constexpr optional() noexcept(noexcept(std::optional<noexcept_fix_t>())) = default;

    constexpr optional(std::nullopt_t /* unused */) noexcept
        : base_type(std::nullopt)
    {
    }

    template <typename U, use_conversion_operator<U> = 0>
    constexpr optional(U&& value)
        noexcept(noexcept(
            base_type(std::forward<U>(value).operator optional())
         )) :
            base_type(std::forward<U>(value).operator optional())
    {
    }

    template <typename U = T, use_implicit_forwarding<U> = 0>
    constexpr optional(U&& value)
        noexcept(noexcept(
            base_type(std::forward<U>(value))
        )) :
            base_type(std::forward<U>(value))
    {
    }

    template <typename U, use_explicit_forwarding<U> = 0>
    explicit
    constexpr optional(U&& value)
        noexcept(noexcept(
            base_type(std::forward<U>(value))
        )) :
            base_type(std::forward<U>(value))
    {
    }

    template <typename U, typename... Args, can_construct_in_place_from<U, Args...> = 0>
    explicit
    constexpr optional(std::in_place_t /* unused */, U&& u, Args&&... args)
        noexcept(noexcept(
            base_type(std::in_place, std::forward<U>(u), std::forward<Args>(args)...)
        )) :
            base_type(std::in_place, std::forward<U>(u), std::forward<Args>(args)...)
    {
    }

    template <typename U, typename... Args, can_construct_in_place_from<std::initializer_list<U>&, Args...> = 0>
    explicit
    constexpr optional(std::in_place_t /* unused */, std::initializer_list<U> u, Args&&... args)
        noexcept(noexcept(
            base_type(std::in_place, u, std::forward<Args>(args)...)
        )) :
            base_type(std::in_place, u, std::forward<Args>(args)...)
    {
    }

    // *INDENT-ON*
};

template<class T, class U>
constexpr bool operator == (const optional<T>& lhs, const optional<U>& rhs)
{
    return lhs.base() == rhs.base();
}

template<class T, class U>
constexpr bool operator != (const optional<T>& lhs, const optional<U>& rhs)
{
    return lhs.base() != rhs.base();
}

template<class T, class U>
constexpr bool operator < (const optional<T>& lhs, const optional<U>& rhs)
{
    return lhs.base() < rhs.base();
}

template<class T, class U>
constexpr bool operator <= (const optional<T>& lhs, const optional<U>& rhs)
{
    return lhs.base() <= rhs.base();
}

template<class T, class U>
constexpr bool operator > (const optional<T>& lhs, const optional<U>& rhs)
{
    return lhs.base() > rhs.base();
}

template<class T, class U>
constexpr bool operator >= (const optional<T>& lhs, const optional<U>& rhs)
{
    return lhs.base() >= rhs.base();
}

}  // namespace nlohmann

#endif // JSON_HAS_CPP_17
