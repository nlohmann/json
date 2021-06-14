#pragma once

#include <type_traits>
#include <utility>

#include <nlohmann/detail/conversions/from_json.hpp>
#include <nlohmann/detail/conversions/to_json.hpp>
#include <nlohmann/detail/meta/identity_tag.hpp>
#include <nlohmann/detail/meta/type_traits.hpp>

namespace nlohmann
{

template<typename ValueType, typename>
struct adl_serializer
{
    /*!
    @brief convert a JSON value to any value type

    This function is usually called by the `get()` function of the
    @ref basic_json class (either explicit or via conversion operators).

    @note This function is chosen for default-constructible value types.

    @param[in] j        JSON value to read from
    @param[in,out] val  value to write to
    */
    template<typename BasicJsonType, typename TargetType = ValueType>
    static auto from_json(BasicJsonType && j, TargetType& val) noexcept(
        noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j), val)))
    -> decltype(::nlohmann::from_json(std::forward<BasicJsonType>(j), val), void())
    {
        ::nlohmann::from_json(std::forward<BasicJsonType>(j), val);
    }

    /*!
    @brief convert a JSON value to any value type

    This function is usually called by the `get()` function of the
    @ref basic_json class (either explicit or via conversion operators).

    @note This function is chosen for value types which are not default-constructible.

    @param[in] j  JSON value to read from

    @return copy of the JSON value, converted to @a ValueType
    */
    template<typename BasicJsonType, typename TargetType = ValueType>
    static auto from_json(BasicJsonType && j) noexcept(
    noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j), detail::identity_tag<TargetType> {})))
    -> decltype(::nlohmann::from_json(std::forward<BasicJsonType>(j), detail::identity_tag<TargetType> {}))
    {
        return ::nlohmann::from_json(std::forward<BasicJsonType>(j), detail::identity_tag<TargetType> {});
    }

    /*!
    @brief convert any value type to a JSON value

    This function is usually called by the constructors of the @ref basic_json
    class.

    @param[in,out] j  JSON value to write to
    @param[in] val    value to read from
    */
    template<typename BasicJsonType, typename TargetType = ValueType>
    static auto to_json(BasicJsonType& j, TargetType && val) noexcept(
        noexcept(::nlohmann::to_json(j, std::forward<TargetType>(val))))
    -> decltype(::nlohmann::to_json(j, std::forward<TargetType>(val)), void())
    {
        ::nlohmann::to_json(j, std::forward<TargetType>(val));
    }
};
}  // namespace nlohmann
