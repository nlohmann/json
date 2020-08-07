#pragma once

#include <utility>

#include <nlohmann/detail/conversions/from_json.hpp>
#include <nlohmann/detail/conversions/to_json.hpp>

namespace nlohmann
{

template<typename, typename>
struct adl_serializer
{
    /*!
    @brief convert a JSON value to any value type

    This function is usually called by the `get()` function of the
    @ref basic_json class (either explicit or via conversion operators).

    @param[in] j        JSON value to read from
    @param[in,out] val  value to write to
    */
    template<typename BasicJsonType, typename ValueType>
    static auto from_json(BasicJsonType&& j, ValueType& val) noexcept(
        noexcept(::nlohmann::from_json(std::forward<BasicJsonType>(j), val)))
    -> decltype(::nlohmann::from_json(std::forward<BasicJsonType>(j), val), void())
    {
        ::nlohmann::from_json(std::forward<BasicJsonType>(j), val);
    }

    /*!
    @brief convert any value type to a JSON value

    This function is usually called by the constructors of the @ref basic_json
    class.

    @param[in,out] j  JSON value to write to
    @param[in] val    value to read from
    */
    template<typename BasicJsonType, typename ValueType>
    static auto to_json(BasicJsonType& j, ValueType&& val) noexcept(
        noexcept(::nlohmann::to_json(j, std::forward<ValueType>(val))))
    -> decltype(::nlohmann::to_json(j, std::forward<ValueType>(val)), void())
    {
        ::nlohmann::to_json(j, std::forward<ValueType>(val));
    }
};

}  // namespace nlohmann
