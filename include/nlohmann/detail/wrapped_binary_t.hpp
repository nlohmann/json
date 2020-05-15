#pragma once

#include <cstdint> // uint8_t
#include <utility> // move

namespace nlohmann
{
namespace detail
{

/*!
@brief an internal type for a backed binary type

This type is designed to be `binary_t` but with the subtype implementation
detail.  This type exists so that the user does not have to specify a struct
his- or herself with a specific naming scheme in order to override the
binary type.  I.e. it's for ease of use.
*/
template<typename BinaryType>
struct wrapped_binary_t : public BinaryType
{
    using binary_t = BinaryType;

    wrapped_binary_t() noexcept(noexcept(binary_t()))
        : binary_t()
    {}

    wrapped_binary_t(const binary_t& bint) noexcept(noexcept(binary_t(bint)))
        : binary_t(bint)
    {}

    wrapped_binary_t(binary_t&& bint) noexcept(noexcept(binary_t(std::move(bint))))
        : binary_t(std::move(bint))
    {}

    wrapped_binary_t(const binary_t& bint,
                     std::uint8_t st) noexcept(noexcept(binary_t(bint)))
        : binary_t(bint)
        , subtype(st)
        , has_subtype(true)
    {}

    wrapped_binary_t(binary_t&& bint, std::uint8_t st) noexcept(noexcept(binary_t(std::move(bint))))
        : binary_t(std::move(bint))
        , subtype(st)
        , has_subtype(true)
    {}

    std::uint8_t subtype = 0;
    bool has_subtype = false;
};

}  // namespace detail
}  // namespace nlohmann
