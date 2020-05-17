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
detail. This type exists so that the user does not have to specify a type
themselves with a specific naming scheme in order to override the binary type.
*/
template<typename BinaryType>
class wrapped_binary_t : public BinaryType
{
  public:
    using binary_t = BinaryType;

    wrapped_binary_t() noexcept(noexcept(binary_t()))
        : binary_t()
    {}

    wrapped_binary_t(const binary_t& b) noexcept(noexcept(binary_t(b)))
        : binary_t(b)
    {}

    wrapped_binary_t(binary_t&& b) noexcept(noexcept(binary_t(std::move(b))))
        : binary_t(std::move(b))
    {}

    wrapped_binary_t(const binary_t& b,
                     std::uint8_t subtype) noexcept(noexcept(binary_t(b)))
        : binary_t(b)
        , m_subtype(subtype)
        , m_has_subtype(true)
    {}

    wrapped_binary_t(binary_t&& b, std::uint8_t subtype) noexcept(noexcept(binary_t(std::move(b))))
        : binary_t(std::move(b))
        , m_subtype(subtype)
        , m_has_subtype(true)
    {}

    /*!
    @brief set the subtype
    @param subtype subtype to set (implementation specific)
    */
    void set_subtype(std::uint8_t subtype) noexcept
    {
        m_subtype = subtype;
        m_has_subtype = true;
    }

    /*!
    @brief get the subtype
    @return subtype (implementation specific)
    */
    constexpr std::uint8_t subtype() const noexcept
    {
        return m_subtype;
    }

    /*!
    @brief get whether a subtype was set
    @return whether a subtype was set
    */
    constexpr bool has_subtype() const noexcept
    {
        return m_has_subtype;
    }

    /*!
    @brief clear the subtype
    */
    void clear_subtype() noexcept
    {
        m_subtype = 0;
        m_has_subtype = false;
    }

  private:
    std::uint8_t m_subtype = 0;
    bool m_has_subtype = false;
};

}  // namespace detail
}  // namespace nlohmann
