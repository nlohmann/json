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
    /// the type of the underlying container
    using container_type = BinaryType;

    wrapped_binary_t() noexcept(noexcept(container_type()))
        : container_type()
    {}

    wrapped_binary_t(const container_type& b) noexcept(noexcept(container_type(b)))
        : container_type(b)
    {}

    wrapped_binary_t(container_type&& b) noexcept(noexcept(container_type(std::move(b))))
        : container_type(std::move(b))
    {}

    wrapped_binary_t(const container_type& b,
                     std::uint8_t subtype) noexcept(noexcept(container_type(b)))
        : container_type(b)
        , m_subtype(subtype)
        , m_has_subtype(true)
    {}

    wrapped_binary_t(container_type&& b, std::uint8_t subtype) noexcept(noexcept(container_type(std::move(b))))
        : container_type(std::move(b))
        , m_subtype(subtype)
        , m_has_subtype(true)
    {}

    /*!
    @brief sets the binary subtype

    Sets the binary subtype of the value, also flags a binary JSON value as
    having a subtype, which has implications for serialization.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @sa @ref subtype() -- return the binary subtype
    @sa @ref clear_subtype() -- clears the binary subtype
    @sa @ref has_subtype() -- returns whether or not the binary value has a
    subtype

    @since version 3.8.0
    */
    void set_subtype(std::uint8_t subtype) noexcept
    {
        m_subtype = subtype;
        m_has_subtype = true;
    }

    /*!
    @brief return the binary subtype

    Returns the numerical subtype of the value if it has a subtype. If it does
    not have a subtype, this function will return size_t(-1) as a sentinel
    value.

    @return the numerical subtype of the binary value

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @sa @ref set_subtype() -- sets the binary subtype
    @sa @ref clear_subtype() -- clears the binary subtype
    @sa @ref has_subtype() -- returns whether or not the binary value has a
    subtype

    @since version 3.8.0
    */
    constexpr std::uint8_t subtype() const noexcept
    {
        return m_subtype;
    }

    /*!
    @brief return whether the value has a subtype

    @return whether the value has a subtype

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @sa @ref subtype() -- return the binary subtype
    @sa @ref set_subtype() -- sets the binary subtype
    @sa @ref clear_subtype() -- clears the binary subtype

    @since version 3.8.0
    */
    constexpr bool has_subtype() const noexcept
    {
        return m_has_subtype;
    }

    /*!
    @brief clears the binary subtype

    Clears the binary subtype and flags the value as not having a subtype, which
    has implications for serialization; for instance MessagePack will prefer the
    bin family over the ext family.

    @complexity Constant.

    @exceptionsafety No-throw guarantee: this member function never throws
    exceptions.

    @sa @ref subtype() -- return the binary subtype
    @sa @ref set_subtype() -- sets the binary subtype
    @sa @ref has_subtype() -- returns whether or not the binary value has a
    subtype

    @since version 3.8.0
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
