#pragma once

#include <cstdint> // uint8_t
#include <tuple> // tie
#include <utility> // move

namespace nlohmann
{

/*!
@brief an internal type for a backed binary type

This type extends the template parameter @a BinaryType provided to `basic_json`
with a subtype used by BSON and MessagePack. This type exists so that the user
does not have to specify a type themselves with a specific naming scheme in
order to override the binary type.

@tparam BinaryType container to store bytes (`std::vector<std::uint8_t>` by
                   default)

@since version 3.8.0
*/
template<typename BinaryType>
class byte_container_with_subtype : public BinaryType
{
  public:
    /// the type of the underlying container
    using container_type = BinaryType;

    byte_container_with_subtype() noexcept(noexcept(container_type()))
        : container_type()
    {}

    byte_container_with_subtype(const container_type& b) noexcept(noexcept(container_type(b)))
        : container_type(b)
    {}

    byte_container_with_subtype(container_type&& b) noexcept(noexcept(container_type(std::move(b))))
        : container_type(std::move(b))
    {}

    byte_container_with_subtype(const container_type& b, std::uint8_t subtype_) noexcept(noexcept(container_type(b)))
        : container_type(b)
        , m_subtype(subtype_)
        , m_has_subtype(true)
    {}

    byte_container_with_subtype(container_type&& b, std::uint8_t subtype_) noexcept(noexcept(container_type(std::move(b))))
        : container_type(std::move(b))
        , m_subtype(subtype_)
        , m_has_subtype(true)
    {}

    bool operator==(const byte_container_with_subtype& rhs) const
    {
        return std::tie(static_cast<const BinaryType&>(*this), m_subtype, m_has_subtype) ==
               std::tie(static_cast<const BinaryType&>(rhs), rhs.m_subtype, rhs.m_has_subtype);
    }

    bool operator!=(const byte_container_with_subtype& rhs) const
    {
        return !(rhs == *this);
    }

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
    void set_subtype(std::uint8_t subtype_) noexcept
    {
        m_subtype = subtype_;
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

}  // namespace nlohmann
