//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint> // uint8_t
#include <cstddef> // size_t
#include <functional> // hash
#include <limits> // numeric_limits
#include <cmath> // isfinite

#include <nlohmann/detail/abi_macros.hpp>
#include <nlohmann/detail/value_t.hpp>

NLOHMANN_JSON_NAMESPACE_BEGIN
namespace detail
{

// boost::hash_combine
inline std::size_t combine(std::size_t seed, std::size_t h) noexcept
{
    seed ^= h + 0x9e3779b9 + (seed << 6U) + (seed >> 2U);
    return seed;
}

// Check if a number_integer_t value is exactly representable as number_float_t
// Returns true if static_cast<number_integer_t>(static_cast<number_float_t>(val)) == val
template<typename BasicJsonType>
inline bool is_exactly_representable_as_float(typename BasicJsonType::number_integer_t val) noexcept
{
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_float_t = typename BasicJsonType::number_float_t;

    // If the float type's mantissa covers the integer type's entire range, all values round-trip
    constexpr int float_digits = std::numeric_limits<number_float_t>::digits;
    constexpr int int_digits = std::numeric_limits<number_integer_t>::digits;

#ifdef JSON_HEDLEY_MSVC_VERSION
#pragma warning(push )
#pragma warning(disable : 4127) // ignore warning to replace if with if constexpr
#endif
    if (float_digits >= int_digits)
    {
        return true;
    }
#ifdef JSON_HEDLEY_MSVC_VERSION
#pragma warning( pop )
#endif

    // For values outside float's exact range, they don't round-trip
    // The safe way to check: compute the max magnitude that round-trips
    // Using unsigned arithmetic to avoid UB with negating INT_MIN

    // Max magnitude representable exactly: 2^(digits-1) - 1 for signed, 2^digits - 1 for unsigned range
    // But we're checking a signed value, so use 2^digits as the threshold
    constexpr auto max_exact = static_cast<number_integer_t>(1) << (float_digits - 1);

    // Check absolute value against this threshold
    if (val >= 0)
    {
        if (val >= max_exact)
        {
            return false;
        }
    }
    else
    {
        // For negative values, check via unsigned wrapping arithmetic
        // -val in unsigned domain; if it wraps, the value is too negative
        auto unsigned_abs = static_cast<typename BasicJsonType::number_unsigned_t>(-val);
        if (unsigned_abs >= static_cast<typename BasicJsonType::number_unsigned_t>(max_exact))
        {
            return false;
        }
    }

    // For values within the exact range, verify the round-trip
    const auto f = static_cast<number_float_t>(val);
    return std::isfinite(f) && static_cast<number_integer_t>(f) == val;
}

/*!
@brief hash a JSON value

The hash function tries to rely on std::hash where possible. Furthermore, the
type of the JSON value is taken into account to have different hash values for
most types. However, numeric types (number_integer, number_unsigned, number_float)
are hashed to satisfy the std::hash contract: if two json values compare equal,
they must have equal hash values. This means json(42), json(42u), and json(42.0)
all hash to the same value (since they compare equal). For large integer values
outside the exact representable range of the float type, integer values are hashed
in their own domain to avoid precision loss.

@tparam BasicJsonType basic_json specialization
@param j JSON value to hash
@return hash value of j
*/
template<typename BasicJsonType>
std::size_t hash(const BasicJsonType& j)
{
    using string_t = typename BasicJsonType::string_t;
    using number_integer_t = typename BasicJsonType::number_integer_t;
    using number_unsigned_t = typename BasicJsonType::number_unsigned_t;
    using number_float_t = typename BasicJsonType::number_float_t;

    const auto type = static_cast<std::size_t>(j.type());
    switch (j.type())
    {
        case BasicJsonType::value_t::null:
        case BasicJsonType::value_t::discarded:
        {
            return combine(type, 0);
        }

        case BasicJsonType::value_t::object:
        {
            auto seed = combine(type, j.size());
            for (const auto& element : j.items())
            {
                const auto h = std::hash<string_t> {}(element.key());
                seed = combine(seed, h);
                seed = combine(seed, hash(element.value()));
            }
            return seed;
        }

        case BasicJsonType::value_t::array:
        {
            auto seed = combine(type, j.size());
            for (const auto& element : j)
            {
                seed = combine(seed, hash(element));
            }
            return seed;
        }

        case BasicJsonType::value_t::string:
        {
            const auto h = std::hash<string_t> {}(j.template get_ref<const string_t&>());
            return combine(type, h);
        }

        case BasicJsonType::value_t::boolean:
        {
            const auto h = std::hash<bool> {}(j.template get<bool>());
            return combine(type, h);
        }

        case BasicJsonType::value_t::number_integer:
        {
            const auto v = j.template get<number_integer_t>();
            // Use a shared numeric type tag so all numeric types that are equal hash the same
            const auto numeric_type = static_cast<std::size_t>(BasicJsonType::value_t::number_float);

            if (is_exactly_representable_as_float<BasicJsonType>(v))
            {
                const auto h = std::hash<number_float_t> {}(static_cast<number_float_t>(v));
                return combine(numeric_type, h);
            }

            const auto h = std::hash<number_integer_t> {}(v);
            return combine(numeric_type, h);
        }

        case BasicJsonType::value_t::number_unsigned:
        {
            const auto v = j.template get<number_unsigned_t>();
            // Normalize to signed (matching operator== behavior for U-vs-I comparison)
            const auto v_as_signed = static_cast<number_integer_t>(v);
            // Use a shared numeric type tag so all numeric types that are equal hash the same
            const auto numeric_type = static_cast<std::size_t>(BasicJsonType::value_t::number_float);

            if (is_exactly_representable_as_float<BasicJsonType>(v_as_signed))
            {
                const auto h = std::hash<number_float_t> {}(static_cast<number_float_t>(v_as_signed));
                return combine(numeric_type, h);
            }

            const auto h = std::hash<number_integer_t> {}(v_as_signed);
            return combine(numeric_type, h);
        }

        case BasicJsonType::value_t::number_float:
        {
            const auto h = std::hash<number_float_t> {}(j.template get<number_float_t>());
            return combine(type, h);
        }

        case BasicJsonType::value_t::binary:
        {
            auto seed = combine(type, j.get_binary().size());
            const auto h = std::hash<bool> {}(j.get_binary().has_subtype());
            seed = combine(seed, h);
            seed = combine(seed, static_cast<std::size_t>(j.get_binary().subtype()));
            for (const auto byte : j.get_binary())
            {
                seed = combine(seed, std::hash<std::uint8_t> {}(byte));
            }
            return seed;
        }

        default:                   // LCOV_EXCL_LINE
            JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
            return 0;              // LCOV_EXCL_LINE
    }
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
