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
#include <vector> // vector

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

/// the number of levels @ref hash descends into before handing over to
/// @ref hash_iteratively
constexpr std::size_t hash_depth_limit() noexcept
{
    return 128;
}

template<typename BasicJsonType>
std::size_t hash_iteratively(const BasicJsonType& j);

/*!
@brief hash a JSON value

The hash function tries to rely on std::hash where possible. Furthermore, the
type of the JSON value is taken into account to have different hash values for
null, 0, 0U, and false, etc.

Hashing an array or an object hashes its elements, which used to call this
function again once per nesting level, so a value nested deeply enough
exhausted the call stack and terminated the process. The descent is bounded
here: once @ref hash_depth_limit levels have been entered, @ref
hash_iteratively hashes what is left without the call stack. A value nested
less deeply than that - all but a vanishing minority - is hashed exactly as
before, without allocating.

@tparam BasicJsonType basic_json specialization
@param j JSON value to hash
@param depth nesting level of @a j, counted from the value passed by the caller
@return hash value of j
*/
template<typename BasicJsonType>
std::size_t hash(const BasicJsonType& j, const std::size_t depth = 0)
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
            if (JSON_HEDLEY_UNLIKELY(depth >= hash_depth_limit()))
            {
                return hash_iteratively(j);
            }

            auto seed = combine(type, j.size());
            for (const auto& element : j.items())
            {
                const auto h = std::hash<string_t> {}(element.key());
                seed = combine(seed, h);
                seed = combine(seed, hash(element.value(), depth + 1));
            }
            return seed;
        }

        case BasicJsonType::value_t::array:
        {
            if (JSON_HEDLEY_UNLIKELY(depth >= hash_depth_limit()))
            {
                return hash_iteratively(j);
            }

            auto seed = combine(type, j.size());
            for (const auto& element : j)
            {
                seed = combine(seed, hash(element, depth + 1));
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
            const auto h = std::hash<number_integer_t> {}(j.template get<number_integer_t>());
            return combine(type, h);
        }

        case BasicJsonType::value_t::number_unsigned:
        {
            const auto h = std::hash<number_unsigned_t> {}(j.template get<number_unsigned_t>());
            return combine(type, h);
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
                // the cast is needed for binary types whose value type is not
                // an integer (e.g., std::byte)
                seed = combine(seed, std::hash<std::uint8_t> {}(static_cast<std::uint8_t>(byte)));
            }
            return seed;
        }

        default:                   // LCOV_EXCL_LINE
            JSON_ASSERT(false); // NOLINT(cert-dcl03-c,hicpp-static-assert,misc-static-assert) LCOV_EXCL_LINE
            return 0;              // LCOV_EXCL_LINE
    }
}

/// an array or object whose elements @ref hash_iteratively is hashing
template<typename BasicJsonType>
struct hash_frame
{
    hash_frame(const BasicJsonType* value_, std::size_t seed_)
        : value(value_), position(value_->cbegin()), seed(seed_)
    {}

    const BasicJsonType* value;
    typename BasicJsonType::const_iterator position;
    std::size_t seed;
};

/*!
@brief hash the array or object @a j without the call stack

Computes the same value as @ref hash, keeping the arrays and objects it has
entered on an explicit stack instead of descending into them. Only reached for
values nested deeper than @ref hash_depth_limit.

@tparam BasicJsonType basic_json specialization
@param j array or object to hash
@return hash value of j
*/
template<typename BasicJsonType>
std::size_t hash_iteratively(const BasicJsonType& j)
{
    using string_t = typename BasicJsonType::string_t;

    std::vector<hash_frame<BasicJsonType>> stack;
    stack.emplace_back(&j, combine(static_cast<std::size_t>(j.type()), j.size()));

    while (true)
    {
        hash_frame<BasicJsonType>& frame = stack.back();

        if (frame.position == frame.value->cend())
        {
            // all elements are hashed: fold this value's hash into its parent's
            // seed, exactly where the recursive version returns it
            const std::size_t h = frame.seed;
            stack.pop_back();
            if (stack.empty())
            {
                return h;
            }
            stack.back().seed = combine(stack.back().seed, h);
            continue;
        }

        if (frame.value->is_object())
        {
            frame.seed = combine(frame.seed, std::hash<string_t> {}(frame.position.key()));
        }

        // read the element and advance before entering it: entering can
        // reallocate the stack and so invalidate `frame`
        const BasicJsonType& element = *frame.position;
        ++frame.position;

        if (element.is_structured())
        {
            stack.emplace_back(&element, combine(static_cast<std::size_t>(element.type()), element.size()));
        }
        else
        {
            frame.seed = combine(frame.seed, hash(element));
        }
    }
}

}  // namespace detail
NLOHMANN_JSON_NAMESPACE_END
