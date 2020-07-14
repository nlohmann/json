#pragma once

#include <functional> // hash

namespace nlohmann
{
namespace detail
{

std::size_t combine(std::size_t seed, std::size_t h)
{
    seed ^= h + 0x9e3779b9 + (seed << 6U) + (seed >> 2U);
    return seed;
}

template<typename BasicJsonType>
std::size_t hash(const BasicJsonType& j)
{
    switch (j.type())
    {
        case BasicJsonType::value_t::null:
        case BasicJsonType::discarded:
            return combine(static_cast<std::size_t>(j.type()), 0);

        case BasicJsonType::value_t::object:
        {
            auto seed = combine(static_cast<std::size_t>(j.type()), j.size());
            for (const auto& element : j.items())
            {
                const auto h = std::hash<typename BasicJsonType::string_t> {}(element.key());
                seed = combine(seed, h);
                seed = combine(seed, hash(element.value()));
            }
            return seed;
        }

        case BasicJsonType::value_t::array:
        {
            auto seed = combine(static_cast<std::size_t>(j.type()), j.size());
            for (const auto& element : j)
            {
                seed = combine(seed, hash(element));
            }
            return seed;
        }

        case BasicJsonType::value_t::string:
        {
            const auto h = std::hash<typename BasicJsonType::string_t> {}(j.template get_ref<const typename BasicJsonType::string_t&>());
            return combine(static_cast<std::size_t>(j.type()), h);
        }

        case BasicJsonType::value_t::boolean:
        {
            const auto h = std::hash<bool> {}(j.template get<bool>());
            return combine(static_cast<std::size_t>(j.type()), h);
        }

        case BasicJsonType::value_t::number_integer:
        {
            const auto h = std::hash<typename BasicJsonType::number_integer_t> {}(j.template get<typename BasicJsonType::number_integer_t>());
            return combine(static_cast<std::size_t>(j.type()), h);
        }

        case nlohmann::detail::value_t::number_unsigned:
        {
            const auto h = std::hash<typename BasicJsonType::number_unsigned_t> {}(j.template get<typename BasicJsonType::number_unsigned_t>());
            return combine(static_cast<std::size_t>(j.type()), h);
        }

        case nlohmann::detail::value_t::number_float:
        {
            const auto h = std::hash<typename BasicJsonType::number_float_t> {}(j.template get<typename BasicJsonType::number_float_t>());
            return combine(static_cast<std::size_t>(j.type()), h);
        }

        case nlohmann::detail::value_t::binary:
        {
            auto seed = combine(static_cast<std::size_t>(j.type()), j.get_binary().size());
            seed = combine(seed, j.get_binary().subtype());
            for (const auto byte : j.get_binary())
            {
                seed = combine(seed, std::hash<std::uint8_t> {}(byte));
            }
            return seed;
        }
    }

    return 0;
}

}  // namespace detail
}  // namespace nlohmann
