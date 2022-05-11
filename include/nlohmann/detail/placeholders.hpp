#pragma once

namespace nlohmann
{
namespace placeholders
{

struct basic_json_value_placeholder_t
{
    explicit basic_json_value_placeholder_t() = default;
};

static constexpr basic_json_value_placeholder_t basic_json_value{};

template<typename T>
struct basic_json_value_as_placeholder_t
{
    using type = T;
    explicit basic_json_value_as_placeholder_t() = default;
};

template<typename T>
inline constexpr basic_json_value_as_placeholder_t<T> basic_json_value_as() noexcept
{
    return basic_json_value_as_placeholder_t<T> {};
}

} // namespace placeholders
} // namespace nlohmann
