#pragma once

namespace nlohmann
{
namespace detail
{

template<int I>
struct placeholder_t
{
    static constexpr int value = I;

    explicit placeholder_t() = default;
};

} // namespace detail

namespace placeholders
{

static constexpr detail::placeholder_t < -1 > basic_json_value{};

} // namespace placeholders
} // namespace nlohmann
