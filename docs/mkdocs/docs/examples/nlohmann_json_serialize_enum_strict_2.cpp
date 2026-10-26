#include <iostream>
#include <nlohmann/json.hpp>

using nlohmann::json;

namespace ns
{
enum class Color
{
    red, green, blue, unknown
};

NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(Color,
{
    { Color::unknown, "unknown" }, { Color::red, "red" },
    { Color::green, "green" }, { Color::blue, "blue" },
    { Color::red, "rot" } // a second conversion for Color::red
})
}

int main()
{
    // serialization
    json j_red = ns::Color::red;
    std::cout << static_cast<int>(ns::Color::red) << " -> " << j_red << '\n';

    // deserialization
    json j_rot = "rot";
    auto rot = j_rot.get<ns::Color>();
    auto red = j_red.get<ns::Color>();
    std::cout << j_rot << " -> " << static_cast<int>(rot) << '\n';
    std::cout << j_red << " -> " << static_cast<int>(red) << '\n';
}
