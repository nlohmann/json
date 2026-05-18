#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace ns
{

enum class Color
{
    red,
    green,
    blue,
    unknown // not mapped in JSON_SERIALIZE_ENUM_STRICT
};

NLOHMANN_JSON_SERIALIZE_ENUM_STRICT(Color,
{
    {Color::red, "red"},
    {Color::green, "green"},
    {Color::blue, "blue"}
})

} // namespace ns


int main()
{
    // invalid serialization
    try
    {
        // ns::color::unknown was not mapped in macro
        json invalid_serialization = ns::Color::unknown;
    }
    catch (const json::exception e)
    {
        std::cout << "deserialization failed: " << e.what() << std::endl;
    }

    // invalid deserialization
    try
    {
        // what does not map to an enum
        json invalid_deserialization("what");
        ns::Color color = invalid_deserialization.get<ns::Color>();
    }
    catch (const json::exception e)
    {
        std::cout << "deserialization failed: " << e.what() << std::endl;
    }

    return 0;
}
