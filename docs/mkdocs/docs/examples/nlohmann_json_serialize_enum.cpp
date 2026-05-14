#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace ns
{
enum TaskState
{
    TS_STOPPED,
    TS_RUNNING,
    TS_COMPLETED,
    TS_INVALID = -1
};

NLOHMANN_JSON_SERIALIZE_ENUM(TaskState,
{
    { TS_INVALID, nullptr },
    { TS_STOPPED, "stopped" },
    { TS_RUNNING, "running" },
    { TS_COMPLETED, "completed" }
})

enum class Color
{
    red, green, blue, unknown
};

NLOHMANN_JSON_SERIALIZE_ENUM(Color,
{
    { Color::unknown, "unknown" }, { Color::red, "red" },
    { Color::green, "green" }, { Color::blue, "blue" }
})
} // namespace ns

int main()
{
    // serialization
    json j_stopped = ns::TS_STOPPED;
    json j_red = ns::Color::red;
    std::cout << "ns::TS_STOPPED -> " << j_stopped
              << ", ns::Color::red -> " << j_red << std::endl;

    // deserialization
    json j_running = "running";
    json j_blue = "blue";
    auto running = j_running.get<ns::TaskState>();
    auto blue = j_blue.get<ns::Color>();
    std::cout << j_running << " -> " << running
              << ", " << j_blue << " -> " << static_cast<int>(blue) << std::endl;

    // deserializing undefined JSON value to enum
    // (where the first map entry above is the default)
    json j_pi = 3.14;
    auto invalid = j_pi.get<ns::TaskState>();
    auto unknown = j_pi.get<ns::Color>();
    std::cout << j_pi << " -> " << invalid << ", "
              << j_pi << " -> " << static_cast<int>(unknown) << std::endl;
}
