#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // parsing invalid JSON without exceptions yields a discarded value
    json j_invalid = json::parse("[1,2,3", nullptr, false);

    // a callback that discards the top-level value does not leave it
    // "discarded" -- it is replaced by null instead
    json j_discarded_by_callback = json::parse("[1,2,3]", [](int /*depth*/, json::parse_event_t event, json& /*parsed*/)
    {
        return event != json::parse_event_t::array_start;
    });

    std::cout << std::boolalpha;
    std::cout << "j_invalid.is_discarded()               = " << j_invalid.is_discarded() << '\n';
    std::cout << "j_discarded_by_callback                = " << j_discarded_by_callback << '\n';
    std::cout << "j_discarded_by_callback.is_discarded() = " << j_discarded_by_callback.is_discarded() << '\n';
}
