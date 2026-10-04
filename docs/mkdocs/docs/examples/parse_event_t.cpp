#include <iostream>
#include <string>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// translate a parse_event_t to a human-readable name
std::string event_name(json::parse_event_t event)
{
    switch (event)
    {
        case json::parse_event_t::object_start:
            return "object_start";
        case json::parse_event_t::object_end:
            return "object_end";
        case json::parse_event_t::array_start:
            return "array_start";
        case json::parse_event_t::array_end:
            return "array_end";
        case json::parse_event_t::key:
            return "key";
        case json::parse_event_t::value:
            return "value";
        default:
            return "unknown";
    }
}

int main()
{
    // a small JSON text
    auto text = R"({"pi": 3.141, "numbers": [1, 2]})";

    // parse the text and report every event together with its depth;
    // returning true keeps every value unchanged
    json j = json::parse(text, [](int depth, json::parse_event_t event, json& /*parsed*/)
    {
        std::cout << depth << " " << event_name(event) << '\n';
        return true;
    });

    // the callback did not change anything, so the parsed value is unaffected
    std::cout << j << '\n';
}
