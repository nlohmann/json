#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a JSON text with an array and a number inside an object
    auto text = R"({"IDs": [116, 943], "Width": 800})";

    // discard the array when the parser reads its opening bracket
    json j_array_start = json::parse(text, [](int /*depth*/, json::parse_event_t event, json & /*parsed*/)
    {
        return event != json::parse_event_t::array_start;
    });

    // discard the same array when the parser reads its closing bracket
    json j_array_end = json::parse(text, [](int /*depth*/, json::parse_event_t event, json & /*parsed*/)
    {
        return event != json::parse_event_t::array_end;
    });

    // discard the number, but keep its key
    json j_value = json::parse(text, [](int /*depth*/, json::parse_event_t event, json & parsed)
    {
        return !(event == json::parse_event_t::value && parsed == json(800));
    });

    // discard the key of the number
    json j_key = json::parse(text, [](int /*depth*/, json::parse_event_t event, json & parsed)
    {
        return !(event == json::parse_event_t::key && parsed == json("Width"));
    });

    // discard the top-level object
    json j_root = json::parse(text, [](int /*depth*/, json::parse_event_t event, json & /*parsed*/)
    {
        return event != json::parse_event_t::object_end;
    });

    // in every case, the discarded value is removed together with its key
    std::cout << j_array_start << '\n'
              << j_array_end << '\n'
              << j_value << '\n'
              << j_key << '\n'
              << j_root << '\n';
}
