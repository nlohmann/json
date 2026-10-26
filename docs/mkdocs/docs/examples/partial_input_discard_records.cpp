#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

void handle(const json& record)
{
    std::cout << "handling " << record << '\n';
}

int main()
{
    std::istringstream file(R"([{"id": 1}, {"id": 2}, {"id": 3}])");

    json result = json::parse(file, [](int depth, json::parse_event_t event, json & record)
    {
        if (depth == 1 && event == json::parse_event_t::object_end)
        {
            handle(record);
            return false; // discard the record
        }
        return true;
    });

    std::cout << "result: " << result << '\n';
}
