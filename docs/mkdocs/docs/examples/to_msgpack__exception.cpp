#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value with a binary subtype that exceeds 255
    json j = json::binary({1, 2, 3}, 300);

    // exception out_of_range.415
    try
    {
        json::to_msgpack(j);
    }
    catch (const json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}
