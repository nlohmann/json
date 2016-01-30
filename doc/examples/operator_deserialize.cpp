#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create stream with serialized JSON
    std::stringstream ss;
    ss << R"({
        "number": 23,
        "string": "Hello, world!",
        "array": [1, 2, 3, 4, 5],
        "boolean": false,
        "null": null
    })";

    // create JSON value and read the serialization from the stream
    json j;
    j << ss;

    // serialize JSON
    std::cout << std::setw(2) << j << '\n';
}
