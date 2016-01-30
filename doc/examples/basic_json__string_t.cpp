#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create an string_t value
    json::string_t value = "The quick brown fox jumps over the lazy doc";

    // create a JSON string from the value
    json j(value);

    // serialize the JSON array
    std::cout << j << '\n';
}
