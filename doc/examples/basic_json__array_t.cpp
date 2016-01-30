#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create an array_t value
    json::array_t value = {"one", "two", 3, 4.5, false};

    // create a JSON array from the value
    json j(value);

    // serialize the JSON array
    std::cout << j << '\n';
}
