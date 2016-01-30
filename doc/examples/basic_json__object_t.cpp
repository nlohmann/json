#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create an object_t value
    json::object_t value = { {"one", 1}, {"two", 2} };

    // create a JSON object from the value
    json j(value);

    // serialize the JSON object
    std::cout << j << '\n';
}
