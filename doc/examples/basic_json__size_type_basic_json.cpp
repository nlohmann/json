#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create an array by creating copies of a JSON value
    json value = "Hello";
    json array_0 = json(0, value);
    json array_1 = json(1, value);
    json array_5 = json(5, value);

    // serialize the JSON arrays
    std::cout << array_0 << '\n';
    std::cout << array_1 << '\n';
    std::cout << array_5 << '\n';
}
