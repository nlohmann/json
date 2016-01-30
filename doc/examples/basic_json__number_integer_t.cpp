#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON number from number_integer_t
    json::number_integer_t value = 42;

    json j(value);

    // serialize the JSON numbers
    std::cout << j << '\n';
}
