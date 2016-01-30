#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_null;
    json j_boolean = true;
    json j_number_integer = 17;
    json j_number_float = 23.42;
    json j_object = {{"one", 1}, {"two", 2}};
    json j_object_empty(json::value_t::object);
    json j_array = {1, 2, 4, 8, 16};
    json j_array_empty(json::value_t::array);
    json j_string = "Hello, world";

    // call empty()
    std::cout << std::boolalpha;
    std::cout << j_null.empty() << '\n';
    std::cout << j_boolean.empty() << '\n';
    std::cout << j_number_integer.empty() << '\n';
    std::cout << j_number_float.empty() << '\n';
    std::cout << j_object.empty() << '\n';
    std::cout << j_object_empty.empty() << '\n';
    std::cout << j_array.empty() << '\n';
    std::cout << j_array_empty.empty() << '\n';
    std::cout << j_string.empty() << '\n';
}
