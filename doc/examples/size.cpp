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

    // call size()
    std::cout << j_null.size() << '\n';
    std::cout << j_boolean.size() << '\n';
    std::cout << j_number_integer.size() << '\n';
    std::cout << j_number_float.size() << '\n';
    std::cout << j_object.size() << '\n';
    std::cout << j_object_empty.size() << '\n';
    std::cout << j_array.size() << '\n';
    std::cout << j_array_empty.size() << '\n';
    std::cout << j_string.size() << '\n';
}
