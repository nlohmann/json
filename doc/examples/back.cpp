#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_boolean = true;
    json j_number_integer = 17;
    json j_number_float = 23.42;
    json j_object = {{"one", 1}, {"two", 2}};
    json j_object_empty(json::value_t::object);
    json j_array = {1, 2, 4, 8, 16};
    json j_array_empty(json::value_t::array);
    json j_string = "Hello, world";

    // call back()
    std::cout << j_boolean.back() << '\n';
    std::cout << j_number_integer.back() << '\n';
    std::cout << j_number_float.back() << '\n';
    std::cout << j_object.back() << '\n';
    //std::cout << j_object_empty.back() << '\n';  // undefined behavior
    std::cout << j_array.back() << '\n';
    //std::cout << j_array_empty.back() << '\n';   // undefined behavior
    std::cout << j_string.back() << '\n';

    // back() called on a null value
    try
    {
        json j_null;
        j_null.back();
    }
    catch (json::invalid_iterator& e)
    {
        std::cout << e.what() << '\n';
    }
}
