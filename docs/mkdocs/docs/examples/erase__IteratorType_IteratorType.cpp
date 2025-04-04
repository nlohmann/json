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
    json j_array = {1, 2, 4, 8, 16};
    json j_string = "Hello, world";

    // call erase()
    j_boolean.erase(j_boolean.begin(), j_boolean.end());
    j_number_integer.erase(j_number_integer.begin(), j_number_integer.end());
    j_number_float.erase(j_number_float.begin(), j_number_float.end());
    j_object.erase(j_object.find("two"), j_object.end());
    j_array.erase(j_array.begin() + 1, j_array.begin() + 3);
    j_string.erase(j_string.begin(), j_string.end());

    // print values
    std::cout << j_boolean << '\n';
    std::cout << j_number_integer << '\n';
    std::cout << j_number_float << '\n';
    std::cout << j_object << '\n';
    std::cout << j_array << '\n';
    std::cout << j_string << '\n';
}
