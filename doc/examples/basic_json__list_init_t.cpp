#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_empty_init_list = json({});
    json j_object = { {"one", 1}, {"two", 2} };
    json j_array = {1, 2, 3, 4};
    json j_nested_object = { {"one", {1}}, {"two", {1, 2}} };
    json j_nested_array = { {{1}, "one"}, {{1, 2}, "two"} };

    // serialize the JSON value
    std::cout << j_empty_init_list << '\n';
    std::cout << j_object << '\n';
    std::cout << j_array << '\n';
    std::cout << j_nested_object << '\n';
    std::cout << j_nested_array << '\n';
}
