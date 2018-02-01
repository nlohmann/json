#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create several JSON values
    json array_1 = {1, 2, 3};
    json array_2 = {1, 2, 4};
    json object_1 = {{"A", "a"}, {"B", "b"}};
    json object_2 = {{"B", "b"}, {"A", "a"}};
    json number_1 = 17;
    json number_2 = 17.0000000000001L;
    json string_1 = "foo";
    json string_2 = "bar";

    // output values and comparisons
    std::cout << std::boolalpha;
    std::cout << array_1 << " >= " << array_2 << " " << (array_1 >= array_2) << '\n';
    std::cout << object_1 << " >= " << object_2 << " " << (object_1 >= object_2) << '\n';
    std::cout << number_1 << " >= " << number_2 << " " << (number_1 >= number_2) << '\n';
    std::cout << string_1 << " >= " << string_2 << " " << (string_1 >= string_2) << '\n';
}
