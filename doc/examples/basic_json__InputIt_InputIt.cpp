#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_array = {"alpha", "bravo", "charly", "delta", "easy"};
    json j_number = 42;
    json j_object = {{"one", "eins"}, {"two", "zwei"}};

    // create copies using iterators
    json j_array_range(j_array.begin() + 1, j_array.end() - 2);
    json j_number_range(j_number.begin(), j_number.end());
    json j_object_range(j_object.begin(), j_object.find("two"));

    // serialize the values
    std::cout << j_array_range << '\n';
    std::cout << j_number_range << '\n';
    std::cout << j_object_range << '\n';

    // example for an exception
    try
    {
        json j_invalid(j_number.begin() + 1, j_number.end());
    }
    catch (json::invalid_iterator& e)
    {
        std::cout << e.what() << '\n';
    }
}
