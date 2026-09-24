#include <iostream>
#include <string_view>
#include <nlohmann/json.hpp>

using namespace std::string_view_literals;
using json = nlohmann::json;

int main()
{
    // create a JSON object
    json j_object = {{"one", 1}, {"two", 2}};

    // call count()
    auto count_two = j_object.count("two"sv);
    auto count_three = j_object.count("three"sv);

    // print values
    std::cout << "number of elements with key \"two\": " << count_two << '\n';
    std::cout << "number of elements with key \"three\": " << count_three << '\n';
}
