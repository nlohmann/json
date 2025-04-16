#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    // create some JSON values
    json j_object = R"( {"key": "value"} )"_json;
    json j_array = R"( [1, 2, 3] )"_json;

    // call contains
    std::cout << std::boolalpha <<
              "j_object contains 'key': " << j_object.contains("key") << '\n' <<
              "j_object contains 'another': " << j_object.contains("another") << '\n' <<
              "j_array contains 'key': " << j_array.contains("key") << std::endl;
}
