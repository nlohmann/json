#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using std::to_string;

int main()
{
    // create values
    json j = {{"one", 1}, {"two", 2}};
    int i = 42;

    // use ADL to select best to_string function
    auto j_str = to_string(j);  // calling nlohmann::to_string
    auto i_str = to_string(i);  // calling std::to_string

    // serialize without indentation
    std::cout << j_str << "\n\n"
              << i_str << std::endl;
}
