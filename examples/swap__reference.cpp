#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create two JSON values
    json j1 = {1, 2, 3, 4, 5};
    json j2 = {{"pi", 3.141592653589793}, {"e", 2.718281828459045}};

    // swap the values
    j1.swap(j2);

    // output the values
    std::cout << "j1 = " << j1 << '\n';
    std::cout << "j2 = " << j2 << '\n';
}
