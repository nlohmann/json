#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json array = {1, 2, 3, 4, 5};
    json null;

    // print values
    std::cout << array << '\n';
    std::cout << null << '\n';

    // add values
    array.push_back(6);
    array += 7;
    null += "first";
    null += "second";

    // print values
    std::cout << array << '\n';
    std::cout << null << '\n';
}
