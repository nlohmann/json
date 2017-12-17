#include <iostream>
#include "json.hpp"

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
    array.emplace_back(6);
    null.emplace_back("first");
    null.emplace_back(3, "second");

    // print values
    std::cout << array << '\n';
    std::cout << null << '\n';
}
