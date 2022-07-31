#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object
    json object =
    {
        {"one", 1}, {"two", 2}, {"three", 2.9}
    };

    // output element with key "two"
    std::cout << object["two"] << "\n\n";

    // change element with key "three"
    object["three"] = 3;

    // output changed array
    std::cout << std::setw(4) << object << "\n\n";

    // mention nonexisting key
    object["four"];

    // write to nonexisting key
    object["five"]["really"]["nested"] = true;

    // output changed object
    std::cout << std::setw(4) << object << '\n';
}
