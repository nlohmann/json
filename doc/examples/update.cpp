#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create two JSON objects
    json o1 = R"( {"color": "red", "price": 17.99} )"_json;
    json o2 = R"( {"color": "blue", "speed": 100} )"_json;

    // add all keys from o2 to o1 (updating "color")
    o1.update(o2);

    // output updated object o1
    std::cout << std::setw(2) << o1 << '\n';
}
