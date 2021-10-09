#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create two JSON objects
    json o1 = R"( {"color": "red", "price": 17.99, "names": {"de": "Flugzeug"}} )"_json;
    json o2 = R"( {"color": "blue", "speed": 100, "names": {"en": "plane"}} )"_json;
    json o3 = o1;

    // add all keys from o2 to o1 (updating "color", replacing "names")
    o1.update(o2);

    // add all keys from o2 to o1 (updating "color", merging "names")
    o3.update(o2, true);

    // output updated object o1 and o3
    std::cout << std::setw(2) << o1 << '\n';
    std::cout << std::setw(2) << o3 << '\n';
}
