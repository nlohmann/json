#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

int main()
{
    // create an ordered_json value; insertion order is preserved
    ordered_json oj = {{"c", 3}, {"a", 1}, {"b", 2}};

    // convert to json -- overload (4) is used; keys end up sorted
    json j(oj);

    // convert back to ordered_json -- the original insertion order is lost,
    // because it was already given up when converting to json
    ordered_json oj2(j);

    std::cout << oj << '\n';
    std::cout << j << '\n';
    std::cout << oj2 << '\n';
}
