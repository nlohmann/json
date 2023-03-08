#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};

    // example for an object
    for (auto& x : j_object.items())
    {
        std::cout << "key: " << x.key() << ", value: " << x.value() << '\n';
    }

    // example for an array
    for (auto& x : j_array.items())
    {
        std::cout << "key: " << x.key() << ", value: " << x.value() << '\n';
    }
}
