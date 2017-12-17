#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // create a JSON value
    json value = { {"translation", {{"one", "eins"}, {"two", "zwei"}}} };

    // create an object_t
    json::object_t object = {{"cow", "Kuh"}, {"dog", "Hund"}};

    // swap the object stored in the JSON value
    value["translation"].swap(object);

    // output the values
    std::cout << "value = " << value << '\n';
    std::cout << "object = " << object << '\n';
}
