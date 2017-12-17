#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // create JSON values
    json object = {{"one", 1}, {"two", 2}};
    json null;

    // print values
    std::cout << object << '\n';
    std::cout << null << '\n';

    // add values
    object.push_back(json::object_t::value_type("three", 3));
    object += json::object_t::value_type("four", 4);
    null += json::object_t::value_type("A", "a");
    null += json::object_t::value_type("B", "b");

    // print values
    std::cout << object << '\n';
    std::cout << null << '\n';
}
