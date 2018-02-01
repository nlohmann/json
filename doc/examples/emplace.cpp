#include <iostream>
#include <nlohmann/json.hpp>

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
    auto res1 = object.emplace("three", 3);
    null.emplace("A", "a");
    null.emplace("B", "b");

    // the following call will not add an object, because there is already
    // a value stored at key "B"
    auto res2 = null.emplace("B", "c");

    // print values
    std::cout << object << '\n';
    std::cout << *res1.first << " " << std::boolalpha << res1.second << '\n';

    std::cout << null << '\n';
    std::cout << *res2.first << " " << std::boolalpha << res2.second << '\n';
}
