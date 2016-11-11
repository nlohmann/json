#include <json.hpp>

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
    object.emplace("three", 3);
    null.emplace("A", "a");
    null.emplace("B", "b");

    // print values
    std::cout << object << '\n';
    std::cout << null << '\n';
}
