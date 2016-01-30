#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object
    json j_object = {{"one", 1}, {"two", 2}};

    // call find
    auto it_two = j_object.find("two");
    auto it_three = j_object.find("three");

    // print values
    std::cout << std::boolalpha;
    std::cout << "\"two\" was found: " << (it_two != j_object.end()) << '\n';
    std::cout << "value at key \"two\": " << *it_two << '\n';
    std::cout << "\"three\" was found: " << (it_three != j_object.end()) << '\n';
}
