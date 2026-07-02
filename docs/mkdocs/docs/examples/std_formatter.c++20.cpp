#include <format>
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j = {{"one", 1}, {"two", 2}};

    // compact formatting, like dump()
    std::cout << std::format("{}", j) << "\n\n";

    // pretty-printed formatting, like dump(4)
    std::cout << std::format("{:#}", j) << "\n\n";

    // a width sets the indent, like dump(2)
    std::cout << std::format("{:2}", j) << "\n\n";

    // fill-and-align sets the indent character, like dump(4, '.')
    std::cout << std::format("{:.>#}", j) << std::endl;
}
