#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value
    json j = {{"one", 1}, {"two", 2}};

    // format_as() is found via argument-dependent lookup, the same way
    // fmt::format/fmt::print would find it
    auto j_str = format_as(j);

    std::cout << j_str << std::endl;
}
