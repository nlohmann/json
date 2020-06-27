#include <nlohmann/json.hpp>
#include <iostream>

using json = nlohmann::json;

int main()
{
    std::cout << json::meta() << std::endl;
}
