#include <json.hpp>
#include <iostream>
#include <iomanip>

using nlohmann::json;

int main()
{
    std::cout << std::setw(4) << json::meta() << std::endl;
}
