#include <iostream>
#include <iomanip> // for std::setw
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // call meta()
    std::cout << std::setw(4) << json::meta() << '\n';
}
