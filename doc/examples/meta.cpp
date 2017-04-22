#include "json.hpp"
#include <iomanip> // for std::setw

using json = nlohmann::json;

int main()
{
    // call meta()
    std::cout << std::setw(4) << json::meta() << '\n';
}
