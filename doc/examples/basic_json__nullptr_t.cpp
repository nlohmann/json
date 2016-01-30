#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON null value
    json j(nullptr);

    // serialize the JSON null value
    std::cout << j << '\n';
}
