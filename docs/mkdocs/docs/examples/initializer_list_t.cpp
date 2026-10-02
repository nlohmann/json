#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // an initializer_list_t is what a braced-init-list of JSON values is deduced as
    json::initializer_list_t init = {"a", 1, 2.0, false};

    json j(init);
    std::cout << j.dump() << std::endl;
}
