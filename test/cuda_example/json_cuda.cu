#include <nlohmann/json.hpp>

int main()
{
    nlohmann::ordered_json json = {"Test"};
    json.dump();
}
