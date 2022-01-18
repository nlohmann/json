#include <nlohmann/json.hpp>

int main()
{
    nlohmann::ordered_json json = {"Test"};
    json.dump();

    // regression for #3013 (ordered_json::reset() compile error with nvcc)
    nlohmann::ordered_json metadata;
    metadata.erase("key");
}
