#include <iostream>
#include <map>
#include <nlohmann/json.hpp>

// a JSON type that stores objects in a std::map (which keeps keys sorted)
// instead of the default ordered associative container
using sorted_json = nlohmann::json::with_object_t<std::map>;

int main()
{
    sorted_json j;
    j["c"] = 1;
    j["a"] = 2;
    j["b"] = 3;

    // keys are sorted, because std::map is used to store the object
    std::cout << j.dump() << std::endl;
}
