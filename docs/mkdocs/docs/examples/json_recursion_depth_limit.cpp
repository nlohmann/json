#include <functional>
#include <iostream>
#include <utility>

// walk over at most 16 nesting levels on the call stack, and over the rest with an explicit stack
#define JSON_RECURSION_DEPTH_LIMIT 16
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // an array nested 5,000 levels deep, built without recursion
    json j = 1;
    for (int i = 0; i < 5000; ++i)
    {
        json outer = json::array();
        outer.push_back(std::move(j));
        j = std::move(outer);
    }

    // the results are those of any other limit
    const json copy = j;
    std::cout << std::boolalpha;
    std::cout << "limit: " << JSON_RECURSION_DEPTH_LIMIT << '\n';
    std::cout << "copy equals original: " << (copy == j) << '\n';
    std::cout << "length of dump(): " << j.dump().size() << '\n';
    std::cout << "same hash: " << (std::hash<json> {}(copy) == std::hash<json> {}(j)) << '\n';
}
