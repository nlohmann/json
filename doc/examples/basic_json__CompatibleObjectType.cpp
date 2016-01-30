#include <json.hpp>
#include <unordered_map>

using json = nlohmann::json;

int main()
{
    // create an object from std::map
    std::map<std::string, int> c_map
    {
        {"one", 1}, {"two", 2}, {"three", 3}
    };
    json j_map(c_map);

    // create an object from std::unordered_map
    std::unordered_map<const char*, double> c_umap
    {
        {"one", 1.2}, {"two", 2.3}, {"three", 3.4}
    };
    json j_umap(c_umap);

    // create an object from std::multimap
    std::multimap<std::string, bool> c_mmap
    {
        {"one", true}, {"two", true}, {"three", false}, {"three", true}
    };
    json j_mmap(c_mmap); // only one entry for key "three" is used

    // create an object from std::unordered_multimap
    std::unordered_multimap<std::string, bool> c_ummap
    {
        {"one", true}, {"two", true}, {"three", false}, {"three", true}
    };
    json j_ummap(c_ummap); // only one entry for key "three" is used

    // serialize the JSON objects
    std::cout << j_map << '\n';
    std::cout << j_umap << '\n';
    std::cout << j_mmap << '\n';
    std::cout << j_ummap << '\n';
}
