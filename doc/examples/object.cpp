#include <json.hpp>

using namespace nlohmann;

int main()
{
    // create JSON arrays
    json j_no_init_list = json::object();
    json j_empty_init_list = json::object({});
    json j_list_of_pairs = json::object({ {"one", 1}, {"two", 2} });
    //json j_invalid_list = json::object({ "one", 1 }); // would throw

    // serialize the JSON arrays
    std::cout << j_no_init_list << '\n';
    std::cout << j_empty_init_list << '\n';
    std::cout << j_list_of_pairs << '\n';
}
