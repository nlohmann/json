#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};

    // call dump()
    std::cout << j_object.dump() << "\n\n";
    std::cout << j_object.dump(-1) << "\n\n";
    std::cout << j_object.dump(0) << "\n\n";
    std::cout << j_object.dump(4) << "\n\n";
    std::cout << j_array.dump() << "\n\n";
    std::cout << j_array.dump(-1) << "\n\n";
    std::cout << j_array.dump(0) << "\n\n";
    std::cout << j_array.dump(4) << "\n\n";
}
