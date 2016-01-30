#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};

    // serialize without indentation
    std::cout << j_object << "\n\n";
    std::cout << j_array << "\n\n";

    // serialize with indentation
    std::cout << std::setw(4) << j_object << "\n\n";
    std::cout << std::setw(2) << j_array << "\n\n";
}
