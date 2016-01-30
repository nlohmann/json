#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON array
    json array = {"first", "2nd", "third", "fourth"};

    // output element at index 2 (third element)
    std::cout << array.at(2) << '\n';
}
