#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON array
    json array = {"first", "2nd", "third", "fourth"};

    // output element at index 2 (third element)
    std::cout << array.at(2) << '\n';

    // try to read beyond the array limit
    try
    {
        std::cout << array.at(5) << '\n';
    }
    catch (std::out_of_range)
    {
        std::cout << "out of range" << '\n';
    }
}
