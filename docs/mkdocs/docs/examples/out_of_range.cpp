#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    try
    {
        // calling at() for an invalid index
        json j = {1, 2, 3, 4};
        j.at(4) = 10;
    }
    catch (const json::out_of_range& e)
    {
        // output exception information
        std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << std::endl;
    }
}
