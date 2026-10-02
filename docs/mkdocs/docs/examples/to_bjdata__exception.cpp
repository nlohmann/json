#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a non-empty JSON array
    json j = {1, 2, 3};

    // exception other_error.502
    try
    {
        json::to_bjdata(j, false, true);
    }
    catch (const json::other_error& e)
    {
        std::cout << e.what() << '\n';
    }
}
