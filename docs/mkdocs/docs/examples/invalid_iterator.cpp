#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    try
    {
        // calling iterator::key() on non-object iterator
        json j = "string";
        json::iterator it = j.begin();
        auto k = it.key();
    }
    catch (const json::invalid_iterator& e)
    {
        // output exception information
        std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << std::endl;
    }
}
