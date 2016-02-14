/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (fuzz test support)
|  |  |__   |  |  | | | |  version 2.0.0
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Run "make fuzz_testing" and follow the instructions.

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
*/

#include <json.hpp>

using json = nlohmann::json;

int main()
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    while (__AFL_LOOP(1000))
    {
#endif
        try
        {
            json j(std::cin);
            std::cout << j << std::endl;
        }
        catch (std::invalid_argument& e)
        {
            std::cout << "Invalid argument in parsing" << e.what() << '\n';
        }
#ifdef __AFL_HAVE_MANUAL_CONTROL
    }
#endif
}
