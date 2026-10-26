#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    std::istringstream input(R"({"a":1} [2,3] 4 "s")");

    // check for the end of the stream before each read, because a read at the end throws
    json j;
    while (input >> std::ws && input.peek() != std::char_traits<char>::eof())
    {
        input >> j;
        std::cout << j << '\n';
    }
}
