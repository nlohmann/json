#include <iostream>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a buffer containing a JSON text followed by more data
    std::vector<std::uint8_t> input = {'[', '1', ',', '2', ',', '3', ']', 'o', 't', 'h', 'e', 'r'};

    std::cout << std::boolalpha
              << json::accept(input.begin(), input.begin() + 7) << ' '
              << json::accept(input.begin(), input.end()) << '\n';
}
