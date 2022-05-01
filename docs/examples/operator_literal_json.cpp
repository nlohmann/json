#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j = R"( {"hello": "world", "answer": 42} )"_json;

    std::cout << std::setw(2) << j << '\n';
}
