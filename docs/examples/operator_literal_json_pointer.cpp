#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j = R"( {"hello": "world", "answer": 42} )"_json;
    auto val = j["/hello"_json_pointer];

    std::cout << std::setw(2) << val << '\n';
}
