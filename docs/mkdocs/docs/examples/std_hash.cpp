#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace nlohmann::literals;

int main()
{
    std::cout << "hash(null) = " << std::hash<json> {}(json(nullptr)) << '\n'
              << "hash(false) = " << std::hash<json> {}(json(false)) << '\n'
              << "hash(0) = " << std::hash<json> {}(json(0)) << '\n'
              << "hash(0U) = " << std::hash<json> {}(json(0U)) << '\n'
              << "hash(\"\") = " << std::hash<json> {}(json("")) << '\n'
              << "hash({}) = " << std::hash<json> {}(json::object()) << '\n'
              << "hash([]) = " << std::hash<json> {}(json::array()) << '\n'
              << "hash({\"hello\": \"world\"}) = " << std::hash<json> {}("{\"hello\": \"world\"}"_json)
              << std::endl;
}
