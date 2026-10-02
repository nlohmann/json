#include <iostream>
#include <nlohmann/json_view.hpp>

int main()
{
    nlohmann::ordered_json_document doc = nlohmann::ordered_json_document::parse(R"({"z": 1, "a": 2})");
    nlohmann::ordered_json_view v = doc.root();

    std::cout << std::boolalpha << v.is_object() << ' ' << v.size() << '\n';
}
