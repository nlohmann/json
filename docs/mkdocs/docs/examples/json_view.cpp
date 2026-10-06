#include <iostream>
#include <nlohmann/json_view.hpp>

int main()
{
    std::cout << std::boolalpha;

    // json_view is basic_json_view<nlohmann::json>: a read-only handle
    // returned by json_document::root()
    nlohmann::json_document doc = nlohmann::json_document::parse("[1, 2, 3]");
    nlohmann::json_view v = doc.root();

    std::cout << v.is_array() << ' ' << v.size() << '\n';
}
