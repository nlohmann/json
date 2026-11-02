#include <iostream>
#include <type_traits>
#include <nlohmann/json_view.hpp>

using nlohmann::json;

namespace ns
{
struct person
{
    std::string name;
    int age = 0;
};

// reads json values and views (of any document type), but nothing else
template < typename J, typename std::enable_if < nlohmann::is_json_view<J>::value || std::is_same<J, json>::value, int >::type = 0 >
void from_json(const J& j, person& p)
{
    p.name = j.at("name").template get<std::string>();
    p.age = j.at("age").template get<int>();
}
} // namespace ns

int main()
{
    std::cout << std::boolalpha
              << nlohmann::is_json_view<nlohmann::json_view>::value << ' '
              << nlohmann::is_json_view<nlohmann::ordered_json_editable_view>::value << ' '
              << nlohmann::is_json_view<json>::value << '\n';

    const nlohmann::json_document doc = nlohmann::json_document::parse(R"({"name": "Ada", "age": 36})");
    const auto p = doc.root().get<ns::person>(); // reads the view, no json value is built
    std::cout << p.name << ' ' << p.age << '\n';
}
