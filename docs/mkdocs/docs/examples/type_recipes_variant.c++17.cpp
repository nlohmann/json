#include <iostream>
#include <stdexcept>
#include <variant>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace geo
{
struct circ
{
    double radius;
};

struct rect
{
    double width;
    double height;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(circ, radius)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(rect, width, height)

using figure = std::variant<circ, rect>;

void to_json(json& j, const figure& f)
{
    std::visit([&j](const auto & alternative)
    {
        j = alternative;
    }, f);
    j["type"] = std::holds_alternative<circ>(f) ? "circ" : "rect";
}

void from_json(const json& j, figure& f)
{
    const auto& type = j.at("type").get_ref<const std::string&>();
    if (type == "circ")
    {
        f = j.get<circ>();
    }
    else if (type == "rect")
    {
        f = j.get<rect>();
    }
    else
    {
        throw std::invalid_argument("unknown figure type: " + type);
    }
}
} // namespace geo

int main()
{
    const std::vector<geo::figure> figures = {geo::circ{2}, geo::rect{3, 4}};

    const json j = figures;
    std::cout << j << '\n';

    const auto back = j.get<std::vector<geo::figure>>();
    std::cout << "alternatives read back: " << back[0].index() << ", " << back[1].index() << '\n';
}
