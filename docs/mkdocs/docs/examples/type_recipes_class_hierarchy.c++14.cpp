#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

struct shape
{
    virtual ~shape() = default;
    virtual json serialize() const = 0;
};

struct circle : shape
{
    double radius;

    explicit circle(double r) : radius(r) {}

    json serialize() const override
    {
        return {{"type", "circle"}, {"radius", radius}};
    }
};

struct rectangle : shape
{
    double width;
    double height;

    rectangle(double w, double h) : width(w), height(h) {}

    json serialize() const override
    {
        return {{"type", "rectangle"}, {"width", width}, {"height", height}};
    }
};

namespace nlohmann
{
template <>
struct adl_serializer<std::unique_ptr<shape>>
{
    static void to_json(json& j, const std::unique_ptr<shape>& p)
    {
        j = p ? p->serialize() : json(nullptr);
    }

    static void from_json(const json& j, std::unique_ptr<shape>& p)
    {
        if (j.is_null())
        {
            p.reset();
            return;
        }

        const auto& type = j.at("type").get_ref<const std::string&>();
        if (type == "circle")
        {
            p = std::make_unique<circle>(j.at("radius").get<double>());
        }
        else if (type == "rectangle")
        {
            p = std::make_unique<rectangle>(j.at("width").get<double>(), j.at("height").get<double>());
        }
        else
        {
            throw std::invalid_argument("unknown shape type: " + type);
        }
    }
};
} // namespace nlohmann

int main()
{
    std::vector<std::unique_ptr<shape>> shapes;
    shapes.push_back(std::make_unique<circle>(1.5));
    shapes.push_back(std::make_unique<rectangle>(2, 3));

    const json j = shapes;
    std::cout << j << '\n';

    // reading creates objects of the derived types
    const auto back = j.get<std::vector<std::unique_ptr<shape>>>();
    std::cout << std::boolalpha;
    std::cout << "first is a circle: " << (dynamic_cast<circle*>(back[0].get()) != nullptr) << '\n';
    std::cout << "second is a rectangle: " << (dynamic_cast<rectangle*>(back[1].get()) != nullptr) << '\n';

    // an unknown type tag is reported
    try
    {
        json{{"type", "star"}}.get<std::unique_ptr<shape>>();
    }
    catch (const std::invalid_argument& e)
    {
        std::cout << e.what() << '\n';
    }
}
