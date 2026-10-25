#include <iostream>
#include <memory>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace nlohmann
{
template <typename T>
struct adl_serializer<std::shared_ptr<T>>
{
    static void to_json(json& j, const std::shared_ptr<T>& p)
    {
        if (p)
        {
            j = *p;
        }
        else
        {
            j = nullptr;
        }
    }

    static void from_json(const json& j, std::shared_ptr<T>& p)
    {
        if (j.is_null())
        {
            p = nullptr;
        }
        else
        {
            p = std::make_shared<T>(j.get<typename std::remove_const<T>::type>());
        }
    }
};

template <typename T>
struct adl_serializer<std::unique_ptr<T>>
{
    static void to_json(json& j, const std::unique_ptr<T>& p)
    {
        if (p)
        {
            j = *p;
        }
        else
        {
            j = nullptr;
        }
    }

    static void from_json(const json& j, std::unique_ptr<T>& p)
    {
        if (j.is_null())
        {
            p = nullptr;
        }
        else
        {
            p = std::make_unique<T>(j.get<T>());
        }
    }
};
} // namespace nlohmann

struct point
{
    int x;
    int y;
};

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(point, x, y)

int main()
{
    // an empty pointer is written as null
    const std::vector<std::shared_ptr<point>> points = {std::make_shared<point>(point{1, 2}), nullptr};
    const json j = points;
    std::cout << j << '\n';

    // reading allocates new objects
    const auto back = j.get<std::vector<std::shared_ptr<point>>>();
    std::cout << back[0]->x << ", " << back[0]->y << ", " << (back[1] == nullptr) << '\n';

    // pointers to const and unique_ptr work as well
    const auto const_ptr = j[0].get<std::shared_ptr<const point>>();
    const auto unique = j[0].get<std::unique_ptr<point>>();
    std::cout << const_ptr->y << ", " << unique->x << '\n';
}
