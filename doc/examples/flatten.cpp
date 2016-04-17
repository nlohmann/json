#include <json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON value
    json j =
    {
        {"pi", 3.141},
        {"happy", true},
        {"name", "Niels"},
        {"nothing", nullptr},
        {
            "answer", {
                {"everything", 42}
            }
        },
        {"list", {1, 0, 2}},
        {
            "object", {
                {"currency", "USD"},
                {"value", 42.99},
                {"", "empty string"},
                {"/", "slash"},
                {"~", "tilde"},
                {"~1", "tilde1"}
            }
        }
    };

    // call flatten()
    std::cout << std::setw(4) << j.flatten() << '\n';

    // flatten for a primitive value
    std::cout << j["pi"].flatten() << '\n';
}
