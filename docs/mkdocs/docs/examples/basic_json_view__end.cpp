#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // scan a (possibly large) array of readings for the first one over a
    // threshold; the loop stops at end() as soon as one is found, and only
    // the matching reading is ever materialized
    json_document readings = json_document::parse("[12, 18, 25, 31, 9]");
    const auto values = readings.root();

    auto it = values.begin();
    for (; it != values.end(); ++it)
    {
        if (it->materialize().get<int>() > 20)
        {
            break;
        }
    }

    if (it != values.end())
    {
        std::cout << "first reading over 20: " << it->materialize().dump() << '\n';
    }
}
