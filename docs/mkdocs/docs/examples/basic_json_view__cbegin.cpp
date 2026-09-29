#include <iostream>
#include <numeric>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

int main()
{
    // sum many measurements with std::accumulate; cbegin()/cend() (identical
    // to begin()/end() here -- the view is always read-only) let the view be
    // used with standard algorithms without ever materializing the whole
    // array into a nlohmann::json value
    json_document measurements = json_document::parse("[3, 1, 4, 1, 5, 9, 2, 6]");
    const auto values = measurements.root();

    const int sum = std::accumulate(values.cbegin(), values.cend(), 0,
                                    [](int total, const json_view & v)
    {
        return total + v.materialize().get<int>();
    });

    std::cout << sum << '\n';
}
