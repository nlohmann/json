#include <algorithm>
#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

int main()
{
    // check that every element of a (possibly large) batch is an object,
    // before materializing any of them -- cbegin()/cend() (identical to
    // begin()/end() here) work as the range for std::all_of like they would
    // for any standard container
    json_document batch = json_document::parse(R"([{"id": 1}, {"id": 2}, {"id": 3}])");
    const auto records = batch.root();

    const bool all_objects = std::all_of(records.cbegin(), records.cend(),
                                         [](const json_view & v)
    {
        return v.is_object();
    });

    std::cout << std::boolalpha << all_objects << '\n';
}
