#include <iostream>
#include <nlohmann/json_view.hpp>

using json = nlohmann::json;
using json_editable_document = nlohmann::json_editable_document;

int main()
{
    // "events" starts out null -- the first push_back() turns it into an
    // array, exactly like set() turns a null object member into an object
    json_editable_document doc = json_editable_document::parse(R"({"source": "sensor-1", "events": null})");

    const auto first = doc.push_back(doc.root()["events"], json{{"type", "start"}, {"t", 0}});
    for (int t = 1; t <= 3; ++t)
    {
        doc.push_back(doc.root()["events"], json{{"type", "tick"}, {"t", t}});
    }

    // push_back() never moves an existing element: a view taken from an
    // earlier call still refers to the same element after later ones
    std::cout << first.dump() << '\n';
    std::cout << doc.root()["events"].size() << '\n';
    std::cout << doc.root().dump(2) << '\n';
}
