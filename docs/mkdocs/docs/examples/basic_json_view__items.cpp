#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // a settings object whose source text records every update to a key as
    // a duplicate member. items() visits all of them, in document order, so
    // the update history is visible; operator[] only ever sees the first
    // one, and materialize() -- like basic_json::parse() -- keeps the last
    json_document updates = json_document::parse(R"({"retries": 1, "timeout": 30, "retries": 5})");
    const auto settings = updates.root();

    for (const auto& item : settings.items())
    {
        std::cout << item.key() << '=' << item.value().materialize().dump() << '\n';
    }

    std::cout << "first \"retries\" seen by operator[]: " << settings["retries"].materialize().dump() << '\n';
    std::cout << "last \"retries\" kept by materialize(): " << settings.materialize()["retries"].dump() << '\n';
}
