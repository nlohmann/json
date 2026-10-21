#include <array>
#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // three incoming messages; skip the ones that are not useful without ever
    // building a nlohmann::json value for them
    json_document heartbeat = json_document::parse("null");
    json_document empty_batch = json_document::parse("[]");
    json_document batch = json_document::parse(R"([{"id": 1}, {"id": 2}, {"id": 3}])");
    std::array<const json_document*, 3> messages = {{&heartbeat, &empty_batch, &batch}};

    for (const json_document* d : messages)
    {
        // is_array()/empty() only look at the flat index: a discarded
        // heartbeat or an empty batch is never turned into a nlohmann::json
        // value, so no per-element allocation happens for them
        if (!d->root().is_array() || d->root().empty())
        {
            std::cout << "skipped\n";
            continue;
        }

        // materialize() replays the subtree through the same SAX builder
        // basic_json::parse() uses, so the result is exactly what
        // basic_json::parse() would have produced for the same text
        nlohmann::json value = d->root().materialize();
        std::cout << value.dump() << '\n';
    }
}
