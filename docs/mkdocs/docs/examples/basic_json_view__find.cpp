#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // a batch of incoming events; only some carry a "user_id" -- find()
    // locates it without throwing for the events that turn out to not be
    // objects, and without materializing an event that does not match
    json_document batch = json_document::parse(R"(
      [
        {"type": "click", "user_id": 42},
        {"type": "ping"},
        {"type": "click", "user_id": 7}
      ]
    )");

    const auto events = batch.root();
    for (std::size_t i = 0; i < events.size(); ++i)
    {
        const auto event = events[i];
        const auto it = event.find("user_id");
        if (it != event.end())
        {
            std::cout << "user " << it->materialize().dump() << '\n';
        }
    }
}
