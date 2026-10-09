#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // two user records from a large API response; only the fields that are
    // actually read are ever touched, and no nlohmann::json tree is built
    // for the batch
    json_document batch = json_document::parse(R"(
      [
        {"name": "Alice", "email": "alice@example.com", "tags": ["admin", "ops"]},
        {"name": "Bob", "tags": []}
      ]
    )");

    const auto users = batch.root();
    for (std::size_t i = 0; i < users.size(); ++i)
    {
        const auto user = users[i];
        std::cout << user["name"].materialize().dump();

        // operator[] on a missing object key gives a discarded view -- test
        // it with is_discarded(). The const overload of json::operator[]
        // would instead be undefined behavior (guarded by an assertion) for
        // a missing key
        const auto email = user["email"];
        if (!email.is_discarded())
        {
            std::cout << " <" << email.materialize().dump() << ">";
        }

        // the same holds for an array index past the end: a discarded view,
        // not undefined behavior
        const auto first_tag = user["tags"][0];
        if (!first_tag.is_discarded())
        {
            std::cout << " #" << first_tag.materialize().dump();
        }

        std::cout << '\n';
    }
}
