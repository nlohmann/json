#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_pointer = nlohmann::json::json_pointer;

int main()
{
    // "retry_of" is only present on some records, nested a level down
    // inside "meta"
    json_document batch = json_document::parse(R"(
      [
        {"id": 1, "meta": {}},
        {"id": 2, "meta": {"retry_of": 1}}
      ]
    )");

    const auto records = batch.root();
    const json_pointer retry_of("/meta/retry_of");
    for (std::size_t i = 0; i < records.size(); ++i)
    {
        const auto record = records[i];
        if (record.contains(retry_of))
        {
            std::cout << "record " << i << " is a retry of " << record[retry_of].get<int>() << '\n';
        }
        else
        {
            std::cout << "record " << i << " is original\n";
        }
    }

    // contains() with a JSON pointer never throws -- not even for a
    // pointer that indexes into a primitive ("/0/id/x") or uses a
    // malformed array index ("/01"), either of which would need a
    // try/catch with json::contains(ptr)
    std::cout << std::boolalpha << records.contains(json_pointer("/0/id/x")) << '\n';
    std::cout << std::boolalpha << records.contains(json_pointer("/01")) << '\n';
}
