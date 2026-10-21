#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // count how many of many incoming records carry an optional "retry_of"
    // field -- contains() only walks the flat index, so scanning a large
    // batch like this never builds a single nlohmann::json value
    json_document batch = json_document::parse(R"(
      [
        {"id": 1},
        {"id": 2, "retry_of": 1},
        {"id": 3},
        {"id": 4, "retry_of": 3}
      ]
    )");

    const auto records = batch.root();
    std::size_t retries = 0;
    for (std::size_t i = 0; i < records.size(); ++i)
    {
        if (records[i].contains("retry_of"))
        {
            ++retries;
        }
    }
    std::cout << retries << " of " << records.size() << " records are retries\n";
}
