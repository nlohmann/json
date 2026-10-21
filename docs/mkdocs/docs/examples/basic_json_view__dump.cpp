#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

int main()
{
    // a large batch of sensor readings -- forward just the one that changed,
    // without ever building a basic_json value for the batch or for the
    // readings that are not needed
    const json_document batch = json_document::parse(R"(
      [{"id": 1, "temp": 21.5}, {"id": 2, "temp": 87.3}, {"id": 3, "temp": 21.7}]
    )");
    const json_view readings = batch.root();
    std::cout << readings[1].dump() << '\n';

    // a configuration file -- dump() on the view keeps the member order of
    // the source text; a json value's object_t is std::map, so
    // materialize().dump() of the very same view sorts the keys instead
    const json_document config = json_document::parse(
                                     R"({"name": "cache", "host": "db1", "port": 6379, "timeout": 30})");
    std::cout << config.root().dump(2) << "\n\n";
    std::cout << config.root().materialize().dump(2) << '\n';
}
