#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // a log record: the fields matter in the order they were written, e.g.
    // to reproduce the record as it was logged. A nlohmann::json object
    // sorts its keys, so materializing and iterating it would instead print
    // them alphabetically ("level", "message", "time")
    json_document record = json_document::parse(R"({"time": "10:00:01", "level": "info", "message": "started"})");

    for (auto it = record.root().begin(); it != record.root().end(); ++it)
    {
        std::cout << it.key() << '=' << it->materialize().dump() << '\n';
    }
}
