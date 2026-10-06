#include <iostream>
#include <iomanip>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

int main()
{
    // one order out of a large incoming batch -- write it straight to a log
    // stream without ever building a basic_json value for it, or for the
    // rest of the batch
    const json_document doc = json_document::parse(R"(
      [{"id": 1, "item": "cable"}, {"id": 2, "item": "adapter"}]
    )");
    const json_view orders = doc.root();

    // compact, for a one-line log entry
    std::cout << orders[1] << '\n';

    // std::setw sets the indentation level, exactly as for basic_json
    std::cout << std::setw(2) << orders[1] << "\n\n";

    // std::setfill changes the indentation character
    std::cout << std::setw(1) << std::setfill('\t') << orders[1] << '\n';
}
