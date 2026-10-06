#include <iostream>
#include <nlohmann/json_view.hpp>

using json = nlohmann::json;
using json_editable_document = nlohmann::json_editable_document;
using json_editable_view = nlohmann::json_editable_view;

int main()
{
    // a deployment plan -- "budget" is written with a trailing zero that has
    // no effect on its value
    const std::string text = R"({
  "release": "2026.09",
  "steps": ["build", "test", "deploy"],
  "budget": 19.90
})";

    json_editable_document doc = json_editable_document::parse(text);

    const std::size_t deploy_index = 2;
    const auto deploy = doc.root()["steps"][deploy_index];  // held across the insert

    doc.insert(doc.root()["steps"], deploy_index, "smoke-test"); // insert before "deploy"

    // the held view still refers to "deploy", even though its index moved
    // from 2 to 3, and nothing else in the document was touched
    std::cout << deploy.dump() << '\n';
    std::cout << doc.root().dump(2, ' ', false, json_editable_view::number_format::source) << "\n\n";

    // the same edit on a plain json value: an index held from before the
    // insert now refers to whatever moved into that slot, and dump()
    // rewrites "budget" to its shortest form even though it was never
    // touched
    json plain = json::parse(text);
    plain["steps"].insert(plain["steps"].begin() + static_cast<std::ptrdiff_t>(deploy_index), "smoke-test");
    std::cout << plain["steps"][deploy_index].dump() << '\n';
    std::cout << plain.dump(2) << '\n';
}
