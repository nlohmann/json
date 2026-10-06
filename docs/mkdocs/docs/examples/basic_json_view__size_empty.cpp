#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // decide whether a batch is worth processing before building any
    // nlohmann::json value for it
    json_document batch = json_document::parse(R"([1, 2, 3, 4, 5])");
    json_document empty_batch = json_document::parse("[]");

    std::cout << batch.root().empty() << ' ' << batch.root().size() << '\n';
    std::cout << empty_batch.root().empty() << ' ' << empty_batch.root().size() << '\n';

    // as for basic_json: null has size 0, every other scalar has size 1
    json_document n = json_document::parse("null");
    json_document s = json_document::parse(R"("hi")");
    std::cout << n.root().size() << ' ' << s.root().size() << '\n';
}
