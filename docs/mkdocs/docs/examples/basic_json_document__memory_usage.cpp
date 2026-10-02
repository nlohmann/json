#include <iostream>
#include <string>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // long enough that copying it needs a real (heap) allocation, so the
    // comparison below does not depend on the standard library's small
    // string optimization threshold
    const std::string text = std::string(200, ' ') + "[1, 2, 3, 4, 5]";

    // memory_usage() is not portable across platforms/allocators/compilers, so
    // compare it relatively instead of printing the raw byte count
    json_document borrowed = json_document::parse(text);
    json_document owned = json_document::parse_copy(text);

    // the owned document additionally stores its own copy of the source text
    std::cout << (owned.memory_usage() > borrowed.memory_usage()) << '\n';

    // a document with more values needs a larger index
    json_document small = json_document::parse(std::string("[1]"));
    json_document large = json_document::parse(std::string("[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]"));
    std::cout << (large.memory_usage() > small.memory_usage()) << '\n';
}
