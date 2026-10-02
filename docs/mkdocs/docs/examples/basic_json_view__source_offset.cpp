#include <iostream>
#include <string>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // source_offset() points into source(): useful to report *where* in the
    // original text a value came from (error messages, syntax highlighting,
    // forwarding a sub-range verbatim, ...) without materializing it
    json_document doc = json_document::parse(R"(  123)");
    auto v = doc.root();
    std::cout << v.source_offset() << ' '
              << std::string(doc.source().data() + v.source_offset(), 3) << '\n';

    // a string without escapes also stays in the source text
    json_document plain = json_document::parse(R"("ab")");
    std::cout << plain.source()[plain.root().source_offset()] << '\n';

    // a string with escapes is decoded once into the document's own buffer, so
    // there is no single byte range in source() to point at: source_offset()
    // returns the "not applicable" sentinel
    json_document escaped = json_document::parse(R"("a\nb")");
    std::cout << (escaped.root().source_offset() == static_cast<std::size_t>(-1)) << '\n';

    // a discarded view -- default-constructed, or the root of a failed parse
    // with allow_exceptions == false -- has no offset either
    json_document failed = json_document::parse("not json", false);
    std::cout << (failed.root().source_offset() == static_cast<std::size_t>(-1)) << '\n';
}
