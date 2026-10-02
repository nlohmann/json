#include <iostream>
#include <string>
#include <utility>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // BORROWED: doc only points into `text`; `text` must outlive `doc`
    std::string text = R"({"a": 1})";
    json_document doc = json_document::parse(text);
    std::cout << doc.owns_source() << '\n'; // false

    // a view is valid as long as the document is alive, has not been
    // re-parsed (read()) or shrunk (shrink_to_fit()), and -- if borrowed --
    // the source text is alive
    nlohmann::json_view v = doc.root();
    std::cout << v.is_object() << '\n';

    // re-parsing the SAME document invalidates views taken before the call;
    // `v` above must not be used after this line
    doc.read(R"([1, 2, 3])");
    v = doc.root(); // take a fresh view instead
    std::cout << v.is_array() << '\n';

    // moving the document does not invalidate views: the node index is
    // heap-allocated and does not move with the document object
    json_document moved = std::move(doc);
    std::cout << v.is_array() << '\n';
}
