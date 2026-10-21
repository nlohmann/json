#include <iostream>
#include <string>
#include <vector>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    std::vector<std::string> messages =
    {
        R"({"id": 1})", R"({"id": 2, "tag": "x"})", R"({"id": 3})"
    };

    // parse into the same document over and over: its node index and decode
    // buffer are reused instead of being freed and reallocated for each message
    json_document doc;
    std::size_t total = 0;
    for (const auto& msg : messages)
    {
        doc.read(msg);
        total += doc.root().size();
    }
    std::cout << total << '\n';

    // read() can also change what kind of input is owned/borrowed between calls
    doc.read(std::string(R"({"owned": true})"));
    std::cout << doc.owns_source() << '\n';
}
