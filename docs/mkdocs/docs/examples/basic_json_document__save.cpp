#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // a configuration a service parses once and then caches as an image, so
    // that later requests can load() it instead of parsing the text again
    const std::string text = R"({"name": "cache", "host": "db1", "port": 6379, "replicas": ["db2", "db3"]})";
    const json_document config = json_document::parse(text);

    // save() turns the parsed document into a byte buffer: a 64-byte header,
    // the node index, the source text, and the decoded strings
    const std::vector<std::uint8_t> image = config.save();
    std::cout << image.size() << '\n';

    // the same document always saves to the same bytes
    std::cout << (image == json_document::parse(text).save()) << '\n';

    // loading the image back needs no parsing, yet dumps exactly what
    // parsing the text produced
    const json_document reloaded = json_document::load(image);
    std::cout << (reloaded.root().dump() == config.root().dump()) << '\n';
}
