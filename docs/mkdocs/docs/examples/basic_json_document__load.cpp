#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <nlohmann/json_view.hpp>

using json = nlohmann::json;
using json_document = nlohmann::json_document;
using image_check = json_document::image_check;

int main()
{
    std::cout << std::boolalpha;

    // the image of a parsed document -- as if read back from a cache file or
    // received from another process running the same build of the library
    const std::string text = R"({"name": "cache", "note": "caf\u00e9", "replicas": ["db2", "db3"]})";
    const json_document parsed = json_document::parse(text);
    const std::vector<std::uint8_t> image = parsed.save();

    // (1)/(2) load() needs no parsing, yet dumps exactly what parsing did
    const json_document borrowed = json_document::load(image);
    std::cout << (borrowed.root().dump() == parsed.root().dump()) << '\n';
    std::cout << borrowed.owns_source() << '\n'; // borrowed: still points into `image`

    // (3) load(std::move(image)) keeps the vector instead of copying it
    std::vector<std::uint8_t> to_move = image;
    const json_document owned = json_document::load(std::move(to_move));
    std::cout << owned.owns_source() << '\n';

    // a damaged image -- the last byte of the decoded string "note" holds
    // (an escape sequence, so it was unescaped into the document's own
    // buffer), flipped, as storage or transport corruption might do
    std::vector<std::uint8_t> damaged = image;
    damaged[damaged.size() - 2] = 0xFF;

    // image_check::full inspects strings and numbers, so it catches the damage
    try
    {
        static_cast<void>(json_document::load(damaged, image_check::full));
    }
    catch (const json::parse_error& e)
    {
        std::cout << e.id << '\n';
    }

    // image_check::bounds only checks structure and bounds, so a cache the
    // process already trusts loads without the extra scan -- reading a value
    // the damage did not touch is still safe
    const json_document trusted = json_document::load(damaged, image_check::bounds);
    std::cout << trusted.root()["name"].get<std::string>() << '\n';
}
