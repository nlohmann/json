#include <iostream>
#include <nlohmann/json_view.hpp>
#include <string>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

int main()
{
    // a "large response" stand-in: only the "id" field is ever read out of it
    const std::string text =
        R"({"id": "8f14e45f-ceea-467e-bb92-963f5e3c7a08", "note": "created via API\n", "payload": "..."})";
    const json_document doc = json_document::parse(text);
    const json_view response = doc.root();

    const json_view::string_view_t id = response["id"].get_string();
    std::cout << id << '\n';

    // no std::string was allocated for "id": its bytes still live inside
    // the original buffer, so id's data lies inside [text.data(),
    // text.data() + text.size())
    const bool id_in_source = id.data() >= text.data() && id.data() + id.size() <= text.data() + text.size();
    std::cout << std::boolalpha << id_in_source << '\n';

    // "note" contains an escape sequence ('\n'), so it was decoded once
    // into the document's own buffer -- get_string() still avoids a copy
    // into a new std::string, but the bytes no longer live inside "text"
    const json_view::string_view_t note = response["note"].get_string();
    const bool note_in_source = note.data() >= text.data() && note.data() + note.size() <= text.data() + text.size();
    std::cout << std::boolalpha << note_in_source << '\n';
}
