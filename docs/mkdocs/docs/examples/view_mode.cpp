#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::basic_json_view;
using nlohmann::view_mode;

// accepts the views of read-only and of editable documents, of json and of ordered_json
template<typename BasicJsonType, view_mode Mode>
std::size_t count_members(basic_json_view<BasicJsonType, Mode> v)
{
    return v.is_object() ? v.size() : 0;
}

// accepts only the views of editable documents
template<typename BasicJsonType>
bool is_edited(basic_json_view<BasicJsonType, view_mode::editable> v)
{
    return v.is_string() && v.get_string() == "edited";
}

int main()
{
    const nlohmann::json_document doc = nlohmann::json_document::parse(R"({"a": 1, "b": 2})");
    nlohmann::json_editable_document edoc = nlohmann::json_editable_document::parse(R"({"a": 1})");
    edoc.set(edoc.root()["a"], "edited");

    std::cout << count_members(doc.root()) << ' ' << count_members(edoc.root()) << '\n';
    std::cout << std::boolalpha << is_edited(edoc.root()["a"]) << '\n';
}
