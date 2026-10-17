#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json = nlohmann::json;

int main()
{
    // two snapshots of a polled configuration endpoint -- compare them
    // directly as views, without ever building a nlohmann::json value for
    // either one
    const json_document previous = json_document::parse(
                                       R"({"name": "cache", "port": 6379, "timeout": 30})");
    const json_document current = json_document::parse(
                                      R"({"port": 6379.0, "timeout": 30, "name": "cache"})");

    // same members, reordered, and 6379 written as a float -- operator==
    // treats them the same way BasicJsonType::operator== would
    std::cout << std::boolalpha << (previous.root() == current.root()) << '\n';

    // an actually changed value is detected the same way
    const json_document changed = json_document::parse(
                                      R"({"name": "cache", "port": 6380, "timeout": 30})");
    std::cout << (previous.root() == changed.root()) << '\n';

    // comparing a view directly against an expected json value -- handy in a
    // test, without materializing the received document at all
    const json expected = {{"name", "cache"}, {"port", 6379}, {"timeout", 30}};
    std::cout << (previous.root() == expected) << '\n';
}
