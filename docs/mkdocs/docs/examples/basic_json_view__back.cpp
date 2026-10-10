#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // the same build log; back() reads only the final status. It is linear
    // in the number of events (unlike front(), which is constant), but
    // still far less work than materializing the whole array
    json_document log = json_document::parse(R"(["queued", "started", "compiling", "linking", "done"])");
    std::cout << log.root().back().materialize().dump() << '\n';

    // an empty log -- back() throws instead of the undefined behavior
    // basic_json::back() has for an empty array
    json_document empty_log = json_document::parse("[]");
    try
    {
        static_cast<void>(empty_log.root().back());
    }
    catch (const nlohmann::json::invalid_iterator& e)
    {
        std::cout << e.what() << '\n';
    }
}
