#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // the build log of a running job; front() reads just the earliest event
    // without materializing the (possibly long) rest of the log
    json_document log = json_document::parse(R"(["queued", "started", "compiling", "linking", "done"])");
    std::cout << log.root().front().materialize().dump() << '\n';

    // an empty log -- front() throws instead of the undefined behavior
    // basic_json::front() has for an empty array
    json_document empty_log = json_document::parse("[]");
    try
    {
        static_cast<void>(empty_log.root().front());
    }
    catch (const nlohmann::json::invalid_iterator& e)
    {
        std::cout << e.what() << '\n';
    }
}
