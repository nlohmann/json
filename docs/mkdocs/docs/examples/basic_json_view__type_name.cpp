#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

int main()
{
    // report why some parsed messages were rejected, using only
    // type_name() -- no nlohmann::json value is built for the ones that
    // are wrong
    json_document good = json_document::parse(R"({"id": 1})");
    json_document bad = json_document::parse("[1, 2, 3]");
    json_document failed = json_document::parse("not json", /* allow_exceptions */ false);

    for (const json_view v :
            {
                good.root(), bad.root(), failed.root()
            })
    {
        if (v.is_object())
        {
            std::cout << "ok\n";
        }
        else
        {
            std::cout << "expected an object, got " << v.type_name() << '\n';
        }
    }
}
