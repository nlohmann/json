#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    std::cout << std::boolalpha;

    // several incoming messages, one json_document per message. type() and
    // is_*() only look at the flat index built by parse(); no nlohmann::json
    // tree exists yet, and none is built unless materialize() is called
    json_document d_null = json_document::parse("null");
    json_document d_bool = json_document::parse("true");
    json_document d_int = json_document::parse("-42");
    json_document d_unsigned = json_document::parse("42");
    json_document d_float = json_document::parse("4.2");
    json_document d_string = json_document::parse(R"("hi")");
    json_document d_array = json_document::parse("[1, 2, 3]");
    json_document d_object = json_document::parse(R"({"a": 1})");

    std::cout << d_null.root().is_null() << '\n';
    std::cout << d_bool.root().is_boolean() << '\n';
    std::cout << d_int.root().is_number() << ' ' << d_int.root().is_number_integer() << '\n';
    std::cout << d_unsigned.root().is_number_unsigned() << '\n';
    std::cout << d_float.root().is_number_float() << '\n';
    std::cout << d_string.root().is_string() << '\n';
    std::cout << d_array.root().is_array() << ' ' << d_array.root().is_structured() << '\n';
    std::cout << d_object.root().is_object() << ' ' << d_object.root().is_primitive() << '\n';

    // JSON text can never produce a binary value: is_binary() is always false
    std::cout << d_array.root().is_binary() << '\n';

    // a default-constructed view, and the root of a document that failed to
    // parse without exceptions, are both discarded
    nlohmann::json_view invalid;
    json_document failed = json_document::parse("not json", /* allow_exceptions */ false);
    std::cout << static_cast<bool>(invalid) << ' ' << invalid.is_discarded() << '\n';
    std::cout << static_cast<bool>(failed.root()) << ' ' << failed.root().is_discarded() << '\n';

    // type() returns the same value_t enumeration as basic_json::type()
    std::cout << (d_object.root().type() == nlohmann::json::value_t::object) << '\n';
}
