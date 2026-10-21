#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

int main()
{
    // a price and an order id from an incoming order -- both need to be
    // reproduced exactly, e.g. for an invoice or an audit log
    json_document doc = json_document::parse(R"(
      {"price": 19.90, "order_id": 1234567890123456789012345, "quantity": 3}
    )");
    const json_view order = doc.root();

    // number_token() returns the number exactly as written in the source
    std::cout << order["price"].number_token() << '\n';
    std::cout << order["order_id"].number_token() << '\n';

    // get<double>() converts it instead -- the exact source text is gone:
    // "19.90" becomes the double closest to 19.9, printed without the
    // trailing zero, and the 25-digit order id -- far beyond any 64-bit
    // integer -- can only be approximated as a double
    std::cout << order["price"].get<double>() << '\n';
    std::cout << order.materialize()["order_id"].dump() << '\n';

    // an ordinary quantity has nothing to lose either way
    std::cout << order["quantity"].number_token() << " == " << order["quantity"].get<int>() << '\n';
}
