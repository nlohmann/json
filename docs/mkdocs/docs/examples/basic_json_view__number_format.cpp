#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;
using json_view = nlohmann::json_view;

int main()
{
    // a price list received from a supplier feed -- prices and account
    // numbers must be forwarded exactly, e.g. into an invoice
    const json_document doc = json_document::parse(R"(
      [{"sku": "A1", "price": 19.90, "account_id": 12345678901234567890123456},
       {"sku": "A2", "price": 1E2, "account_id": 98765432109876543210987654}]
    )");
    const json_view list = doc.root();

    // number_format::shortest (the default) writes numbers the way
    // basic_json::dump() would: "19.90" becomes "19.9", "1E2" becomes
    // "100.0", and each account number -- far beyond any 64-bit integer --
    // is rounded to the nearest double, exactly as materialize().dump()
    // (or a plain nlohmann::json) would round it
    std::cout << list.dump() << '\n';

    // number_format::source copies every number exactly as it was written
    // in the source text instead -- something basic_json cannot do at all,
    // since parsing already reduces every number to its parsed value
    std::cout << list.dump(-1, ' ', false, json_view::number_format::source) << '\n';
}
