#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // validate that every transaction of a batch carries exactly one
    // "amount" field before materializing any of them into a nlohmann::json
    // value -- count() counts every member with the key
    json_document batch = json_document::parse(R"(
      [
        {"id": 1, "amount": 9.99},
        {"id": 2},
        {"id": 3, "amount": 5.00, "amount": 500.00}
      ]
    )");

    const auto transactions = batch.root();
    for (std::size_t i = 0; i < transactions.size(); ++i)
    {
        const auto transaction = transactions[i];
        const auto amounts = transaction.count("amount");
        if (amounts != 1)
        {
            std::cout << "transaction " << i << " has " << amounts << " \"amount\" fields\n";
            continue;
        }
        std::cout << "transaction " << i << ": " << transaction["amount"].materialize().dump() << '\n';
    }
}
