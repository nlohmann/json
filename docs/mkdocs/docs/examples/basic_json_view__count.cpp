#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // validate that every transaction of a batch carries a mandatory
    // "amount" field before materializing any of them into a nlohmann::json
    // value -- count() returns 0 or 1 for an object
    json_document batch = json_document::parse(R"(
      [
        {"id": 1, "amount": 9.99},
        {"id": 2}
      ]
    )");

    const auto transactions = batch.root();
    for (std::size_t i = 0; i < transactions.size(); ++i)
    {
        const auto transaction = transactions[i];
        if (transaction.count("amount") == 0)
        {
            std::cout << "transaction " << i << " is missing \"amount\"\n";
            continue;
        }
        std::cout << "transaction " << i << ": " << transaction["amount"].materialize().dump() << '\n';
    }
}
