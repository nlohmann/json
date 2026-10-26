# nlohmann::basic_json_view::count

```
size_type count(string_view_t key) const;
size_type count(const char* key) const;
size_type count(const string_t& key) const;
```

Returns the number of members with key `key` if the value is an object, `0` otherwise. Members with a repeated key are all counted.

## Parameters

`key` (in) : key value of the element to count

## Return value

the number of members of the object with key `key` (duplicates included), or `0` if the value is not an object or has no such member.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Linear in the number of members: unlike the lookup functions, `count()` does not stop at the first match, because it has to count every member with the key. Members are compared one after another, in document order. Each comparison first checks the key's length -- already known from the index, without reading the key bytes -- before comparing its content. The hash index of the keys of objects with 128 or more members does not help here, since every member is visited.

## Notes

This method always returns `0` when the value is not an object -- including a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view.

If the source text repeats a key, `count()` returns more than `1` for it, even though the [materialized](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) value (like the result of `parse()`) would have only one member with that key. Hence `count(key) > 1` detects duplicate keys. This is unlike the lookup functions ([`operator[]`](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/index.md), [`at`](https://json.nlohmann.me/api/basic_json_view/at/index.md), [`find`](https://json.nlohmann.me/api/basic_json_view/find/index.md), [`contains`](https://json.nlohmann.me/api/basic_json_view/contains/index.md)), which resolve to the *first* member; see the [Notes on duplicate keys](https://json.nlohmann.me/api/basic_json_view/operator%5B%5D/#notes) of `operator[]`.

## Examples

Example

The example below validates that every transaction of a batch carries exactly one `amount` field, using `count()` before deciding whether to materialize a transaction at all. It reports a transaction with no `amount` field and one with a duplicated `amount` field.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;

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
```

Output:

```
transaction 0: 9.99
transaction 1 has 0 "amount" fields
transaction 2 has 2 "amount" fields
```

## See also

- [find](https://json.nlohmann.me/api/basic_json_view/find/index.md) - find a value in an object
- [contains](https://json.nlohmann.me/api/basic_json_view/contains/index.md) - checks whether a key exists
- [`BasicJsonType::count`](https://json.nlohmann.me/api/basic_json/count/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
