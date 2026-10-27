# <small>nlohmann::basic_json_view::</small>number_format

```cpp
enum class number_format {
    shortest,
    source
};
```

This enumeration is used in [`dump`](dump.md) to choose how numbers are written. Two values are differentiated:

shortest
:   integers are copied from the source text — already canonical in JSON — except that `#!cpp -0` becomes
    `#!cpp 0`, the way [`BasicJsonType::parse()`](../basic_json/parse.md) reads it; floats are written with the
    library's shortest round-trip conversion, exactly as [`BasicJsonType::dump()`](../basic_json/dump.md) would (e.g.
    `#!cpp 1.5`, `#!cpp 100.0`, `#!cpp 1e+100`)

source
:   every number is copied exactly as it appears in the source text — `#!cpp 1.50`, `#!cpp 1E2`, `#!cpp -0`, all
    digits of an integer literal with more digits than any number type holds — something `BasicJsonType` cannot do,
    since parsing already reduces every number to its parsed value

## Examples

??? example

    The example below writes back a price list received from a supplier: with `number_format::shortest` (the
    default), a trailing zero and scientific notation are normalized away and a long account number that overflows
    every number type is rounded, the same way `#!cpp materialize().dump()` (or `basic_json::dump()`) would;
    `number_format::source` keeps every number exactly as it was written in the source text instead.

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json_document;
    using nlohmann::json_view;
    
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
    
    ```

    Output:

    ```json
    [{"sku":"A1","price":19.9,"account_id":1.2345678901234568e+25},{"sku":"A2","price":100.0,"account_id":9.876543210987655e+25}]
    [{"sku":"A1","price":19.90,"account_id":12345678901234567890123456},{"sku":"A2","price":1E2,"account_id":98765432109876543210987654}]
    
    ```

## See also

- [`dump`](dump.md) - serialize to a JSON-formatted string
- [`number_token`](number_token.md) - get a single number's token text without dumping the whole value
- [`BasicJsonType::error_handler_t`](../basic_json/error_handler_t.md) - the analogous enumeration for
  `BasicJsonType::dump`'s decoding-error behavior
- [Zero-copy JSON views](../../features/json_view.md#writing-a-view-back) - writing numbers as they appeared in the source

## Version history

- Added in version 3.13.0.
