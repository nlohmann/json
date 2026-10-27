# nlohmann::basic_json_view::number_token

```
string_view_t number_token() const;
```

Returns the number exactly as it appears in the source text, without parsing or rounding it.

## Return value

The number's token text, as a [`string_view_t`](https://json.nlohmann.me/api/basic_json_view/#member-types) into the document's [`source()`](https://json.nlohmann.me/api/basic_json_document/source/index.md) text — for example `"1.50"`, `"1E2"`, `"-0"`, or an integer literal with more digits than any number type holds (such as a 30-digit integer, which [`get<T>()`](https://json.nlohmann.me/api/basic_json_view/get/index.md) and [`materialize()`](https://json.nlohmann.me/api/basic_json_view/materialize/index.md) can only represent approximately, as a `number_float_t`).

## Exception safety

Strong guarantee: there are no changes to the view or the document it refers to.

## Exceptions

Throws [`type_error.302`](https://json.nlohmann.me/home/exceptions/#jsonexceptiontype_error302) if the value is not a number; example: `"type must be number, but is string"`.

This exception does not carry a [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) path: the view has no `BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with `JSON_DIAGNOSTICS` enabled.

## Complexity

Constant.

## Notes

`BasicJsonType` has no counterpart to this function: once a number is parsed into `number_integer_t`, `number_unsigned_t`, or `number_float_t`, its original textual form (leading zeros aside, which are already rejected by the grammar; trailing zeros in the fraction; the case and sign of the exponent; ...) is gone. `number_token()` is useful precisely where that form must survive — a price or an identifier that must be reproduced exactly, or a number too large for any of `BasicJsonType`'s number types to hold without loss.

The returned [`string_view_t`](https://json.nlohmann.me/api/basic_json_view/#member-types) always points into the document's [`source()`](https://json.nlohmann.me/api/basic_json_document/source/index.md) text — numbers are never decoded into the document's separate string buffer — and is valid exactly as long as that text is, see the [validity rules](https://json.nlohmann.me/api/basic_json_view/index.md) of `basic_json_view`.

## Examples

Example

The example below keeps a price and an order ID exactly as they were written in an incoming order, where converting them with [`get<T>()`](https://json.nlohmann.me/api/basic_json_view/get/index.md) would lose information: the price picks up floating-point rounding, and the order ID — more digits than a 64-bit integer holds — can only be approximated as a `double` once `materialize()`d.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;
using nlohmann::json_view;

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
```

Output:

```
19.90
1234567890123456789012345
19.9
1.2345678901234568e+24
3 == 3
```

## See also

- [`get`](https://json.nlohmann.me/api/basic_json_view/get/index.md) - convert the value to a given type
- [`get_string`](https://json.nlohmann.me/api/basic_json_view/get_string/index.md) - the string, without a copy
- [`BasicJsonType::number_integer_t`](https://json.nlohmann.me/api/basic_json/number_integer_t/index.md), [`number_unsigned_t`](https://json.nlohmann.me/api/basic_json/number_unsigned_t/index.md), [`number_float_t`](https://json.nlohmann.me/api/basic_json/number_float_t/index.md) - the number types `get<T>()` and `materialize()` convert into
- [Zero-copy JSON views](https://json.nlohmann.me/features/json_view/#getting-values-out-without-copying) - reading a number exactly as written

## Version history

- Added in version 3.13.0 unreleased.
