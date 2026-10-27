# nlohmann::basic_json_view::type_name

```
const char* type_name() const noexcept;
```

Returns the type name as string to be used in error messages — usually to indicate that a function was called on a wrong JSON type. Identical to [`BasicJsonType::type_name()`](https://json.nlohmann.me/api/basic_json/type_name/index.md), including the extra `"discarded"` return value for a [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md) view (`BasicJsonType::type_name()` produces the same string for a discarded `BasicJsonType` value).

## Return value

a string representation of the type ([`value_t`](https://json.nlohmann.me/api/basic_json/value_t/index.md)):

| Value type                                         | return value  |
| -------------------------------------------------- | ------------- |
| `null`                                             | `"null"`      |
| boolean                                            | `"boolean"`   |
| string                                             | `"string"`    |
| number (integer, unsigned integer, floating-point) | `"number"`    |
| object                                             | `"object"`    |
| array                                              | `"array"`     |
| discarded                                          | `"discarded"` |

`type_name()` never returns `"binary"`, since a JSON text has no binary values (see [`is_binary()`](https://json.nlohmann.me/api/basic_json_view/is_binary/index.md)); it also never returns `"invalid"`, since a view's `kind` always comes from a value the parser actually produced.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Examples

Example

The example below reports why some parsed messages were rejected, using only `type_name()` — no `BasicJsonType` value is ever built for the ones that are wrong, and the message text matches what [`BasicJsonType::type_name()`](https://json.nlohmann.me/api/basic_json/type_name/index.md) would produce for the same value.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using nlohmann::json_document;
using nlohmann::json_view;

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
```

Output:

```
ok
expected an object, got array
expected an object, got discarded
```

## See also

- [`type`](https://json.nlohmann.me/api/basic_json_view/type/index.md) - return the type of the value
- [`BasicJsonType::type_name`](https://json.nlohmann.me/api/basic_json/type_name/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
