# <small>nlohmann::basic_json_view::</small>type

```cpp
value_t type() const noexcept;
```

Returns the type of the value this view refers to, as a value from the [`value_t`](../basic_json/value_t.md)
enumeration -- the same enumeration [`BasicJsonType::type()`](../basic_json/type.md) uses.

## Return value

The type of the value; `#!cpp value_t::discarded` for a [discarded](is_discarded.md) view.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

Unlike [`BasicJsonType::type()`](../basic_json/type.md), this function can never return `#!cpp value_t::binary`: a
JSON text has no binary values, so `type()` only distinguishes the eight ordinary JSON value types (plus
`#!cpp discarded`).

## Examples

??? example

    The example below classifies several parsed documents by the type of their root value, without materializing any
    of them into a `BasicJsonType` value.

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json_document;
    
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
        std::cout << invalid.is_discarded() << '\n';
        std::cout << failed.root().is_discarded() << '\n';
    
        // type() returns the same value_t enumeration as basic_json::type()
        std::cout << (d_object.root().type() == nlohmann::json::value_t::object) << '\n';
    }
    
    ```

    Output:

    ```json
    true
    true
    true true
    true
    true
    true
    true true
    true false
    false
    true
    true
    true
    
    ```

## See also

- [is_null](is_null.md), [is_boolean](is_boolean.md), [is_number](is_number.md), [is_string](is_string.md),
  [is_array](is_array.md), [is_object](is_object.md) - type-specific predicates built on `type()`
- [`BasicJsonType::type`](../basic_json/type.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
