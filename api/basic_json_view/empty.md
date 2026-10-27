# <small>nlohmann::basic_json_view::</small>empty

```cpp
bool empty() const noexcept;
```

Checks whether [`size()`](size.md) is `0`, as [`BasicJsonType::empty()`](../basic_json/empty.md) would for the same
value.

## Return value

The return value depends on the type and is defined as follows:

| Value type          | return value    |
|----------------------|-----------------|
| null                  | `#!cpp true`     |
| discarded             | `#!cpp true`     |
| boolean               | `#!cpp false`    |
| string                | `#!cpp false`    |
| number                | `#!cpp false`    |
| object                | `#!cpp object_t::empty()` |
| array                 | `#!cpp array_t::empty()`  |

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

As for [`BasicJsonType::empty()`](../basic_json/empty.md), this does not return whether a string value is empty — it
is `#!cpp false` for any string, regardless of its length.

## Examples

??? example

    The example below uses [`size()`](size.md) and `empty()` to decide whether a parsed message is worth acting on,
    without materializing it into a `BasicJsonType` value.

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using nlohmann::json_document;
    
    int main()
    {
        std::cout << std::boolalpha;
    
        // decide whether a batch is worth processing before building any
        // nlohmann::json value for it
        json_document batch = json_document::parse(R"([1, 2, 3, 4, 5])");
        json_document empty_batch = json_document::parse("[]");
    
        std::cout << batch.root().empty() << ' ' << batch.root().size() << '\n';
        std::cout << empty_batch.root().empty() << ' ' << empty_batch.root().size() << '\n';
    
        // as for basic_json: null has size 0, every other scalar has size 1
        json_document n = json_document::parse("null");
        json_document s = json_document::parse(R"("hi")");
        std::cout << n.root().size() << ' ' << s.root().size() << '\n';
    }
    
    ```

    Output:

    ```json
    false 5
    true 0
    0 1
    
    ```

## See also

- [`size`](size.md) - return the number of elements
- [`BasicJsonType::empty`](../basic_json/empty.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
