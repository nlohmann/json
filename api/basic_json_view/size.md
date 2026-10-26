# <small>nlohmann::basic_json_view::</small>size

```cpp
size_type size() const noexcept;
```

Returns the number of elements, as [`BasicJsonType::size()`](../basic_json/size.md) would for the same value.

## Return value

The return value depends on the type and is defined as follows:

| Value type | return value              |
|------------|---------------------------|
| null       | `0`                       |
| discarded  | `0`                       |
| boolean    | `1`                       |
| string     | `1`                       |
| number     | `1`                       |
| object     | number of key/value pairs |
| array      | number of elements        |

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant: for an object or array, the element count is stored in the index, not counted on demand.

## Notes

As for [`BasicJsonType::size()`](../basic_json/size.md), this does not return the length of a string value -- it is
`1` for a string, regardless of its length.

If the source text has an object with a duplicate key, every occurrence counts towards its `size()` -- unlike
[`materialize()`](materialize.md) (and [`BasicJsonType::parse()`](../basic_json/parse.md)), which keeps only the last
value for a repeated key. This means `#!cpp v.size()` can be larger than `#!cpp v.materialize().size()`. See the
[Notes on duplicate keys](operator[].md#notes) of `operator[]` for why lookups and iteration disagree on how many
members there are.

## Examples

??? example

    The example below uses `size()` and [`empty()`](empty.md) to decide whether a parsed message is worth acting on,
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

- [empty](empty.md) - return whether the value has no elements
- [`BasicJsonType::size`](../basic_json/size.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
