# <small>nlohmann::basic_json_view::</small>end

```cpp
iterator end() const noexcept;
```

Returns an iterator to one past the last element of an array, one past the last member value of an object, in
**document order** -- see [`begin()`](begin.md). A primitive value iterates as a range of one element (itself), and a
`#!json null` value or a [discarded](is_discarded.md) view iterates as an empty range (`#!cpp begin() == end()`).

## Return value

Iterator one past the last element.

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

`#!cpp iterator` is a forward iterator: unlike `BasicJsonType::iterator`, it cannot be decremented, so there is no
way to reach the last element by stepping back from `end()`. Use [`back()`](back.md) instead.

## Examples

??? example

    The example below scans a (possibly large) array of readings for the first one over a threshold, stopping the
    loop at `end()` as soon as one is found. Only the matching reading, if any, is ever materialized.

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using json_document = nlohmann::json_document;
    
    int main()
    {
        // scan a (possibly large) array of readings for the first one over a
        // threshold; the loop stops at end() as soon as one is found, and only
        // the matching reading is ever materialized
        json_document readings = json_document::parse("[12, 18, 25, 31, 9]");
        const auto values = readings.root();
    
        auto it = values.begin();
        for (; it != values.end(); ++it)
        {
            if (it->materialize().get<int>() > 20)
            {
                break;
            }
        }
    
        if (it != values.end())
        {
            std::cout << "first reading over 20: " << it->materialize().dump() << '\n';
        }
    }
    
    ```

    Output:

    ```json
    first reading over 20: 25
    
    ```

## See also

- [begin](begin.md) - returns an iterator to the first element
- [cend](cend.md) - returns a const iterator to one past the last element
- [`BasicJsonType::end`](../basic_json/end.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
