# <small>nlohmann::basic_json_view::</small>back

```cpp
basic_json_view back() const;
```

Returns the last element of an array, the last member value of an object, or the value itself if it is primitive
(as for [`BasicJsonType::back()`](../basic_json/back.md), a primitive value is a range of one element).

## Return value

The last element or member value. For a primitive value (number, string, boolean), the value itself.

## Exception safety

Strong guarantee: there are no changes to the view or the document it refers to.

## Exceptions

Throws [`invalid_iterator.214`](../../home/exceptions.md#jsonexceptioninvalid_iterator214) if the view is
[null](is_null.md) or [discarded](is_discarded.md), or if it is an empty array or object.

This exception does not carry a [`JSON_DIAGNOSTICS`](../macros/json_diagnostics.md) path: the view has no
`BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with
`JSON_DIAGNOSTICS` enabled.

## Complexity

Linear in the size of the array or object: unlike [`front()`](front.md), which only ever looks at the first
element, `back()` has to walk every element to find where they end, since elements are not a fixed size in the
index.

## Notes

Unlike [`BasicJsonType::back()`](../basic_json/back.md), which has undefined behavior for an empty array or object,
`back()` throws `invalid_iterator.214` for an empty array, an empty object, a null value, or a discarded view.

## Examples

??? example

    The example below reads only the final status of a build log with `back()`. Even though `back()` is linear in
    the number of events (unlike [`front()`](front.md), which is constant), it still avoids building a
    `BasicJsonType` value for the events that are not needed.

    ```cpp
    #include <iostream>
    #include <nlohmann/json_view.hpp>
    
    using json_document = nlohmann::json_document;
    
    int main()
    {
        // the same build log; back() reads only the final status. It is linear
        // in the number of events (unlike front(), which is constant), but
        // still far less work than materializing the whole array
        json_document log = json_document::parse(R"(["queued", "started", "compiling", "linking", "done"])");
        std::cout << log.root().back().materialize().dump() << '\n';
    
        // an empty log -- back() throws instead of the undefined behavior
        // basic_json::back() has for an empty array
        json_document empty_log = json_document::parse("[]");
        try
        {
            static_cast<void>(empty_log.root().back());
        }
        catch (const nlohmann::json::invalid_iterator& e)
        {
            std::cout << e.what() << '\n';
        }
    }
    
    ```

    Output:

    ```json
    "done"
    [json.exception.invalid_iterator.214] cannot get value
    
    ```

## See also

- [front](front.md) - access the first element
- [`BasicJsonType::back`](../basic_json/back.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
