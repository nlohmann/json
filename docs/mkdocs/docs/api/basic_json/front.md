# <small>nlohmann::basic_json::</small>front

```cpp
reference front();
const_reference front() const;
```

Returns a reference to the first element in the container. For a JSON container `#!cpp c`, the expression
`#!cpp c.front()` is equivalent to `#!cpp *c.begin()`.
    
## Return value

In case of a structured type (array or object), a reference to the first element is returned. In case of number, string,
boolean, or binary values, a reference to the value is returned.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

If the JSON value is `#!json null`, exception
[`invalid_iterator.214`](../../home/exceptions.md#jsonexceptioninvalid_iterator214) is thrown.

## Complexity

Constant.

## Notes

!!! info "Precondition"

    The array or object must not be empty. Calling `front` on an empty array or object yields undefined behavior.

## Examples

??? example

    The following code shows an example for `front()`.
     
    ```cpp
    --8<-- "examples/front.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/front.output"
    ```

## See also

- [back](back.md) to access the last element

## Version history

- Added in version 1.0.0.
- Adjusted code to return reference to binary values in version 3.8.0.
