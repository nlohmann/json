# <small>nlohmann::basic_json::</small>back

```cpp
reference back();

const_reference back() const;
```

Returns a reference to the last element in the container. For a JSON container `c`, the expression `c.back()` is
equivalent to

```cpp
auto tmp = c.end();
--tmp;
return *tmp;
```
    
## Return value

In the case of a structured type (array or object), a reference to the last element is returned. In the case of number,
string, boolean, or binary values, a reference to the value is returned.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Exceptions

If the JSON value is `#!json null`, exception
[`invalid_iterator.214`](../../home/exceptions.md#jsonexceptioninvalid_iterator214) is thrown.

## Complexity

Constant.

## Notes

!!! info "Precondition"

    The array or object must not be empty. Calling `back` on an empty array or object yields undefined behavior.

## Examples

??? example

    The following code shows an example for `back()`.
     
    ```cpp
    --8<-- "examples/back.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/back.output"
    ```

## See also

- [front](front.md) to access the first element

## Version history

- Added in version 1.0.0.
- Adjusted code to return reference to binary values in version 3.8.0.
