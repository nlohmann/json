# basic_json::back

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

In case of a structured type (array or object), a reference to the last element is returned. In case of number, string,
boolean, or binary values, a reference to the value is returned.

## Exceptions

If the JSON value is `#!json null`, exception
[`invalid_iterator.214`](../../home/exceptions.md#jsonexceptioninvalid_iterator214) is thrown.

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Constant.

## Note

!!! danger

    Calling `back` on an empty array or object is undefined behavior and is **guarded by an assertion**!

## Example

??? example

    The following code shows an example for `back()`.
     
    ```cpp
    --8<-- "examples/back.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/back.output"
    ```

## Version history

- Added in version 1.0.0.
- Adjusted code to return reference to binary values in version 3.8.0.
