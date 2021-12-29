# operator<<(basic_json)

```cpp
std::ostream& operator<<(std::ostream& o, const basic_json& j);
```

Serialize the given JSON value `j` to the output stream `o`. The JSON value will be serialized using the
[`dump`](dump.md) member function.

- The indentation of the output can be controlled with the member variable `width` of the output stream `o`. For
  instance, using the manipulator `std::setw(4)` on `o` sets the indentation level to `4` and the serialization result
  is the same as calling `dump(4)`.
- The indentation character can be controlled with the member variable `fill` of the output stream `o`. For instance,
  the manipulator `std::setfill('\\t')` sets indentation to use a tab character rather than the default space character.

## Parameters

`o` (in, out)
:   stream to serialize to

`j` (in)
:   JSON value to serialize

## Return value

the stream `o`

## Exceptions

Throws [`type_error.316`](../../home/exceptions.md#jsonexceptiontype_error316) if a string stored inside the JSON value
is not UTF-8 encoded. Note that unlike the [`dump`](dump.md) member functions, no `error_handler` can be set.

## Complexity

Linear.

## Examples

??? example

    The example below shows the serialization with different parameters to `width` to adjust the indentation level.
        
    ```cpp
    --8<-- "examples/operator_serialize.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/operator_serialize.output"
    ```

## Version history

- Added in version 1.0.0
- Support for indentation character added in version 3.0.0.

!!! warning "Deprecation"

    This function replaces function `#!cpp std::ostream& operator>>(const basic_json& j, std::ostream& o)` which has
    been deprecated in version 3.0.0. It will be removed in version 4.0.0. Please replace calls like `#!cpp j >> o;`
    with `#!cpp o << j;`.
