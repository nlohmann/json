# <small>nlohmann::basic_json_view::</small>get_to

```cpp
template<typename T>
T& get_to(T& v) const;
```

Converts the value to `T` and assigns it to `v`. Equivalent to

```cpp
v = get<T>();
return v;
```

## Template parameters

`T`
:   the type to convert the value to

## Parameters

`v` (out)
:   the variable to store the converted value in

## Return value

`v`, allowing calls to chain

## Exception safety

Strong exception safety: if an exception is thrown, `v` is not modified.

## Exceptions

Whatever [`get<T>()`](get.md) throws for the same value and `T`.

## Complexity

Whatever [`get<T>()`](get.md) has for the same `T`.

## Examples

??? example

    The example below reads several fields of a service configuration directly into existing variables, then uses
    the returned reference to fold the `#!cpp host`/`#!cpp port` pair into a single string in the same expression.

    ```cpp
    --8<-- "examples/basic_json_view__get_to.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/basic_json_view__get_to.output"
    ```

## See also

- [get](get.md) - convert the value to a given type
- [`BasicJsonType::get_to`](../basic_json/get_to.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0.
