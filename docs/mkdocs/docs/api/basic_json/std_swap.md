# std::swap<basic_json\>

```cpp
namespace std {
    void swap(nlohmann::basic_json& j1, nlohmann::basic_json& j2) noexcept(
        is_nothrow_move_constructible<nlohmann::basic_json>::value &&
        is_nothrow_move_assignable<nlohmann::basic_json>::value
    );
}
```

Exchanges the values of two JSON objects.

This specialization is only provided before C++20, which no longer allows specializing function templates in
namespace `std`. With C++20 (and in generic code with any standard), use the idiom `#!cpp using std::swap; swap(j1, j2);`: it finds
the [`swap`](swap.md) friend function (overload 2) by argument-dependent lookup. A qualified `#!cpp std::swap(j1, j2)`
still compiles with C++20, but uses the generic `std::swap`, which swaps by three moves instead of exchanging the
contents.

## Parameters

`j1` (in, out)
:   value to be replaced by `j2`

`j2` (in, out)
:   value to be replaced by `j1`

## Exception safety

No-throw guarantee if the `noexcept` condition above holds: it holds unless moving the
[`json_base_class_t`](json_base_class_t.md) can throw. With the default base class, this function never throws
exceptions.

## Complexity

Constant.

## Possible implementation

```cpp
void swap(nlohmann::basic_json& j1, nlohmann::basic_json& j2)
{
    j1.swap(j2);
}
```

## Examples

??? example

    The following code shows how two values are swapped with `std::swap`.
     
    ```cpp
    --8<-- "examples/std_swap.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/std_swap.output"
    ```

## See also

- [`swap`](swap.md) - exchange the contents of two JSON values

## Version history

- Added in version 1.0.0.
- Extended for arbitrary basic_json types in version 3.10.5.
- Not provided with C++20 since version 3.9.0.
