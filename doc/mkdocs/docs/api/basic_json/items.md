# basic_json::items

```cpp
iteration_proxy<iterator> items() noexcept;
iteration_proxy<const_iterator> items() const noexcept;
```

This function allows to access `iterator::key()` and `iterator::value()` during range-based for loops. In these loops, a
reference to the JSON values is returned, so there is no access to the underlying iterator.

For loop without `items()` function:

```cpp
for (auto it = j_object.begin(); it != j_object.end(); ++it)
{
    std::cout << "key: " << it.key() << ", value:" << it.value() << '\n';
}
```

Range-based for loop without `items()` function:

```cpp
for (auto it : j_object)
{
    // "it" is of type json::reference and has no key() member
    std::cout << "value: " << it << '\n';
}
```

Range-based for loop with `items()` function:

```cpp
for (auto& el : j_object.items())
{
    std::cout << "key: " << el.key() << ", value:" << el.value() << '\n';
}
```

The `items()` function also allows to use
[structured bindings](https://en.cppreference.com/w/cpp/language/structured_binding) (C++17):

```cpp
for (auto& [key, val] : j_object.items())
{
    std::cout << "key: " << key << ", value:" << val << '\n';
}
```

## Return value

iteration proxy object wrapping the current value with an interface to use in range-based for loops

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Constant.

## Notes

When iterating over an array, `key()` will return the index of the element as string (see example). For primitive types
(e.g., numbers), `key()` returns an empty string.

!!! warning

    Using `items()` on temporary objects is dangerous. Make sure the object's lifetime exeeds the iteration. See
    <https://github.com/nlohmann/json/issues/2040> for more information.

## Example

??? example

    The following code shows an example for `items()`.
    
    ```cpp
    --8<-- "examples/items.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/items.output"
    ```

## Version history

- Added in version 3.0.0.
- Added structured binding support in version 3.5.0.

!!! note

    This function replaces the static function `iterator_wrapper` which was introduced in version 1.0.0, but has been
    deprecated in version 3.1.0. Function `iterator_wrapper` will be removed in version 4.0.0. Please replace all
    occurrences of `#!cpp iterator_wrapper(j)` with `#!cpp j.items()`.
