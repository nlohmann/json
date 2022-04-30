# <small>nlohmann::json_pointer::</small>operator string_t

```cpp
operator string_t() const
```

Return a string representation of the JSON pointer.

## Return value

A string representation of the JSON pointer

## Possible implementation

```cpp
operator string_t() const
{
    return to_string();
}
```

## Version history

- Since version 2.0.0.
- Changed type to `string_t` in version 3.11.0.
