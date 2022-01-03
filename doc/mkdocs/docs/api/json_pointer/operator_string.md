# <small>nlohmann::json_pointer::</small>operator std::string

```cpp
operator std::string() const
```

Return a string representation of the JSON pointer.

## Return value

A string representation of the JSON pointer

## Possible implementation

```cpp
operator std::string() const
{
    return to_string();
}
```

## Version history

Since version 2.0.0.
