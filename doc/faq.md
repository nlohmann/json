# FAQ

## Parsing

### How can I parse from a string?

```cpp
json j = json::parse("[1,2,3,4]");
```

You can pass string literals (as above), `std::string`, `const char*` or byte containers such as `std::vector<uint8_t>`.

### How can I parse from a file?

```cpp
std::ifstream i("your_file.json");
json j = json::parse(i);
```

## Serialization

### How can I serialize a JSON value

```cpp
std::cout << j << std::endl;
```

This is equivalent to

```cpp
std::string s = j.dump();
std::cout << s << std::endl;
```

### How can I pretty-print a JSON value

```cpp
std::cout << std::setw(4) << j << std::endl;
```

This is equivalent to

```cpp
std::string s = j.dump(4);
std::cout << s << std::endl;
```

The number `4` denotes the number of spaces used for indentation.

## Iterating

### How can I iterate over a JSON value?

```cpp
for (json& val : j)
{
    // val is a reference for the current value
}
```

This works with any JSON value, also primitive values like numbers.

### How can I access the keys when iterating over a JSON object?

```cpp
for (auto it = j.begin(); it != j.end(); ++it)
{
    // the value
    json &val = it.value();
    
    // the key (for objects)
    const std::string &key = it.key();
}
```

You can also use an iteration wrapper and use range for:

```cpp
for (auto it : json::iteration_wrapper(j))
{
    // the value
    json &val = it.value();
    
    // the key (for objects)
    const std::string &key = it.key();
}
```
