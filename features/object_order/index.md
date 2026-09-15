# Object Order

The [JSON standard](https://tools.ietf.org/html/rfc8259.html) defines objects as "an unordered collection of zero or more name/value pairs". As such, an implementation does not need to preserve any specific order of object keys.

## Default behavior: sort keys

The default type `nlohmann::json` uses a `std::map` to store JSON objects, and thus stores object keys **sorted alphabetically**.

Example

```
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    json j;
    j["one"] = 1;
    j["two"] = 2;
    j["three"] = 3;

    std::cout << j.dump(2) << '\n';
}
```

Output:

```
{
  "one": 1,
  "three": 3,
  "two": 2
}
```

## Alternative behavior: preserve insertion order

If you do want to preserve the **insertion order**, you can use the type [`nlohmann::ordered_json`](https://json.nlohmann.me/api/ordered_json/index.md).

Example

```
#include <iostream>
#include <nlohmann/json.hpp>

using ordered_json = nlohmann::ordered_json;

int main()
{
    ordered_json j;
    j["one"] = 1;
    j["two"] = 2;
    j["three"] = 3;

    std::cout << j.dump(2) << '\n';
}
```

Output:

```
{
  "one": 1,
  "two": 2,
  "three": 3
}
```

Alternatively, [`nlohmann::fifo_map`](https://github.com/nlohmann/fifo_map) also preserves the insertion order and, unlike [`ordered_map`](https://json.nlohmann.me/api/ordered_map/index.md), keeps a lookup index, so it does not have the quadratic cost described below. It is used through a small adapter ([integration](https://github.com/nlohmann/json/issues/485#issuecomment-333652309)).

If the order does not matter and you only want faster lookup, `boost::unordered_flat_map`, `absl::flat_hash_map`, `absl::node_hash_map`, and several other hash maps work through an adapter that restores the template argument order `basic_json` expects; see [Template Parameter Requirements](https://json.nlohmann.me/features/types/template_parameters/#objecttype). Note these are *unordered*, not insertion-ordered.

[`tsl::ordered_map`](https://github.com/Tessil/ordered-map) cannot be used: its iterators expose the mapped value as `const`, while `basic_json` needs to modify it in place.

The [`ordered_map`](https://json.nlohmann.me/api/ordered_map/index.md) behind `nlohmann::ordered_json` is deliberately minimal and has no lookup index, so every key access is a linear scan and building an object of `n` keys costs O(n²). This is unnoticeable at typical object sizes but becomes significant for objects with many thousands of keys; see [`ordered_map` complexity](https://json.nlohmann.me/api/ordered_map/#complexity). The alternatives above keep a lookup index and do not have this cost.

### Notes on parsing

Note that you also need to call the right [`parse`](https://json.nlohmann.me/api/basic_json/parse/index.md) function when reading from a file. Assume file `input.json` contains the JSON object above:

```
{
  "one": 1,
  "two": 2,
  "three": 3
}
```

Right way

The following code correctly calls the `parse` function from `nlohmann::ordered_json`:

```
std::ifstream i("input.json");
auto j = nlohmann::ordered_json::parse(i);
std::cout << j.dump(2) << std::endl;
```

The output will be:

```
{
  "one": 1,
  "two": 2,
  "three": 3
}
```

Wrong way

The following code incorrectly calls the `parse` function from `nlohmann::json` which does not preserve the insertion order, but sorts object keys. Assigning the result to `nlohmann::ordered_json` compiles, but does not restore the order from the input file.

```
std::ifstream i("input.json");
nlohmann::ordered_json j = nlohmann::json::parse(i);
std::cout << j.dump(2) << std::endl;
```

The output will be:

```
{
  "one": 1,
  "three": 3,
  "two": 2
}
```
