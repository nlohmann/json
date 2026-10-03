# Element Access

There are many ways elements in a JSON value can be accessed:

- unchecked access via [`operator[]`](https://json.nlohmann.me/features/element_access/unchecked_access/index.md)
- checked access via [`at`](https://json.nlohmann.me/features/element_access/checked_access/index.md)
- access with default value via [`value`](https://json.nlohmann.me/features/element_access/default_value/index.md)
- [iterators](https://json.nlohmann.me/features/iterators/index.md)
- [JSON pointers](https://json.nlohmann.me/features/json_pointer/index.md)

Testing whether a key or index exists before accessing it is also possible, with [`contains`](https://json.nlohmann.me/api/basic_json/contains/index.md) or [`find`](https://json.nlohmann.me/api/basic_json/find/index.md) (which returns an iterator to the value, or `end()` if it is not found).

```
flowchart TD
    A["accessing a value"] --> B{"must it exist?"}
    B -->|"yes, missing is an error"| C["at() -- throws"]
    B -->|"yes, but checking is my job"| D["operator[] -- unchecked"]
    B -->|"no, a fallback is fine"| E["value() -- default value"]
    A --> F{"just testing first?"}
    F -->|"yes"| G["contains() / find()"]
```
