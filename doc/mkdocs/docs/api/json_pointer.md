# json_pointer

```cpp
template<typename BasicJsonType>
class json_pointer;
```

## Template parameters

`BasicJsonType`
:   a specialization of [`basic_json`](basic_json/index.md)

## Member functions

- (constructor)
- **to_string** - return a string representation of the JSON pointer
- **operator std::string**- return a string representation of the JSON pointer
- **operator/=** - append to the end of the JSON pointer
- **operator/** - create JSON Pointer by appending
- **parent_pointer** - returns the parent of this JSON pointer
- **pop_back** - remove last reference token
- **back** - return last reference token
- **push_back** - append an unescaped token at the end of the pointer
- **empty** - return whether pointer points to the root document
