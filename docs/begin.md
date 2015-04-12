```cpp
iterator begin();
const_iterator begin() const;
const_iterator cbegin() const;
```

## Description

Returns an iterator to the first value in the JSON container. If the JSON container is empty, the returned iterator will be equal to [`end()`](https://github.com/nlohmann/json/wiki/nlohmann::basicjson::end).

![illustration of iterators](http://upload.cppreference.com/mwiki/images/1/1b/range-begin-end.svg)

## Parameters

None.

## Return value

Iterator to the first value. Note the return value its deferencabilty depends on the different value types:

| value type | deferenceable | description |
| ---------- | ------------- | ----------- |
| null       | no | `null` has no value, always equal to [`end()`](https://github.com/nlohmann/json/wiki/nlohmann::basicjson::end) |
| boolean    | yes | iterator to the boolean value |
| string     | yes | iterator to the string value |
| number     | yes | iterator to the number value |
| object     | only if object is not empty | iterator to the begin of the object |
| array      | only if array is not empty | iterator to the begin of the array |

## Complexity

Constant, as long as `ArrayType` and `ObjectType` satisfy the [Container concept](http://en.cppreference.com/w/cpp/concept/Container).

## Exceptions

None. The function's noexcept-specification is `noexcept`.

## See also

- [**end**, **cend**](https://github.com/nlohmann/json/wiki/nlohmann::basicjson::end)<br>
  returns an iterator to the end
