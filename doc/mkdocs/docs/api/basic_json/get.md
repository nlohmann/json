# basic_json::get

```cpp
// (1)
template<typename ValueType>
ValueType get() const noexcept(
    noexcept(JSONSerializer<ValueType>::from_json(
        std::declval<const basic_json_t&>(), std::declval<ValueType&>())));

// (2)
template<typename BasicJsonType>
BasicJsonType get() const;

// (3)
template<typename PointerType>
PointerType get_ptr();

template<typename PointerType>
constexpr const PointerType get_ptr() const noexcept;
```

1. Explicit type conversion between the JSON value and a compatible value which is
   [CopyConstructible](https://en.cppreference.com/w/cpp/named_req/CopyConstructible) and
   [DefaultConstructible](https://en.cppreference.com/w/cpp/named_req/DefaultConstructible). The value is converted by
   calling the `json_serializer<ValueType>` `from_json()` method.
   
    The function is equivalent to executing
    ```cpp
    ValueType ret;
    JSONSerializer<ValueType>::from_json(*this, ret);
    return ret;
    ```

    This overloads is chosen if:
    
    - `ValueType` is not `basic_json`,
    - `json_serializer<ValueType>` has a `from_json()` method of the form
      `void from_json(const basic_json&, ValueType&)`, and
    - `json_serializer<ValueType>` does not have a `from_json()` method of the form
      `ValueType from_json(const basic_json&)`

    If the type is **not** [CopyConstructible](https://en.cppreference.com/w/cpp/named_req/CopyConstructible) and
    **not** [DefaultConstructible](https://en.cppreference.com/w/cpp/named_req/DefaultConstructible), the value is
    converted by calling the `json_serializer<ValueType>` `from_json()` method.
   
    The function is then equivalent to executing
    ```cpp
    return JSONSerializer<ValueTypeCV>::from_json(*this);
    ``` 
   
    This overloads is chosen if:
    
    - `ValueType` is not `basic_json` and
    - `json_serializer<ValueType>` has a `from_json()` method of the form
     `ValueType from_json(const basic_json&)`

    If `json_serializer<ValueType>` has both overloads of `from_json()`, the latter one is chosen.

2. Overload for `basic_json` specializations. The function is equivalent to executing
    ```cpp
    return *this;
    ```

3. Explicit pointer access to the internally stored JSON value. No copies are made.

## Template parameters

`ValueType`
:   the value type to return

`BasicJsonType`
:   a specialization of `basic_json`

`PointerType`
:   pointer type; must be a pointer to [`array_t`](array_t.md), [`object_t`](object_t.md), [`string_t`](string_t.md),
    [`boolean_t`](boolean_t.md), [`number_integer_t`](number_integer_t.md), or
    [`number_unsigned_t`](number_unsigned_t.md), [`number_float_t`](number_float_t.md), or [`binary_t`](binary_t.md).
    Other types will not compile.

## Return value

1. copy of the JSON value, converted to `ValueType`
2. a copy of `#!cpp *this`, converted into `BasicJsonType`
3. pointer to the internally stored JSON value if the requested pointer type fits to the JSON value; `#!cpp nullptr`
   otherwise

## Exceptions

Depends on what `json_serializer<ValueType>` `from_json()` method throws

## Notes

!!! warning

    Writing data to the pointee (overload 3) of the result yields an undefined state.

## Example

??? example

    The example below shows several conversions from JSON values
    to other types. There a few things to note: (1) Floating-point numbers can
    be converted to integers, (2) A JSON array can be converted to a standard
    `std::vector<short>`, (3) A JSON object can be converted to C++
    associative containers such as `std::unordered_map<std::string, json>`.
        
    ```cpp
    --8<-- "examples/get__ValueType_const.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/get__ValueType_const.output"
    ```

??? example

    The example below shows how pointers to internal values of a JSON value can be requested. Note that no type
    conversions are made and a `#cpp nullptr` is returned if the value and the requested pointer type does not match.
        
    ```cpp
    --8<-- "examples/get__PointerType.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/get__PointerType.output"
    ```

## Version history

1. Since version 2.1.0.
2. Since version 2.1.0. Extended to work with other specializations of `basic_json` in version 3.2.0.
3. Since version 1.0.0.
