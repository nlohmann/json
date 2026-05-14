# <small>nlohmann::basic_json::</small>get_ptr

```cpp
template<typename PointerType>
PointerType get_ptr() noexcept;

template<typename PointerType>
constexpr const PointerType get_ptr() const noexcept;
```

Implicit pointer access to the internally stored JSON value. No copies are made.

## Template parameters

`PointerType`
:   pointer type; must be a pointer to [`array_t`](array_t.md), [`object_t`](object_t.md), [`string_t`](string_t.md),
    [`boolean_t`](boolean_t.md), [`number_integer_t`](number_integer_t.md), or
    [`number_unsigned_t`](number_unsigned_t.md), [`number_float_t`](number_float_t.md), or [`binary_t`](binary_t.md).
    Other types will not compile.

## Return value

pointer to the internally stored JSON value if the requested pointer type fits to the JSON value; `#!cpp nullptr`
otherwise

## Exception safety

No-throw guarantee: this function never throws exceptions.

## Complexity

Constant.

## Notes

!!! danger "Undefined behavior"

    The pointer becomes invalid if the underlying JSON object changes.

    Consider the following example code where the pointer `ptr` changes after the array is resized. As a result,
    reading or writing to `ptr` after the array change would be undefined behavior. The address of the first array
    element changes, because the underlying `std::vector` is resized after adding a fifth element.

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    
    using json = nlohmann::json;
    
    int main()
    {
        json j = {1, 2, 3, 4};
        auto* ptr = j[0].get_ptr<std::int64_t*>();
        std::cout << "value at " << ptr << " is " << *ptr << std::endl;
    
        j.push_back(5);
    
        ptr = j[0].get_ptr<std::int64_t*>();
        std::cout << "value at " << ptr << " is " << *ptr << std::endl;
    }
    ```

    Output:

    ```
    value at 0x6000012fc1c8 is 1
    value at 0x6000029fc088 is 1
    ```

## Examples

??? example

    The example below shows how pointers to internal values of a JSON value can be requested. Note that no type
    conversions are made and a `#!cpp nullptr` is returned if the value and the requested pointer type does not match.
    
    ```cpp
    --8<-- "examples/get_ptr.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/get_ptr.output"
    ```

## See also

- [get_ref()](get_ref.md) get a reference value

## Version history

- Added in version 1.0.0.
- Extended to binary types in version 3.8.0.
