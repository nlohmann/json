# <small>nlohmann::basic_json::</small>basic_json

```cpp
// (1)
basic_json(const value_t v);

// (2)
basic_json(std::nullptr_t = nullptr) noexcept;

// (3)
template<typename CompatibleType>
basic_json(CompatibleType&& val) noexcept(noexcept(
           JSONSerializer<U>::to_json(std::declval<basic_json_t&>(),
                                      std::forward<CompatibleType>(val))));

// (4)
template<typename BasicJsonType>
basic_json(const BasicJsonType& val);

// (5)
basic_json(initializer_list_t init,
           bool type_deduction = true,
           value_t manual_type = value_t::array);

// (6)
basic_json(size_type cnt, const basic_json& val);

// (7)
basic_json(iterator first, iterator last);
basic_json(const_iterator first, const_iterator last);

// (8)
basic_json(const basic_json& other);

// (9)
basic_json(basic_json&& other) noexcept;
```

1. Create an empty JSON value with a given type. The value will be default initialized with an empty value which depends
   on the type:
   
    | Value type | initial value  |
    |------------|----------------|
    | null       | `#!json null`  |
    | boolean    | `#!json false` |
    | string     | `#!json ""`    |
    | number     | `#!json 0`     |
    | object     | `#!json {}`    |
    | array      | `#!json []`    |
    | binary     | empty array    |

    The postcondition of this constructor can be restored by calling [`clear()`](clear.md).

2. Create a `#!json null` JSON value. It either takes a null pointer as parameter (explicitly creating `#!json null`)
   or no parameter (implicitly creating `#!json null`). The passed null pointer itself is not read -- it is only used to
   choose the right constructor.

3. This is a "catch all" constructor for all compatible JSON types; that is, types for which a `to_json()` method
   exists. The constructor forwards the parameter `val` to that method (to `json_serializer<U>::to_json` method with
   `U = uncvref_t<CompatibleType>`, to be exact).
   
    Template type `CompatibleType` includes, but is not limited to, the following types:

    - **arrays**: [`array_t`](array_t.md) and all kinds of compatible containers such as `std::vector`, `std::deque`,
     `std::list`, `std::forward_list`, `std::array`, `std::valarray`, `std::set`, `std::unordered_set`, `std::multiset`,
     and `std::unordered_multiset` with a `value_type` from which a `basic_json` value can be constructed.
    - **objects**: [`object_t`](object_t.md) and all kinds of compatible associative containers such as `std::map`,
     `std::unordered_map`, `std::multimap`, and `std::unordered_multimap` with a `key_type` compatible to `string_t`
     and a `value_type` from which a `basic_json` value can be constructed.
    - **strings**: `string_t`, string literals, and all compatible string containers can be used.
    - **numbers**: [`number_integer_t`](number_integer_t.md), [`number_unsigned_t`](number_unsigned_t.md),
     [`number_float_t`](number_float_t.md), and all convertible number types such as `int`, `size_t`, `int64_t`, `float`
     or `double` can be used.
    - **boolean**: `boolean_t` / `bool` can be used.
    - **binary**: `binary_t` / `std::vector<uint8_t>` may be used; unfortunately because string literals cannot be
     distinguished from binary character arrays by the C++ type system, all types compatible with `const char*` will be
     directed to the string constructor instead. This is both for backwards compatibility, and due to the fact that a
     binary type is not a standard JSON type.
    
    See the examples below.

4. This is a constructor for existing `basic_json` types. It does not hijack copy/move constructors, since the parameter
   has different template arguments than the current ones.

    The constructor tries to convert the internal `m_value` of the parameter.

5. Creates a JSON value of type array or object from the passed initializer list `init`. In case `type_deduction` is
   `#!cpp true` (default), the type of the JSON value to be created is deducted from the initializer list `init`
   according to the following rules:
   
    1. If the list is empty, an empty JSON object value `{}` is created.
    2. If the list consists of pairs whose first element is a string, a JSON object value is created where the first
      elements of the pairs are treated as keys and the second elements are as values.
    3. In all other cases, an array is created.
    
    The rules aim to create the best fit between a C++ initializer list and JSON values. The rationale is as follows:
    
    1. The empty initializer list is written as `#!cpp {}` which is exactly an empty JSON object.
    2. C++ has no way of describing mapped types other than to list a list of pairs. As JSON requires that keys must be
       of type string, rule 2 is the weakest constraint one can pose on initializer lists to interpret them as an
       object.
    3. In all other cases, the initializer list could not be interpreted as JSON object type, so interpreting it as JSON
       array type is safe.
    
    With the rules described above, the following JSON values cannot be expressed by an initializer list:
    
    - the empty array (`#!json []`): use `array(initializer_list_t)` with an empty initializer list in this case
    - arrays whose elements satisfy rule 2: use `array(initializer_list_t)` with the same initializer list in this case
   
    Function [`array()`](array.md) and [`object()`](object.md) force array and object creation from initializer lists,
    respectively.
        
6. Constructs a JSON array value by creating `cnt` copies of a passed value. In case `cnt` is `0`, an empty array is
   created.

7. Constructs the JSON value with the contents of the range `[first, last)`. The semantics depends on the different
   types a JSON value can have:

    - In case of a `#!json null` type, [invalid_iterator.206](../../home/exceptions.md#jsonexceptioninvalid_iterator206)
      is thrown.
    - In case of other primitive types (number, boolean, or string), `first` must be `begin()` and `last` must be
      `end()`. In this case, the value is copied. Otherwise,
      [`invalid_iterator.204`](../../home/exceptions.md#jsonexceptioninvalid_iterator204) is thrown.
    - In case of structured types (array, object), the constructor behaves as similar versions for `std::vector` or
      `std::map`; that is, a JSON array or object is constructed from the values in the range.

8. Creates a copy of a given JSON value.

9. Move constructor. Constructs a JSON value with the contents of the given value `other` using move semantics. It
   "steals" the resources from `other` and leaves it as JSON `#!json null` value.

## Template parameters

`CompatibleType`
:   a type such that:

    - `CompatibleType` is not derived from `std::istream`,
    - `CompatibleType` is not `basic_json` (to avoid hijacking copy/move constructors),
    - `CompatibleType` is not a different `basic_json` type (i.e. with different template arguments)
    - `CompatibleType` is not a `basic_json` nested type (e.g., `json_pointer`, `iterator`, etc.)
    - `json_serializer<U>` (with `U = uncvref_t<CompatibleType>`) has a `to_json(basic_json_t&, CompatibleType&&)`
       method

`BasicJsonType`:
:   a type such that:

    - `BasicJsonType` is a `basic_json` type.
    - `BasicJsonType` has different template arguments than `basic_json_t`.

`U`:
:   `uncvref_t<CompatibleType>`

## Parameters

`v` (in)
:   the type of the value to create

`val` (in)
:   the value to be forwarded to the respective constructor

`init` (in)
:   initializer list with JSON values

`type_deduction` (in)
:   internal parameter; when set to `#!cpp true`, the type of the JSON value is deducted from the initializer list
    `init`; when set to `#!cpp false`, the type provided via `manual_type` is forced. This mode is used by the functions
    `array(initializer_list_t)` and `object(initializer_list_t)`.

`manual_type` (in)
:   internal parameter; when `type_deduction` is set to `#!cpp false`, the created JSON value will use the provided type
    (only `value_t::array` and `value_t::object` are valid); when `type_deduction` is set to `#!cpp true`, this
    parameter has no effect

`cnt` (in)
:   the number of JSON copies of `val` to create

`first` (in)
:   begin of the range to copy from (included)

`last` (in)
:   end of the range to copy from (excluded)

`other` (in)
:   the JSON value to copy/move

## Exception safety

1. Strong guarantee: if an exception is thrown, there are no changes to any JSON value.
2. No-throw guarantee: this constructor never throws exceptions.
3. Depends on the called constructor. For types directly supported by the library (i.e., all types for which no
   `to_json()` function was provided), strong guarantee holds: if an exception is thrown, there are no changes to any
   JSON value.
4. Depends on the called constructor. For types directly supported by the library (i.e., all types for which no
   `to_json()` function was provided), strong guarantee holds: if an exception is thrown, there are no changes to any
   JSON value.
5. Strong guarantee: if an exception is thrown, there are no changes to any JSON value.
6. Strong guarantee: if an exception is thrown, there are no changes to any JSON value.
7. Strong guarantee: if an exception is thrown, there are no changes to any JSON value.
8. Strong guarantee: if an exception is thrown, there are no changes to any JSON value.
9. No-throw guarantee: this constructor never throws exceptions.

## Exceptions

1. (none)
2. The function does not throw exceptions.
3. (none)
4. (none)
5. The function can throw the following exceptions:
    - Throws [`type_error.301`](../../home/exceptions.md#jsonexceptiontype_error301) if `type_deduction` is
      `#!cpp false`, `manual_type` is `value_t::object`, but `init` contains an element which is not a pair whose first
      element is a string. In this case, the constructor could not create an object. If `type_deduction` would have been
      `#!cpp true`, an array would have been created. See `object(initializer_list_t)` for an example.
6. (none)
7. The function can throw the following exceptions:
    - Throws [`invalid_iterator.201`](../../home/exceptions.md#jsonexceptioninvalid_iterator201) if iterators `first`
      and `last` are not compatible (i.e., do not belong to the same JSON value). In this case, the range
      `[first, last)` is undefined.
    - Throws [`invalid_iterator.204`](../../home/exceptions.md#jsonexceptioninvalid_iterator204) if iterators `first`
      and `last` belong to a primitive type (number, boolean, or string), but `first` does not point to the first
      element anymore. In this case, the range `[first, last)` is undefined. See example code below.
    - Throws [`invalid_iterator.206`](../../home/exceptions.md#jsonexceptioninvalid_iterator206) if iterators `first`
      and `last` belong to a `#!json null` value. In this case, the range `[first, last)` is undefined.
8. (none)
9. The function does not throw exceptions.

## Complexity

1. Constant.
2. Constant.
3. Usually linear in the size of the passed `val`, also depending on the implementation of the called `to_json()`
   method.
4. Usually linear in the size of the passed `val`, also depending on the implementation of the called `to_json()`
   method.
5. Linear in the size of the initializer list `init`.
6. Linear in `cnt`.
7. Linear in distance between `first` and `last`.
8. Linear in the size of `other`.
9. Constant.

## Notes

- Overload 5:

    !!! note

        When used without parentheses around an empty initializer list, `basic_json()` is called instead of this
        function, yielding the JSON `#!json null` value.

- Overload 7:

    !!! info "Preconditions"

        - Iterators `first` and `last` must be initialized. **This precondition is enforced with a
          [runtime assertion](../../features/assertions.md).
        - Range `[first, last)` is valid. Usually, this precondition cannot be checked efficiently. Only certain edge
          cases are detected; see the description of the exceptions above. A violation of this precondition yields
          undefined behavior.
    
    !!! danger "Runtime assertion"

        A precondition is enforced with a [runtime assertion](../../features/assertions.md).
    
- Overload 8:

    !!! info "Postcondition"

        `#!cpp *this == other`

- Overload 9:

    !!! info "Postconditions"

        - `#!cpp `*this` has the same value as `other` before the call.
        - `other` is a JSON `#!json null` value

## Examples

??? example "Example: (1) create an empty value with a given type"

    The following code shows the constructor for different `value_t` values.
     
    ```cpp
    --8<-- "examples/basic_json__value_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/basic_json__value_t.output"
    ```

??? example "Example: (2) create a `#!json null` object"

    The following code shows the constructor with and without a null pointer parameter.
     
    ```cpp
    --8<-- "examples/basic_json__nullptr_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/basic_json__nullptr_t.output"
    ```

??? example "Example: (3) create a JSON value from compatible types"

    The following code shows the constructor with several compatible types.
     
    ```cpp
    --8<-- "examples/basic_json__CompatibleType.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/basic_json__CompatibleType.output"
    ```

??? example "Example: (5) create a container (array or object) from an initializer list"

    The example below shows how JSON values are created from initializer lists.
     
    ```cpp
    --8<-- "examples/basic_json__list_init_t.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/basic_json__list_init_t.output"
    ```

??? example "Example: (6) construct an array with count copies of given value"

    The following code shows examples for creating arrays with several copies of a given value.
     
    ```cpp
    --8<-- "examples/basic_json__size_type_basic_json.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/basic_json__size_type_basic_json.output"
    ```

??? example "Example: (7) construct a JSON container given an iterator range"

    The example below shows several ways to create JSON values by specifying a subrange with iterators.
     
    ```cpp
    --8<-- "examples/basic_json__InputIt_InputIt.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/basic_json__InputIt_InputIt.output"
    ```

??? example "Example: (8) copy constructor"

    The following code shows an example for the copy constructor.
     
    ```cpp
    --8<-- "examples/basic_json__basic_json.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/basic_json__basic_json.output"
    ```

??? example "Example: (9) move constructor"

    The code below shows the move constructor explicitly called via `std::move`.
     
    ```cpp
    --8<-- "examples/basic_json__moveconstructor.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/basic_json__moveconstructor.output"
    ```

## Version history

1. Since version 1.0.0.
2. Since version 1.0.0.
3. Since version 2.1.0.
4. Since version 3.2.0.
5. Since version 1.0.0.
6. Since version 1.0.0.
7. Since version 1.0.0.
8. Since version 1.0.0.
9. Since version 1.0.0.
