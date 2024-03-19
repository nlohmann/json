# basic_json::to_bon8

```cpp
// (1)
static std::vector<std::uint8_t> to_bon8(const basic_json& j);

// (2)
static void to_bon8(const basic_json& j, detail::output_adapter<std::uint8_t> o);
static void to_bon8(const basic_json& j, detail::output_adapter<char> o);
```

Serializes a given JSON value `j` to a byte vector using the BON8 serialization format. BON8 is a binary  serialization
format which aims to be more compact than JSON itself, yet more efficient to parse.

1. Returns a byte vector containing the BON8 serialization.
2. Writes the BON8 serialization to an output adapter.

## Parameters

`j` (in)
:   JSON value to serialize

`o` (in)
:   output adapter to write serialization to

## Return value

1. BON8 serialization as byte vector
2. /

## Exception safety

Strong guarantee: if an exception is thrown, there are no changes in the JSON value.

## Complexity

Linear in the size of the JSON value `j`.

## Example

??? example

    The example shows the serialization of a JSON value to a byte vector in BON8 format.
     
    ```cpp
    --8<-- "examples/to_bon8.cpp"
    ```
    
    Output:
    
    ```json
    --8<-- "examples/to_bon8.output"
    ```

## Version history

- Added in version 3.11.0.
