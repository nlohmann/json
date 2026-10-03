# Specializing enum conversion

By default, enum values are serialized to JSON as integers. In some cases, this could result in undesired behavior. If
the integer values of any enum values are changed after data using those enum values has been serialized to JSON, then
deserializing that JSON would result in a different enum value being restored, or the value not being found at all.

It is possible to more precisely specify how a given enum is mapped to and from JSON as shown below:

```cpp
// example enum type declaration
enum TaskState {
    TS_STOPPED,
    TS_RUNNING,
    TS_COMPLETED,
    TS_INVALID=-1,
};

// map TaskState values to JSON as strings
NLOHMANN_JSON_SERIALIZE_ENUM( TaskState, {
    {TS_INVALID, nullptr},
    {TS_STOPPED, "stopped"},
    {TS_RUNNING, "running"},
    {TS_COMPLETED, "completed"},
})
```

The [`NLOHMANN_JSON_SERIALIZE_ENUM()` macro](../api/macros/nlohmann_json_serialize_enum.md) declares a set of
`to_json()` / `from_json()` functions for type `TaskState` while avoiding repetition and boilerplate serialization code.

## Usage

Serialization converts an enum value to its mapped string, deserialization does the reverse, and an unrecognized JSON
value deserializes to the first pair in the map:

```cpp
// enum to JSON as string
json j = TS_STOPPED;
assert(j == "stopped");

// json string to enum
json j3 = "running";
assert(j3.get<TaskState>() == TS_RUNNING);

// undefined json value to enum (where the first map entry above is the default)
json jPi = 3.14;
assert(jPi.get<TaskState>() == TS_INVALID );
```

??? example "Example: serializing/deserializing enums, including a second enum type"

    ```cpp
    --8<-- "examples/nlohmann_json_serialize_enum.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/nlohmann_json_serialize_enum.output"
    ```

## Notes

Just as in [Arbitrary Type Conversions](arbitrary_types.md) above,

- [`NLOHMANN_JSON_SERIALIZE_ENUM()`](../api/macros/nlohmann_json_serialize_enum.md) MUST be declared in your enum type's
  namespace (which can be the global namespace), or the library will not be able to locate it, and it will default to
  integer serialization.
- It MUST be available (e.g., proper headers must be included) everywhere you use the conversions.

Other Important points:

- When using [`get<ENUM_TYPE>()`](../api/basic_json/get.md), undefined JSON values will default to the first pair
  specified in your map. Select this default pair carefully. If you desire an exception in this circumstance use
  [`NLOHMANN_JSON_SERIALIZE_ENUM_STRICT()`](../api/macros/nlohmann_json_serialize_enum_strict.md) which behaves
  identically except for throwing an
  [`out_of_range.410`](../home/exceptions.md#jsonexceptionout_of_range410) exception on unrecognized values, both when
  serializing an enum value not listed in the map and when deserializing a JSON value that matches none of the map's
  entries.
- If an enum or JSON value is specified more than once in your map, the first matching occurrence from the top of the
  map will be returned when converting to or from JSON.
- To disable the default serialization of enumerators as integers and force a compiler error instead, see [`JSON_DISABLE_ENUM_SERIALIZATION`](../api/macros/json_disable_enum_serialization.md).

??? example "Example: `NLOHMANN_JSON_SERIALIZE_ENUM_STRICT` throwing on unrecognized values"

    ```cpp
    --8<-- "examples/nlohmann_json_serialize_enum_strict_err.cpp"
    ```

    Output:

    ```json
    --8<-- "examples/nlohmann_json_serialize_enum_strict_err.output"
    ```
