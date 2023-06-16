# Specializing enum conversion

By default, enum values are serialized to JSON as integers. In some cases this could result in undesired behavior. If an
enum is modified or re-ordered after data has been serialized to JSON, the later de-serialized JSON data may be
undefined or a different enum value than was originally intended.

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

```cpp
// enum to JSON as string
json j = TS_STOPPED;
assert(j == "stopped");

// json string to enum
json j3 = "running";
assert(j3.template get<TaskState>() == TS_RUNNING);

// undefined json value to enum (where the first map entry above is the default)
json jPi = 3.14;
assert(jPi.template get<TaskState>() == TS_INVALID );
```

## Notes

Just as in [Arbitrary Type Conversions](arbitrary_types.md) above,

- [`NLOHMANN_JSON_SERIALIZE_ENUM()`](../api/macros/nlohmann_json_serialize_enum.md) MUST be declared in your enum type's
  namespace (which can be the global namespace), or the library will not be able to locate it, and it will default to
  integer serialization.
- It MUST be available (e.g., proper headers must be included) everywhere you use the conversions.

Other Important points:

- When using `template get<ENUM_TYPE>()`, undefined JSON values will default to the first pair specified in your map. Select this
  default pair carefully.
- If an enum or JSON value is specified more than once in your map, the first matching occurrence from the top of the
  map will be returned when converting to or from JSON.
- To disable the default serialization of enumerators as integers and force a compiler error instead, see [`JSON_DISABLE_ENUM_SERIALIZATION`](../api/macros/json_disable_enum_serialization.md).
