# JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS

```cpp
#define JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS /* value */
```

When defined to `1`, maps whose keys are enums (such as `std::map<E, T>` or `std::unordered_map<E, T>`) are stored as
JSON objects, using the enum's own conversion for the keys. By default, they are stored as arrays of `[key, value]`
pairs.

## Default definition

The default value is `0` (disabled — existing behavior is preserved).

```cpp
#define JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS 0
```

## Notes

!!! note "Background"

    JSON object keys are strings, so a map is only stored as an object if its keys can be converted to a string type.
    Enums are not, even if [`NLOHMANN_JSON_SERIALIZE_ENUM`](nlohmann_json_serialize_enum.md) maps them to strings, so a
    map with enum keys becomes an array of `[key, value]` pairs:

    ```json
    [["stopped", "aa"], ["completed", "bb"]]
    ```

    With this macro, the same map becomes an object
    (see [#4378](https://github.com/nlohmann/json/issues/4378)):

    ```json
    {"completed": "bb", "stopped": "aa"}
    ```

!!! note "Reading"

    Reading is not affected by the macro: a map with enum keys can always be read from both an array of pairs and an
    object. For the latter, each key is converted to the enum with its `from_json` function, e.g., the one defined by
    [`NLOHMANN_JSON_SERIALIZE_ENUM`](nlohmann_json_serialize_enum.md). Data written without the macro can therefore
    still be read after enabling it.

!!! warning "Keys must serialize to distinct strings"

    Each key is converted with the enum's `to_json` function. If a key is not converted to a string (for instance, an
    enum without [`NLOHMANN_JSON_SERIALIZE_ENUM`](nlohmann_json_serialize_enum.md), which is stored as an integer, or an
    enumerator mapped to `nullptr`), [`type_error.302`](../../home/exceptions.md#jsonexceptiontype_error302) is thrown.
    If two keys are converted to the same string (for instance, because
    [`NLOHMANN_JSON_SERIALIZE_ENUM`](nlohmann_json_serialize_enum.md) maps an unlisted enumerator to the first entry),
    [`type_error.318`](../../home/exceptions.md#jsonexceptiontype_error318) is thrown. In both cases, the target value
    is not changed.

!!! warning "Opt-in only"

    This macro must be defined **before** including `<nlohmann/json.hpp>`. Defining it after the include has no effect.

!!! note "ABI compatibility"

    The value of this macro is encoded in the [namespace](../../features/namespace.md) (tag `_ekmo`), resulting in
    distinct symbol names. Translation units compiled with and without it can therefore be linked into the same program
    without One Definition Rule (ODR) violations, but they cannot exchange instances of library types.

## Examples

??? example "Default behavior (macro not defined)"

    Without the macro, a map with enum keys is stored as an array of pairs:

    ```cpp
    #include <map>
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    enum TaskState { TS_STOPPED, TS_RUNNING, TS_COMPLETED };

    NLOHMANN_JSON_SERIALIZE_ENUM(TaskState, {
        {TS_STOPPED, "stopped"},
        {TS_RUNNING, "running"},
        {TS_COMPLETED, "completed"},
    })

    int main()
    {
        std::map<TaskState, std::string> m = {{TS_STOPPED, "aa"}, {TS_COMPLETED, "bb"}};

        json j = m;
        // j is [["stopped","aa"],["completed","bb"]]
    }
    ```

??? example "Objects for enum-keyed maps (macro defined to 1)"

    With the macro, the same map is stored as an object:

    ```cpp
    #define JSON_USE_OBJECTS_FOR_ENUM_KEYED_MAPS 1
    #include <map>
    #include <nlohmann/json.hpp>

    using json = nlohmann::json;

    enum TaskState { TS_STOPPED, TS_RUNNING, TS_COMPLETED };

    NLOHMANN_JSON_SERIALIZE_ENUM(TaskState, {
        {TS_STOPPED, "stopped"},
        {TS_RUNNING, "running"},
        {TS_COMPLETED, "completed"},
    })

    int main()
    {
        std::map<TaskState, std::string> m = {{TS_STOPPED, "aa"}, {TS_COMPLETED, "bb"}};

        json j = m;
        // j is {"completed":"bb","stopped":"aa"}

        auto m2 = j.get<std::map<TaskState, std::string>>();
        // m2 == m
    }
    ```

## See also

- [Specializing enum conversion](../../features/enum_conversion.md)
- [**NLOHMANN_JSON_SERIALIZE_ENUM**](nlohmann_json_serialize_enum.md) - serialize/deserialize an enum
- [**NLOHMANN_JSON_SERIALIZE_ENUM_STRICT**](nlohmann_json_serialize_enum_strict.md) - serialize/deserialize an enum with
  exceptions

## Version history

- Added in version 3.13.0.
