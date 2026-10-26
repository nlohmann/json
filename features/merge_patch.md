# JSON Merge Patch

The library supports JSON Merge Patch ([RFC 7396](https://tools.ietf.org/html/rfc7396)) as a patch format.
The merge patch format is primarily intended for use with the HTTP PATCH method as a means of describing a set of
modifications to a target resource's content. Applying a merge patch changes the JSON value the patch is applied to.

Instead of using [JSON Pointer](json_pointer.md) to specify values to be manipulated, it describes the changes using a
syntax that closely mimics the document being modified. Unlike [JSON Patch](json_patch.md), a JSON Merge Patch cannot
express every kind of change (e.g., it cannot reorder array elements or remove a specific array element), but it is
easier to read and write for object-shaped documents.

The function [`merge_diff`](../api/basic_json/merge_diff.md) creates a merge patch that changes one JSON value into
another.

!!! tip "Not a general deep merge"

    A merge patch is not a general deep merge: a `#!json null` value in the patch deletes the key from the target.
    To merge two objects recursively (e.g., defaults and user settings), use
    [`update`](../api/basic_json/update.md) with `merge_objects` set to `#!cpp true`; see
    [Merging objects](modifying_values.md#merging-objects).

!!! note "Limitations of RFC 7396"

    - A patch cannot set a member to `#!json null`, because `#!json null` removes the member:
      `#!json {"a":1}` patched with `#!json {"a":null}` gives `#!json {}`.
    - Arrays are replaced as a whole, never merged, and a `#!json null` inside an array is kept.
    - `#!json null` members of the target that the patch does not mention are preserved.
    - A `#!json null` that would remove a member of a not yet existing object still creates that object:
      `#!json {}` patched with `#!json {"a":{"b":null}}` gives `#!json {"a":{}}`.
    - A patch that is not an object replaces the whole target (a `#!json null` patch makes the target
      `#!json null`); an object patch applied to a non-object target starts from an empty object.
    - [`merge_diff`](../api/basic_json/merge_diff.md#notes) has a matching limitation for `#!json null` members.

??? example

    The following code shows how a JSON Merge Patch is applied to a JSON document.

    ```cpp
    #include <iostream>
    #include <nlohmann/json.hpp>
    #include <iomanip> // for std::setw
    
    using nlohmann::json;
    using namespace nlohmann::literals;
    
    int main()
    {
        // the original document
        json document = R"({
                    "title": "Goodbye!",
                    "author": {
                        "givenName": "John",
                        "familyName": "Doe"
                    },
                    "tags": [
                        "example",
                        "sample"
                    ],
                    "content": "This will be unchanged"
                })"_json;
    
        // the patch
        json patch = R"({
                    "title": "Hello!",
                    "phoneNumber": "+01-123-456-7890",
                    "author": {
                        "familyName": null
                    },
                    "tags": [
                        "example"
                    ]
                })"_json;
    
        // apply the patch
        document.merge_patch(patch);
    
        // output original and patched document
        std::cout << std::setw(4) << document << '\n';
    }
    
    ```
    
    Output:

    ```json
    {
        "author": {
            "givenName": "John"
        },
        "content": "This will be unchanged",
        "phoneNumber": "+01-123-456-7890",
        "tags": [
            "example"
        ],
        "title": "Hello!"
    }
    
    ```

## See also

- [JSON Patch and Diff](json_patch.md) - a more expressive alternative that describes a sequence of operations
- [JSON Pointer](json_pointer.md) - the addressing scheme used by JSON Patch
- Function [`merge_patch`](../api/basic_json/merge_patch.md)
- Function [`merge_diff`](../api/basic_json/merge_diff.md)
- Function [`update`](../api/basic_json/update.md) - merge objects, optionally recursively
