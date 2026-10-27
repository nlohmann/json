# JSON Merge Patch

The library supports JSON Merge Patch ([RFC 7396](https://tools.ietf.org/html/rfc7396)) as a patch format. The merge patch format is primarily intended for use with the HTTP PATCH method as a means of describing a set of modifications to a target resource's content. Applying a merge patch changes the JSON value the patch is applied to.

Instead of using [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md) to specify values to be manipulated, it describes the changes using a syntax that closely mimics the document being modified. Unlike [JSON Patch](https://json.nlohmann.me/features/json_patch/index.md), a JSON Merge Patch cannot express every kind of change (e.g., it cannot reorder array elements or remove a specific array element), but it is easier to read and write for object-shaped documents.

The function [`merge_diff`](https://json.nlohmann.me/api/basic_json/merge_diff/index.md) creates a merge patch that changes one JSON value into another.

The example below applies one patch to one document. Here is the document before:

```
{
    "title": "Goodbye!",
    "author": {
        "givenName": "John",
        "familyName": "Doe"
    },
    "tags": ["example", "sample"],
    "content": "This will be unchanged"
}
```

This is the patch:

```
{
    "title": "Hello!",
    "phoneNumber": "+01-123-456-7890",
    "author": {
        "familyName": null
    },
    "tags": ["example"]
}
```

And this is the document after applying it:

```
{
    "title": "Hello!",
    "author": {
        "givenName": "John"
    },
    "tags": ["example"],
    "content": "This will be unchanged",
    "phoneNumber": "+01-123-456-7890"
}
```

The table goes through the members one by one. "Member" is the name of an object member in the patch (and in the document); it is not a [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md) and nothing of it is passed to the function: the whole patch is passed to [`merge_patch`](https://json.nlohmann.me/api/basic_json/merge_patch/index.md).

| Rule                      | Member                       | Before                                       | Patch                  | After                      |
| ------------------------- | ---------------------------- | -------------------------------------------- | ---------------------- | -------------------------- |
| change value              | `title`                      | `"Goodbye!"`                                 | `"Hello!"`             | `"Hello!"`                 |
| add key                   | `phoneNumber`                | (no member)                                  | `"+01-123-456-7890"`   | `"+01-123-456-7890"`       |
| object merges recursively | `author`                     | `{"givenName": "John", "familyName": "Doe"}` | `{"familyName": null}` | `{"givenName": "John"}`    |
| null removes key          | `familyName` inside `author` | `"Doe"`                                      | `null`                 | (removed)                  |
| array replaced whole      | `tags`                       | `["example", "sample"]`                      | `["example"]`          | `["example"]`              |
| unchanged key             | `content`                    | `"This will be unchanged"`                   | (no member)            | `"This will be unchanged"` |

An array in the patch replaces the array in the target, so a merge patch cannot change a single element. Each member of the patch is applied like this; a patch that is not an object replaces the whole target.

```
flowchart LR
    M["member of the patch"] --> N{{"value null?"}}
    N -->|yes| D["delete the key"]
    N -->|no| O{{"value an object?"}}
    O -->|yes| R["merge recursively into the target's value"]
    O -->|no| S["set the key to the value"]
```

How one member of a merge patch is applied: a `null` value deletes the key, an object is merged recursively, and any other value replaces the value of the key.

Not a general deep merge

A merge patch is not a general deep merge: a `null` value in the patch deletes the key from the target. To merge two objects recursively (e.g., defaults and user settings), use [`update`](https://json.nlohmann.me/api/basic_json/update/index.md) with `merge_objects` set to `true`; see [Merging objects](https://json.nlohmann.me/features/modifying_values/#merging-objects).

Limitations of RFC 7396

- A patch cannot set a member to `null`, because `null` removes the member: `{"a":1}` patched with `{"a":null}` gives `{}`.
- Arrays are replaced as a whole, never merged, and a `null` inside an array is kept.
- `null` members of the target that the patch does not mention are preserved.
- A `null` that would remove a member of a not yet existing object still creates that object: `{}` patched with `{"a":{"b":null}}` gives `{"a":{}}`.
- A patch that is not an object replaces the whole target (a `null` patch makes the target `null`); an object patch applied to a non-object target starts from an empty object.
- [`merge_diff`](https://json.nlohmann.me/api/basic_json/merge_diff/#notes) has a matching limitation for `null` members.

Example

The following code shows how a JSON Merge Patch is applied to a JSON document.

```
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

```
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

- [JSON Patch and Diff](https://json.nlohmann.me/features/json_patch/index.md) - a more expressive alternative that describes a sequence of operations
- [JSON Pointer](https://json.nlohmann.me/features/json_pointer/index.md) - the addressing scheme used by JSON Patch
- [`merge_patch`](https://json.nlohmann.me/api/basic_json/merge_patch/index.md) - apply a JSON Merge Patch to a value
- [`merge_diff`](https://json.nlohmann.me/api/basic_json/merge_diff/index.md) - create a JSON Merge Patch from two values
- Function [`update`](https://json.nlohmann.me/api/basic_json/update/index.md) - merge objects, optionally recursively
- [Modifying values](https://json.nlohmann.me/features/modifying_values/index.md) - simple in-place modifications
