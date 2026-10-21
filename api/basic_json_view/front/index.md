# nlohmann::basic_json_view::front

```
basic_json_view front() const;
```

Returns the first element of an array, the first member value of an object, or the value itself if it is primitive (as for [`BasicJsonType::front()`](https://json.nlohmann.me/api/basic_json/front/index.md), a primitive value is a range of one element).

## Return value

The first element or member value. For a primitive value (number, string, boolean), the value itself.

## Exception safety

Strong guarantee: there are no changes to the view or the document it refers to.

## Exceptions

Throws [`invalid_iterator.214`](https://json.nlohmann.me/home/exceptions/#jsonexceptioninvalid_iterator214) if the view is [null](https://json.nlohmann.me/api/basic_json_view/is_null/index.md) or [discarded](https://json.nlohmann.me/api/basic_json_view/is_discarded/index.md), or if it is an empty array or object.

This exception does not carry a [`JSON_DIAGNOSTICS`](https://json.nlohmann.me/api/macros/json_diagnostics/index.md) path: the view has no `BasicJsonType` value to point at, so the exception is created without one, even if `BasicJsonType` was built with `JSON_DIAGNOSTICS` enabled.

## Complexity

Constant.

## Notes

Unlike [`BasicJsonType::front()`](https://json.nlohmann.me/api/basic_json/front/index.md), which has undefined behavior for an empty array or object, `front()` throws `invalid_iterator.214` for an empty array, an empty object, a null value, or a discarded view.

## Examples

Example

The example below reads only the earliest entry of a build log with `front()`, without materializing the rest of the (possibly long) log.

```
#include <iostream>
#include <nlohmann/json_view.hpp>

using json_document = nlohmann::json_document;

int main()
{
    // the build log of a running job; front() reads just the earliest event
    // without materializing the (possibly long) rest of the log
    json_document log = json_document::parse(R"(["queued", "started", "compiling", "linking", "done"])");
    std::cout << log.root().front().materialize().dump() << '\n';

    // an empty log -- front() throws instead of the undefined behavior
    // basic_json::front() has for an empty array
    json_document empty_log = json_document::parse("[]");
    try
    {
        static_cast<void>(empty_log.root().front());
    }
    catch (const nlohmann::json::invalid_iterator& e)
    {
        std::cout << e.what() << '\n';
    }
}
```

Output:

```
"queued"
[json.exception.invalid_iterator.214] cannot get value
```

## See also

- [back](https://json.nlohmann.me/api/basic_json_view/back/index.md) - access the last element
- [`BasicJsonType::front`](https://json.nlohmann.me/api/basic_json/front/index.md) - the corresponding function of `basic_json`

## Version history

- Added in version 3.13.0 unreleased.
