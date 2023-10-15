## Purpose

Suppose that your application has a complex configuration and:
  * that configuration is represented as a set of JSON files
  * the files are supposed to be edited by the end-users
  * the application on its own provides/dumps only a "default" set of files
somehow annotating the dumped JSON makes much more sense than maintaining a separate documentation
for the allowed values and expected keys, which will get out of date on the nearest occasion.

As per the [original JSON's RFC](https://datatracker.ietf.org/doc/html/rfc8259) comments are not allowed in JSON. But, knowing that the world
is not ideal, [nlohmann's JSON library](https://github.com/nlohmann/json) does support parsing JSON files with so-called "comments", encoded as follows:

```
{
  /* this is a comment */
  "property_1": 5
}
```

A specific overload of the `parse` method has to be called, as per [this](https://json.nlohmann.me/features/comments/) part of the reference:

```
json j = json::parse(s,
                     /* callback */ nullptr,
                     /* allow exceptions */ true,
                     /* ignore_comments */ true);
```

(so, more specifically, the library allows ignoring them)

However, the library does not allow for annotating (adding the comments) when serializing your custom classes or structures. Best you could 
possibly do is post-process the dumped string or file through raw string processing, which is error-prone and problematic.

This fork of the [nlohmann's JSON library](https://github.com/nlohmann/json) adds a possibility to add annotations (known at compile-time) to your classes and structures. I'll try to keep the fork up to date with the original repository, potentially "shadowing" the releases in the future as well[^1].

## How to use

Currently, the extension applies exclusively[^2] to [`NLOHMANN_DEFINE_TYPE_INTRUSIVE` macro](https://github.com/nlohmann/json#simplify-your-life-with-macros):

```
class ExampleClass {
private:
    int property1{1};
    double property2{2.5};
    std::string property3{"test"};
    std::map<std::string, int> property4{{"x", 1}, {"y", 2}};
    std::vector<double> property5{1.5, 5.4, 3.2};
public:
    ExampleClass() = default;

    NLOHMANN_DEFINE_TYPE_INTRUSIVE_ANNOTATED(ExampleClass, property1, "comment两两", 
                                                           property2, "multiline\ncomment2", 
                                                           property3, "comment3",
                                                           property4, "comment4",
                                                           property5, "comment5");
};
```

Dumping is as simple as that:

```
int main() {
    ExampleClass ec;
    std::ofstream example_file;
    example_file.open("example_1.json");

    nlohmann::json j = ec;
    example_file << j.dump_annotated<ExampleClass>(4) << std::endl;
    // instead of the original:
    // example_file << j.dump(4) << std::endl;

    return 0;
}
```

This is then going to produce a JSON file like this:

```
{
    /* comment两两 */
    "property1": 1,
    /* multiline */
    /* comment2 */
    "property2": 2.5,
    /* comment3 */
    "property3": "test",
    /* comment4 */
    "property4": {
        "x": 1,
        "y": 2
    },
    /* comment5 */
    "property5": [
        1.5,
        5.4,
        3.2
    ]
}
```

[^1]: Tried creating a pull request in the original repository, but I doubt it's ever going to be considered.
[^2]: If you look closely at the new macro, it's relatively easy to figure out how to actually *avoid* using the macro, but I need to document that to make it officially supported.
