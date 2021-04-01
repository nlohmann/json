#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    try
    {
        // executing a failing JSON Patch operation
        json value = R"({
            "best_biscuit": {
                "name": "Oreo"
            }
        })"_json;
        json patch = R"([{
            "op": "test",
            "path": "/best_biscuit/name",
            "value": "Choco Leibniz"
        }])"_json;
        value.patch(patch);
    }
    catch (json::other_error& e)
    {
        // output exception information
        std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << std::endl;
    }
}using number_float_t = NumberFloatType;define MergePatch(Target, Patch):
  if Patch is an Object:
    if Target is not an Object:
      Target = {} // Ignore the contents and set it to an empty Object
    for each Name/Value pair in Patch:
      if Value is null:
        if Name exists in Target:
          remove the Name/Value pair from Target
      else:
        Target[Name] = MergePatch(Target[Name], Value)
    return Target
  else:
    return Patch{
    "compiler": {
        "c++": "201103",
        "family": "clang",
        "version": "12.0.0 (clang-1200.0.32.28)"
    },
    "copyright": "(C) 2013-2021 Niels Lohmann",
    "name": "JSON for Modern C++",
    "platform": "apple",
    "url": "https://github.com/nlohmann/json",
    "version": {
        "major": 3,
        "minor": 9,
        "patch": 1,
        "string": "3.9.1"
    }
}#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // call meta()
    std::cout << std::setw(4) << json::meta() << '\n';
}static basic_json meta();size_type max_size() const noexcept;key: one, value: 1
key: two, value: 2
key: 0, value: 1
key: 1, value: 2
key: 2, value: 4
key: 3, value: 8
key: 4, value: 16for (auto& [key, val] : j_object.items())
{
    std::cout << "key: " << key << ", value:" << val << '\n';
}for (auto& el : j_object.items())
{
    std::cout << "key: " << el.key() << ", value:" << el.value() << '\n';
}for (auto it : j_object)
{
    // "it" is of type json::reference and has no key() member
    std::cout << "value: " << it << '\n';
}for (auto it = j_object.begin(); it != j_object.end(); ++it)
{
    std::cout << "key: " << it.key() << ", value:" << it.value() << '\n';
}iteration_proxy<iterator> items() noexcept;
iteration_proxy<const_iterator> items() const noexcept;true
true
true
true
true
false
false
true
true#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json j_null;
    json j_boolean = true;
    json j_number_integer = 17;
    json j_number_float = 23.42;
    json j_number_unsigned_integer = 12345678987654321u;
    json j_object = {{"one", 1}, {"two", 2}};
    json j_array = {1, 2, 4, 8, 16};
    json j_string = "Hello, world";
    json j_binary = json::binary({1, 2, 3});

    // call is_primitive()
    std::cout << std::boolalpha;
    std::cout << j_null.is_primitive() << '\n';
    std::cout << j_boolean.is_primitive() << '\n';
    std::cout << j_number_integer.is_primitive() << '\n';
    std::cout << j_number_unsigned_integer.is_primitive() << '\n';
    std::cout << j_number_float.is_primitive() << '\n';
    std::cout << j_object.is_primitive() << '\n';
    std::cout << j_array.is_primitive() << '\n';
    std::cout << j_string.is_primitive() << '\n';
    std::cout << j_binary.is_primitive() << '\n';
}constexpr bool is_primitive() const noexcept
{
    return is_null() || is_string() || is_boolean() || is_number() || is_binary();
}false
false
false
false
false
false
false
false
true#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    try
    {
        // calling iterator::key() on non-object iterator
        json j = "string";
        json::iterator it = j.begin();
        auto k = it.key();
    }
    catch (json::invalid_iterator& e)
    {
        // output exception information
        std::cout << "message: " << e.what() << '\n'
                  << "exception id: " << e.id << std::endl;
    }
}static allocator_type get_allocator();ValueType ret;
JSONSerializer<ValueType>::from_json(*this, ret);
return ret;// (1)
template<typename InputType>
static basic_json from_cbor(InputType&& i,
                            const bool strict = true,
                            const bool allow_exceptions = true,
                            const cbor_tag_handler_t tag_handler = cbor_tag_handler_t::error);

// (2)
template<typename IteratorType>
static basic_json from_cbor(IteratorType first, IteratorType last,
                            const bool strict = true,
                            const bool allow_exceptions = true,
                            const cbor_tag_handler_t tag_handler = cbor_tag_handler_t::error);// (1)
template<typename InputType>
static basic_json from_bson(InputType&& i,
                            const bool strict = true,
                            const bool allow_exceptions = true);
// (2)
template<typename IteratorType>
static basic_json from_bson(IteratorType first, IteratorType last,
                            const bool strict = true,
                            const bool allow_exceptions = true);basic_json flatten() const;#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON object
    json j_object = {{"one", 1}, {"two", 2}};

    // call find
    auto it_two = j_object.find("two");
    auto it_three = j_object.find("three");

    // print values
    std::cout << std::boolalpha;
    std::cout << "\"two\" was found: " << (it_two != j_object.end()) << '\n';
    std::cout << "value at key \"two\": " << *it_two << '\n';
    std::cout << "\"three\" was found: " << (it_three != j_object.end()) << '\n';
}"two" was found: true
value at key "two": 2
"three" was found: falseenum class error_handler_t {
    strict,
    replace,
    ignore
};5iterator end() noexcept;
const_iterator end() const noexcept;[1,2,3,4,5]
null
[1,2,3,4,5,6]
["first",["second","second","second"]]#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON values
    json array = {1, 2, 3, 4, 5};
    json null;

    // print values
    std::cout << array << '\n';
    std::cout << null << '\n';

    // add values
    array.emplace_back(6);
    null.emplace_back("first");
    null.emplace_back(3, "second");

    // print values
    std::cout << array << '\n';
    std::cout << null << '\n';
}j_object contains 'key': true
j_object contains 'another': false
j_array contains 'key': false#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create some JSON values
    json j_object = R"( {"key": "value"} )"_json;
    json j_array = R"( [1, 2, 3] )"_json;

    // call contains
    std::cout << std::boolalpha <<
              "j_object contains 'key': " << j_object.contains("key") << '\n' <<
              "j_object contains 'another': " << j_object.contains("another") << '\n' <<
              "j_array contains 'key': " << j_array.contains("key") << std::endl;
}const_iterator cbegin() const noexcept;using boolean_t = BooleanType;1
"foo"
[1,2]
2
[json.exception.parse_error.109] parse error: array index 'one' is not a number
[json.exception.out_of_range.401] array index 4 is out of range
[json.exception.out_of_range.402] array index '-' (2) is out of range
[json.exception.out_of_range.403] key 'foo' not found
[json.exception.out_of_range.404] unresolved reference token 'foo'#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value
    const json j =
    {
        {"number", 1}, {"string", "foo"}, {"array", {1, 2}}
    };

    // read-only access

    // output element with JSON pointer "/number"
    std::cout << j.at("/number"_json_pointer) << '\n';
    // output element with JSON pointer "/string"
    std::cout << j.at("/string"_json_pointer) << '\n';
    // output element with JSON pointer "/array"
    std::cout << j.at("/array"_json_pointer) << '\n';
    // output element with JSON pointer "/array/1"
    std::cout << j.at("/array/1"_json_pointer) << '\n';

    // out_of_range.109
    try
    {
        // try to use an array index that is not a number
        json::const_reference ref = j.at("/array/one"_json_pointer);
    }
    catch (json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.401
    try
    {
        // try to use a an invalid array index
        json::const_reference ref = j.at("/array/4"_json_pointer);
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.402
    try
    {
        // try to use the array index '-'
        json::const_reference ref = j.at("/array/-"_json_pointer);
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.403
    try
    {
        // try to use a JSON pointer to an nonexistent object key
        json::const_reference ref = j.at("/foo"_json_pointer);
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.404
    try
    {
        // try to use a JSON pointer that cannot be resolved
        json::const_reference ref = j.at("/number/foo"_json_pointer);
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}1
"foo"
[1,2]
2
"bar"
[1,21]
[json.exception.parse_error.106] parse error: array index '01' must not begin with '0'
[json.exception.parse_error.109] parse error: array index 'one' is not a number
[json.exception.out_of_range.401] array index 4 is out of range
[json.exception.out_of_range.402] array index '-' (2) is out of range
[json.exception.out_of_range.403] key 'foo' not found
[json.exception.out_of_range.404] unresolved reference token 'foo'#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create a JSON value
    json j =
    {
        {"number", 1}, {"string", "foo"}, {"array", {1, 2}}
    };

    // read-only access

    // output element with JSON pointer "/number"
    std::cout << j.at("/number"_json_pointer) << '\n';
    // output element with JSON pointer "/string"
    std::cout << j.at("/string"_json_pointer) << '\n';
    // output element with JSON pointer "/array"
    std::cout << j.at("/array"_json_pointer) << '\n';
    // output element with JSON pointer "/array/1"
    std::cout << j.at("/array/1"_json_pointer) << '\n';

    // writing access

    // change the string
    j.at("/string"_json_pointer) = "bar";
    // output the changed string
    std::cout << j["string"] << '\n';

    // change an array element
    j.at("/array/1"_json_pointer) = 21;
    // output the changed array
    std::cout << j["array"] << '\n';


    // out_of_range.106
    try
    {
        // try to use an array index with leading '0'
        json::reference ref = j.at("/array/01"_json_pointer);
    }
    catch (json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.109
    try
    {
        // try to use an array index that is not a number
        json::reference ref = j.at("/array/one"_json_pointer);
    }
    catch (json::parse_error& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.401
    try
    {
        // try to use a an invalid array index
        json::reference ref = j.at("/array/4"_json_pointer);
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.402
    try
    {
        // try to use the array index '-'
        json::reference ref = j.at("/array/-"_json_pointer);
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.403
    try
    {
        // try to use a JSON pointer to an nonexistent object key
        json::const_reference ref = j.at("/foo"_json_pointer);
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }

    // out_of_range.404
    try
    {
        // try to use a JSON pointer that cannot be resolved
        json::reference ref = j.at("/number/foo"_json_pointer);
    }
    catch (json::out_of_range& e)
    {
        std::cout << e.what() << '\n';
    }
}"il brutto"
[json.exception.type_error.304] cannot use at() with string
out of range"third"
["first","second","third","fourth"]
[json.exception.type_error.304] cannot use at() with string
[json.exception.out_of_range.401] array index 5 is out of rangeusing array_t = ArrayType<basic_json, AllocatorType<basic_json>>;#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // create JSON arrays
    json j_no_init_list = json::array();
    json j_empty_init_list = json::array({});
    json j_nonempty_init_list = json::array({1, 2, 3, 4});
    json j_list_of_pairs = json::array({ {"one", 1}, {"two", 2} });

    // serialize the JSON arrays
    std::cout << j_no_init_list << '\n';
    std::cout << j_empty_init_list << '\n';
    std::cout << j_nonempty_init_list << '\n';
    std::cout << j_list_of_pairs << '\n';
}true false#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // a valid JSON text
    auto valid_text = R"(
    {
        "numbers": [1, 2, 3]
    }
    )";

    // an invalid JSON text
    auto invalid_text = R"(
    {
        "strings": ["extra", "comma", ]
    }
    )";

    std::cout << std::boolalpha
              << json::accept(valid_text) << ' '
              << json::accept(invalid_text) << '\n';
}// (1)
template<typename InputType>
static bool accept(InputType&& i,
                   const bool ignore_comments = false);

// (2)
template<typename IteratorType>
static bool accept(IteratorType first, IteratorType last,
                   const bool ignore_comments = false);brew tap nlohmann/json
brew install nlohmann-json --HEADbrew tap nlohmann/json
brew install nlohmann-json#include <nlohmann/json.hpp>
#include <iostream>

using json = nlohmann::json;

int main()
{
    std::cout << json::meta() << std::endl;
}# thirdparty/CMakeLists.txt
...
if(FOO_USE_EXTERNAL_JSON)
  find_package(nlohmann_json 3.2.0 REQUIRED)
else()
  set(JSON_BuildTests OFF CACHE INTERNAL "")
  add_subdirectory(nlohmann_json)
endif()
...# Top level CMakeLists.txt
project(FOO)
...
option(FOO_USE_EXTERNAL_JSON "Use an external JSON library" OFF)
...
add_subdirectory(thirdparty)
...
add_library(foo ...)
...
# Note that the namespaced target will always be available regardless of the
# import method
target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)include(FetchContent)

FetchContent_Declare(json
  GIT_REPOSITORY https://github.com/nlohmann/json
  GIT_TAG v3.7.3)

FetchContent_GetProperties(json)
if(NOT json_POPULATED)
  FetchContent_Populate(json)
  add_subdirectory(${json_SOURCE_DIR} ${json_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)# Typically you don't care so much for a third party library's tests to be
# run from your own project's code.
set(JSON_BuildTests OFF CACHE INTERNAL "")

# If you only include this third party in PRIVATE source files, you do not
# need to install it when your main project gets installed.
# set(JSON_Install OFF CACHE INTERNAL "")

# Don't use include(nlohmann_json/CMakeLists.txt) since that carries with it
# unintended consequences that will break the build.  It's generally
# discouraged (although not necessarily well documented as such) to use
# include(...) for pulling in other CMake projects anyways.
add_subdirectory(nlohmann_json)
...
add_library(foo ...)
...
target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)# CMakeLists.txt
find_package(nlohmann_json 3.2.0 REQUIRED)
...
add_library(foo ...)
...
target_link_libraries(foo PRIVATE nlohmann_json::nlohmann_json)#include <nlohmann/json.hpp>

// for convenience
using json = nlohmann::json;std::vector<
  basic_json, // value_type
  std::allocator<basic_json> // allocator_type
>template<
    template<typename U, typename V, typename... Args> class ObjectType = std::map,
    template<typename U, typename... Args> class ArrayType = std::vector,
    class StringType = std::string,
    class BooleanType = bool,
    class NumberIntegerType = std::int64_t,
    class NumberUnsignedType = std::uint64_t,
    class NumberFloatType = double,
    template<typename U> class AllocatorType = std::allocator,
    template<typename T, typename SFINAE = void> class JSONSerializer = adl_serializer,
    class BinaryType = std::vector<std::uint8_t>
>
class basic_json;json j = "Hello, world!";
auto s = j.get<std::string>();json j = "Hello, world!";
std::string s = j;// example enum type declaration
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
})// called when null is parsed
bool null();

// called when a boolean is parsed; value is passed
bool boolean(bool val);

// called when a signed or unsigned integer number is parsed; value is passed
bool number_integer(number_integer_t val);
bool number_unsigned(number_unsigned_t val);

// called when a floating-point number is parsed; value and original string is passed
bool number_float(number_float_t val, const string_t& s);

// called when a string is parsed; value is passed and can be safely moved away
bool string(string_t& val);
// called when a binary value is parsed; value is passed and can be safely moved away
bool binary(binary& val);

// called when an object or array begins or ends, resp. The number of elements is passed (or -1 if not known)
bool start_object(std::size_t elements);
bool end_object();
bool start_array(std::size_t elements);
bool end_array();
// called when an object key is parsed; value is passed and can be safely moved away
bool key(string_t& val);

// called when a parse error occurs; byte position, the last token, and an exception is passed
bool parse_error(std::size_t position, const std::string& last_token, const json::exception& ex);#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

class sax_no_exception : public nlohmann::detail::json_sax_dom_parser<json>
{
  public:
    sax_no_exception(json& j)
      : nlohmann::detail::json_sax_dom_parser<json>(j, false)
    {}

    bool parse_error(std::size_t position,
                     const std::string& last_token,
                     const json::exception& ex)
    {
        std::cerr << "parse error at input byte " << position << "\n"
                  << ex.what() << "\n"
                  << "last read: \"" << last_token << "\""
                  << std::endl;
        return false;
    }
};

int main()
{
    std::string myinput = "[1,2,3,]";

    json result;
    sax_no_exception sax(result);

    bool parse_result = json::sax_parse(myinput, &sax);
    if (!parse_result)
    {
        std::cerr << "parsing unsuccessful!" << std::endl;
    }

    std::cout << "parsed value: " << result << std::endl;
}parse error at input byte 8
[json.exception.parse_error.101] parse error at line 1, column 8: syntax error while parsing value - unexpected ']'; expected '[', '{', or a literal
last read: "3,]"
parsing unsuccessful!
parsed value: [1,2,3]bool parse_error(std::size_t position,
                 const std::string& last_token,
                 const json::exception& ex);if (!json::accept(my_input))
{
    std::cerr << "parse error" << std::endl;
}json j = json::parse(my_input, nullptr, false);
if (j.is_discarded())
{
    std::cerr << "parse error" << std::endl;
}json j;
try
{
    j = json::parse(my_input);
}
catch (json::parse_error& ex)
{
    std::cerr << "parse error at byte " << ex.byte << std::endl;
}{
  "one": 1,
  "two": 2,
  "three": 3
}#include <iostream>
#include <nlohmann/json.hpp>

using ordered_json = nlohmann::ordered_json;

int main()
{
    ordered_json j;
    j["one"] = 1;
    j["two"] = 2;
    j["three"] = 3;

    std::cout << j.dump(2) << '\n';
}{
  "one": 1,
  "three": 3,
  "two": 2
}#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    json j;
    j["one"] = 1;
    j["two"] = 2;
    j["three"] = 3;

    std::cout << j.dump(2) << '\n';
}{
    "author": {
        "givenName": "Heather Jones"
    },
    "content": "This will be unchanged",
    "phoneNumber": "+01-123-456-7890",
    "tags": [
        "example"
    ],
    "title": "Hello!"#include <iostream>
#include <nlohmann/json.hpp>
#include <iomanip> // for std::setw

using json = nlohmann::json;

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
    std::cout << std::setw(4) << document << std::endl;
}[
    {
        "op": "replace",
        "path": "/baz",
        "value": "boo"
    },
    {
        "op": "remove",
        "path": "/foo"
    },
    {
        "op": "add",
        "path": "/hello",
        "value": [
            "world"
        ]
    }
]

{
    "baz": "boo",
    "hello": [
        "world"
    ]
}#include <iostream>
#include <iomanip>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main()
{
    // the source document
    json source = R"(
        {
            "baz": "qux",
            "foo": "bar"
        }
    )"_json;

    // the target document
    json target = R"(
        {
            "baz": "boo",
            "hello": [
                "world"
            ]
        }
    )"_json;

    // create the patch
    json patch = json::diff(source, target);

    // roundtrip
    json patched_source = source.patch(patch);

    // output patch and roundtrip result
    std::cout << std::setw(4) << patch << "\n\n"
              << std::setw(4) << patched_source << std::endl;
}// a JSON value
json j_original = R"({
  "baz": ["one", "two", "three"],
  "foo": "bar"
})"_json;

// access members with a JSON pointer (RFC 6901)
j_original["/baz/1"_json_pointer];
// "two"#include <iostream>

#define JSON_TRY_USER if(true)
#define JSON_CATCH_USER(exception) if(false)
#define JSON_THROW_USER(exception)                           \
    {std::clog << "Error in " << __FILE__ << ":" << __LINE__ \
               << " (function " << __FUNCTION__ << ") - "    \
               << (exception).what() << std::endl;           \
     std::abort();}

#include <nlohmann/json.hpp>Python Examples
Basics Strings Lists Dictionary Files Logging sqlite3 OpenCV Pillow Pandas Numpy PyMongo
Python *args
Contents

Example: Python *args
args in *args is just a name
args in *args is a tuple
*args with other parameters
*args with **kwargs
Summary
Python *args parameter in a function definition allows the function to accept multiple arguments without knowing how many arguments. In other words it lets the function accept a variable number of arguments.

Datatype of args is tuple. Inside the function, you can access all the arguments passed as *args using a for loop. Or, you can use index to access the individual arguments. We will verify the datatype of args in an example below.

In this tutorial, we will learn how to use *args in function definition with the help of example programs.

Example: Python *args
We already know that *args parameter lets the function accept any number of arguments. In this example, we will write an addition function that can accept any number of arguments and returns the addition of all these arguments.

Python Program

def addition(*args):
    result = 0
    for arg in args:
        result += arg
    return result

if __name__ == "__main__":
    sum = addition(2, 5, 1, 9)
    print(sum)

    sum = addition(5)
    print(sum)

    sum = addition(5, 4, 0.5, 1.5, 9, 2)
    print(sum)
 Run
Output

17
5
22.0

args in *args is just a name
args is just the parameter name. You can provide any name, instead of args, just like any other parameter in function definition. Asterisk symbol (*) before the parameter name is the important part. It tells Python that this parameter is going to accept a variable number of arguments. Because of its functionality, the asterisk symbol is called unpacking operator.

We shall use the same example above, and use a different name for args, say numbers.

Python Program

def addition(*numbers):
    result = 0
    for number in numbers:
        result += number
    return result

if __name__ == "__main__":
    sum = addition(2, 5, 1, 9)
    print(sum)
 Run
Output

17
args in *args is a tuple
Based on the previous examples, it is already established that we can use args as an iterator. Well! if we could use an iterator on args, then what could be the datatype of args. Only one way to find out. Use Python type() builtin function.

Python Program

def addition(*numbers):
    print(type(numbers))

if __name__ == "__main__":
    addition(2, 5, 1, 9)
 Run
Output

<class 'tuple'>
Loud and clear as it says. The datatype of args parameter is tuple. So, we get a tuple when we use unpacking operator with parameter (*args) to accept variable number of arguments.

Since tuple is immutable (at least shallow level), it is logical to keep the datatype of args as tuple instead of list.

*args with other parameters
*args is just another parameter that can accept multiple number of positional arguments. You can use *args with other parameters in your function definition.

In the following example, we will create a function that will accept arguments for some specified parameters, and then any number of arguments using *args.

Python Program

def calculator(operation, *numbers):
    if operation == "add":
        result = 0
        for num in numbers:
            result += num
        return result
    
    if operation == "product":
        result = 1
        for num in numbers:
            result *= num
        return result

if __name__ == "__main__":
    x = calculator("add", 2, 5, 1, 9)
    print(x)
    x = calculator("product", 3, 5, 2)
    print(x)
 Run
Output

17
30
*args with **kwargs
While *args can accept any number of positional arguments, Python **kwargs can accept any number of named arguments.

You can use *args and **kwargs in a function definition to accept both positional arguments and named arguments, whose count is unknown.

In the following example, we will define a function with both *args and **kwargs.

Python Program

def myFunction(*args, **kwargs):
    print(args)
    print(kwargs)

if __name__ == "__main__":
    myFunction("hello", "mars", a = 24, b = 87, c = 3, d = 46)
 Run
Output

('hello', 'mars')
{'a': 24, 'b': 87, 'c': 3, 'd': 46}
Just to remind, the datatype of args is tuple, and the datatype of kwargs is dictionary.

Summary
In this tutorial of Python Examples, we learned how to use *args to write functions that can accept any number of arguments.




Sitemap Privacy Policy Terms of Use Contact Us
permalinkPin copied text snippets to stop them expiring after 1 hour
}
