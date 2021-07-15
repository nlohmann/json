# Arbitrary Types Conversions

Every type can be serialized in JSON, not just STL containers and scalar types. Usually, you would do something along those lines:

```cpp
namespace ns {
    // a simple struct to model a person
    struct person {
        std::string name;
        std::string address;
        int age;
    };
}

ns::person p = {"Ned Flanders", "744 Evergreen Terrace", 60};

// convert to JSON: copy each value into the JSON object
json j;
j["name"] = p.name;
j["address"] = p.address;
j["age"] = p.age;

// ...

// convert from JSON: copy each value from the JSON object
ns::person p {
    j["name"].get<std::string>(),
    j["address"].get<std::string>(),
    j["age"].get<int>()
};
```

It works, but that's quite a lot of boilerplate... Fortunately, there's a better way:

```cpp
// create a person
ns::person p {"Ned Flanders", "744 Evergreen Terrace", 60};

// conversion: person -> json
json j = p;

std::cout << j << std::endl;
// {"address":"744 Evergreen Terrace","age":60,"name":"Ned Flanders"}

// conversion: json -> person
auto p2 = j.get<ns::person>();

// that's it
assert(p == p2);
```

## Basic usage

To make this work with one of your types, you only need to provide two functions:

```cpp
using json = nlohmann::json;

namespace ns {
    void to_json(json& j, const person& p) {
        j = json{ {"name", p.name}, {"address", p.address}, {"age", p.age} };
    }

    void from_json(const json& j, person& p) {
        j.at("name").get_to(p.name);
        j.at("address").get_to(p.address);
        j.at("age").get_to(p.age);
    }
} // namespace ns
```

That's all! When calling the `json` constructor with your type, your custom `to_json` method will be automatically called.
Likewise, when calling `get<your_type>()` or `get_to(your_type&)`, the `from_json` method will be called.

Some important things:

* Those methods **MUST** be in your type's namespace (which can be the global namespace), or the library will not be able to locate them (in this example, they are in namespace `ns`, where `person` is defined).
* Those methods **MUST** be available (e.g., proper headers must be included) everywhere you use these conversions. Look at [issue 1108](https://github.com/nlohmann/json/issues/1108) for errors that may occur otherwise.
* When using `get<your_type>()`, `your_type` **MUST** be [DefaultConstructible](https://en.cppreference.com/w/cpp/named_req/DefaultConstructible). (There is a way to bypass this requirement described later.)
* In function `from_json`, use function [`at()`](https://nlohmann.github.io/json/classnlohmann_1_1basic__json_a93403e803947b86f4da2d1fb3345cf2c.html#a93403e803947b86f4da2d1fb3345cf2c) to access the object values rather than `operator[]`. In case a key does not exist, `at` throws an exception that you can handle, whereas `operator[]` exhibits undefined behavior.
* You do not need to add serializers or deserializers for STL types like `std::vector`: the library already implements these.


## Simplify your life with macros

If you just want to serialize/deserialize some structs, the `to_json`/`from_json` functions can be a lot of boilerplate.

There are two macros to make your life easier as long as you (1) want to use a JSON object as serialization and (2) want to use the member variable names as object keys in that object:

- `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(name, member1, member2, ...)` is to be defined inside of the namespace of the class/struct to create code for.
- `NLOHMANN_DEFINE_TYPE_INTRUSIVE(name, member1, member2, ...)` is to be defined inside of the class/struct to create code for. This macro can also access private members.

In both macros, the first parameter is the name of the class/struct, and all remaining parameters name the members.

!!! note

    At most 64 member variables can be passed to `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE` or `NLOHMANN_DEFINE_TYPE_INTRUSIVE`.

??? example

    The `to_json`/`from_json` functions for the `person` struct above can be created with:
    
    ```cpp
    namespace ns {
        NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(person, name, address, age)
    }
    ```
    
    Here is an example with private members, where `NLOHMANN_DEFINE_TYPE_INTRUSIVE` is needed:
    
    ```cpp
    namespace ns {
        class address {
          private:
            std::string street;
            int housenumber;
            int postcode;
            
          public:
            NLOHMANN_DEFINE_TYPE_INTRUSIVE(address, street, housenumber, postcode)
        };
    }
    ```

## How do I convert third-party types?

This requires a bit more advanced technique. But first, let's see how this conversion mechanism works:

The library uses **JSON Serializers** to convert types to json.
The default serializer for `nlohmann::json` is `nlohmann::adl_serializer` (ADL means [Argument-Dependent Lookup](https://en.cppreference.com/w/cpp/language/adl)).

It is implemented like this (simplified):

```cpp
template <typename T>
struct adl_serializer {
    static void to_json(json& j, const T& value) {
        // calls the "to_json" method in T's namespace
    }

    static void from_json(const json& j, T& value) {
        // same thing, but with the "from_json" method
    }
};
```

This serializer works fine when you have control over the type's namespace. However, what about `boost::optional` or `std::filesystem::path` (C++17)? Hijacking the `boost` namespace is pretty bad, and it's illegal to add something other than template specializations to `std`...

To solve this, you need to add a specialization of `adl_serializer` to the `nlohmann` namespace, here's an example:

```cpp
// partial specialization (full specialization works too)
namespace nlohmann {
    template <typename T>
    struct adl_serializer<boost::optional<T>> {
        static void to_json(json& j, const boost::optional<T>& opt) {
            if (opt == boost::none) {
                j = nullptr;
            } else {
              j = *opt; // this will call adl_serializer<T>::to_json which will
                        // find the free function to_json in T's namespace!
            }
        }

        static void from_json(const json& j, boost::optional<T>& opt) {
            if (j.is_null()) {
                opt = boost::none;
            } else {
                opt = j.get<T>(); // same as above, but with
                                  // adl_serializer<T>::from_json
            }
        }
    };
}
```

## How can I use `get()` for non-default constructible/non-copyable types?

There is a way, if your type is [MoveConstructible](https://en.cppreference.com/w/cpp/named_req/MoveConstructible). You will need to specialize the `adl_serializer` as well, but with a special `from_json` overload:

```cpp
struct move_only_type {
    move_only_type() = delete;
    move_only_type(int ii): i(ii) {}
    move_only_type(const move_only_type&) = delete;
    move_only_type(move_only_type&&) = default;

    int i;
};

namespace nlohmann {
    template <>
    struct adl_serializer<move_only_type> {
        // note: the return type is no longer 'void', and the method only takes
        // one argument
        static move_only_type from_json(const json& j) {
            return {j.get<int>()};
        }

        // Here's the catch! You must provide a to_json method! Otherwise you
        // will not be able to convert move_only_type to json, since you fully
        // specialized adl_serializer on that type
        static void to_json(json& j, move_only_type t) {
            j = t.i;
        }
    };
}
```

## Can I write my own serializer? (Advanced use)

Yes. You might want to take a look at [`unit-udt.cpp`](https://github.com/nlohmann/json/blob/develop/test/src/unit-udt.cpp) in the test suite, to see a few examples.

If you write your own serializer, you'll need to do a few things:

- use a different `basic_json` alias than `nlohmann::json` (the last template parameter of `basic_json` is the `JSONSerializer`)
- use your `basic_json` alias (or a template parameter) in all your `to_json`/`from_json` methods
- use `nlohmann::to_json` and `nlohmann::from_json` when you need ADL

Here is an example, without simplifications, that only accepts types with a size <= 32, and uses ADL.

```cpp
// You should use void as a second template argument
// if you don't need compile-time checks on T
template<typename T, typename SFINAE = typename std::enable_if<sizeof(T) <= 32>::type>
struct less_than_32_serializer {
    template <typename BasicJsonType>
    static void to_json(BasicJsonType& j, T value) {
        // we want to use ADL, and call the correct to_json overload
        using nlohmann::to_json; // this method is called by adl_serializer,
                                 // this is where the magic happens
        to_json(j, value);
    }

    template <typename BasicJsonType>
    static void from_json(const BasicJsonType& j, T& value) {
        // same thing here
        using nlohmann::from_json;
        from_json(j, value);
    }
};
```

Be **very** careful when reimplementing your serializer, you can stack overflow if you don't pay attention:

```cpp
template <typename T, void>
struct bad_serializer
{
    template <typename BasicJsonType>
    static void to_json(BasicJsonType& j, const T& value) {
      // this calls BasicJsonType::json_serializer<T>::to_json(j, value);
      // if BasicJsonType::json_serializer == bad_serializer ... oops!
      j = value;
    }

    template <typename BasicJsonType>
    static void to_json(const BasicJsonType& j, T& value) {
      // this calls BasicJsonType::json_serializer<T>::from_json(j, value);
      // if BasicJsonType::json_serializer == bad_serializer ... oops!
      value = j.template get<T>(); // oops!
    }
};
```
