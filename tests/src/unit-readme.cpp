//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013 - 2025 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;
#ifdef JSON_TEST_NO_GLOBAL_UDLS
    using namespace nlohmann::literals; // NOLINT(google-build-using-namespace)
#endif

#include <deque>
#include <forward_list>
#include <list>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <sstream>
#include <iomanip>

// local variable is initialized but not referenced
DOCTEST_MSVC_SUPPRESS_WARNING_PUSH
DOCTEST_MSVC_SUPPRESS_WARNING(4189)

TEST_CASE("README" * doctest::skip())
{
    {
        // redirect std::cout for the README file
        auto* old_cout_buffer = std::cout.rdbuf();
        std::ostringstream const new_stream;
        std::cout.rdbuf(new_stream.rdbuf());
        {
            // create an empty structure (null)
            json j;

            // add a number that is stored as double (note the implicit conversion of j to an object)
            j["pi"] = 3.141;

            // add a Boolean that is stored as bool
            j["happy"] = true;

            // add a string that is stored as std::string
            j["name"] = "Niels";

            // add another null object by passing nullptr
            j["nothing"] = nullptr;

            // add an object inside the object
            j["answer"]["everything"] = 42;

            // add an array that is stored as std::vector (using an initializer list)
            j["list"] = { 1, 0, 2 };

            // add another object (using an initializer list of pairs)
            j["object"] = { {"currency", "USD"}, {"value", 42.99} };

            // instead, you could also write (which looks very similar to the JSON above)
            json const j2 =
            {
                {"pi", 3.141},
                {"happy", true},
                {"name", "Niels"},
                {"nothing", nullptr},
                {
                    "answer", {
                        {"everything", 42}
                    }
                },
                {"list", {1, 0, 2}},
                {
                    "object", {
                        {"currency", "USD"},
                        {"value", 42.99}
                    }
                }
            };
        }

        {
            // ways to express the empty array []
            json const empty_array_implicit = {{}};
            CHECK(empty_array_implicit.is_array());
            json const empty_array_explicit = json::array();
            CHECK(empty_array_explicit.is_array());

            // a way to express the empty object {}
            json const empty_object_explicit = json::object();
            CHECK(empty_object_explicit.is_object());

            // a way to express an _array_ of key/value pairs [["currency", "USD"], ["value", 42.99]]
            json array_not_object = json::array({ {"currency", "USD"}, {"value", 42.99} });
            CHECK(array_not_object.is_array());
            CHECK(array_not_object.size() == 2);
            CHECK(array_not_object[0].is_array());
            CHECK(array_not_object[1].is_array());
        }

        {
            // create object from string literal
            json const j = "{ \"happy\": true, \"pi\": 3.141 }"_json; // NOLINT(modernize-raw-string-literal)

            // or even nicer with a raw string literal
            auto j2 = R"({
                "happy": true,
                "pi": 3.141
            })"_json;

            // or explicitly
            auto j3 = json::parse(R"({"happy": true, "pi": 3.141})");

            // explicit conversion to string
            std::string const s = j.dump();     // NOLINT(bugprone-unused-local-non-trivial-variable) // {\"happy\":true,\"pi\":3.141}

            // serialization with pretty printing
            // pass in the amount of spaces to indent
            std::cout << j.dump(4) << std::endl; // NOLINT(performance-avoid-endl)
            // {
            //     "happy": true,
            //     "pi": 3.141
            // }

            std::cout << std::setw(2) << j << std::endl; // NOLINT(performance-avoid-endl)
        }

        {
            // create an array using push_back
            json j;
            j.push_back("foo");
            j.push_back(1);
            j.push_back(true);

            // comparison
            bool x = (j == R"(["foo", 1, true])"_json);  // true
            CHECK(x == true);

            // iterate the array
            for (json::iterator it = j.begin(); it != j.end(); ++it) // NOLINT(modernize-loop-convert)
            {
                std::cout << *it << '\n';
            }

            // range-based for
            for (auto& element : j)
            {
                std::cout << element << '\n';
            }

            // getter/setter
            const auto tmp = j[0].get<std::string>(); // NOLINT(bugprone-unused-local-non-trivial-variable)
            j[1] = 42;
            bool foo{j.at(2)};
            CHECK(foo == true);

            // other stuff
            CHECK(j.size() == 3);                     // 3 entries
            CHECK_FALSE(j.empty());                   // false
            CHECK(j.type() == json::value_t::array);  // json::value_t::array
            j.clear();                                // the array is empty again

            // create an object
            json o;
            o["foo"] = 23;
            o["bar"] = false;
            o["baz"] = 3.141;

            // find an entry
            CHECK(o.find("foo") != o.end());
            if (o.find("foo") != o.end()) // NOLINT(readability-container-contains)
            {
                // there is an entry with key "foo"
            }
        }

        {
            std::vector<int> const c_vector {1, 2, 3, 4};
            json const j_vec(c_vector);
            // [1, 2, 3, 4]

            std::deque<float> const c_deque {1.2f, 2.3f, 3.4f, 5.6f};
            json const j_deque(c_deque);
            // [1.2, 2.3, 3.4, 5.6]

            std::list<bool> const c_list {true, true, false, true};
            json const j_list(c_list);
            // [true, true, false, true]

            std::forward_list<int64_t> const c_flist {12345678909876, 23456789098765, 34567890987654, 45678909876543};
            json const j_flist(c_flist);
            // [12345678909876, 23456789098765, 34567890987654, 45678909876543]

            std::array<unsigned long, 4> const c_array {{1, 2, 3, 4}};
            json const j_array(c_array);
            // [1, 2, 3, 4]

            std::set<std::string> const c_set {"one", "two", "three", "four", "one"};
            json const j_set(c_set); // only one entry for "one" is used
            // ["four", "one", "three", "two"]

            std::unordered_set<std::string> const c_uset {"one", "two", "three", "four", "one"};
            json const j_uset(c_uset); // only one entry for "one" is used
            // maybe ["two", "three", "four", "one"]

            std::multiset<std::string> const c_mset {"one", "two", "one", "four"};
            json const j_mset(c_mset); // both entries for "one" are used
            // maybe ["one", "two", "one", "four"]

            std::unordered_multiset<std::string> const c_umset {"one", "two", "one", "four"};
            json const j_umset(c_umset); // both entries for "one" are used
            // maybe ["one", "two", "one", "four"]
        }

        {
            std::map<std::string, int> const c_map { {"one", 1}, {"two", 2}, {"three", 3} };
            json const j_map(c_map);
            // {"one": 1, "two": 2, "three": 3}

            std::unordered_map<const char*, float> const c_umap { {"one", 1.2f}, {"two", 2.3f}, {"three", 3.4f} };
            json const j_umap(c_umap);
            // {"one": 1.2, "two": 2.3, "three": 3.4}

            std::multimap<std::string, bool> const c_mmap { {"one", true}, {"two", true}, {"three", false}, {"three", true} };
            json const j_mmap(c_mmap); // only one entry for key "three" is used
            // maybe {"one": true, "two": true, "three": true}

            std::unordered_multimap<std::string, bool> const c_ummap { {"one", true}, {"two", true}, {"three", false}, {"three", true} };
            json const j_ummap(c_ummap); // only one entry for key "three" is used
            // maybe {"one": true, "two": true, "three": true}
        }

        {
            // strings
            std::string const s1 = "Hello, world!";
            json const js = s1;
            auto s2 = js.get<std::string>(); // NOLINT(bugprone-unused-local-non-trivial-variable)

            // Booleans
            bool const b1 = true;
            json const jb = b1;
            bool b2{jb};
            CHECK(b2 == true);

            // numbers
            int const i = 42;
            json const jn = i;
            double f{jn};
            CHECK(f == 42);

            // etc.

            std::string const vs = js.get<std::string>(); // NOLINT(bugprone-unused-local-non-trivial-variable)
            bool vb = jb.get<bool>();
            CHECK(vb == true);
            int vi = jn.get<int>();
            CHECK(vi == 42);

            // etc.
        }

        {
            // a JSON value
            json j_original = R"({
                "baz": ["one", "two", "three"],
                "foo": "bar"
            })"_json;

            // access members with a JSON pointer (RFC 6901)
            j_original["/baz/1"_json_pointer];
            // "two"

            // a JSON patch (RFC 6902)
            json const j_patch = R"([
                { "op": "replace", "path": "/baz", "value": "boo" },
                { "op": "add", "path": "/hello", "value": ["world"] },
                { "op": "remove", "path": "/foo"}
            ])"_json;

            // apply the patch
            json const j_result = j_original.patch(j_patch);
            // {
            //    "baz": "boo",
            //    "hello": ["world"]
            // }

            // calculate a JSON patch from two JSON values
            auto res = json::diff(j_result, j_original);
            // [
            //   { "op":" replace", "path": "/baz", "value": ["one", "two", "three"] },
            //   { "op":"remove","path":"/hello" },
            //   { "op":"add","path":"/foo","value":"bar" }
            // ]
        }

        // restore old std::cout
        std::cout.rdbuf(old_cout_buffer);
    }
}

DOCTEST_MSVC_SUPPRESS_WARNING_POP
