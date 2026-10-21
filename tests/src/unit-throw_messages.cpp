//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <string>

// The exceptions in hot core functions are constructed out of line. These tests pin the
// exact what() texts of the sites that moved, so the refactoring cannot change them.

#define CHECK_MSG(expr, msg) CHECK_THROWS_WITH(expr, msg)

TEST_CASE("exception messages of out-of-line throw sites")
{
    json arr = {1, 2, 3};
    json arr2 = {4, 5};
    json obj = {{"a", 1}, {"b", 2}};
    json obj2 = {{"c", 3}};
    json num = 1;

    SECTION("iterators")
    {
        CHECK_MSG((void)(arr.begin() == arr2.begin()), "[json.exception.invalid_iterator.212] cannot compare iterators of different containers");
        CHECK_MSG((void)(arr.begin() < arr2.begin()), "[json.exception.invalid_iterator.212] cannot compare iterators of different containers");
        CHECK_MSG((void)(obj.begin() < obj.end()), "[json.exception.invalid_iterator.213] cannot compare order of object iterators");
        CHECK_MSG(obj.begin() += 1, "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
        CHECK_MSG((void)(obj.begin() - 1), "[json.exception.invalid_iterator.209] cannot use offsets with object iterators");
        CHECK_MSG((void)obj.begin()[0], "[json.exception.invalid_iterator.208] cannot use operator[] for object iterators");
        CHECK_MSG((void)arr.begin().key(), "[json.exception.invalid_iterator.207] cannot use key() for non-object iterators");
        json null;
        CHECK_MSG((void)*null.end(), "[json.exception.invalid_iterator.214] cannot get value");
    }

    SECTION("constructors")
    {
        CHECK_MSG(json(arr.begin(), arr2.end()), "[json.exception.invalid_iterator.201] iterators are not compatible");
        CHECK_MSG(json(num.begin() + 1, num.end() + 1), "[json.exception.invalid_iterator.204] iterators out of range");
        CHECK_MSG(json(json::initializer_list_t{1, 2}, false, json::value_t::object), "[json.exception.type_error.301] cannot create object from initializer list");
    }

    SECTION("get_ref and operator[]")
    {
        CHECK_MSG((void)num.get_ref<std::string&>(), "[json.exception.type_error.303] incompatible ReferenceType for get_ref, actual type is number");
        CHECK_MSG((void)num[0], "[json.exception.type_error.305] cannot use operator[] with a numeric argument with number");
    }

    SECTION("at")
    {
        const json& carr = arr;
        const json& cobj = obj;
        CHECK_MSG((void)arr.at(static_cast<json::size_type>(10)), "[json.exception.out_of_range.401] array index 10 is out of range");
        CHECK_MSG((void)carr.at(static_cast<json::size_type>(3)), "[json.exception.out_of_range.401] array index 3 is out of range");
        CHECK_MSG((void)num.at(static_cast<json::size_type>(0)), "[json.exception.type_error.304] cannot use at() with number");
        CHECK_MSG((void)obj.at("z"), "[json.exception.out_of_range.403] key 'z' not found");
        CHECK_MSG((void)cobj.at("z"), "[json.exception.out_of_range.403] key 'z' not found");
        CHECK_MSG((void)obj.at(std::string("zz")), "[json.exception.out_of_range.403] key 'zz' not found");
        CHECK_MSG((void)num.at("a"), "[json.exception.type_error.304] cannot use at() with number");

        nlohmann::ordered_json oobj = {{"a", 1}};
        const nlohmann::ordered_json& coobj = oobj;
        CHECK_MSG((void)oobj.at("z"), "[json.exception.out_of_range.403] key 'z' not found");
        CHECK_MSG((void)coobj.at("z"), "[json.exception.out_of_range.403] key 'z' not found");
        CHECK_MSG((void)coobj.at(std::string("zz")), "[json.exception.out_of_range.403] key 'zz' not found");
    }

    SECTION("erase")
    {
        CHECK_MSG(arr.erase(arr2.begin()), "[json.exception.invalid_iterator.202] iterator does not fit current value");
        CHECK_MSG(num.erase(num.end()), "[json.exception.invalid_iterator.205] iterator out of range");
        CHECK_MSG(arr.erase(arr.begin(), arr2.end()), "[json.exception.invalid_iterator.203] iterators do not fit current value");
        CHECK_MSG(num.erase(num.begin() + 1, num.end()), "[json.exception.invalid_iterator.204] iterators out of range");
        CHECK_MSG(arr.erase(static_cast<json::size_type>(10)), "[json.exception.out_of_range.401] array index 10 is out of range");
    }

    SECTION("insert")
    {
        CHECK_MSG(arr.insert(arr2.begin(), 1), "[json.exception.invalid_iterator.202] iterator does not fit current value");
        CHECK_MSG(arr.insert(arr2.begin(), 2, 1), "[json.exception.invalid_iterator.202] iterator does not fit current value");
        CHECK_MSG(arr.insert(arr2.begin(), arr2.begin(), arr2.end()), "[json.exception.invalid_iterator.202] iterator does not fit current value");
        CHECK_MSG(arr.insert(arr.begin(), arr.begin(), arr2.end()), "[json.exception.invalid_iterator.210] iterators do not fit");
        CHECK_MSG(arr.insert(arr.begin(), arr.begin(), arr.end()), "[json.exception.invalid_iterator.211] passed iterators may not belong to container");
        CHECK_MSG(arr.insert(arr.begin(), obj.begin(), obj.end()), "[json.exception.invalid_iterator.202] iterators first and last must point to arrays");
        CHECK_MSG(arr.insert(arr2.begin(), {1, 2}), "[json.exception.invalid_iterator.202] iterator does not fit current value");
        CHECK_MSG(obj.insert(obj2.begin(), arr.end()), "[json.exception.invalid_iterator.210] iterators do not fit");
        CHECK_MSG(obj.insert(arr.begin(), arr.end()), "[json.exception.invalid_iterator.202] iterators first and last must point to objects");
        CHECK_MSG(obj.update(arr.begin(), arr2.end()), "[json.exception.invalid_iterator.210] iterators do not fit");
    }

#if !defined(JSON_NOEXCEPTION) // patch_msg() catches the exceptions, which JSON_NOEXCEPTION turns into std::abort()
    SECTION("patch")
    {
        const auto patch_msg = [](const char* doc, const char* patch) -> std::string
        {
            try
            {
                json d = json::parse(doc);
                d.patch(json::parse(patch));
            }
            catch (const json::exception& e)
            {
                // with JSON_DIAGNOSTICS, what() names the offending value like "(/0) ",
                // and with JSON_DIAGNOSTIC_POSITIONS its position like "(bytes 0-2) "; drop both
                std::string msg = e.what();
                for (const char* marker :
            {
                " (/", " (bytes "
            })
                {
                    const auto pos = msg.find(marker);
                    if (pos != std::string::npos)
                    {
                        msg.erase(pos + 1, msg.find(") ", pos) - pos + 1);
                    }
                }
                return msg;
            }
            return {};
        };

        CHECK(patch_msg("{}", "{}") == "[json.exception.parse_error.104] parse error: JSON patch must be an array of objects");
        CHECK(patch_msg("{}", "[1]") == "[json.exception.parse_error.104] parse error: JSON patch must be an array of objects");
        CHECK(patch_msg("{}", "[{}]") == "[json.exception.parse_error.105] parse error: operation must have member 'op'");
        CHECK(patch_msg("{}", "[{\"op\":1}]") == "[json.exception.parse_error.105] parse error: operation must have string member 'op'");
        CHECK(patch_msg("{}", "[{\"op\":\"add\"}]") == "[json.exception.parse_error.105] parse error: operation 'add' must have member 'path'");
        CHECK(patch_msg("{}", "[{\"op\":\"add\",\"path\":1}]") == "[json.exception.parse_error.105] parse error: operation 'add' must have string member 'path'");
        CHECK(patch_msg("{}", "[{\"op\":\"foo\",\"path\":\"\"}]") == "[json.exception.parse_error.105] parse error: operation value 'foo' is invalid");
        CHECK(patch_msg("{\"a\":1}", "[{\"op\":\"remove\",\"path\":\"/b\"}]") == "[json.exception.out_of_range.403] key 'b' not found");
        CHECK(patch_msg("[1]", "[{\"op\":\"add\",\"path\":\"/5\",\"value\":0}]") == "[json.exception.out_of_range.401] array index 5 is out of range");
        CHECK(patch_msg("{\"a\":1}", "[{\"op\":\"add\",\"path\":\"/a/b\",\"value\":0}]") == "[json.exception.out_of_range.411] cannot add value: the JSON Patch 'add' target's parent is of type number, but must be an object or array");
        CHECK(patch_msg("{\"a\":1}", "[{\"op\":\"remove\",\"path\":\"/a/b\"}]") == "[json.exception.out_of_range.413] cannot remove value: the JSON Patch 'remove' target's parent is of type number, but must be an object or array");
        CHECK(patch_msg("{\"a\":{}}", "[{\"op\":\"move\",\"from\":\"/a\",\"path\":\"/a/b\"}]") == "[json.exception.out_of_range.414] cannot move value: 'from' path '/a' is a proper prefix of 'path' '/a/b'");
        CHECK(patch_msg("{\"a\":1}", "[{\"op\":\"test\",\"path\":\"/a\",\"value\":2}]") == "[json.exception.other_error.501] unsuccessful: {\"op\":\"test\",\"path\":\"/a\",\"value\":2}");
        CHECK(patch_msg("{\"a\":1}", "[{\"op\":\"move\",\"path\":\"/a\"}]") == "[json.exception.parse_error.105] parse error: operation 'move' must have member 'from'");
    }
#endif
}
