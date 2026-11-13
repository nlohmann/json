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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

// JSON_RECURSION_DEPTH_LIMIT changes only how much call stack the walks over a
// value use, never what they return. This file checks both: the macro is
// honoured (the number of levels the containers handle themselves is the limit)
// and every walk returns what it returns with the default limit. The expected
// results are built here, without the library, so that the same file passes for
// every limit; tests/CMakeLists.txt builds it with limits 0, 1, and 254 besides
// the default. Values are nested up to 300 levels (and past every limit, so that
// the explicit stack of every walk is exercised, even for the limit of 254) and
// are built and taken apart without recursion. Keep the depths moderate: walks
// like diff and dump with indentation are quadratic in the depth.

namespace
{
constexpr std::size_t limit()
{
    return nlohmann::detail::recursion_depth_limit();
}

// a value nested as @a kinds says, outermost level first: 'a' is an array of
// one element, 'o' an object with the single key "a"; @a leaf is innermost
json build(const std::string& kinds, json leaf)
{
    json j = std::move(leaf);
    for (std::size_t i = kinds.size(); i-- > 0;)
    {
        if (kinds[i] == 'a')
        {
            json a = json::array();
            a.push_back(std::move(j));
            j = std::move(a);
        }
        else
        {
            json o = json::object();
            o["a"] = std::move(j);
            j = std::move(o);
        }
    }
    return j;
}

std::string repeat(const std::string& s, std::size_t n)
{
    std::string result;
    for (std::size_t i = 0; i < n; ++i)
    {
        result += s;
    }
    return result;
}

// the nesting of the given shape and depth: arrays, objects, or both alternating
std::string make_kinds(char shape, std::size_t depth)
{
    std::string kinds;
    for (std::size_t i = 0; i < depth; ++i)
    {
        if (shape == 'm')
        {
            kinds += i % 2 == 0 ? 'a' : 'o';
        }
        else
        {
            kinds += shape;
        }
    }
    return kinds;
}

std::string expected_compact(const std::string& kinds, const std::string& leaf)
{
    std::string s;
    for (const char kind : kinds)
    {
        s += kind == 'a' ? "[" : "{\"a\":";
    }
    s += leaf;
    for (std::size_t i = kinds.size(); i-- > 0;)
    {
        s += kinds[i] == 'a' ? "]" : "}";
    }
    return s;
}

// dump(1)
std::string expected_indented(const std::string& kinds, const std::string& leaf)
{
    std::string s;
    for (std::size_t i = 0; i < kinds.size(); ++i)
    {
        s += kinds[i] == 'a' ? "[\n" : "{\n";
        s += std::string(i + 1, ' ');
        if (kinds[i] == 'o')
        {
            s += "\"a\": ";
        }
    }
    s += leaf;
    for (std::size_t i = kinds.size(); i-- > 0;)
    {
        s += "\n" + std::string(i, ' ') + (kinds[i] == 'a' ? "]" : "}");
    }
    return s;
}

// the JSON pointer to the innermost value
std::string pointer(const std::string& kinds)
{
    std::string s;
    for (const char kind : kinds)
    {
        s += kind == 'a' ? "/0" : "/a";
    }
    return s;
}

// the binary formats: the bytes that open and close a level, and the leaf 1
std::vector<std::uint8_t> expected_cbor(const std::string& kinds)
{
    std::vector<std::uint8_t> bytes;
    for (const char kind : kinds)
    {
        if (kind == 'a')
        {
            bytes.push_back(0x81);
        }
        else
        {
            bytes.push_back(0xA1);
            bytes.push_back(0x61);
            bytes.push_back('a');
        }
    }
    bytes.push_back(0x01);
    return bytes;
}

std::vector<std::uint8_t> expected_msgpack(const std::string& kinds)
{
    std::vector<std::uint8_t> bytes;
    for (const char kind : kinds)
    {
        if (kind == 'a')
        {
            bytes.push_back(0x91);
        }
        else
        {
            bytes.push_back(0x81);
            bytes.push_back(0xA1);
            bytes.push_back('a');
        }
    }
    bytes.push_back(0x01);
    return bytes;
}

std::vector<std::uint8_t> expected_ubjson(const std::string& kinds)
{
    std::vector<std::uint8_t> bytes;
    for (const char kind : kinds)
    {
        if (kind == 'a')
        {
            bytes.push_back('[');
        }
        else
        {
            bytes.push_back('{');
            bytes.push_back('i');
            bytes.push_back(1);
            bytes.push_back('a');
        }
    }
    bytes.push_back('i');
    bytes.push_back(1);
    for (std::size_t i = kinds.size(); i-- > 0;)
    {
        bytes.push_back(kinds[i] == 'a' ? ']' : '}');
    }
    return bytes;
}

// the depths worth trying for the limit: either side of it, twice it (if that
// is not too deep to be quick), and a value nested well past all limits
std::vector<std::size_t> depths()
{
    std::vector<std::size_t> result;
    result.push_back(1);
    result.push_back(2);
    result.push_back(limit() > 0 ? limit() - 1 : 3);
    result.push_back(limit());
    result.push_back(limit() + 1);
    if ((2 * limit()) + 5 <= 300)
    {
        result.push_back((2 * limit()) + 5);
    }
    result.push_back(300);
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    result.erase(std::remove(result.begin(), result.end(), static_cast<std::size_t>(0)), result.end());
    return result;
}

// the call for every shape and depth
void for_each_value(const std::function<void(const std::string&)>& check)
{
    const std::string shapes = "aom";
    for (const char shape : shapes)
    {
        for (const std::size_t depth : depths())
        {
            CAPTURE(shape)
            CAPTURE(depth)
            check(make_kinds(shape, depth));
        }
    }
}

// An array type that counts how many of its copies are being made at once. A
// copy of a value copies one level at a time through the array type until the
// limit has been reached, so the peak is the number of levels that were copied
// with the call stack.
std::size_t copies_going_on = 0;
std::size_t copies_peak = 0;
std::size_t equal_going_on = 0;
std::size_t equal_peak = 0;

template<class T, class Allocator = std::allocator<T>>
class counting_vector : public std::vector<T, Allocator>
{
  public:
    counting_vector() = default;

    template<class InputIt>
    counting_vector(InputIt first, InputIt last) : std::vector<T, Allocator>(first, last) {}

    counting_vector(const counting_vector& other) : std::vector<T, Allocator>()
    {
        ++copies_going_on;
        copies_peak = (std::max)(copies_peak, copies_going_on);
        this->std::vector<T, Allocator>::operator=(static_cast<const std::vector<T, Allocator>&>(other));
        --copies_going_on;
    }

    counting_vector(counting_vector&&) = default;
    counting_vector& operator=(const counting_vector&) = default;
    counting_vector& operator=(counting_vector&&) = default;
    ~counting_vector() = default;

    friend bool operator==(const counting_vector& lhs, const counting_vector& rhs)
    {
        ++equal_going_on;
        equal_peak = (std::max)(equal_peak, equal_going_on);
        const bool result = static_cast<const std::vector<T, Allocator>&>(lhs) == static_cast<const std::vector<T, Allocator>&>(rhs);
        --equal_going_on;
        return result;
    }
};

using counting_json = json::with_array_t<counting_vector>;

// A base class whose copy constructor copies a whole value of the same
// specialization when it copies a marked element, as user code may do from a
// hook. That copy runs while the copy that it is part of is going on.
struct copy_hook // NOLINT(cppcoreguidelines-special-member-functions,hicpp-special-member-functions)
{
    int mark = 0;

    copy_hook() = default;
    copy_hook(const copy_hook& other);
    copy_hook(copy_hook&&) = default;
    copy_hook& operator=(const copy_hook&) = default;
    copy_hook& operator=(copy_hook&&) = default;
};

using hook_json = nlohmann::basic_json<std::map, counting_vector, std::string, bool, std::int64_t, std::uint64_t, double,
      std::allocator, nlohmann::adl_serializer, std::vector<std::uint8_t>, copy_hook>;

const hook_json* hook_copy_source = nullptr;
int hook_copies_going_on = 0;

copy_hook::copy_hook(const copy_hook& other) : mark(other.mark)
{
    // the value that is copied is marked, too: its copy copies it again, once
    if (other.mark == 1 && hook_copy_source != nullptr && hook_copies_going_on < 2)
    {
        ++hook_copies_going_on;
        const hook_json nested = *hook_copy_source; // NOLINT(performance-unnecessary-copy-initialization)
        static_cast<void>(nested);
        --hook_copies_going_on;
    }
}

// an array nested @a depth levels around the integer 1, which is marked if @a marked
hook_json hook_nested(std::size_t depth, bool marked)
{
    hook_json j = 1;
    if (marked)
    {
        static_cast<copy_hook&>(j).mark = 1;
    }
    for (std::size_t i = 0; i < depth; ++i)
    {
        hook_json a = hook_json::array();
        a.push_back(std::move(j));
        j = std::move(a);
    }
    return j;
}
} // namespace

// the macro is the limit, and is in the range the library supports
static_assert(nlohmann::detail::recursion_depth_limit() == static_cast<std::size_t>(JSON_RECURSION_DEPTH_LIMIT),
              "the library does not use JSON_RECURSION_DEPTH_LIMIT");
static_assert(nlohmann::detail::recursion_depth_limit() <= 254, "the nesting depth must fit in a byte");

// the macro must not be a character or bool: every character type is refused
static_assert(nlohmann::detail::recursion_depth_limit_is_char_or_bool<bool>::value, "bool is refused");
static_assert(nlohmann::detail::recursion_depth_limit_is_char_or_bool<char>::value, "char is refused");
static_assert(nlohmann::detail::recursion_depth_limit_is_char_or_bool<signed char>::value, "signed char is refused");
static_assert(nlohmann::detail::recursion_depth_limit_is_char_or_bool<unsigned char>::value, "unsigned char is refused");
static_assert(nlohmann::detail::recursion_depth_limit_is_char_or_bool<wchar_t>::value, "wchar_t is refused");
static_assert(nlohmann::detail::recursion_depth_limit_is_char_or_bool<char16_t>::value, "char16_t is refused");
static_assert(nlohmann::detail::recursion_depth_limit_is_char_or_bool<char32_t>::value, "char32_t is refused");
#if defined(__cpp_char8_t)
    static_assert(nlohmann::detail::recursion_depth_limit_is_char_or_bool<char8_t>::value, "char8_t is refused");
#endif
static_assert(!nlohmann::detail::recursion_depth_limit_is_char_or_bool<int>::value, "int is accepted");
static_assert(!nlohmann::detail::recursion_depth_limit_is_char_or_bool<unsigned long long>::value, "unsigned long long is accepted");

TEST_CASE("JSON_RECURSION_DEPTH_LIMIT is honoured")
{
    SECTION("copying and comparing stop descending at the limit")
    {
        // copy and compare a value nested deeper than the limit, with the array type that counts
        counting_json inner = 1;
        for (std::size_t i = 0; i < (2 * limit()) + 5; ++i)
        {
            counting_json a = counting_json::array();
            a.push_back(std::move(inner));
            inner = std::move(a);
        }

        copies_going_on = copies_peak = 0;
        const counting_json copy = inner;
        CHECK(copies_going_on == 0);

        equal_going_on = equal_peak = 0;
        CHECK((inner == copy));
        CHECK(equal_going_on == 0);

#ifdef JSON_NO_THREAD_LOCAL
        // without the counters of the levels, no level is descended into
        CHECK(copies_peak == 0);
        CHECK(equal_peak == 0);
#else
        // copying descends into as many levels as the limit says, and nothing further
        CHECK(copies_peak == limit());
        CHECK(equal_peak == limit());
#endif

        // a value that is not nested deeper than the limit is not cut short
        const std::size_t shallow = limit() > 0 ? limit() : 1;
        counting_json small = 1;
        for (std::size_t i = 0; i < shallow; ++i)
        {
            counting_json a = counting_json::array();
            a.push_back(std::move(small));
            small = std::move(a);
        }
        copies_going_on = copies_peak = 0;
        const counting_json small_copy = small;
        CHECK(copies_going_on == 0);
#ifndef JSON_NO_THREAD_LOCAL
        CHECK(copies_peak == limit());
#endif
        CHECK(small_copy.dump() == expected_compact(make_kinds('a', shallow), "1"));
    }
}

TEST_CASE("a copy made while a copy is going on is bounded, too")
{
    // The innermost element of the value is marked, and copying it (which happens
    // after limit() levels have been entered, when the copy continues without the
    // call stack) copies the value again, and that copy once more. Those copies
    // must not be given limit() levels of their own: the count of the levels entered
    // never exceeds the limit, not even by one, which for the largest limit would
    // wrap the byte that holds it around to 0.
    const hook_json marked = hook_nested((2 * limit()) + 5, true);
    hook_copy_source = &marked;

    copies_going_on = copies_peak = 0;
    const hook_json copy = marked; // NOLINT(performance-unnecessary-copy-initialization)
    hook_copy_source = nullptr;
    CHECK(copies_going_on == 0);
    CHECK(static_cast<const copy_hook&>(copy).mark == 0); // (the top level is not marked)

#ifdef JSON_NO_THREAD_LOCAL
    CHECK(copies_peak == 0);
#else
    CHECK(copies_peak == limit());
#endif
}

TEST_CASE("walks over values nested around the recursion depth limit")
{
    SECTION("copying and comparing")
    {
        for_each_value([](const std::string & kinds)
        {
            const json a = build(kinds, 1);
            const json b = a; // NOLINT(performance-unnecessary-copy-initialization)
            CHECK((a == b));
            CHECK_FALSE((a != b));
            CHECK_FALSE((a < b));
            CHECK((a <= b));
            CHECK((a >= b));
            CHECK_FALSE((a > b));

            json assigned;
            assigned = a;
            CHECK((assigned == a));

            // differing only in the innermost value
            const json c = build(kinds, 2);
            CHECK((a != c));
            CHECK((a < c));
            CHECK((c > a));
            CHECK_FALSE((c < a));
            CHECK_FALSE((a == c));

            // a same-shape array or object that is one level shallower
            const json shallower = build(kinds.substr(1), 1);
            CHECK((shallower != a));
            const json outer = build(kinds.substr(0, 1), 1);
            CHECK((outer != a) == (kinds.size() > 1));

            const json moved = std::move(assigned);
            CHECK((moved == a));
        });
    }

    SECTION("serializing")
    {
        for_each_value([](const std::string & kinds)
        {
            const json a = build(kinds, 1);
            const std::string compact = expected_compact(kinds, "1");
            const std::string indented = expected_indented(kinds, "1");

            CHECK(a.dump() == compact);
            CHECK(a.dump(1) == indented);

            std::ostringstream compact_stream;
            compact_stream << a;
            CHECK(compact_stream.str() == compact);
            std::ostringstream indented_stream;
            indented_stream << std::setw(1) << a;
            CHECK(indented_stream.str() == indented);

            CHECK((json::parse(compact) == a));
            CHECK((json::parse(indented) == a));
        });
    }

    SECTION("hashing")
    {
        for_each_value([](const std::string & kinds)
        {
            const json a = build(kinds, 1);
            const std::hash<json> hash{};
            CHECK(hash(a) == hash(json(a)));
            CHECK(hash(a) == hash(json::parse(expected_compact(kinds, "1"))));
            CHECK(hash(a) != hash(build(kinds, 2)));
            CHECK(hash(a) != hash(build(kinds.substr(1), 1)));
        });
    }

    SECTION("diff and patch")
    {
        for_each_value([](const std::string & kinds)
        {
            const json a = build(kinds, 1);
            const json b = build(kinds, 2);

            const json difference = json::diff(a, b);
            CHECK(difference.dump() == "[{\"op\":\"replace\",\"path\":\"" + pointer(kinds) + "\",\"value\":2}]");
            CHECK((a.patch(difference) == b));
            CHECK((json::diff(a, a) == json::array()));
        });
    }

    SECTION("flatten and unflatten")
    {
        for_each_value([](const std::string & kinds)
        {
            const json a = build(kinds, 1);
            const json flat = a.flatten();
            CHECK(flat.dump() == "{\"" + pointer(kinds) + "\":1}");
            CHECK((flat.unflatten() == a));
        });
    }

    SECTION("merge_patch and update")
    {
        for (const std::size_t depth : depths())
        {
            CAPTURE(depth)
            const std::string kinds = make_kinds('o', depth);
            const std::string all_but_leaf = repeat("{\"a\":", depth - 1);

            // the patch removes the innermost member, or replaces it
            json target = build(kinds, 1);
            target.merge_patch(build(kinds, json(nullptr)));
            CHECK(target.dump() == all_but_leaf + "{}" + repeat("}", depth - 1));

            target = build(kinds, 1);
            target.merge_patch(build(kinds, 2));
            CHECK(target.dump() == expected_compact(kinds, "2"));

            // merging the objects of two values nested alike, and replacing the first level
            const json base = build(kinds.substr(1), json::parse("{\"x\":1}"));
            const json other = build(kinds.substr(1), json::parse("{\"y\":2}"));
            json merged = json{{"a", base}};
            merged.update(json{{"a", other}}, true);
            CHECK(merged.dump() == expected_compact(kinds, "{\"x\":1,\"y\":2}"));

            json replaced = json{{"a", base}};
            replaced.update(json{{"a", other}});
            CHECK(replaced.dump() == expected_compact(kinds, "{\"y\":2}"));

            // update from a range
            json from_range = json{{"a", base}};
            const json source = json{{"a", other}};
            from_range.update(source.begin(), source.end(), true);
            CHECK((from_range == merged));
        }
    }

    SECTION("binary formats")
    {
        for_each_value([](const std::string & kinds)
        {
            const json a = build(kinds, 1);

            const std::vector<std::uint8_t> cbor = json::to_cbor(a);
            CHECK(cbor == expected_cbor(kinds));
            CHECK((json::from_cbor(cbor) == a));

            const std::vector<std::uint8_t> msgpack = json::to_msgpack(a);
            CHECK(msgpack == expected_msgpack(kinds));
            CHECK((json::from_msgpack(msgpack) == a));

            const std::vector<std::uint8_t> ubjson = json::to_ubjson(a);
            CHECK(ubjson == expected_ubjson(kinds));
            CHECK((json::from_ubjson(ubjson) == a));

            CHECK((json::from_bjdata(json::to_bjdata(a)) == a));
            CHECK((json::from_bon8(json::to_bon8(a)) == a));

            // BSON documents are objects
            const json document = json{{"a", a}};
            CHECK((json::from_bson(json::to_bson(document)) == document));
        });
    }

    SECTION("conversion to another specialization")
    {
        for_each_value([](const std::string & kinds)
        {
            const json a = build(kinds, 1);
            const nlohmann::ordered_json ordered = a;
            CHECK(ordered.dump() == expected_compact(kinds, "1"));
            const json back = ordered;
            CHECK((back == a));
        });
    }

    SECTION("destroying")
    {
        for_each_value([](const std::string & kinds)
        {
            json a = build(kinds, 1);
            a = nullptr;
            CHECK(a.is_null());
        });
    }
}
