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
#include <string>
#include <utility>
#include <vector>

TEST_CASE("tests on very large JSONs")
{
    SECTION("issue #1419 - Segmentation fault (stack overflow) due to unbounded recursion")
    {
        const auto depth = 500000;

        std::string s(static_cast<std::size_t>(2 * depth), '[');
        std::fill(s.begin() + depth, s.end(), ']');

        json _;
        CHECK_NOTHROW(_ = nlohmann::json::parse(s));
    }
}

namespace
{

// Descend a chain of single-element containers and return the value at its end,
// reporting the number of levels traversed in @a depth.
//
// The values in the test case below are nested far deeper than the call stack
// can follow, so they must not be inspected with operator== or dump(): both are
// still recursive and would overflow the stack themselves.
const json* innermost_value(const json& j, std::size_t& depth)
{
    const json* current = &j;
    depth = 0;

    while ((current->is_array() || current->is_object()) && !current->empty())
    {
        current = current->is_array()
                  ? &current->front()
                  : &current->begin().value();
        ++depth;
    }

    return current;
}

// The text of a value nested depth levels deep around the number 0. Level i is
// an array if pattern[i % pattern.size()] is '[', and otherwise an object with
// the single member "a", which every object type enumerates in the same order.
std::string nested_text(std::size_t depth, const std::string& pattern)
{
    std::string text;
    std::string closing;
    for (std::size_t i = 0; i < depth; ++i)
    {
        const bool array = pattern[i % pattern.size()] == '[';
        text += array ? "[" : "{\"a\":";
        closing += array ? ']' : '}';
    }
    text += '0';
    text.append(closing.rbegin(), closing.rend());
    return text;
}

} // namespace

TEST_CASE("tests on deeply nested JSONs")
{
    // deep enough to exhaust the call stack, but small enough to stay cheap:
    // parsing is iterative, so building the values below costs little
    const std::size_t depth = 100000;

    SECTION("issue #5387 - stack overflow in the copy constructor")
    {
        SECTION("array")
        {
            const json j = json::parse(std::string(depth, '[') + '0' + std::string(depth, ']'));

            const json copy(j); // NOLINT(performance-unnecessary-copy-initialization): the copy is what is tested

            std::size_t copy_depth = 0;
            CHECK(*innermost_value(copy, copy_depth) == 0);
            CHECK(copy_depth == depth);
        }

        SECTION("object")
        {
            std::string s;
            s.reserve((6 * depth) + 1);
            for (std::size_t i = 0; i < depth; ++i)
            {
                s += "{\"a\":";
            }
            s += '1';
            s.append(depth, '}');

            const json j = json::parse(s);

            const json copy(j); // NOLINT(performance-unnecessary-copy-initialization): the copy is what is tested

            std::size_t copy_depth = 0;
            CHECK(*innermost_value(copy, copy_depth) == 1);
            CHECK(copy_depth == depth);
        }

        SECTION("copy assignment")
        {
            // operator=(basic_json) takes its argument by value, so the deep
            // copy happens in the copy constructor
            const json j = json::parse(std::string(depth, '[') + '0' + std::string(depth, ']'));

            json target;
            target = j;

            std::size_t target_depth = 0;
            CHECK(*innermost_value(target, target_depth) == 0);
            CHECK(target_depth == depth);
        }

        SECTION("depths around the bound of the recursive descent")
        {
            // The copy constructor descends into a bounded number of levels and
            // completes whatever is below that without the call stack. Cover
            // every depth around that bound, so that the two ways of copying
            // are known to meet cleanly - wherever the bound is set.
            for (std::size_t d = 1; d <= 300; ++d)
            {
                CAPTURE(d)

                const json array = json::parse(std::string(d, '[') + '0' + std::string(d, ']'));
                const json array_copy(array); // NOLINT(performance-unnecessary-copy-initialization): the copy is what is tested
                std::size_t array_depth = 0;
                CHECK(*innermost_value(array_copy, array_depth) == 0);
                CHECK(array_depth == d);

                std::string object_text;
                for (std::size_t i = 0; i < d; ++i)
                {
                    object_text += "{\"a\":";
                }
                object_text += '1';
                object_text.append(d, '}');

                const json object = json::parse(object_text);
                const json object_copy(object); // NOLINT(performance-unnecessary-copy-initialization): the copy is what is tested
                std::size_t object_depth = 0;
                CHECK(*innermost_value(object_copy, object_depth) == 1);
                CHECK(object_depth == d);
            }
        }

        SECTION("a value that is deep in one place only")
        {
            json j = json::object();
            j["shallow"] = 1;
            j["deep"] = json::parse(std::string(depth, '[') + '0' + std::string(depth, ']'));
            j["also_shallow"] = json::array({1, 2, 3});

            const json copy(j);

            CHECK(copy["shallow"] == 1);
            CHECK(copy["also_shallow"] == json::array({1, 2, 3}));

            std::size_t deep_depth = 0;
            CHECK(*innermost_value(copy["deep"], deep_depth) == 0);
            CHECK(deep_depth == depth);
        }

        SECTION("comparing")
        {
            // Comparing used to descend once per level, and an ordered
            // comparison used to compare every pair of elements twice, once in
            // each direction, which took exponentially long in the nesting
            // depth. Both are gone: these finish in milliseconds, where the
            // second used to take longer than anyone would wait even for a
            // value nested only a few dozen levels deep.
            const std::string text = std::string(depth, '[') + '0' + std::string(depth, ']');
            const json j = json::parse(text);
            const json same = json::parse(text);
            const json larger = json::parse(std::string(depth, '[') + '1' + std::string(depth, ']'));

            CHECK(j == same);
            CHECK_FALSE(j == larger);
            CHECK(j != larger);

            CHECK(j < larger);
            CHECK_FALSE(larger < j);
            CHECK(larger > j);
            CHECK(j <= same);
            CHECK(j >= same);

            // a value that ends earlier is the smaller one
            const json shorter = json::parse(std::string(depth - 1, '[') + '0' + std::string(depth - 1, ']'));
            CHECK_FALSE(j == shorter);
        }

        SECTION("comparing objects")
        {
            std::string text;
            text.reserve((6 * depth) + 1);
            for (std::size_t i = 0; i < depth; ++i)
            {
                text += "{\"a\":";
            }
            text += '1';
            text.append(depth, '}');

            const json j = json::parse(text);
            const json same = json::parse(text);

            CHECK(j == same);
            CHECK_FALSE(j != same);
            CHECK(j <= same);
            CHECK(j >= same);
        }

        SECTION("the copy is independent of the original")
        {
            const json j = json::parse(std::string(depth, '[') + '0' + std::string(depth, ']'));

            json copy(j);

            // reach the innermost value without recursing and replace it
            json* current = &copy;
            while (current->is_array() && !current->empty())
            {
                current = &current->front();
            }
            *current = 42;

            std::size_t unused = 0;
            CHECK(*innermost_value(copy, unused) == 42);
            CHECK(*innermost_value(j, unused) == 0);
        }
    }

    SECTION("issue #5650 - stack overflow converting between specializations")
    {
        const std::vector<std::string> patterns = {"[", "{", "[{"};

        SECTION("json to ordered_json")
        {
            for (const auto& pattern : patterns)
            {
                CAPTURE(pattern)
                const std::string text = nested_text(depth, pattern);
                const json j = json::parse(text);

                const nlohmann::ordered_json converted = j;
                CHECK(converted.dump() == text);
            }
        }

        SECTION("ordered_json to json")
        {
            for (const auto& pattern : patterns)
            {
                CAPTURE(pattern)
                const std::string text = nested_text(depth, pattern);
                const nlohmann::ordered_json o = nlohmann::ordered_json::parse(text);

                const json converted = o;
                CHECK(converted.dump() == text);
            }
        }

        SECTION("get<ordered_json>()")
        {
            for (const auto& pattern : patterns)
            {
                CAPTURE(pattern)
                const std::string text = nested_text(depth, pattern);
                const json j = json::parse(text);

                CHECK(j.get<nlohmann::ordered_json>().dump() == text);
            }
        }

        SECTION("depths around the bound of the recursive descent")
        {
            for (std::size_t d = 1; d <= 300; ++d)
            {
                CAPTURE(d)
                for (const auto& pattern : patterns)
                {
                    CAPTURE(pattern)
                    const std::string text = nested_text(d, pattern);
                    const json j = json::parse(text);

                    const nlohmann::ordered_json converted = j;
                    CHECK(converted.dump() == text);
                    const json back = converted;
                    CHECK(back.dump() == text);
                }
            }
        }

        SECTION("values below the bound are converted as values above it")
        {
            // Bury a value below the bound, where it is converted without the
            // call stack, and compare it with the same value converted on its
            // own by the containers' range constructors. Its objects have
            // members that the two object types enumerate in different orders.
            const auto bury = [](nlohmann::ordered_json value)
            {
                for (std::size_t i = 0; i < 200; ++i)
                {
                    value = nlohmann::ordered_json::array({std::move(value)});
                }
                return value;
            };
            const auto dig = [](const json & value)
            {
                const json* current = &value;
                for (std::size_t i = 0; i < 200; ++i)
                {
                    current = &current->at(0);
                }
                return current;
            };

            nlohmann::ordered_json value = nlohmann::ordered_json::object();
            value["z"] = {1, -2, 3U, 4.5, true, nullptr, "six", nlohmann::ordered_json::binary({7, 8}, 9),
                          nlohmann::ordered_json::binary({10}), nlohmann::ordered_json::array(), nlohmann::ordered_json::object()
                         };
            value["y"] = {{"x", {{"w", 1}, {"v", 2}}}, {"u", {3, {{"t", 4}, {"s", 5}}}}};
            value["r"] = nlohmann::ordered_json::array({nlohmann::ordered_json(nlohmann::ordered_json::value_t::discarded)});

            const json converted_above = value;
            const json buried = bury(value);
            const json& converted_below = *dig(buried);

            CHECK(converted_below.dump() == converted_above.dump());
            CHECK(converted_below.at("z").at(7).get_binary().subtype() == 9);
            CHECK_FALSE(converted_below.at("z").at(8).get_binary().has_subtype());
            CHECK(converted_below.at("r").at(0).is_discarded());

            // a discarded value is never equal to anything, so compare the rest
            value.erase("r");
            const json without_discarded_above = value;
            const json without_discarded_buried = bury(value);
            CHECK(*dig(without_discarded_buried) == without_discarded_above);
        }
    }
}

namespace
{
json nested_array(const std::size_t depth, json leaf)
{
    json j = std::move(leaf);
    for (std::size_t i = 0; i < depth; ++i)
    {
        json a = json::array();
        a.push_back(std::move(j));
        j = std::move(a);
    }
    return j;
}

json nested_object(const std::size_t depth, json leaf)
{
    json j = std::move(leaf);
    for (std::size_t i = 0; i < depth; ++i)
    {
        json o = json::object();
        o["k"] = std::move(j);
        j = std::move(o);
    }
    return j;
}
} // namespace

TEST_CASE("issue #5392 - binary writers on deeply nested values")
{
    // 200 is past the point where the writers stop recursing, and still
    // shallow enough that from_* and operator== (which still recurse) are fine.
    const json deep_array = nested_array(200, json(0));
    const json deep_object = nested_object(200, json("x"));
    const json empty_array = nested_array(200, json::array());
    const json empty_object = nested_object(200, json::object());
    const json mixed = nested_object(80, nested_array(80, json(true)));

    SECTION("roundtrip past the recursion bound")
    {
        CHECK(json::from_cbor(json::to_cbor(deep_array)) == deep_array);
        CHECK(json::from_msgpack(json::to_msgpack(deep_array)) == deep_array);
        CHECK(json::from_ubjson(json::to_ubjson(deep_array)) == deep_array);
        CHECK(json::from_ubjson(json::to_ubjson(deep_array, true, false)) == deep_array);
        CHECK(json::from_ubjson(json::to_ubjson(deep_array, true, true)) == deep_array);
        CHECK(json::from_bjdata(json::to_bjdata(deep_array)) == deep_array);

        CHECK(json::from_cbor(json::to_cbor(deep_object)) == deep_object);
        CHECK(json::from_msgpack(json::to_msgpack(deep_object)) == deep_object);
        CHECK(json::from_ubjson(json::to_ubjson(deep_object)) == deep_object);
        CHECK(json::from_ubjson(json::to_ubjson(deep_object, true, true)) == deep_object);
        CHECK(json::from_bjdata(json::to_bjdata(deep_object)) == deep_object);

        CHECK(json::from_cbor(json::to_cbor(empty_array)) == empty_array);
        CHECK(json::from_msgpack(json::to_msgpack(empty_array)) == empty_array);
        CHECK(json::from_ubjson(json::to_ubjson(empty_array)) == empty_array);
        CHECK(json::from_ubjson(json::to_ubjson(empty_array, true, true)) == empty_array);

        CHECK(json::from_cbor(json::to_cbor(empty_object)) == empty_object);
        CHECK(json::from_msgpack(json::to_msgpack(empty_object)) == empty_object);
        CHECK(json::from_ubjson(json::to_ubjson(empty_object)) == empty_object);

        CHECK(json::from_cbor(json::to_cbor(mixed)) == mixed);
        CHECK(json::from_msgpack(json::to_msgpack(mixed)) == mixed);
        CHECK(json::from_ubjson(json::to_ubjson(mixed)) == mixed);
        CHECK(json::from_bjdata(json::to_bjdata(mixed)) == mixed);
    }

    SECTION("the two ways of writing a value meet at the bound")
    {
        for (std::size_t depth = 120; depth <= 140; ++depth)
        {
            CAPTURE(depth)

            const json array = nested_array(depth, json(7));
            CHECK(json::from_cbor(json::to_cbor(array)) == array);
            CHECK(json::from_msgpack(json::to_msgpack(array)) == array);
            CHECK(json::from_ubjson(json::to_ubjson(array, true, true)) == array);

            const json object = nested_object(depth, json(7));
            CHECK(json::from_cbor(json::to_cbor(object)) == object);
            CHECK(json::from_msgpack(json::to_msgpack(object)) == object);
            CHECK(json::from_bjdata(json::to_bjdata(object)) == object);
        }
    }

    SECTION("a BJData ndarray below the bound is still an ndarray")
    {
        const json ndarray = json({{"_ArrayType_", "uint8"}, {"_ArraySize_", {2, 3}}, {"_ArrayData_", {1, 2, 3, 4, 5, 6}}});
        const json invalid = json({{"_ArrayType_", "nope"}, {"_ArraySize_", {1}}, {"_ArrayData_", {1}}});

        const json deep_ndarray = nested_array(140, ndarray);
        const json deep_invalid = nested_array(140, invalid);

        CHECK(json::from_bjdata(json::to_bjdata(deep_ndarray)) == deep_ndarray);
        CHECK(json::from_bjdata(json::to_bjdata(deep_invalid)) == deep_invalid);
        CHECK(json::from_bjdata(json::to_bjdata(ndarray)) == ndarray);
    }

    SECTION("byte-exact across the switch-over")
    {
        // nested one-element arrays around the recursion bound: the exact
        // bytes a writer produces do not depend on whether it stayed on the
        // call stack or moved to the heap one partway through
        for (const std::size_t depth :
                {
                    nlohmann::detail::recursion_depth_limit() - 1, nlohmann::detail::recursion_depth_limit(),
                    nlohmann::detail::recursion_depth_limit() + 1, nlohmann::detail::recursion_depth_limit() + 2
                })
        {
            CAPTURE(depth)
            const json array = nested_array(depth, json(0));

            std::vector<std::uint8_t> expected_cbor(depth, 0x81);
            expected_cbor.push_back(0x00);
            CHECK(json::to_cbor(array) == expected_cbor);

            std::vector<std::uint8_t> expected_msgpack(depth, 0x91);
            expected_msgpack.push_back(0x00);
            CHECK(json::to_msgpack(array) == expected_msgpack);

            std::string expected_ubjson(depth, '[');
            expected_ubjson += "i";
            expected_ubjson += '\0';
            expected_ubjson.append(depth, ']');
            const auto packed_ubjson = json::to_ubjson(array);
            CHECK(std::string(packed_ubjson.begin(), packed_ubjson.end()) == expected_ubjson);
        }
    }

    SECTION("a deep object, and a BJData ndarray, past the recursion bound")
    {
        const std::size_t depth = nlohmann::detail::recursion_depth_limit() + 50;

        const json object = nested_object(depth, json(42));
        CHECK(json::from_cbor(json::to_cbor(object)) == object);
        CHECK(json::from_msgpack(json::to_msgpack(object)) == object);
        CHECK(json::from_ubjson(json::to_ubjson(object, true, true)) == object);
        CHECK(json::from_bjdata(json::to_bjdata(object)) == object);

        const json ndarray = json({{"_ArrayType_", "uint8"}, {"_ArraySize_", {2, 3}}, {"_ArrayData_", {1, 2, 3, 4, 5, 6}}});
        const json deep_ndarray = nested_array(depth, ndarray);
        CHECK(json::from_bjdata(json::to_bjdata(deep_ndarray)) == deep_ndarray);
    }

    SECTION("a discarded value past the recursion bound still throws type_error.321")
    {
        const std::size_t depth = nlohmann::detail::recursion_depth_limit() + 50;
        const json discarded_leaf(json::value_t::discarded);
        const json deep_discarded = nested_array(depth, discarded_leaf);

        // with diagnostics, the message names the path to the discarded leaf
        std::string prefix = "[json.exception.type_error.321] ";
#if JSON_DIAGNOSTICS
        prefix += '(';
        for (std::size_t i = 0; i < depth; ++i)
        {
            prefix += "/0";
        }
        prefix += ") ";
#endif

        CHECK_THROWS_WITH_AS(json::to_cbor(deep_discarded), (prefix + "cannot serialize discarded value to CBOR").c_str(), json::type_error);
        CHECK_THROWS_WITH_AS(json::to_msgpack(deep_discarded), (prefix + "cannot serialize discarded value to MessagePack").c_str(), json::type_error);
        CHECK_THROWS_WITH_AS(json::to_ubjson(deep_discarded), (prefix + "cannot serialize discarded value to UBJSON").c_str(), json::type_error);
        CHECK_THROWS_WITH_AS(json::to_bjdata(deep_discarded), (prefix + "cannot serialize discarded value to BJData").c_str(), json::type_error);
    }

    SECTION("does not overflow the C++ stack")
    {
        const std::size_t depth = 100000;
        const json j = json::parse(std::string(depth, '[') + "0" + std::string(depth, ']'));

        std::vector<std::uint8_t> packed;
        CHECK_NOTHROW(packed = json::to_cbor(j));
        CHECK(json::from_cbor(packed) == j);

        CHECK_NOTHROW(packed = json::to_msgpack(j));
        CHECK(json::from_msgpack(packed) == j);

        CHECK_NOTHROW(packed = json::to_ubjson(j));
        CHECK(json::from_ubjson(packed) == j);

        CHECK_NOTHROW(packed = json::to_ubjson(j, true, false));
        CHECK(json::from_ubjson(packed) == j);

        CHECK_NOTHROW(packed = json::to_bjdata(j));
        CHECK(json::from_bjdata(packed) == j);
    }

    SECTION("regression test for https://issues.oss-fuzz.com/issues/566583014")
    {
        // 200000 nested one-element CBOR arrays, the innermost holding null;
        // round-tripping this used to recurse once per level on the way back
        // out through to_cbor(), deep enough to overflow the stack
        std::vector<std::uint8_t> v(200000, 0x81);
        v.push_back(0xf6);
        const json j = json::from_cbor(v);
        CHECK(json::to_cbor(j) == v);

        // the MessagePack analogue: fixarray of 1 nesting down to nil
        std::vector<std::uint8_t> v_msgpack(200000, 0x91);
        v_msgpack.push_back(0xc0);
        const json j_msgpack = json::from_msgpack(v_msgpack);
        CHECK(json::to_msgpack(j_msgpack) == v_msgpack);
    }
}

