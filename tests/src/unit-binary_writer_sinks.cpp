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

#include <array>
#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

namespace
{

// a spread of values exercising every writer path: scalars of each width, the
// float paths, strings, binary, and containers big enough to reallocate
std::vector<json> test_values()
{
    json big_array = json::array();
    for (int i = 0; i < 5000; ++i)
    {
        big_array.push_back(i);
    }

    json big_object = json::object();
    for (int i = 0; i < 1000; ++i)
    {
        big_object[std::to_string(i)] = i;
    }

    // large strings and binary values between small ones: a write too large
    // for the space the vector sink has ahead takes a different path than a
    // small one, and the small writes after it must still land behind it
    json large_payloads = json::array();
    for (int i = 0; i < 50; ++i)
    {
        large_payloads.push_back(std::string(300, static_cast<char>('a' + (i % 26))));
        large_payloads.push_back(i);
        large_payloads.push_back(json::binary(std::vector<std::uint8_t>(static_cast<std::size_t>(100 * i), static_cast<std::uint8_t>(i))));
    }

    return
    {
        json(nullptr), json(true), json(false),
        json(0), json(-1), json(255), json(-129), json(65535), json(-32769),
        json(4294967295U), json(-2147483649LL), json(18446744073709551615ULL),
        json(0.0), json(-0.5), json(3.1415926535897932),
        json(""), json("hello"), json(std::string(1000, 'x')),
        json::binary({0x00, 0x01, 0x02}, 42),
        json::array(), json::object(),
        json::array({1, 2, 3}), json({{"a", 1}, {"b", nullptr}}),
        json({{"nested", {{"deep", json::array({1, "two", 3.0, nullptr})}}}}),
        big_array, big_object, large_payloads,
        json::binary(std::vector<std::uint8_t>(5000, 0x42))
    };
}

// explicit char -> uint8_t conversion (the iterator-range constructor converts implicitly, which -fsanitize=integer flags)
std::vector<std::uint8_t> to_bytes(const std::string& str)
{
    std::vector<std::uint8_t> result;
    result.reserve(str.size());
    for (const char c : str)
    {
        result.push_back(static_cast<std::uint8_t>(c));
    }
    return result;
}

// BON8 has no integers above the int64 range, so to_bon8() rejects them
bool bon8_representable(const json& j)
{
    return !j.is_number_unsigned() || j.get<std::uint64_t>() <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
}

// values to_bson() accepts: the document must be an object
std::vector<json> bson_values()
{
    json big_object = json::object();
    for (int i = 0; i < 1000; ++i)
    {
        big_object[std::to_string(i)] = i;
    }

    return
    {
        json::object(),
        json({{"a", 1}, {"b", nullptr}, {"c", true}, {"d", 2.5}, {"e", "text"}}),
        json({{"arr", json::array({1, 2, 3})}, {"obj", {{"k", "v"}}}}),
        big_object
    };
}

} // namespace

// The vector-returning to_*(j) overloads write through the non-virtual
// output_vector_sink, while to_*(j, adapter) goes through output_adapter_sink.
// The two are separate code paths that must stay byte-for-byte identical; these
// checks fail if either overload is ever changed without the other.
TEST_CASE("binary writer output sinks")
{
    SECTION("vector sink and adapter sink agree")
    {
        // note: no SUBCASE inside these loops - doctest keys subcases by
        // name/file/line, so a subcase in a loop body would only ever run for
        // the first iteration
        for (const auto& j : test_values())
        {
            CAPTURE(j.dump(-1, ' ', false, json::error_handler_t::replace))

            std::vector<std::uint8_t> cbor;
            json::to_cbor(j, cbor);
            CHECK(json::to_cbor(j) == cbor);

            std::vector<std::uint8_t> msgpack;
            json::to_msgpack(j, msgpack);
            CHECK(json::to_msgpack(j) == msgpack);

            if (bon8_representable(j))
            {
                std::vector<std::uint8_t> bon8;
                json::to_bon8(j, bon8);
                CHECK(json::to_bon8(j) == bon8);
            }

            for (const bool use_size :
                    {
                        false, true
                    })
            {
                for (const bool use_type :
                        {
                            false, true
                        })
                {
                    if (use_type && !use_size)
                    {
                        continue; // not a supported combination
                    }
                    CAPTURE(use_size)
                    CAPTURE(use_type)
                    std::vector<std::uint8_t> ubjson;
                    json::to_ubjson(j, ubjson, use_size, use_type);
                    CHECK(json::to_ubjson(j, use_size, use_type) == ubjson);
                }
            }

            for (const auto version :
                    {
                        json::bjdata_version_t::draft2, json::bjdata_version_t::draft3
                    })
            {
                std::vector<std::uint8_t> bjdata;
                json::to_bjdata(j, bjdata, false, false, version);
                CHECK(json::to_bjdata(j, false, false, version) == bjdata);
            }
        }

        for (const auto& j : bson_values())
        {
            CAPTURE(j.dump())
            std::vector<std::uint8_t> bson;
            json::to_bson(j, bson);
            CHECK(json::to_bson(j) == bson);
        }
    }

    SECTION("the char adapter produces the same bytes")
    {
        for (const auto& j : test_values())
        {
            CAPTURE(j.dump(-1, ' ', false, json::error_handler_t::replace))

            const std::vector<std::uint8_t> expected = json::to_cbor(j);
            std::vector<char> as_char;
            json::to_cbor(j, as_char);

            REQUIRE(as_char.size() == expected.size());
            std::vector<std::uint8_t> as_bytes;
            as_bytes.reserve(as_char.size());
            for (const char c : as_char)
            {
                as_bytes.push_back(static_cast<std::uint8_t>(c));
            }
            CHECK(as_bytes == expected);
        }
    }
}

namespace
{

// the CBOR head of an integer, encoded independently of binary_writer
void reference_cbor_head(std::vector<std::uint8_t>& out, const std::uint8_t major_type, const std::uint64_t argument)
{
    if (argument <= 23)
    {
        out.push_back(static_cast<std::uint8_t>(major_type + argument));
        return;
    }

    int length = 8;
    std::uint8_t additional = 27;
    if (argument <= 0xFF)
    {
        length = 1;
        additional = 24;
    }
    else if (argument <= 0xFFFF)
    {
        length = 2;
        additional = 25;
    }
    else if (argument <= 0xFFFFFFFF)
    {
        length = 4;
        additional = 26;
    }

    out.push_back(static_cast<std::uint8_t>(major_type + additional));
    for (int i = length - 1; i >= 0; --i)
    {
        out.push_back(static_cast<std::uint8_t>(argument >> (8 * i)));
    }
}

// the CBOR encoding of an integer value
void reference_cbor_integer(std::vector<std::uint8_t>& out, const json& j)
{
    if (j.is_number_unsigned())
    {
        reference_cbor_head(out, 0x00, j.get<std::uint64_t>());
        return;
    }

    const auto n = j.get<std::int64_t>();
    if (n >= 0)
    {
        reference_cbor_head(out, 0x00, static_cast<std::uint64_t>(n));
    }
    else
    {
        reference_cbor_head(out, 0x20, static_cast<std::uint64_t>(-1 - n));
    }
}

// the MessagePack encoding of an integer value, encoded independently of
// binary_writer
void reference_msgpack_integer(std::vector<std::uint8_t>& out, const json& j)
{
    const auto put = [&out](const std::uint8_t marker, const std::uint64_t bits, const int length)
    {
        out.push_back(marker);
        for (int i = length - 1; i >= 0; --i)
        {
            out.push_back(static_cast<std::uint8_t>(bits >> (8 * i)));
        }
    };

    if (j.is_number_unsigned() || j.get<std::int64_t>() >= 0)
    {
        const auto u = j.get<std::uint64_t>();
        if (u < 128)
        {
            out.push_back(static_cast<std::uint8_t>(u));
        }
        else if (u <= 0xFF)
        {
            put(0xCC, u, 1);
        }
        else if (u <= 0xFFFF)
        {
            put(0xCD, u, 2);
        }
        else if (u <= 0xFFFFFFFF)
        {
            put(0xCE, u, 4);
        }
        else
        {
            put(0xCF, u, 8);
        }
        return;
    }

    const auto n = j.get<std::int64_t>();
    const auto bits = static_cast<std::uint64_t>(n);
    if (n >= -32)
    {
        out.push_back(static_cast<std::uint8_t>(bits));
    }
    else if (n >= -128)
    {
        put(0xD0, bits, 1);
    }
    else if (n >= -32768)
    {
        put(0xD1, bits, 2);
    }
    else if (n >= -2147483648LL)
    {
        put(0xD2, bits, 4);
    }
    else
    {
        put(0xD3, bits, 8);
    }
}

// integers at every boundary of the CBOR and MessagePack sizes, signed and
// unsigned
std::vector<json> boundary_integers()
{
    std::vector<json> result;
    const std::array<std::uint64_t, 38> boundaries =
    {
        {
            0, 1, 22, 23, 24, 25, 31, 32, 33, 126, 127, 128, 129, 254, 255, 256, 257,
            32766, 32767, 32768, 32769, 65534, 65535, 65536, 65537,
            2147483646ULL, 2147483647ULL, 2147483648ULL, 2147483649ULL,
            4294967294ULL, 4294967295ULL, 4294967296ULL, 4294967297ULL,
            9223372036854775806ULL, 9223372036854775807ULL, 9223372036854775808ULL,
            18446744073709551614ULL, 18446744073709551615ULL
        }
    };
    for (const std::uint64_t u : boundaries)
    {
        result.emplace_back(u);
        if (u <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
        {
            const auto n = static_cast<std::int64_t>(u);
            result.emplace_back(n);
            result.emplace_back(-n);
            result.emplace_back(-n - 1);
        }
    }
    return result;
}

} // namespace

// Arrays of integers are written in runs straight into space reserved from the
// sink, with branch-free encodings; check them against independent encoders for
// runs shorter and longer than one reservation, broken up by other values, and
// through each sink.
TEST_CASE("CBOR and MessagePack integer arrays")
{
    const std::vector<json> integers = boundary_integers();

    for (const std::size_t length :
            {
                std::size_t{1}, std::size_t{27}, std::size_t{28}, std::size_t{29}, std::size_t{57}, std::size_t{1000}
            })
    {
        for (const std::size_t break_every :
                {
                    std::size_t{0}, std::size_t{1}, std::size_t{7}, std::size_t{28}
                })
        {
            CAPTURE(length)
            CAPTURE(break_every)

            json array = json::array();
            std::vector<std::uint8_t> expected_cbor;
            std::vector<std::uint8_t> expected_msgpack;
            for (std::size_t i = 0; i < length; ++i)
            {
                if (break_every != 0 && i % (break_every + 1) == break_every)
                {
                    array.push_back("x");
                    expected_cbor.push_back(0x61);
                    expected_cbor.push_back('x');
                    expected_msgpack.push_back(0xA1);
                    expected_msgpack.push_back('x');
                }
                else
                {
                    const json& value = integers[(i * 7) % integers.size()];
                    array.push_back(value);
                    reference_cbor_integer(expected_cbor, value);
                    reference_msgpack_integer(expected_msgpack, value);
                }
            }

            std::vector<std::uint8_t> head;
            reference_cbor_head(head, 0x80, length);
            expected_cbor.insert(expected_cbor.begin(), head.begin(), head.end());

            head.clear();
            if (length <= 15)
            {
                head.push_back(static_cast<std::uint8_t>(0x90 + length));
            }
            else
            {
                head = {0xDC, static_cast<std::uint8_t>(length >> 8), static_cast<std::uint8_t>(length)};
            }
            expected_msgpack.insert(expected_msgpack.begin(), head.begin(), head.end());

            CHECK(json::to_cbor(array) == expected_cbor);
            CHECK(json::to_msgpack(array) == expected_msgpack);

            std::vector<std::uint8_t> through_adapter = {0xAA};
            json::to_cbor(array, through_adapter);
            CHECK(std::vector<std::uint8_t>(through_adapter.begin() + 1, through_adapter.end()) == expected_cbor);
            through_adapter = {0xAA};
            json::to_msgpack(array, through_adapter);
            CHECK(std::vector<std::uint8_t>(through_adapter.begin() + 1, through_adapter.end()) == expected_msgpack);

            std::ostringstream stream;
            json::to_cbor(array, stream);
            std::string streamed = stream.str();
            CHECK(to_bytes(streamed) == expected_cbor);
            stream.str("");
            json::to_msgpack(array, stream);
            streamed = stream.str();
            CHECK(to_bytes(streamed) == expected_msgpack);

            CHECK(json::from_cbor(expected_cbor) == array);
            CHECK(json::from_msgpack(expected_msgpack) == array);

            // the same array as object members
            const json object = {{"a", array}, {"b", array}};
            CHECK(json::from_cbor(json::to_cbor(object)) == object);
            CHECK(json::from_msgpack(json::to_msgpack(object)) == object);
        }
    }

    // single values, outside an array
    for (const auto& value : integers)
    {
        CAPTURE(value)
        std::vector<std::uint8_t> expected;
        reference_cbor_integer(expected, value);
        CHECK(json::to_cbor(value) == expected);
        expected.clear();
        reference_msgpack_integer(expected, value);
        CHECK(json::to_msgpack(value) == expected);
    }
}

// binary_reserve_hint() is documented as a *lower* bound on the serialized size,
// so that reserving it up front can never leave the returned vector holding
// capacity beyond what the value actually needs.
TEST_CASE("binary_reserve_hint never over-reserves")
{
    for (const auto& j : test_values())
    {
        CAPTURE(j.dump(-1, ' ', false, json::error_handler_t::replace))

        const std::size_t hint = nlohmann::detail::binary_reserve_hint(j);

        CHECK(hint <= json::to_cbor(j).size());
        CHECK(hint <= json::to_msgpack(j).size());
        CHECK(hint <= json::to_ubjson(j).size());
        CHECK(hint <= json::to_ubjson(j, true, true).size());
        CHECK(hint <= json::to_bjdata(j).size());
        if (bon8_representable(j))
        {
            CHECK(hint <= json::to_bon8(j).size());
        }
    }

    for (const auto& j : bson_values())
    {
        CAPTURE(j.dump())
        CHECK(nlohmann::detail::binary_reserve_hint(j) <= json::to_bson(j).size());
    }

    SECTION("scalars get no hint")
    {
        CHECK(nlohmann::detail::binary_reserve_hint(json(nullptr)) == 0);
        CHECK(nlohmann::detail::binary_reserve_hint(json(42)) == 0);
        CHECK(nlohmann::detail::binary_reserve_hint(json("a string")) == 0);
        CHECK(nlohmann::detail::binary_reserve_hint(json::binary({0x01})) == 0);
    }

    SECTION("containers are hinted from their element count")
    {
        CHECK(nlohmann::detail::binary_reserve_hint(json::array()) == 1);
        CHECK(nlohmann::detail::binary_reserve_hint(json::array({1, 2, 3})) == 4);
        CHECK(nlohmann::detail::binary_reserve_hint(json::object()) == 1);
        CHECK(nlohmann::detail::binary_reserve_hint(json({{"a", 1}, {"b", 2}})) == 5);
    }
}

namespace
{

// numbers around every boundary of the integer encodings, and floats of each
// kind (exact in float, needing double, special values)
std::vector<json> boundary_numbers()
{
    std::vector<json> numbers;
    for (int k = 0; k < 64; ++k)
    {
        const std::uint64_t p = std::uint64_t{1} << k;
        for (const std::uint64_t d :
                {
                    p - 1, p, p + 1
                })
        {
            numbers.emplace_back(d);
            if (d <= static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)()))
            {
                numbers.emplace_back(static_cast<std::int64_t>(d));
                numbers.emplace_back(-static_cast<std::int64_t>(d));
                numbers.emplace_back(-static_cast<std::int64_t>(d) - 1);
            }
        }
    }
    numbers.emplace_back((std::numeric_limits<std::int64_t>::min)());
    numbers.emplace_back((std::numeric_limits<std::uint64_t>::max)());
    for (const double f :
            {
                0.0, -0.0, 1.0, -1.0, 0.5, 0.1, 3.25, 1e300, -1e-300, 3.4028234663852886e38, 1e39,
                std::numeric_limits<double>::infinity(), -std::numeric_limits<double>::infinity(),
                std::numeric_limits<double>::quiet_NaN()
            })
    {
        numbers.emplace_back(f);
    }
    return numbers;
}

// the concatenation of the encodings of the elements of @a numbers[first, first + count)
template<typename Single>
std::vector<std::uint8_t> concat_singles(const std::vector<json>& numbers, const std::size_t first, const std::size_t count, Single single)
{
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = first; i < first + count; ++i)
    {
        const auto one = single(numbers[i]);
        bytes.insert(bytes.end(), one.begin(), one.end());
    }
    return bytes;
}

} // namespace

// Runs of numbers in arrays are encoded straight into space reserved from the
// sink, by code that is separate from the encoding of a single value. Both have
// to agree on every number: an array is its head and the encodings of its
// elements, one after the other.
TEST_CASE("runs of numbers in arrays are encoded as the numbers one by one")
{
    const std::vector<json> numbers = boundary_numbers();

    // arrays of every length that a one-byte head covers, so that runs are as
    // long as, and longer and shorter than, what fits one reservation
    for (const std::size_t count :
            {
                1u, 2u, 3u, 5u, 14u, 15u, 23u
            })
    {
        for (std::size_t first = 0; first + count <= numbers.size(); first += 7)
        {
            const json array(std::vector<json>(numbers.begin() + static_cast<std::ptrdiff_t>(first),
                                               numbers.begin() + static_cast<std::ptrdiff_t>(first + count)));
            CAPTURE(array.dump(-1, ' ', false, json::error_handler_t::replace))

            std::vector<std::uint8_t> expected{static_cast<std::uint8_t>(0x80 + count)};
            auto elements = concat_singles(numbers, first, count, [](const json & j)
            {
                return json::to_cbor(j);
            });
            expected.insert(expected.end(), elements.begin(), elements.end());
            CHECK(json::to_cbor(array) == expected);

            expected.assign(1, static_cast<std::uint8_t>(count <= 15 ? 0x90 + count : 0xDC));
            if (count > 15)
            {
                expected.push_back(0);
                expected.push_back(static_cast<std::uint8_t>(count));
            }
            elements = concat_singles(numbers, first, count, [](const json & j)
            {
                return json::to_msgpack(j);
            });
            expected.insert(expected.end(), elements.begin(), elements.end());
            CHECK(json::to_msgpack(array) == expected);

            for (const bool bjdata :
                    {
                        false, true
                    })
            {
                expected.assign(1, static_cast<std::uint8_t>('['));
                elements = concat_singles(numbers, first, count, [bjdata](const json & j)
                {
                    return bjdata ? json::to_bjdata(j) : json::to_ubjson(j);
                });
                expected.insert(expected.end(), elements.begin(), elements.end());
                expected.push_back(static_cast<std::uint8_t>(']'));
                CHECK((bjdata ? json::to_bjdata(array) : json::to_ubjson(array)) == expected);
            }

            // BON8 has no integers above the int64 range
            bool representable = true;
            for (std::size_t i = first; i < first + count; ++i)
            {
                representable = representable && bon8_representable(numbers[i]);
            }
            if (representable)
            {
                expected.assign(1, static_cast<std::uint8_t>(count <= 4 ? 0x80 + count : 0x85));
                elements = concat_singles(numbers, first, count, [](const json & j)
                {
                    return json::to_bon8(j);
                });
                expected.insert(expected.end(), elements.begin(), elements.end());
                if (count > 4)
                {
                    expected.push_back(0xFE);
                }
                CHECK(json::to_bon8(array) == expected);
            }
            else
            {
                CHECK_THROWS_AS(json::to_bon8(array), json::out_of_range&);
            }
        }
    }
}

// An array that is written in more than one reservation (more numbers than fit
// one), and arrays of an index with more digits, round trip for every format.
TEST_CASE("large arrays and many digits of indices round trip")
{
    json array = json::array();
    for (int i = 0; i < 12000; ++i)
    {
        switch (i % 4)
        {
            case 0:
                array.push_back(i);
                break;
            case 1:
                array.push_back(-i);
                break;
            case 2:
                array.push_back(i * 0.25);
                break;
            default:
                array.push_back(i % 8 == 3);
                break;
        }
    }
    json document = json::object();
    document["numbers"] = array;
    document["nested"] = json::array({array, "text", array});

    CHECK(json::from_cbor(json::to_cbor(document)) == document);
    CHECK(json::from_msgpack(json::to_msgpack(document)) == document);
    CHECK(json::from_ubjson(json::to_ubjson(document)) == document);
    CHECK(json::from_ubjson(json::to_ubjson(document, true, true)) == document);
    CHECK(json::from_bjdata(json::to_bjdata(document)) == document);
    CHECK(json::from_bson(json::to_bson(document)) == document);
    CHECK(json::from_bon8(json::to_bon8(document)) == document);
}

// Strings and keys are written with their head in one reservation up to a
// length; around that length, and with every kind of head, they must read back.
TEST_CASE("strings of every head length round trip")
{
    json document = json::object();
    json array = json::array();
    for (const std::size_t length :
            {
                0u, 1u, 2u, 3u, 4u, 7u, 8u, 15u, 16u, 17u, 23u, 24u, 25u, 31u, 32u, 33u, 63u, 127u, 128u, 129u, 200u, 245u, 246u, 247u, 248u, 249u, 250u, 251u, 252u, 253u, 254u, 255u, 256u, 257u, 300u, 1000u, 65535u, 65536u, 70000u
            })
    {
        const std::string text(length, 'x');
        array.push_back(text);
        document[std::string(length, 'k')] = text;
    }
    document["array"] = array;

    CHECK(json::from_cbor(json::to_cbor(document)) == document);
    CHECK(json::from_msgpack(json::to_msgpack(document)) == document);
    CHECK(json::from_ubjson(json::to_ubjson(document)) == document);
    CHECK(json::from_ubjson(json::to_ubjson(document, true, true)) == document);
    CHECK(json::from_bjdata(json::to_bjdata(document)) == document);
    CHECK(json::from_bson(json::to_bson(document)) == document);
    CHECK(json::from_bon8(json::to_bon8(document)) == document);
}

// What a write that throws leaves behind in an output adapter is what was written
// before it, whatever the adapter and however the adapter sink buffers.
TEST_CASE("a write that throws leaves the same bytes in every kind of output")
{
    json array = json::array();
    for (int i = 0; i < 700; ++i)
    {
        array.push_back(i * 1000);
        array.push_back("text " + std::to_string(i));
    }
    array.push_back("bad \xFF byte");
    json document = json::object();
    document["first"] = array;
    document["second"] = 1;

    const auto strict = json::error_handler_t::strict;

    SECTION("cbor")
    {
        std::vector<std::uint8_t> as_vector;
        std::string as_string;
        std::ostringstream as_stream;
        CHECK_THROWS_AS(json::to_cbor(document, as_vector, strict), json::type_error&);
        CHECK_THROWS_AS(json::to_cbor(document, as_string, strict), json::type_error&);
        CHECK_THROWS_AS(json::to_cbor(document, as_stream, strict), json::type_error&);
        CHECK(!as_vector.empty());
        CHECK(std::string(reinterpret_cast<const char*>(as_vector.data()), as_vector.size()) == as_string); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        CHECK(as_stream.str() == as_string);
    }

    SECTION("msgpack")
    {
        std::vector<std::uint8_t> as_vector;
        std::string as_string;
        std::ostringstream as_stream;
        CHECK_THROWS_AS(json::to_msgpack(document, as_vector, strict), json::type_error&);
        CHECK_THROWS_AS(json::to_msgpack(document, as_string, strict), json::type_error&);
        CHECK_THROWS_AS(json::to_msgpack(document, as_stream, strict), json::type_error&);
        CHECK(!as_vector.empty());
        CHECK(std::string(reinterpret_cast<const char*>(as_vector.data()), as_vector.size()) == as_string); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        CHECK(as_stream.str() == as_string);
    }

    SECTION("ubjson")
    {
        std::vector<std::uint8_t> as_vector;
        std::string as_string;
        std::ostringstream as_stream;
        CHECK_THROWS_AS(json::to_ubjson(document, as_vector, false, false, strict), json::type_error&);
        CHECK_THROWS_AS(json::to_ubjson(document, as_string, false, false, strict), json::type_error&);
        CHECK_THROWS_AS(json::to_ubjson(document, as_stream, false, false, strict), json::type_error&);
        CHECK(!as_vector.empty());
        CHECK(std::string(reinterpret_cast<const char*>(as_vector.data()), as_vector.size()) == as_string); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        CHECK(as_stream.str() == as_string);
    }

    SECTION("bson")
    {
        // the size pass finds the string before anything is written
        std::vector<std::uint8_t> as_vector;
        std::string as_string;
        std::ostringstream as_stream;
        CHECK_THROWS_AS(json::to_bson(document, as_vector, strict), json::type_error&);
        CHECK_THROWS_AS(json::to_bson(document, as_string, strict), json::type_error&);
        CHECK_THROWS_AS(json::to_bson(document, as_stream, strict), json::type_error&);
        CHECK(as_vector.empty());
        CHECK(as_string.empty());
        CHECK(as_stream.str().empty());
    }
}
