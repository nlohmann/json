//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

// MessagePack tests with basic_json specializations other than nlohmann::json;
// they are kept apart from unit-msgpack.cpp because every specialization adds
// many sections to the object file, and MinGW cannot link objects with more
// than 65535 sections (see the clang job in .github/workflows/windows.yml)

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <cstdint> // SIZE_MAX, UINT32_MAX
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

// the fake sizes below do not fit into a 32-bit std::size_t
// with clang and libstdc++ 10, the std::filesystem::path conversion that
// C++17 builds consider for every string type is ambiguous for a class
// derived from std::string, so the string case is not tested there
#if !(defined(__clang__) && defined(_GLIBCXX_RELEASE) && _GLIBCXX_RELEASE < 11)
    #define JSON_TEST_BEYOND_UINT32_STRING 1
#endif

#if SIZE_MAX > UINT32_MAX
template<typename T, typename A = std::allocator<T>>
struct huge_array : std::vector<T, A>
{
    using base = std::vector<T, A>;
    using base::base;

    bool fake_size = false;

    std::size_t size() const noexcept
    {
        if (fake_size)
        {
            return (std::numeric_limits<std::uint32_t>::max)() + 1ULL;
        }

        return base::size();
    }
};

using huge_array_json = nlohmann::json::with_array_t<huge_array>;

TEST_CASE("MessagePack Size above uint32 for array")
{
    huge_array_json j = huge_array_json::array();

    j.push_back(1);
    j.push_back(2);
    j.push_back(3);

    auto& array = j.get_ref<huge_array_json::array_t&>();
    array.fake_size = true;

    // write into a caller-owned vector: to_msgpack(j) reserves space based on
    // the (faked) element count, which fails with bad_alloc on Windows
    std::vector<std::uint8_t> result;
    CHECK_THROWS_WITH_AS(
        huge_array_json::to_msgpack(j, result),
        "[json.exception.out_of_range.412] MessagePack length 4294967296 exceeds maximum of 4294967295",
        json::out_of_range&);

    array.fake_size = false;
}

template<typename K, typename V,
         typename C = std::less<K>,
         typename A = std::allocator<std::pair<const K, V>>>
                                     struct huge_map : std::map<K, V, C, A>
{
    using base = std::map<K, V, C, A>;
    using base::base;

    bool fake_size = false;

    std::size_t size() const noexcept
    {
        if (fake_size)
        {
            return static_cast<std::size_t>(UINT32_MAX) + 1ULL;
        }

        return base::size();
    }
};

using huge_object_json = nlohmann::json::with_object_t<huge_map>;

TEST_CASE("MessagePack Size above uint32 for object")
{

    huge_object_json j = huge_object_json::object();

    j["one"] = 1;
    j["two"] = 2;

    auto& object = j.get_ref<huge_object_json::object_t&>();
    object.fake_size = true;

    // write into a caller-owned vector: to_msgpack(j) reserves space based on
    // the (faked) element count, which fails with bad_alloc on Windows
    std::vector<std::uint8_t> result;
    CHECK_THROWS_WITH_AS(
        huge_object_json::to_msgpack(j, result),
        "[json.exception.out_of_range.412] MessagePack length 4294967296 exceeds maximum of 4294967295",
        json::out_of_range&);

    object.fake_size = false;
}

#ifdef JSON_TEST_BEYOND_UINT32_STRING
struct huge_string : std::string
{
    using std::string::string;

    std::size_t size() const noexcept // NOLINT(readability-convert-member-functions-to-static)
    {
        return static_cast<std::size_t>(UINT32_MAX) + 1ULL;
    }
};

using huge_string_json = nlohmann::json::with_string_t<huge_string>;

TEST_CASE("MessagePack Size above uint32 for string")
{
    const huge_string_json j = "hello";

    CHECK_THROWS_WITH_AS(
        huge_string_json::to_msgpack(j),
        "[json.exception.out_of_range.412] MessagePack length 4294967296 exceeds maximum of 4294967295",
        json::out_of_range&);
}
#endif

struct huge_binary : std::vector<std::uint8_t>
{
    using std::vector<std::uint8_t>::vector;

    std::size_t size() const noexcept // NOLINT(readability-convert-member-functions-to-static)
    {
        return static_cast<std::size_t>(UINT32_MAX) + 1ULL;
    }
};

using huge_binary_json = nlohmann::json::with_binary_t<huge_binary>;

TEST_CASE("MessagePack Size above uint32 for binary")
{

    huge_binary_json j = huge_binary_json::binary(huge_binary{});

    j.get_binary().push_back(0x01);
    j.get_binary().push_back(0x02);

    CHECK_THROWS_WITH_AS(
        huge_binary_json::to_msgpack(j),
        "[json.exception.out_of_range.412] MessagePack length 4294967296 exceeds maximum of 4294967295",
        json::out_of_range&);
}
#endif

namespace
{
// types that report a size beyond UINT32_MAX without allocating that much
// memory, so the MessagePack length limit can be tested cheaply; see the
// similar types in unit-bson.cpp
std::size_t beyond_uint32_size()
{
    return static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)()) + 1;
}

class beyond_uint32_binary_t : public std::vector<std::uint8_t>
{
  public:
    using std::vector<std::uint8_t>::vector;

    size_type size() const noexcept // NOLINT(readability-convert-member-functions-to-static)
    {
        return beyond_uint32_size();
    }
};

#ifdef JSON_TEST_BEYOND_UINT32_STRING
class beyond_uint32_string_t : public std::string
{
  public:
    using std::string::string;

    size_type size() const noexcept // NOLINT(readability-convert-member-functions-to-static)
    {
        return beyond_uint32_size();
    }
};

using beyond_uint32_string_json = nlohmann::json::with_string_t<beyond_uint32_string_t>;
#endif

using beyond_uint32_binary_json = nlohmann::json::with_binary_t<beyond_uint32_binary_t>;
} // namespace

TEST_CASE("MessagePack lengths beyond UINT32_MAX cannot be serialized")
{
    // MessagePack stores the length of a string, binary value, array, or
    // object in at most 32 bits; a larger one used to be written without any
    // length at all
#if SIZE_MAX > UINT32_MAX
    {
        const char* const expected = "[json.exception.out_of_range.412] MessagePack length 4294967296 exceeds maximum of 4294967295";

        const beyond_uint32_binary_json binary = beyond_uint32_binary_json::binary(beyond_uint32_binary_t{});
        CHECK_THROWS_WITH_AS(beyond_uint32_binary_json::to_msgpack(binary), expected, beyond_uint32_binary_json::out_of_range&);

        const beyond_uint32_binary_json ext = beyond_uint32_binary_json::binary(beyond_uint32_binary_t{}, 42);
        CHECK_THROWS_WITH_AS(beyond_uint32_binary_json::to_msgpack(ext), expected, beyond_uint32_binary_json::out_of_range&);

#ifdef JSON_TEST_BEYOND_UINT32_STRING
        // created from its type rather than from a beyond_uint32_string_t:
        // that would consider the std::filesystem::path conversion, which
        // libstdc++ 10 cannot decide for a class derived from std::string
        const beyond_uint32_string_json string(beyond_uint32_string_json::value_t::string);
        CHECK_THROWS_WITH_AS(beyond_uint32_string_json::to_msgpack(string), expected, beyond_uint32_string_json::out_of_range&);
#endif
    }
#endif
}

TEST_CASE("MessagePack numbers use the active union member (see #5644)")
{
    // when number_integer_t is narrower than number_unsigned_t, to_msgpack()
    // used to read the union member that was not the active one, writing
    // wrong bytes for some values; std::int64_t/std::uint64_t (the default
    // types, where both members have the same width) were not affected
    using int32_json = nlohmann::json::with_integers_t<std::int32_t, std::uint64_t>;
    using int16_json = nlohmann::json::with_integers_t<std::int16_t, std::uint64_t>;

    SECTION("number_integer_t = std::int32_t")
    {
        SECTION("6442450944 (uint 64; the low 32 bits used to be sign-extended)")
        {
            const int32_json j = 6442450944ULL;
            CHECK(j.is_number_unsigned());

            std::vector<uint8_t> const expected{0xcf, 0x00, 0x00, 0x00, 0x01, 0x80, 0x00, 0x00, 0x00};
            const auto result = int32_json::to_msgpack(j);
            CHECK(result == expected);
            CHECK(int32_json::from_msgpack(result) == j);
        }

        SECTION("4294967496 (uint 64; the low 32 bits used to be the whole value)")
        {
            const int32_json j = 4294967496ULL;
            CHECK(j.is_number_unsigned());

            std::vector<uint8_t> const expected{0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc8};
            const auto result = int32_json::to_msgpack(j);
            CHECK(result == expected);
            CHECK(int32_json::from_msgpack(result) == j);
        }
    }

    SECTION("number_integer_t = std::int16_t, 98304 (uint 32)")
    {
        const int16_json j = 98304ULL;
        CHECK(j.is_number_unsigned());

        std::vector<uint8_t> const expected{0xce, 0x00, 0x01, 0x80, 0x00};
        const auto result = int16_json::to_msgpack(j);
        CHECK(result == expected);
        CHECK(int16_json::from_msgpack(result) == j);
    }

    SECTION("default types (std::int64_t/std::uint64_t) are unaffected")
    {
        const json j = 4294967496ULL;
        CHECK(j.is_number_unsigned());

        std::vector<uint8_t> const expected{0xcf, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc8};
        const auto result = json::to_msgpack(j);
        CHECK(result == expected);
        CHECK(json::from_msgpack(result) == j);
    }
}
