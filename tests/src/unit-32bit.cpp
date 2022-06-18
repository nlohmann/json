#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

#include <climits> // SIZE_MAX
#include <limits> // numeric_limits


template <typename OfType, typename T, bool MinInRange, bool MaxInRange>
struct trait_test_arg
{
    using of_type = OfType;
    using type = T;
    static constexpr bool min_in_range = MinInRange;
    static constexpr bool max_in_range = MaxInRange;
};

TEST_CASE_TEMPLATE_DEFINE("value_in_range_of trait", T, value_in_range_of_test)
{
    using nlohmann::detail::value_in_range_of;

    using of_type = typename T::of_type;
    using type = typename T::type;
    constexpr bool min_in_range = T::min_in_range;
    constexpr bool max_in_range = T::max_in_range;

    type val_min = std::numeric_limits<type>::min();
    type val_min2 = val_min + 1;
    type val_max = std::numeric_limits<type>::max();
    type val_max2 = val_max - 1;

    REQUIRE(CHAR_BIT == 8);

    std::string of_type_str;
    if (std::is_unsigned<of_type>::value)
    {
        of_type_str += "u";
    }
    of_type_str += "int";
    of_type_str += std::to_string(sizeof(of_type) * 8);

    INFO("of_type := ", of_type_str);

    std::string type_str;
    if (std::is_unsigned<type>::value)
    {
        type_str += "u";
    }
    type_str += "int";
    type_str += std::to_string(sizeof(type) * 8);

    INFO("type := ", type_str);

    CAPTURE(val_min);
    CAPTURE(min_in_range);
    CAPTURE(val_max);
    CAPTURE(max_in_range);

    if (min_in_range)
    {
        CHECK(value_in_range_of<of_type>(val_min));
        CHECK(value_in_range_of<of_type>(val_min2));
    }
    else
    {
        CHECK_FALSE(value_in_range_of<of_type>(val_min));
        CHECK_FALSE(value_in_range_of<of_type>(val_min2));
    }

    if (max_in_range)
    {
        CHECK(value_in_range_of<of_type>(val_max));
        CHECK(value_in_range_of<of_type>(val_max2));
    }
    else
    {
        CHECK_FALSE(value_in_range_of<of_type>(val_max));
        CHECK_FALSE(value_in_range_of<of_type>(val_max2));
    }
}


TEST_CASE("32bit")
{
    REQUIRE(SIZE_MAX == 0xffffffff);
}

TEST_CASE_TEMPLATE_INVOKE(value_in_range_of_test, \
                          trait_test_arg<std::size_t, std::int32_t, false, true>, \
                          trait_test_arg<std::size_t, std::uint32_t, true, true>, \
                          trait_test_arg<std::size_t, std::int64_t, false, false>, \
                          trait_test_arg<std::size_t, std::uint64_t, true, false>);

TEST_CASE("BJData")
{
    SECTION("parse errors")
    {
        SECTION("array")
        {
            SECTION("optimized array: negative size")
            {
                std::vector<uint8_t> vM = {'[', '$', 'M', '#', '[', 'I', 0x00, 0x20, 'M', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xFF, ']'};
                std::vector<uint8_t> vMX = {'[', '$', 'U', '#', '[', 'M', 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 'U', 0x01, ']'};

                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vM), "[json.exception.out_of_range.408] syntax error while parsing BJData size: integer value overflow", json::out_of_range&);
                CHECK(json::from_bjdata(vM, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vMX), "[json.exception.out_of_range.408] syntax error while parsing BJData size: integer value overflow", json::out_of_range&);
                CHECK(json::from_bjdata(vMX, true, false).is_discarded());
            }

            SECTION("optimized array: integer value overflow")
            {
                std::vector<uint8_t> vL = {'[', '#', 'L', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F};
                std::vector<uint8_t> vM = {'[', '$', 'M', '#', '[', 'I', 0x00, 0x20, 'M', 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xFF, ']'};

                json _;
                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vL), "[json.exception.out_of_range.408] syntax error while parsing BJData size: integer value overflow", json::out_of_range&);
                CHECK(json::from_bjdata(vL, true, false).is_discarded());

                CHECK_THROWS_WITH_AS(_ = json::from_bjdata(vM), "[json.exception.out_of_range.408] syntax error while parsing BJData size: integer value overflow", json::out_of_range&);
                CHECK(json::from_bjdata(vM, true, false).is_discarded());
            }
        }
    }
}
