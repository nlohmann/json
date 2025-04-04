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

TEST_CASE("byte_container_with_subtype")
{
    using subtype_type = nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>>::subtype_type;

    SECTION("empty container")
    {
        nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>> container;

        CHECK(!container.has_subtype());
        CHECK(container.subtype() == static_cast<subtype_type>(-1));

        container.clear_subtype();
        CHECK(!container.has_subtype());
        CHECK(container.subtype() == static_cast<subtype_type>(-1));

        container.set_subtype(42);
        CHECK(container.has_subtype());
        CHECK(container.subtype() == 42);
    }

    SECTION("subtyped container")
    {
        nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>> container({}, 42);
        CHECK(container.has_subtype());
        CHECK(container.subtype() == 42);

        container.clear_subtype();
        CHECK(!container.has_subtype());
        CHECK(container.subtype() == static_cast<subtype_type>(-1));
    }

    SECTION("comparisons")
    {
        std::vector<std::uint8_t> const bytes = {{0xCA, 0xFE, 0xBA, 0xBE}};
        nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>> container1;
        nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>> container2({}, 42);
        nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>> container3(bytes);
        nlohmann::byte_container_with_subtype<std::vector<std::uint8_t>> container4(bytes, 42);

        CHECK(container1 == container1);
        CHECK(container1 != container2);
        CHECK(container1 != container3);
        CHECK(container1 != container4);
        CHECK(container2 != container1);
        CHECK(container2 == container2);
        CHECK(container2 != container3);
        CHECK(container2 != container4);
        CHECK(container3 != container1);
        CHECK(container3 != container2);
        CHECK(container3 == container3);
        CHECK(container3 != container4);
        CHECK(container4 != container1);
        CHECK(container4 != container2);
        CHECK(container4 != container3);
        CHECK(container4 == container4);

        container3.clear();
        container4.clear();

        CHECK(container1 == container3);
        CHECK(container2 == container4);
    }
}
