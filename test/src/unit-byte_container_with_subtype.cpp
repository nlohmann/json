/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.4
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2019 Niels Lohmann <http://nlohmann.me>.

Permission is hereby  granted, free of charge, to any  person obtaining a copy
of this software and associated  documentation files (the "Software"), to deal
in the Software  without restriction, including without  limitation the rights
to  use, copy,  modify, merge,  publish, distribute,  sublicense, and/or  sell
copies  of  the Software,  and  to  permit persons  to  whom  the Software  is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE  IS PROVIDED "AS  IS", WITHOUT WARRANTY  OF ANY KIND,  EXPRESS OR
IMPLIED,  INCLUDING BUT  NOT  LIMITED TO  THE  WARRANTIES OF  MERCHANTABILITY,
FITNESS FOR  A PARTICULAR PURPOSE AND  NONINFRINGEMENT. IN NO EVENT  SHALL THE
AUTHORS  OR COPYRIGHT  HOLDERS  BE  LIABLE FOR  ANY  CLAIM,  DAMAGES OR  OTHER
LIABILITY, WHETHER IN AN ACTION OF  CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE  OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

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
        CHECK(container.subtype() == subtype_type(-1));

        container.clear_subtype();
        CHECK(!container.has_subtype());
        CHECK(container.subtype() == subtype_type(-1));

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
        CHECK(container.subtype() == subtype_type(-1));
    }

    SECTION("comparisons")
    {
        std::vector<std::uint8_t> bytes = {{0xCA, 0xFE, 0xBA, 0xBE}};
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
