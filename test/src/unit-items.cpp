/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.9.0
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

#if (defined(__cplusplus) && __cplusplus >= 201703L) || (defined(_HAS_CXX17) && _HAS_CXX17 == 1) // fix for issue #464
    #define JSON_HAS_CPP_17
    #define JSON_HAS_CPP_14
#elif (defined(__cplusplus) && __cplusplus >= 201402L) || (defined(_HAS_CXX14) && _HAS_CXX14 == 1)
    #define JSON_HAS_CPP_14
#endif

TEST_CASE("iterator_wrapper")
{
    SECTION("object")
    {
        SECTION("value")
        {
            json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("reference")
        {
            json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));

                        // change the value
                        i.value() = json(11);
                        CHECK(i.value() == json(11));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));

                        // change the value
                        i.value() = json(22);
                        CHECK(i.value() == json(22));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);

            // check if values where changed
            CHECK(j == json({ {"A", 11}, {"B", 22} }));
        }

        SECTION("const value")
        {
            json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const reference")
        {
            json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }
    }

    SECTION("const object")
    {
        SECTION("value")
        {
            const json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("reference")
        {
            const json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const value")
        {
            const json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const reference")
        {
            const json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }
    }

    SECTION("array")
    {
        SECTION("value")
        {
            json j = { "A", "B" };
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("reference")
        {
            json j = { "A", "B" };
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");

                        // change the value
                        i.value() = "AA";
                        CHECK(i.value() == "AA");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");

                        // change the value
                        i.value() = "BB";
                        CHECK(i.value() == "BB");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);

            // check if values where changed
            CHECK(j == json({ "AA", "BB" }));
        }

        SECTION("const value")
        {
            json j = { "A", "B" };
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const reference")
        {
            json j = { "A", "B" };
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }
    }

    SECTION("const array")
    {
        SECTION("value")
        {
            const json j = { "A", "B" };
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("reference")
        {
            const json j = { "A", "B" };
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const value")
        {
            const json j = { "A", "B" };
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const reference")
        {
            const json j = { "A", "B" };
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }
    }

    SECTION("primitive")
    {
        SECTION("value")
        {
            json j = 1;
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("reference")
        {
            json j = 1;
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));

                // change value
                i.value() = json(2);
            }

            CHECK(counter == 2);

            // check if value has changed
            CHECK(j == json(2));
        }

        SECTION("const value")
        {
            json j = 1;
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("const reference")
        {
            json j = 1;
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }
    }

    SECTION("const primitive")
    {
        SECTION("value")
        {
            const json j = 1;
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("reference")
        {
            const json j = 1;
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("const value")
        {
            const json j = 1;
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("const reference")
        {
            const json j = 1;
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }
    }
}

TEST_CASE("items()")
{
    SECTION("object")
    {
        SECTION("value")
        {
            json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (auto i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("reference")
        {
            json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (auto& i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));

                        // change the value
                        i.value() = json(11);
                        CHECK(i.value() == json(11));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));

                        // change the value
                        i.value() = json(22);
                        CHECK(i.value() == json(22));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);

            // check if values where changed
            CHECK(j == json({ {"A", 11}, {"B", 22} }));
        }

        SECTION("const value")
        {
            json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (const auto i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const reference")
        {
            json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (const auto& i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

#ifdef JSON_HAS_CPP_17
        SECTION("structured bindings")
        {
            json j = { {"A", 1}, {"B", 2} };

            std::map<std::string, int> m;

            for (auto const&[key, value] : j.items())
            {
                m.emplace(key, value);
            }

            CHECK(j.get<decltype(m)>() == m);
        }
#endif
    }

    SECTION("const object")
    {
        SECTION("value")
        {
            const json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (auto i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("reference")
        {
            const json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (auto& i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const value")
        {
            const json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (const auto i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const reference")
        {
            const json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (const auto& i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "A");
                        CHECK(i.value() == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "B");
                        CHECK(i.value() == json(2));
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }
    }

    SECTION("array")
    {
        SECTION("value")
        {
            json j = { "A", "B" };
            int counter = 1;

            for (auto i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("reference")
        {
            json j = { "A", "B" };
            int counter = 1;

            for (auto& i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");

                        // change the value
                        i.value() = "AA";
                        CHECK(i.value() == "AA");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");

                        // change the value
                        i.value() = "BB";
                        CHECK(i.value() == "BB");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);

            // check if values where changed
            CHECK(j == json({ "AA", "BB" }));
        }

        SECTION("const value")
        {
            json j = { "A", "B" };
            int counter = 1;

            for (const auto i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const reference")
        {
            json j = { "A", "B" };
            int counter = 1;

            for (const auto& i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }
    }

    SECTION("const array")
    {
        SECTION("value")
        {
            const json j = { "A", "B" };
            int counter = 1;

            for (auto i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("reference")
        {
            const json j = { "A", "B" };
            int counter = 1;

            for (auto& i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const value")
        {
            const json j = { "A", "B" };
            int counter = 1;

            for (const auto i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }

        SECTION("const reference")
        {
            const json j = { "A", "B" };
            int counter = 1;

            for (const auto& i : j.items())
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.key() == "0");
                        CHECK(i.value() == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.key() == "1");
                        CHECK(i.value() == "B");
                        break;
                    }

                    default:
                    {
                        break;
                    }
                }
            }

            CHECK(counter == 3);
        }
    }

    SECTION("primitive")
    {
        SECTION("value")
        {
            json j = 1;
            int counter = 1;

            for (auto i : j.items())
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("reference")
        {
            json j = 1;
            int counter = 1;

            for (auto& i : j.items())
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));

                // change value
                i.value() = json(2);
            }

            CHECK(counter == 2);

            // check if value has changed
            CHECK(j == json(2));
        }

        SECTION("const value")
        {
            json j = 1;
            int counter = 1;

            for (const auto i : j.items())
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("const reference")
        {
            json j = 1;
            int counter = 1;

            for (const auto& i : j.items())
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }
    }

    SECTION("const primitive")
    {
        SECTION("value")
        {
            const json j = 1;
            int counter = 1;

            for (auto i : j.items())
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("reference")
        {
            const json j = 1;
            int counter = 1;

            for (auto& i : j.items())
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("const value")
        {
            const json j = 1;
            int counter = 1;

            for (const auto i : j.items())
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }

        SECTION("const reference")
        {
            const json j = 1;
            int counter = 1;

            for (const auto& i : j.items())
            {
                ++counter;
                CHECK(i.key() == "");
                CHECK(i.value() == json(1));
            }

            CHECK(counter == 2);
        }
    }
}
