/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 2.1.1
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
Copyright (c) 2013-2017 Niels Lohmann <http://nlohmann.me>.

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

#include "catch.hpp"

#include "json.hpp"
using nlohmann::json;

TEST_CASE("iterator_wrapper_first_second")
{
    SECTION("object")
    {
        SECTION("value")
        {
            json j = {{"A", 1}, {"B", 2}};
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "A");
                        CHECK(i.second == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "B");
                        CHECK(i.second == json(2));
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
            json j = {{"A", 1}, {"B", 2}};
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "A");
                        CHECK(i.second == json(1));

                        // change the value
                        i.second = json(11);
                        CHECK(i.second == json(11));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "B");
                        CHECK(i.second == json(2));

                        // change the value
                        i.second = json(22);
                        CHECK(i.second == json(22));
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
            CHECK(j == json({{"A", 11}, {"B", 22}}));
        }

        SECTION("const value")
        {
            json j = {{"A", 1}, {"B", 2}};
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "A");
                        CHECK(i.second == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "B");
                        CHECK(i.second == json(2));
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
            json j = {{"A", 1}, {"B", 2}};
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "A");
                        CHECK(i.second == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "B");
                        CHECK(i.second == json(2));
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
            const json j = {{"A", 1}, {"B", 2}};
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "A");
                        CHECK(i.second == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "B");
                        CHECK(i.second == json(2));
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
            const json j = {{"A", 1}, {"B", 2}};
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "A");
                        CHECK(i.second == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "B");
                        CHECK(i.second == json(2));
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
            const json j = {{"A", 1}, {"B", 2}};
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "A");
                        CHECK(i.second == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "B");
                        CHECK(i.second == json(2));
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
            const json j = {{"A", 1}, {"B", 2}};
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "A");
                        CHECK(i.second == json(1));
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "B");
                        CHECK(i.second == json(2));
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
            json j = {"A", "B"};
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "0");
                        CHECK(i.second == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "1");
                        CHECK(i.second == "B");
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
            json j = {"A", "B"};
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "0");
                        CHECK(i.second == "A");

                        // change the value
                        i.second = "AA";
                        CHECK(i.second == "AA");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "1");
                        CHECK(i.second == "B");

                        // change the value
                        i.second = "BB";
                        CHECK(i.second == "BB");
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
            CHECK(j == json({"AA", "BB"}));
        }

        SECTION("const value")
        {
            json j = {"A", "B"};
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "0");
                        CHECK(i.second == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "1");
                        CHECK(i.second == "B");
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
            json j = {"A", "B"};
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "0");
                        CHECK(i.second == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "1");
                        CHECK(i.second == "B");
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
            const json j = {"A", "B"};
            int counter = 1;

            for (auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "0");
                        CHECK(i.second == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "1");
                        CHECK(i.second == "B");
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
            const json j = {"A", "B"};
            int counter = 1;

            for (auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "0");
                        CHECK(i.second == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "1");
                        CHECK(i.second == "B");
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
            const json j = {"A", "B"};
            int counter = 1;

            for (const auto i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "0");
                        CHECK(i.second == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "1");
                        CHECK(i.second == "B");
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
            const json j = {"A", "B"};
            int counter = 1;

            for (const auto& i : json::iterator_wrapper(j))
            {
                switch (counter++)
                {
                    case 1:
                    {
                        CHECK(i.first == "0");
                        CHECK(i.second == "A");
                        break;
                    }

                    case 2:
                    {
                        CHECK(i.first == "1");
                        CHECK(i.second == "B");
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
                CHECK(i.first == "");
                CHECK(i.second == json(1));
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
                CHECK(i.first == "");
                CHECK(i.second == json(1));

                // change value
                i.second = json(2);
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
                CHECK(i.first == "");
                CHECK(i.second == json(1));
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
                CHECK(i.first == "");
                CHECK(i.second == json(1));
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
                CHECK(i.first == "");
                CHECK(i.second == json(1));
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
                CHECK(i.first == "");
                CHECK(i.second == json(1));
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
                CHECK(i.first == "");
                CHECK(i.second == json(1));
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
                CHECK(i.first == "");
                CHECK(i.second == json(1));
            }

            CHECK(counter == 2);
        }
    }
}
