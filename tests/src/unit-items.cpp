//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.3
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2023 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#include "doctest_compatibility.h"

#include <nlohmann/json.hpp>
using nlohmann::json;

// This test suite uses range for loops where values are copied. This is inefficient in usual code, but required to achieve 100% coverage.
DOCTEST_GCC_SUPPRESS_WARNING_PUSH
#if DOCTEST_GCC >= DOCTEST_COMPILER(11, 0, 0)
    DOCTEST_GCC_SUPPRESS_WARNING("-Wrange-loop-construct")
#endif
DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wrange-loop-construct")

TEST_CASE("iterator_wrapper")
{
    SECTION("object")
    {
        SECTION("value")
        {
            json j = { {"A", 1}, {"B", 2} };
            int counter = 1;

            for (auto i : json::iterator_wrapper(j)) // NOLINT(performance-for-range-copy)
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

            for (auto& i : json::iterator_wrapper(j)) // NOLINT(readability-qualified-auto)
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

            for (const auto i : json::iterator_wrapper(j)) // NOLINT(performance-for-range-copy)
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

            for (auto i : json::iterator_wrapper(j)) // NOLINT(performance-for-range-copy)
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

            for (auto& i : json::iterator_wrapper(j)) // NOLINT(readability-qualified-auto)
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

            for (const auto i : json::iterator_wrapper(j)) // NOLINT(performance-for-range-copy)
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

            for (auto i : json::iterator_wrapper(j)) // NOLINT(performance-for-range-copy)
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

            for (auto& i : json::iterator_wrapper(j)) // NOLINT(readability-qualified-auto)
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

            for (const auto i : json::iterator_wrapper(j)) // NOLINT(performance-for-range-copy)
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

            for (auto i : json::iterator_wrapper(j)) // NOLINT(performance-for-range-copy)
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

            for (auto& i : json::iterator_wrapper(j)) // NOLINT(readability-qualified-auto)
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

            for (const auto i : json::iterator_wrapper(j)) // NOLINT(performance-for-range-copy)
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

            for (auto i : json::iterator_wrapper(j)) // NOLINT(performance-for-range-copy)
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

            for (auto& i : json::iterator_wrapper(j)) // NOLINT(readability-qualified-auto)
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

            for (const auto i : json::iterator_wrapper(j)) // NOLINT(performance-for-range-copy)
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

            for (auto i : json::iterator_wrapper(j)) // NOLINT(performance-for-range-copy)
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

            for (auto& i : json::iterator_wrapper(j)) // NOLINT(readability-qualified-auto)
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

            for (const auto i : json::iterator_wrapper(j)) // NOLINT(performance-for-range-copy)
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

            for (auto i : j.items()) // NOLINT(performance-for-range-copy)
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

            for (auto& i : j.items()) // NOLINT(readability-qualified-auto)
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

            for (const auto i : j.items()) // NOLINT(performance-for-range-copy)
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

            for (auto i : j.items()) // NOLINT(performance-for-range-copy)
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

            for (auto& i : j.items()) // NOLINT(readability-qualified-auto)
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

            for (const auto i : j.items()) // NOLINT(performance-for-range-copy)
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

            for (auto i : j.items()) // NOLINT(performance-for-range-copy)
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

            for (auto& i : j.items()) // NOLINT(readability-qualified-auto)
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

            for (const auto i : j.items()) // NOLINT(performance-for-range-copy)
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

            for (auto i : j.items()) // NOLINT(performance-for-range-copy)
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

            for (auto& i : j.items()) // NOLINT(readability-qualified-auto)
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

            for (const auto i : j.items()) // NOLINT(performance-for-range-copy)
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

            for (auto i : j.items()) // NOLINT(performance-for-range-copy)
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

            for (auto& i : j.items()) // NOLINT(readability-qualified-auto)
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

            for (const auto i : j.items()) // NOLINT(performance-for-range-copy)
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

            for (auto i : j.items()) // NOLINT(performance-for-range-copy)
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

            for (auto& i : j.items()) // NOLINT(readability-qualified-auto)
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

            for (const auto i : j.items()) // NOLINT(performance-for-range-copy)
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

DOCTEST_GCC_SUPPRESS_WARNING_POP
DOCTEST_CLANG_SUPPRESS_WARNING_POP
