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

TEST_CASE("capacity")
{
    SECTION("empty()")
    {
        SECTION("boolean")
        {
            json j = true; // NOLINT(misc-const-correctness)
            const json j_const = true;

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.empty() == (j.begin() == j.end()));
                CHECK(j_const.empty() == (j_const.begin() == j_const.end()));
            }
        }

        SECTION("string")
        {
            json j = "hello world"; // NOLINT(misc-const-correctness)
            const json j_const = "hello world";

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.empty() == (j.begin() == j.end()));
                CHECK(j_const.empty() == (j_const.begin() == j_const.end()));
            }
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                json j = json::array(); // NOLINT(misc-const-correctness)
                const json j_const = json::array();

                SECTION("result of empty")
                {
                    CHECK(j.empty() == true);
                    CHECK(j_const.empty() == true);
                }

                SECTION("definition of empty")
                {
                    CHECK(j.empty() == (j.begin() == j.end()));
                    CHECK(j_const.empty() == (j_const.begin() == j_const.end()));
                }
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3}; // NOLINT(misc-const-correctness)
                const json j_const = {1, 2, 3};

                SECTION("result of empty")
                {
                    CHECK(j.empty() == false);
                    CHECK(j_const.empty() == false);
                }

                SECTION("definition of empty")
                {
                    CHECK(j.empty() == (j.begin() == j.end()));
                    CHECK(j_const.empty() == (j_const.begin() == j_const.end()));
                }
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                json j = json::object(); // NOLINT(misc-const-correctness)
                const json j_const = json::object();

                SECTION("result of empty")
                {
                    CHECK(j.empty() == true);
                    CHECK(j_const.empty() == true);
                }

                SECTION("definition of empty")
                {
                    CHECK(j.empty() == (j.begin() == j.end()));
                    CHECK(j_const.empty() == (j_const.begin() == j_const.end()));
                }
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}}; // NOLINT(misc-const-correctness)
                const json j_const = {{"one", 1}, {"two", 2}, {"three", 3}};

                SECTION("result of empty")
                {
                    CHECK(j.empty() == false);
                    CHECK(j_const.empty() == false);
                }

                SECTION("definition of empty")
                {
                    CHECK(j.empty() == (j.begin() == j.end()));
                    CHECK(j_const.empty() == (j_const.begin() == j_const.end()));
                }
            }
        }

        SECTION("number (integer)")
        {
            json j = -23; // NOLINT(misc-const-correctness)
            const json j_const = -23;

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.empty() == (j.begin() == j.end()));
                CHECK(j_const.empty() == (j_const.begin() == j_const.end()));
            }
        }

        SECTION("number (unsigned)")
        {
            json j = 23u; // NOLINT(misc-const-correctness)
            const json j_const = 23u;

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.empty() == (j.begin() == j.end()));
                CHECK(j_const.empty() == (j_const.begin() == j_const.end()));
            }
        }

        SECTION("number (float)")
        {
            json j = 23.42; // NOLINT(misc-const-correctness)
            const json j_const = 23.42;

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.empty() == (j.begin() == j.end()));
                CHECK(j_const.empty() == (j_const.begin() == j_const.end()));
            }
        }

        SECTION("null")
        {
            json j = nullptr; // NOLINT(misc-const-correctness)
            const json j_const = nullptr;

            SECTION("result of empty")
            {
                CHECK(j.empty() == true);
                CHECK(j_const.empty() == true);
            }

            SECTION("definition of empty")
            {
                CHECK(j.empty() == (j.begin() == j.end()));
                CHECK(j_const.empty() == (j_const.begin() == j_const.end()));
            }
        }
    }

    SECTION("size()")
    {
        SECTION("boolean")
        {
            json j = true; // NOLINT(misc-const-correctness)
            const json j_const = true;

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
            }
        }

        SECTION("string")
        {
            json j = "hello world"; // NOLINT(misc-const-correctness)
            const json j_const = "hello world";

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
            }
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                json j = json::array(); // NOLINT(misc-const-correctness)
                const json j_const = json::array();

                SECTION("result of size")
                {
                    CHECK(j.size() == 0);
                    CHECK(j_const.size() == 0);
                }

                SECTION("definition of size")
                {
                    CHECK(std::distance(j.begin(), j.end()) == j.size());
                    CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                    CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                    CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
                }
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3}; // NOLINT(misc-const-correctness)
                const json j_const = {1, 2, 3};

                SECTION("result of size")
                {
                    CHECK(j.size() == 3);
                    CHECK(j_const.size() == 3);
                }

                SECTION("definition of size")
                {
                    CHECK(std::distance(j.begin(), j.end()) == j.size());
                    CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                    CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                    CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
                }
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                json j = json::object(); // NOLINT(misc-const-correctness)
                const json j_const = json::object();

                SECTION("result of size")
                {
                    CHECK(j.size() == 0);
                    CHECK(j_const.size() == 0);
                }

                SECTION("definition of size")
                {
                    CHECK(std::distance(j.begin(), j.end()) == j.size());
                    CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                    CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                    CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
                }
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}}; // NOLINT(misc-const-correctness)
                const json j_const = {{"one", 1}, {"two", 2}, {"three", 3}};

                SECTION("result of size")
                {
                    CHECK(j.size() == 3);
                    CHECK(j_const.size() == 3);
                }

                SECTION("definition of size")
                {
                    CHECK(std::distance(j.begin(), j.end()) == j.size());
                    CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                    CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                    CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
                }
            }
        }

        SECTION("number (integer)")
        {
            json j = -23; // NOLINT(misc-const-correctness)
            const json j_const = -23;

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
            }
        }

        SECTION("number (unsigned)")
        {
            json j = 23u; // NOLINT(misc-const-correctness)
            const json j_const = 23u;

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
            }
        }

        SECTION("number (float)")
        {
            json j = 23.42; // NOLINT(misc-const-correctness)
            const json j_const = 23.42;

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
            }
        }

        SECTION("null")
        {
            json j = nullptr; // NOLINT(misc-const-correctness)
            const json j_const = nullptr;

            SECTION("result of size")
            {
                CHECK(j.size() == 0);
                CHECK(j_const.size() == 0);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                CHECK(std::distance(j.rbegin(), j.rend()) == j.size());
                CHECK(std::distance(j_const.crbegin(), j_const.crend()) == j_const.size());
            }
        }
    }

    SECTION("max_size()")
    {
        SECTION("boolean")
        {
            json j = true; // NOLINT(misc-const-correctness)
            const json j_const = true;

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("string")
        {
            json j = "hello world"; // NOLINT(misc-const-correctness)
            const json j_const = "hello world";

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                json j = json::array(); // NOLINT(misc-const-correctness)
                const json j_const = json::array();

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3}; // NOLINT(misc-const-correctness)
                const json j_const = {1, 2, 3};

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                json j = json::object(); // NOLINT(misc-const-correctness)
                const json j_const = json::object();

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}}; // NOLINT(misc-const-correctness)
                const json j_const = {{"one", 1}, {"two", 2}, {"three", 3}};

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }
        }

        SECTION("number (integer)")
        {
            json j = -23; // NOLINT(misc-const-correctness)
            const json j_const = -23;

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("number (unsigned)")
        {
            json j = 23u; // NOLINT(misc-const-correctness)
            const json j_const = 23u;

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("number (float)")
        {
            json j = 23.42; // NOLINT(misc-const-correctness)
            const json j_const = 23.42;

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("null")
        {
            json j = nullptr; // NOLINT(misc-const-correctness)
            const json j_const = nullptr;

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 0);
                CHECK(j_const.max_size() == 0);
            }
        }
    }
}
