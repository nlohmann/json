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

TEST_CASE("capacity")
{
    SECTION("empty()")
    {
        SECTION("boolean")
        {
            json j = true;
            const json j_const(j);

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
            json j = "hello world";
            const json j_const(j);

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
                json j = json::array();
                const json j_const(j);

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
                json j = {1, 2, 3};
                const json j_const(j);

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
                json j = json::object();
                const json j_const(j);

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
                json j = {{"one", 1}, {"two", 2}, {"three", 3}};
                const json j_const(j);

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
            json j = -23;
            const json j_const(j);

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
            json j = 23u;
            const json j_const(j);

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
            json j = 23.42;
            const json j_const(j);

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
            json j = nullptr;
            const json j_const(j);

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
            json j = true;
            const json j_const(j);

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
            json j = "hello world";
            const json j_const(j);

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
                json j = json::array();
                const json j_const(j);

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
                json j = {1, 2, 3};
                const json j_const(j);

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
                json j = json::object();
                const json j_const(j);

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
                json j = {{"one", 1}, {"two", 2}, {"three", 3}};
                const json j_const(j);

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
            json j = -23;
            const json j_const(j);

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
            json j = 23u;
            const json j_const(j);

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
            json j = 23.42;
            const json j_const(j);

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
            json j = nullptr;
            const json j_const(j);

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
            json j = true;
            const json j_const = true;

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("string")
        {
            json j = "hello world";
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
                json j = json::array();
                const json j_const = json::array();

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3};
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
                json j = json::object();
                const json j_const = json::object();

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}};
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
            json j = -23;
            const json j_const = -23;

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("number (unsigned)")
        {
            json j = 23u;
            const json j_const = 23u;

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("number (float)")
        {
            json j = 23.42;
            const json j_const = 23.42;

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("null")
        {
            json j = nullptr;
            const json j_const = nullptr;

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 0);
                CHECK(j_const.max_size() == 0);
            }
        }
    }
}
