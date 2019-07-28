/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.7.0
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

namespace
{
// helper function to check std::less<json::value_t>
// see https://en.cppreference.com/w/cpp/utility/functional/less
template <typename A, typename B, typename U = std::less<json::value_t>>
bool f(A a, B b, U u = U())
{
    return u(a, b);
}
}

TEST_CASE("lexicographical comparison operators")
{
    SECTION("types")
    {
        std::vector<json::value_t> j_types =
        {
            json::value_t::null,
            json::value_t::boolean,
            json::value_t::number_integer,
            json::value_t::number_unsigned,
            json::value_t::number_float,
            json::value_t::object,
            json::value_t::array,
            json::value_t::string
        };

        SECTION("comparison: less")
        {
            std::vector<std::vector<bool>> expected =
            {
                {false, true, true, true, true, true, true, true},
                {false, false, true, true, true, true, true, true},
                {false, false, false, false, false, true, true, true},
                {false, false, false, false, false, true, true, true},
                {false, false, false, false, false, true, true, true},
                {false, false, false, false, false, false, true, true},
                {false, false, false, false, false, false, false, true},
                {false, false, false, false, false, false, false, false}
            };

            for (size_t i = 0; i < j_types.size(); ++i)
            {
                for (size_t j = 0; j < j_types.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    // check precomputed values
                    CHECK(operator<(j_types[i], j_types[j]) == expected[i][j]);
                    CHECK(f(j_types[i], j_types[j]) == expected[i][j]);
                }
            }
        }
    }

    SECTION("values")
    {
        json j_values =
        {
            nullptr, nullptr,
            -17, 42,
            8u, 13u,
            3.14159, 23.42,
            "foo", "bar",
            true, false,
            {1, 2, 3}, {"one", "two", "three"},
            {{"first", 1}, {"second", 2}}, {{"a", "A"}, {"b", {"B"}}}
        };

        SECTION("comparison: equal")
        {
            std::vector<std::vector<bool>> expected =
            {
                {true, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false},
                {true, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false},
                {false, false, true, false, false, false, false, false, false, false, false, false, false, false, false, false},
                {false, false, false, true, false, false, false, false, false, false, false, false, false, false, false, false},
                {false, false, false, false, true, false, false, false, false, false, false, false, false, false, false, false},
                {false, false, false, false, false, true, false, false, false, false, false, false, false, false, false, false},
                {false, false, false, false, false, false, true, false, false, false, false, false, false, false, false, false},
                {false, false, false, false, false, false, false, true, false, false, false, false, false, false, false, false},
                {false, false, false, false, false, false, false, false, true, false, false, false, false, false, false, false},
                {false, false, false, false, false, false, false, false, false, true, false, false, false, false, false, false},
                {false, false, false, false, false, false, false, false, false, false, true, false, false, false, false, false},
                {false, false, false, false, false, false, false, false, false, false, false, true, false, false, false, false},
                {false, false, false, false, false, false, false, false, false, false, false, false, true, false, false, false},
                {false, false, false, false, false, false, false, false, false, false, false, false, false, true, false, false},
                {false, false, false, false, false, false, false, false, false, false, false, false, false, false, true, false},
                {false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, true}
            };

            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    CAPTURE(j_values[i])
                    CAPTURE(j_values[j])
                    // check precomputed values
                    CHECK( (j_values[i] == j_values[j]) == expected[i][j] );
                }
            }

            // comparison with discarded elements
            json j_discarded(json::value_t::discarded);
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                CHECK( (j_values[i] == j_discarded) == false);
                CHECK( (j_discarded == j_values[i]) == false);
                CHECK( (j_discarded == j_discarded) == false);
            }

            // compare with null pointer
            json j_null;
            CHECK(j_null == nullptr);
            CHECK(nullptr == j_null);
        }

        SECTION("comparison: not equal")
        {
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    // check definition
                    CHECK( (j_values[i] != j_values[j]) == not(j_values[i] == j_values[j]) );
                }
            }

            // compare with null pointer
            json j_null;
            CHECK( (j_null != nullptr) == false);
            CHECK( (nullptr != j_null) == false);
            CHECK( (j_null != nullptr) == not(j_null == nullptr));
            CHECK( (nullptr != j_null) == not(nullptr == j_null));
        }

        SECTION("comparison: less")
        {
            std::vector<std::vector<bool>> expected =
            {
                {false, false, true, true, true, true, true, true, true, true, true, true, true, true, true, true},
                {false, false, true, true, true, true, true, true, true, true, true, true, true, true, true, true},
                {false, false, false, true, true, true, true, true, true, true, false, false, true, true, true, true},
                {false, false, false, false, false, false, false, false, true, true, false, false, true, true, true, true},
                {false, false, false, true, false, true, false, true, true, true, false, false, true, true, true, true},
                {false, false, false, true, false, false, false, true, true, true, false, false, true, true, true, true},
                {false, false, false, true, true, true, false, true, true, true, false, false, true, true, true, true},
                {false, false, false, true, false, false, false, false, true, true, false, false, true, true, true, true},
                {false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false},
                {false, false, false, false, false, false, false, false, true, false, false, false, false, false, false, false},
                {false, false, true, true, true, true, true, true, true, true, false, false, true, true, true, true},
                {false, false, true, true, true, true, true, true, true, true, true, false, true, true, true, true},
                {false, false, false, false, false, false, false, false, true, true, false, false, false, true, false, false},
                {false, false, false, false, false, false, false, false, true, true, false, false, false, false, false, false},
                {false, false, false, false, false, false, false, false, true, true, false, false, true, true, false, false},
                {false, false, false, false, false, false, false, false, true, true, false, false, true, true, true, false}
            };

            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    CAPTURE(j_values[i])
                    CAPTURE(j_values[j])
                    // check precomputed values
                    CHECK( (j_values[i] < j_values[j]) == expected[i][j] );
                }
            }

            // comparison with discarded elements
            json j_discarded(json::value_t::discarded);
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                CAPTURE(i)
                CHECK( (j_values[i] < j_discarded) == false);
                CHECK( (j_discarded < j_values[i]) == false);
                CHECK( (j_discarded < j_discarded) == false);
            }
        }

        SECTION("comparison: less than or equal equal")
        {
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    // check definition
                    CHECK( (j_values[i] <= j_values[j]) == not(j_values[j] < j_values[i]) );
                }
            }
        }

        SECTION("comparison: greater than")
        {
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    // check definition
                    CHECK( (j_values[i] > j_values[j]) == (j_values[j] < j_values[i]) );
                }
            }
        }

        SECTION("comparison: greater than or equal")
        {
            for (size_t i = 0; i < j_values.size(); ++i)
            {
                for (size_t j = 0; j < j_values.size(); ++j)
                {
                    CAPTURE(i)
                    CAPTURE(j)
                    // check definition
                    CHECK( (j_values[i] >= j_values[j]) == not(j_values[i] < j_values[j]) );
                }
            }
        }
    }
}
