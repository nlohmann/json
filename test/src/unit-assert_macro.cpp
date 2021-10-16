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

// avoid warning when assert does not abort
DOCTEST_GCC_SUPPRESS_WARNING_PUSH
DOCTEST_GCC_SUPPRESS_WARNING("-Wstrict-overflow")
DOCTEST_CLANG_SUPPRESS_WARNING_PUSH
DOCTEST_CLANG_SUPPRESS_WARNING("-Wstrict-overflow")

/// global variable to record side effect of assert calls
static int assert_counter;

/// set failure variable to true instead of calling assert(x)
#define JSON_ASSERT(x) {if (!(x)) ++assert_counter; }

#include <nlohmann/json.hpp>
using nlohmann::json;

// the test assumes exceptions to work
#if !defined(JSON_NOEXCEPTION)
TEST_CASE("JSON_ASSERT(x)")
{
    SECTION("basic_json(first, second)")
    {
        assert_counter = 0;
        CHECK(assert_counter == 0);

        json::iterator it;
        json j;

        // in case assertions do not abort execution, an exception is thrown
        CHECK_THROWS_WITH_AS(json(it, j.end()), "[json.exception.invalid_iterator.201] iterators are not compatible", json::invalid_iterator);

        // check that assertion actually happened
        CHECK(assert_counter == 1);
    }
}
#endif

DOCTEST_GCC_SUPPRESS_WARNING_POP
DOCTEST_CLANG_SUPPRESS_WARNING_POP
