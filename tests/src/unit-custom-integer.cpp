/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 3.10.5
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
SPDX-License-Identifier: MIT
Copyright (c) 2013-2022 Niels Lohmann <http://nlohmann.me>.

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

/// A wrapped integer
template<typename T>
class wrapped_int
{
  public:
    T val;
    operator T() const
    {
        return val;
    }
    wrapped_int() = default;
    wrapped_int(T val) : val(val) {}

    bool operator==(const wrapped_int& other) const
    {
        return static_cast<T>(*this) == static_cast<T>(other);
    }
    bool operator<(const int& other) const
    {
        return static_cast<T>(*this) < other;
    }
    wrapped_int operator+(const wrapped_int& other) const
    {
        return static_cast<T>(*this) + static_cast<T>(other);
    }
    bool operator%(const wrapped_int& other) const
    {
        return static_cast<T>(*this) % static_cast<T>(other.val);
    }
    wrapped_int& operator/=(const wrapped_int& other)
    {
        if (val != nullptr)
        {
            *val /= static_cast<T>(other.val);
        }
        return *this;
    }
    bool operator<(const wrapped_int& other) const
    {
        return static_cast<T>(*this) <  static_cast<T>(other.val);
    }
    bool operator<=(const wrapped_int& other) const
    {
        return static_cast<T>(*this) <=  static_cast<T>(other.val);
    }

    friend void swap(wrapped_int& self, wrapped_int& other)
    {
        swap(self.val, other.val);
    }
};

template<typename T> class std::numeric_limits<wrapped_int<T>>
{
  public:
    static constexpr bool is_signed = std::numeric_limits<T>::is_signed;
    static constexpr bool is_integer = std::numeric_limits<T>::is_integer;
    static constexpr bool is_specialized = std::numeric_limits<T>::is_specialized;
};

TEST_CASE("custom integer types")
{
    using json = nlohmann::basic_json <
                 std::map, std::vector, std::string, bool,
                 wrapped_int<std::int64_t>, wrapped_int<std::uint64_t>, double, std::allocator >;
    std::string data = "[1,2,-3,-4]";
    json as_json = json::parse(data.begin(), data.end());
    wrapped_int<std::uint64_t> i1 = as_json[1];
    wrapped_int<std::int64_t> i2 = as_json[2];
    CHECK(i1 == wrapped_int<std::uint64_t>(2));
    CHECK(i2 == wrapped_int<std::int64_t>(-3));
}
