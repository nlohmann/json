/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 2.0.5
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
Copyright (c) 2013-2016 Niels Lohmann <http://nlohmann.me>.

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

#include <string>
#include <memory>
#include "catch.hpp"

#include "json.hpp"
using nlohmann::json;

namespace udt
{
struct empty_type {};
struct pod_type {
  int a;
  char b;
  short c;
};

struct bit_more_complex_type {
  pod_type a;
  pod_type b;
  std::string c;
};

// best optional implementation ever
template <typename T>
class optional_type
{
public:
  optional_type() = default;
  explicit optional_type(T val) : _val(std::make_shared<T>(std::move(val))) {}
  explicit operator bool() const noexcept { return _val != nullptr; }

  T const &operator*() const { return *_val; }
  optional_type& operator=(T const& t)
  {
    _val = std::make_shared<T>(t);
    return *this;
  }

private:
  std::shared_ptr<T> _val;
};

// free to/from_json functions

json to_json(empty_type)
{
  return json::object();
}

json to_json(pod_type const& p)
{
  return {{"a", p.a}, {"b", p.b}, {"c", p.c}};
}

json to_json(bit_more_complex_type const& p)
{
  using nlohmann::to_json;
  return json{{"a", to_json(p.a)}, {"b", to_json(p.b)}, {"c", p.c}};
}

template <typename T>
json to_json(optional_type<T> const& opt)
{
  using nlohmann::to_json;
  if (!opt)
    return nullptr;
  return json(*opt);
}

void from_json(json const&j, empty_type& t)
{
  assert(j.empty());
  t = empty_type{};
}

void from_json(json const&j, pod_type& t)
{
  t = {j["a"].get<int>(), j["b"].get<char>(), j["c"].get<short>()};
}

void from_json(json const&j, bit_more_complex_type& t)
{
   // relying on json_traits struct here..
   t = {j["a"].get<udt::pod_type>(), j["b"].get<udt::pod_type>(),
        j["c"].get<std::string>()};
}

template <typename T>
void from_json(json const& j, optional_type<T>& t)
{
  if (j.is_null())
    t = optional_type<T>{};
  else
    t = j.get<T>();
}

inline bool operator==(pod_type const& lhs, pod_type const& rhs) noexcept
{
  return std::tie(lhs.a, lhs.b, lhs.c) == std::tie(rhs.a, rhs.b, rhs.c);
}

inline bool operator==(bit_more_complex_type const &lhs,
                       bit_more_complex_type const &rhs) noexcept {
  return std::tie(lhs.a, lhs.b, lhs.c) == std::tie(rhs.a, rhs.b, rhs.c);
}

template <typename T>
inline bool operator==(optional_type<T> const& lhs, optional_type<T> const& rhs)
{
  if (!lhs && !rhs)
    return true;
  if (!lhs || !rhs)
    return false;
  return *lhs == *rhs;
}
}

TEST_CASE("constructors for user-defined types", "[udt]")
{
  SECTION("empty type")
  {
    udt::empty_type const e{};
    auto const j = json{e};
    auto k = json::object();
    CHECK(j == k);
  }

  SECTION("pod type")
  {
    auto const e = udt::pod_type{42, 42, 42};
    auto j = json{e};
    auto k = json{{"a", 42}, {"b", 42}, {"c", 42}};
    CHECK(j == k);
  }

  SECTION("bit more complex type")
  {
    auto const e =
        udt::bit_more_complex_type{{42, 42, 42}, {41, 41, 41}, "forty"};

    auto j = json{e};
    auto k = json{{"a", {{"a", 42}, {"b", 42}, {"c", 42}}},
                  {"b", {{"a", 41}, {"b", 41}, {"c", 41}}},
                  {"c", "forty"}};
    CHECK(j == k);
  }

  SECTION("vector of udt")
  {
    std::vector<udt::bit_more_complex_type> v;
    auto const e =
        udt::bit_more_complex_type{{42, 42, 42}, {41, 41, 41}, "forty"};

    v.emplace_back(e);
    v.emplace_back(e);
    v.emplace_back(e);

    json j = v;
    auto k = json{{"a", {{"a", 42}, {"b", 42}, {"c", 42}}},
                  {"b", {{"a", 41}, {"b", 41}, {"c", 41}}},
                  {"c", "forty"}};
    auto l = json{k, k, k};
    CHECK(j == l);
  }

  SECTION("optional type") {
    SECTION("regular case") {
      udt::optional_type<int> u{3};
      CHECK(json{u} == json(3));
    }

    SECTION("nullopt case") {
      udt::optional_type<float> v;
      CHECK(json{v} == json{});
    }

    SECTION("optional of json convertible type")
    {
      auto const e =
          udt::bit_more_complex_type{{42, 42, 42}, {41, 41, 41}, "forty"};
      udt::optional_type<udt::bit_more_complex_type> o{e};
      auto k = json{{"a", {{"a", 42}, {"b", 42}, {"c", 42}}},
                    {"b", {{"a", 41}, {"b", 41}, {"c", 41}}},
                    {"c", "forty"}};
      CHECK(json{o} == k);
    }

    SECTION("optional of vector of json convertible type")
    {
      std::vector<udt::bit_more_complex_type> v;
      auto const e =
          udt::bit_more_complex_type{{42, 42, 42}, {41, 41, 41}, "forty"};
      v.emplace_back(e);
      v.emplace_back(e);
      v.emplace_back(e);
      udt::optional_type<std::vector<udt::bit_more_complex_type>> o{v};
      auto k = json{{"a", {{"a", 42}, {"b", 42}, {"c", 42}}},
                    {"b", {{"a", 41}, {"b", 41}, {"c", 41}}},
                    {"c", "forty"}};
      auto l = json{k, k, k};
      CHECK(json{o} == l);
    }
  }
}

TEST_CASE("get<> for user-defined types", "[udt]")
{
  SECTION("pod type")
  {
    auto const e = udt::pod_type{42, 42, 42};
    auto const j = json{{"a", 42}, {"b", 42}, {"c", 42}};

    auto const obj = j.get<udt::pod_type>();
    CHECK(e == obj);
  }

  SECTION("bit more complex type")
  {
    auto const e =
        udt::bit_more_complex_type{{42, 42, 42}, {41, 41, 41}, "forty"};
    auto const j = json{{"a", {{"a", 42}, {"b", 42}, {"c", 42}}},
                        {"b", {{"a", 41}, {"b", 41}, {"c", 41}}},
                        {"c", "forty"}};

    auto const obj = j.get<udt::bit_more_complex_type>();
    CHECK(e == obj);
  }

  SECTION("vector of udt")
  {
    auto const e =
        udt::bit_more_complex_type{{42, 42, 42}, {41, 41, 41}, "forty"};
    std::vector<udt::bit_more_complex_type> v{e, e, e};
    auto const j = json(v);

    auto const obj = j.get<decltype(v)>();
    CHECK(v == obj);
  }

  SECTION("optional")
  {
    SECTION("from null")
    {
      udt::optional_type<int> o;
      json j;
      CHECK(j.get<decltype(o)>() == o);
    }

    SECTION("from value")
    {
      json j{{"a", 42}, {"b", 42}, {"c", 42}};
      auto v = j.get<udt::optional_type<udt::pod_type>>();
      auto expected = udt::pod_type{42,42,42};
      REQUIRE(v);
      CHECK(*v == expected);
    }
  }
}

TEST_CASE("to_json free function", "[udt]")
{
  SECTION("pod_type")
  {
    auto const e = udt::pod_type{42, 42, 42};
    auto const expected = json{{"a", 42}, {"b", 42}, {"c", 42}};

    auto const j = nlohmann::to_json(e);
    CHECK(j == expected);
  }

  SECTION("bit_more_complex_type")
  {
    auto const e =
        udt::bit_more_complex_type{{42, 42, 42}, {41, 41, 41}, "forty"};
    auto const expected = json{{"a", {{"a", 42}, {"b", 42}, {"c", 42}}},
                        {"b", {{"a", 41}, {"b", 41}, {"c", 41}}},
                        {"c", "forty"}};
    auto const j = nlohmann::to_json(e);
    CHECK(j == expected);
  }

  SECTION("optional_type")
  {
    SECTION("from null")
    {
      udt::optional_type<udt::pod_type> o;

      json expected;
      auto const j = nlohmann::to_json(o);
      CHECK(expected == j);
    }

    SECTION("from value")
    {
      udt::optional_type<udt::pod_type> o{{42, 42, 42}};

      auto const expected = json{{"a", 42}, {"b", 42}, {"c", 42}};
      auto const j = nlohmann::to_json(o);
      CHECK(expected == j);
    }
  }
}

TEST_CASE("from_json free function", "[udt]")
{
  SECTION("pod_type")
  {
    auto const expected = udt::pod_type{42, 42, 42};
    auto const j = json{{"a", 42}, {"b", 42}, {"c", 42}};

    udt::pod_type p;
    nlohmann::from_json(j, p);
    CHECK(p == expected);
  }

  SECTION("bit_more_complex_type")
  {
    auto const expected =
        udt::bit_more_complex_type{{42, 42, 42}, {41, 41, 41}, "forty"};
    auto const j = json{{"a", {{"a", 42}, {"b", 42}, {"c", 42}}},
                        {"b", {{"a", 41}, {"b", 41}, {"c", 41}}},
                        {"c", "forty"}};
    udt::bit_more_complex_type p;
    nlohmann::from_json(j, p);
    CHECK(p == expected);
  }

  SECTION("optional_type")
  {
    SECTION("from null")
    {
      udt::optional_type<udt::pod_type> expected;
      json j;
      udt::optional_type<udt::pod_type> o;

      nlohmann::from_json(j, o);
      CHECK(expected == o);
    }

    SECTION("from value")
    {
      udt::optional_type<udt::pod_type> expected{{42, 42, 42}};
      auto const j = json{{"a", 42}, {"b", 42}, {"c", 42}};
      udt::optional_type<udt::pod_type> o;

      nlohmann::from_json(j, o);
      CHECK(expected == o);
    }
  }
}
