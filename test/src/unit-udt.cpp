/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (test suite)
|  |  |__   |  |  | | | |  version 2.0.7
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

#include <array>
#include <string>
#include <memory>
#include "catch.hpp"

#include "json.hpp"

namespace udt
{
  struct age
  {
    int val;
  };

  struct name
  {
    std::string val;
  };

  struct address
  {
    std::string val;
  };

  struct person
  {
    age age;
    name name;
  };

  struct contact
  {
    person person;
    address address;
  };

  struct contact_book
  {
    name book_name;
    std::vector<contact> contacts;
  };
}

// to_json methods for default basic_json
namespace udt
{
  void to_json(nlohmann::json& j, age a)
  {
    j = a.val;
  }

  void to_json(nlohmann::json& j, name const& n)
  {
    j = n.val;
  }

  void to_json(nlohmann::json& j, person const& p)
  {
    using nlohmann::json;
    j = json{{"age", json{p.age}}, {"name", json{p.name}}};

    // this unfortunately does not compile ...
    // j["age"] = p.age;
    // j["name"] = p.name;
  }

  void to_json(nlohmann::json& j, address const& a)
  {
    j = a.val;
  }

  void to_json(nlohmann::json& j, contact const& c)
  {
    using nlohmann::json;
    j = json{{"person", json{c.person}}, {"address", json{c.address}}};
  }

  void to_json(nlohmann::json& j, contact_book const& cb)
  {
    using nlohmann::json;
    j = json{{"name", json{cb.book_name}}, {"contacts", cb.contacts}};
  }
}

TEST_CASE("basic usage", "[udt]")
{
  using nlohmann::json;

  SECTION("conversion to json via free-functions")
  {
    udt::age a{23};

    CHECK(json{a} == json{23});

    // a bit narcissic maybe :) ?
    udt::name n{"theo"};
    CHECK(json{n} == json{"theo"});

    udt::person sfinae_addict{a, n};
    CHECK(json{sfinae_addict} == R"({"name":"theo", "age":23})"_json);
  }
}