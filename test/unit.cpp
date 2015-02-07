#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "json.hpp"

#include <unordered_map>
#include <list>
#include <sstream>

using nlohmann::json;

TEST_CASE()
{
    CHECK(json::parser("[1,2,3,4,5,6]").parse().dump() == "[1,2,3,4,5,6]");
}

TEST_CASE()
{
    CHECK(json::escape_string("\\") == "\\\\");
    CHECK(json::escape_string("\"") == "\\\"");
    CHECK(json::escape_string("\n") == "\\n");
    CHECK(json::escape_string("\r") == "\\r");
    CHECK(json::escape_string("\f") == "\\f");
    CHECK(json::escape_string("\b") == "\\b");
    CHECK(json::escape_string("\t") == "\\t");

    CHECK(json::escape_string("Lorem ipsum \"dolor\" sit amet,\nconsectetur \\ adipiscing elit.")
          == "Lorem ipsum \\\"dolor\\\" sit amet,\\nconsectetur \\\\ adipiscing elit.");
    CHECK(json::escape_string("the main said, \"cool!\"") == "the main said, \\\"cool!\\\"");
    CHECK(json::escape_string("\a") == "\\u0007");
    CHECK(json::escape_string("\v") == "\\u000b");

    {
        json j = "AC/DC";
        CHECK(j.dump() == "\"AC/DC\"");
    }

    {
        json j = {1, 2, 3, 4};
        std::cerr << j << std::endl;
    }

    {
        json j = {{}};
        std::cerr << j << std::endl;
    }

    {
        json j = {{"foo", nullptr}};
        std::cerr << j << std::endl;
    }
    {
        json j =
        {
            {"pi", 3.141},
            {"happy", true},
            {"name", "Niels"},
            {"nothing", nullptr},
            {
                "answer", {
                    {"everything", 42}
                }
            },
            {"list", {1, 0, 2}},
            {
                "object", {
                    {"currency", "USD"},
                    {"value", 42.99}
                }
            }
        };
        std::cerr << j.dump(4) << std::endl;
        j["pi"] = {3, 1, 4, 1};
        std::cerr << j << std::endl;

        const json jc(j);
        CHECK(j.find("name") != j.end());
        CHECK(j.find("foo") == j.end());
        CHECK(*(j.find("name")) == json("Niels") );
        CHECK(jc.find("name") != jc.end());
        CHECK(jc.find("foo") == jc.end());
    }
    {
        // ways to express the empty array []
        json empty_array_implicit = {{}};
        std::cerr << "empty_array_implicit: " << empty_array_implicit << std::endl;
        json empty_array_explicit = json::array();
        std::cerr << "empty_array_explicit: " << empty_array_explicit << std::endl;

        // a way to express the empty object {}
        json empty_object_explicit = json::object();
        std::cerr << "empty_object_explicit: " << empty_object_explicit << std::endl;

        // a way to express an _array_ of key/value pairs [["currency", "USD"], ["value", 42.99]]
        json array_not_object = { json::array({"currency", "USD"}), json::array({"value", 42.99}) };
        std::cerr << "array_not_object: " << array_not_object << std::endl;
    }
    {
        CHECK_THROWS_AS(json::object({1, 2, 3}), std::logic_error);
    }
    {
        CHECK(json::object({{"foo", 1}, {"bar", 2}, {"baz", 3}}).size() == 3);
        CHECK(json::object({{"foo", 1}}).size() == 1);
        CHECK(json::object().size() == 0);
    }
    {
        json j = json::object({{"foo", 1}, {"bar", 2}, {"baz", 3}});
        {
            CHECK(j["foo"] == json(1));
            CHECK(j.at("foo") == json(1));
        }
        {
            std::map<std::string, json> m = j;
            auto k = j.get<std::map<std::string, json>>();
            CHECK(m == k);
        }
        {
            std::unordered_map<std::string, json> m = j;
            auto k = j.get<std::unordered_map<std::string, json>>();
            CHECK(m == k);
        }
    }

    {
        json j = {1, 2, 3, 4, 5};
        {
            CHECK(j[0] == json(1));
            CHECK(j.at(0) == json(1));
        }
        {
            std::vector<json> m = j;
            auto k = j.get<std::list<json>>();
            CHECK(m == k);
        }
        {
            std::set<json> m = j;
            auto k = j.get<std::set<json>>();
            CHECK(m == k);
        }
    }
}

TEST_CASE("null")
{
    SECTION("constructors")
    {
        SECTION("no arguments")
        {
            {
                json j;
                CHECK(j.m_type == json::value_t::null);
            }
            {
                json j{};
                CHECK(j.m_type == json::value_t::null);
            }
        }

        SECTION("nullptr_t argument")
        {
            {
                json j(nullptr);
                CHECK(j.m_type == json::value_t::null);
            }
        }

        SECTION("value_t::null argument")
        {
            {
                json j(json::value_t::null);
                CHECK(j.m_type == json::value_t::null);
            }
        }

        SECTION("copy constructor")
        {
            {
                json other;
                json j(other);
                CHECK(j.m_type == json::value_t::null);
            }
            {
                json j = nullptr;
                CHECK(j.m_type == json::value_t::null);
            }
        }

        SECTION("move constructor")
        {
            {
                json other;
                json j(std::move(other));
                CHECK(j.m_type == json::value_t::null);
                CHECK(other.m_type == json::value_t::null);
            }
        }

        SECTION("copy assignment")
        {
            {
                json other;
                json j = other;
                CHECK(j.m_type == json::value_t::null);
            }
        }
    }

    SECTION("object inspection")
    {
        json j;

        SECTION("dump()")
        {
            CHECK(j.dump() == "null");
            CHECK(j.dump(-1) == "null");
            CHECK(j.dump(4) == "null");
        }

        SECTION("type()")
        {
            CHECK(j.type() == j.m_type);
        }

        SECTION("operator value_t()")
        {
            json::value_t t = j;
            CHECK(t == j.m_type);
        }
    }

    SECTION("value conversion")
    {
        json j;

        SECTION("get()/operator() for objects")
        {
            CHECK_THROWS_AS(auto o = j.get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json::object_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for arrays")
        {
            CHECK_THROWS_AS(auto o = j.get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json::array_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for strings")
        {
            CHECK_THROWS_AS(auto o = j.get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json::string_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for booleans")
        {
            CHECK_THROWS_AS(auto o = j.get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json::boolean_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for integer numbers")
        {
            CHECK_THROWS_AS(auto o = j.get<json::number_integer_t>(), std::logic_error);
            CHECK_THROWS_AS(json::number_integer_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for floating point numbers")
        {
            CHECK_THROWS_AS(auto o = j.get<json::number_float_t>(), std::logic_error);
            CHECK_THROWS_AS(json::number_float_t o = j, std::logic_error);
        }
    }

    SECTION("element access")
    {
        json j;
        const json jc;

        SECTION("operator[size_type]")
        {
            CHECK_THROWS_AS(auto o = j[0], std::runtime_error);
            CHECK_THROWS_AS(auto o = jc[0], std::runtime_error);
        }

        SECTION("at(size_type)")
        {
            CHECK_THROWS_AS(auto o = j.at(0), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at(0), std::runtime_error);
        }

        SECTION("operator[object_t::key_type]")
        {
            CHECK_THROWS_AS(j["key"], std::runtime_error);
            CHECK_THROWS_AS(j[std::string("key")], std::runtime_error);
        }

        SECTION("at(object_t::key_type)")
        {
            CHECK_THROWS_AS(auto o = j.at("key"), std::runtime_error);
            CHECK_THROWS_AS(auto o = j.at(std::string("key")), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at("key"), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at(std::string("key")), std::runtime_error);
        }
    }

    SECTION("iterators")
    {
        json j;
        const json jc;

        SECTION("begin()")
        {
            {
                json::iterator it = j.begin();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                json::const_iterator it = jc.begin();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
        }

        SECTION("cbegin()")
        {
            {
                json::const_iterator it = j.cbegin();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                json::const_iterator it = jc.cbegin();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                // check semantics definition of cbegin()
                CHECK(const_cast<json::const_reference>(j).begin() == j.cbegin());
                CHECK(const_cast<json::const_reference>(jc).begin() == jc.cbegin());
            }
        }

        SECTION("end()")
        {
            {
                json::iterator it = j.end();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                json::const_iterator it = jc.end();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
        }

        SECTION("cend()")
        {
            {
                json::const_iterator it = j.cend();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                json::const_iterator it = jc.cend();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                // check semantics definition of cend()
                CHECK(const_cast<json::const_reference>(j).end() == j.cend());
                CHECK(const_cast<json::const_reference>(jc).end() == jc.cend());
            }
        }
    }

    SECTION("capacity")
    {
        json j;
        const json jc;

        SECTION("empty()")
        {
            // null values are empty
            CHECK(j.empty());
            CHECK(jc.empty());

            // check semantics definition of empty()
            CHECK(j.begin() == j.end());
            CHECK(j.cbegin() == j.cend());
        }

        SECTION("size()")
        {
            // null values have size 0
            CHECK(j.size() == 0);
            CHECK(jc.size() == 0);

            // check semantics definition of size()
            CHECK(std::distance(j.begin(), j.end()) == 0);
            CHECK(std::distance(j.cbegin(), j.cend()) == 0);
        }

        SECTION("max_size()")
        {
            // null values have max_size 0
            CHECK(j.max_size() == 0);
            CHECK(jc.max_size() == 0);
        }
    }

    SECTION("modifiers")
    {
        json j;

        SECTION("clear()")
        {
            j.clear();
            CHECK(j.empty());
        }

        SECTION("push_back")
        {
            SECTION("const json&")
            {
                const json v;
                j.push_back(v);
                CHECK(j.type() == json::value_t::array);
                CHECK(j.empty() == false);
                CHECK(j.size() == 1);
                CHECK(j.max_size() >= 1);
            }

            SECTION("json&&")
            {
                j.push_back(nullptr);
                CHECK(j.type() == json::value_t::array);
                CHECK(j.empty() == false);
                CHECK(j.size() == 1);
                CHECK(j.max_size() >= 1);
            }

            SECTION("object_t::value_type&")
            {
                json::object_t::value_type v { "foo", nullptr };
                j.push_back(v);
                CHECK(j.type() == json::value_t::object);
                CHECK(j.empty() == false);
                CHECK(j.size() == 1);
                CHECK(j.max_size() >= 1);
            }
        }

        SECTION("emplace_back")
        {
            j.emplace_back(nullptr);
            CHECK(j.type() == json::value_t::array);
            CHECK(j.empty() == false);
            CHECK(j.size() == 1);
            CHECK(j.max_size() >= 1);
        }

        /*
        SECTION("operator+=")
        {
            SECTION("const json&")
            {
                const json v;
                j += v;
                CHECK(j.type() == json::value_t::array);
                CHECK(j.empty() == false);
                CHECK(j.size() == 1);
                CHECK(j.max_size() >= 1);
            }

            SECTION("json&&")
            {
                j += nullptr;
                CHECK(j.type() == json::value_t::array);
                CHECK(j.empty() == false);
                CHECK(j.size() == 1);
                CHECK(j.max_size() >= 1);
            }

            SECTION("object_t::value_type&")
            {
                json::object_t::value_type v { "foo", nullptr };
                j += v;
                CHECK(j.type() == json::value_t::object);
                CHECK(j.empty() == false);
                CHECK(j.size() == 1);
                CHECK(j.max_size() >= 1);
            }
        }
        */

        SECTION("swap")
        {
            SECTION("array_t&")
            {
                json::array_t other = {nullptr, nullptr, nullptr};
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }

            SECTION("object_t&")
            {
                json::object_t other = {{"key1", nullptr}, {"key2", nullptr}};
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }

            SECTION("string_t&")
            {
                json::string_t other = "string";
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }
        }
    }

    SECTION("lexicographical comparison operators")
    {
        json j1, j2;

        CHECK(j1 == j2);
        CHECK(not(j1 != j2));
        CHECK(not(j1 < j2));
        CHECK(j1 <= j2);
        CHECK(not(j1 > j2));
        CHECK(j1 >= j2);
    }

    SECTION("serialization")
    {
        json j;

        SECTION("operator<<")
        {
            std::stringstream s;
            s << j;
            CHECK(s.str() == "null");
        }

        SECTION("operator>>")
        {
            std::stringstream s;
            j >> s;
            CHECK(s.str() == "null");
        }
    }

    SECTION("convenience functions")
    {
        json j;

        SECTION("type_name")
        {
            CHECK(j.type_name() == "null");
        }
    }

    SECTION("nonmember functions")
    {
        json j1, j2;

        SECTION("swap")
        {
            std::swap(j1, j2);
        }

        SECTION("hash")
        {
            std::hash<json> hash_fn;
            auto h1 = hash_fn(j1);
            auto h2 = hash_fn(j2);
            CHECK(h1 == h2);
        }
    }
}

TEST_CASE("boolean")
{
    SECTION("constructors")
    {
        SECTION("booleant_t argument")
        {
            {
                json j(true);
                CHECK(j.m_type == json::value_t::boolean);
                CHECK(j.m_value.boolean == true);
            }
            {
                json j(false);
                CHECK(j.m_type == json::value_t::boolean);
                CHECK(j.m_value.boolean == false);
            }
        }

        SECTION("value_t::boolean argument")
        {
            {
                json j(json::value_t::boolean);
                CHECK(j.m_type == json::value_t::boolean);
                CHECK(j.m_value.boolean == false);
            }
        }

        SECTION("copy constructor")
        {
            {
                json other(true);
                json j(other);
                CHECK(j.m_type == json::value_t::boolean);
                CHECK(j.m_value.boolean == true);
            }
            {
                json other(false);
                json j(other);
                CHECK(j.m_type == json::value_t::boolean);
                CHECK(j.m_value.boolean == false);
            }
            {
                json j = true;
                CHECK(j.m_type == json::value_t::boolean);
                CHECK(j.m_value.boolean == true);
            }
            {
                json j = false;
                CHECK(j.m_type == json::value_t::boolean);
                CHECK(j.m_value.boolean == false);
            }
        }

        SECTION("move constructor")
        {
            {
                json other = true;
                json j(std::move(other));
                CHECK(j.m_type == json::value_t::boolean);
                CHECK(j.m_value.boolean == true);
                CHECK(other.m_type == json::value_t::null);
            }
        }

        SECTION("copy assignment")
        {
            {
                json other = true;
                json j = other;
                CHECK(j.m_type == json::value_t::boolean);
                CHECK(j.m_value.boolean == true);
            }
            {
                json other = false;
                json j = other;
                CHECK(j.m_type == json::value_t::boolean);
                CHECK(j.m_value.boolean == false);
            }
        }
    }

    SECTION("object inspection")
    {
        json jt = true;
        json jf = false;

        SECTION("dump()")
        {
            CHECK(jt.dump() == "true");
            CHECK(jt.dump(-1) == "true");
            CHECK(jt.dump(4) == "true");
            CHECK(jf.dump() == "false");
            CHECK(jf.dump(-1) == "false");
            CHECK(jf.dump(4) == "false");
        }

        SECTION("type()")
        {
            CHECK(jt.type() == jt.m_type);
            CHECK(jf.type() == jf.m_type);
        }

        SECTION("operator value_t()")
        {
            {
                json::value_t t = jt;
                CHECK(t == jt.m_type);
            }
            {
                json::value_t t = jf;
                CHECK(t == jf.m_type);
            }
        }
    }

    SECTION("value conversion")
    {
        json j = true;

        SECTION("get()/operator() for objects")
        {
            CHECK_THROWS_AS(auto o = j.get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json::object_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for arrays")
        {
            CHECK_THROWS_AS(auto o = j.get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json::array_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for strings")
        {
            CHECK_THROWS_AS(auto o = j.get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json::string_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for booleans")
        {
            {
                auto o = j.get<json::boolean_t>();
                CHECK(o == true);
            }
            {
                json::boolean_t o = j;
                CHECK(o == true);
            }
        }

        SECTION("get()/operator() for integer numbers")
        {
            CHECK_THROWS_AS(auto o = j.get<json::number_integer_t>(), std::logic_error);
            CHECK_THROWS_AS(json::number_integer_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for floating point numbers")
        {
            CHECK_THROWS_AS(auto o = j.get<json::number_float_t>(), std::logic_error);
            CHECK_THROWS_AS(json::number_float_t o = j, std::logic_error);
        }
    }

    SECTION("element access")
    {
        json j = true;
        const json jc = false;

        SECTION("operator[size_type]")
        {
            CHECK_THROWS_AS(auto o = j[0], std::runtime_error);
            CHECK_THROWS_AS(auto o = jc[0], std::runtime_error);
        }

        SECTION("at(size_type)")
        {
            CHECK_THROWS_AS(auto o = j.at(0), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at(0), std::runtime_error);
        }

        SECTION("operator[object_t::key_type]")
        {
            CHECK_THROWS_AS(j["key"], std::runtime_error);
            CHECK_THROWS_AS(j[std::string("key")], std::runtime_error);
        }

        SECTION("at(object_t::key_type)")
        {
            CHECK_THROWS_AS(auto o = j.at("key"), std::runtime_error);
            CHECK_THROWS_AS(auto o = j.at(std::string("key")), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at("key"), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at(std::string("key")), std::runtime_error);
        }
    }

    SECTION("iterators")
    {
        json j = true;
        const json jc = false;

        SECTION("begin()")
        {
            {
                json::iterator it = j.begin();
                CHECK(*it == j);
            }
            {
                json::const_iterator it = jc.begin();
                CHECK(*it == jc);
            }
        }

        SECTION("cbegin()")
        {
            {
                json::const_iterator it = j.cbegin();
                CHECK(*it == j);
            }
            {
                json::const_iterator it = jc.cbegin();
                CHECK(*it == jc);
            }
            {
                // check semantics definition of cbegin()
                CHECK(const_cast<json::const_reference>(j).begin() == j.cbegin());
                CHECK(const_cast<json::const_reference>(jc).begin() == jc.cbegin());
            }
        }

        SECTION("end()")
        {
            {
                json::iterator it = j.end();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                json::const_iterator it = jc.end();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
        }

        SECTION("cend()")
        {
            {
                json::const_iterator it = j.cend();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                json::const_iterator it = jc.cend();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                // check semantics definition of cend()
                CHECK(const_cast<json::const_reference>(j).end() == j.cend());
                CHECK(const_cast<json::const_reference>(jc).end() == jc.cend());
            }
        }
    }

    SECTION("capacity")
    {
        json j = true;
        const json jc = false;

        SECTION("empty()")
        {
            // null values are empty
            CHECK(not j.empty());
            CHECK(not jc.empty());

            // check semantics definition of empty()
            CHECK(j.begin() != j.end());
            CHECK(j.cbegin() != j.cend());
        }

        SECTION("size()")
        {
            // boolean values have size 1
            CHECK(j.size() == 1);
            CHECK(jc.size() == 1);

            // check semantics definition of size()
            CHECK(std::distance(j.begin(), j.end()) == 1);
            CHECK(std::distance(j.cbegin(), j.cend()) == 1);
        }

        SECTION("max_size()")
        {
            // null values have max_size 0
            CHECK(j.max_size() == 1);
            CHECK(jc.max_size() == 1);
        }
    }

    SECTION("modifiers")
    {
        json j = true;

        SECTION("clear()")
        {
            j.clear();
            CHECK(not j.empty());
            CHECK(j.m_value.boolean == false);
        }

        SECTION("push_back")
        {
            SECTION("const json&")
            {
                const json v = true;
                CHECK_THROWS_AS(j.push_back(v), std::runtime_error);
            }

            SECTION("json&&")
            {
                CHECK_THROWS_AS(j.push_back(false), std::runtime_error);
            }

            SECTION("object_t::value_type&")
            {
                json::object_t::value_type v { "foo", true };
                CHECK_THROWS_AS(j.push_back(v), std::runtime_error);
            }
        }

        SECTION("emplace_back")
        {
            CHECK_THROWS_AS(j.emplace_back(true), std::runtime_error);
        }

        /*
        SECTION("operator+=")
        {
            SECTION("const json&")
            {
                const json v = true;
                CHECK_THROWS_AS(j += v, std::runtime_error);
            }

            SECTION("json&&")
            {
                CHECK_THROWS_AS(j += true, std::runtime_error);
            }

            SECTION("object_t::value_type&")
            {
                json::object_t::value_type v { "foo", true };
                CHECK_THROWS_AS(j += v, std::runtime_error);
            }
        }
        */

        SECTION("swap")
        {
            SECTION("array_t&")
            {
                json::array_t other = {true, false};
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }

            SECTION("object_t&")
            {
                json::object_t other = {{"key1", true}, {"key2", false}};
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }

            SECTION("string_t&")
            {
                json::string_t other = "string";
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }
        }
    }

    SECTION("lexicographical comparison operators")
    {
        json j1 = true;
        json j2 = false;

        CHECK(j1 == j1);
        CHECK(not(j1 != j1));
        CHECK(not(j1 < j1));
        CHECK(j1 <= j1);
        CHECK(not(j1 > j1));
        CHECK(j1 >= j1);

        CHECK(j2 == j2);
        CHECK(not(j2 != j2));
        CHECK(not(j2 < j2));
        CHECK(j2 <= j2);
        CHECK(not(j2 > j2));
        CHECK(j2 >= j2);

        CHECK(not(j1 == j2));
        CHECK(j1 != j2);
        CHECK(not(j1 < j2));
        CHECK(not(j1 <= j2));
        CHECK(j1 > j2);
        CHECK(j1 >= j2);
    }

    SECTION("serialization")
    {
        json j1 = true;
        json j2 = false;

        SECTION("operator<<")
        {
            std::stringstream s;
            s << j1 << " " << j2;
            CHECK(s.str() == "true false");
        }

        SECTION("operator>>")
        {
            std::stringstream s;
            j1 >> s;
            j2 >> s;
            CHECK(s.str() == "truefalse");
        }
    }

    SECTION("convenience functions")
    {
        json j = true;

        SECTION("type_name")
        {
            CHECK(j.type_name() == "boolean");
        }
    }

    SECTION("nonmember functions")
    {
        json j1 = true;
        json j2 = false;

        SECTION("swap")
        {
            std::swap(j1, j2);
            CHECK(j1 == json(false));
            CHECK(j2 == json(true));
        }

        SECTION("hash")
        {
            std::hash<json> hash_fn;
            auto h1 = hash_fn(j1);
            auto h2 = hash_fn(j2);
            CHECK(h1 != h2);
        }
    }
}

TEST_CASE("number (integer)")
{
    SECTION("constructors")
    {
        SECTION("number_integer_t argument")
        {
            {
                json j(17);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == 17);
            }
            {
                json j(0);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == 0);
            }
            {
                json j(-42);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == -42);
            }
        }

        SECTION("integer type argument")
        {
            {
                int8_t v = -128;
                json j(v);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == v);
            }
            {
                uint8_t v = 255;
                json j(v);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == v);
            }
            {
                int16_t v = -32768;
                json j(v);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == v);
            }
            {
                uint16_t v = 65535;
                json j(v);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == v);
            }
            {
                int32_t v = -2147483648;
                json j(v);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == v);
            }
            {
                uint32_t v = 4294967295;
                json j(v);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == v);
            }
            {
                int64_t v = INT64_MIN;
                json j(v);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == v);
            }
            {
                int64_t v = INT64_MAX;
                json j(v);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == v);
            }
        }

        SECTION("value_t::number_integer argument")
        {
            {
                json j(json::value_t::number_integer);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == 0);
            }
        }

        SECTION("copy constructor")
        {
            {
                json other(117);
                json j(other);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == 117);
            }
            {
                json other(-49);
                json j(other);
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == -49);
            }
            {
                json j = 110;
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == 110);
            }
            {
                json j = 112;
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == 112);
            }
        }

        SECTION("move constructor")
        {
            {
                json other = 7653434;
                json j(std::move(other));
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == 7653434);
                CHECK(other.m_type == json::value_t::null);
            }
        }

        SECTION("copy assignment")
        {
            {
                json other = 333;
                json j = other;
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == 333);
            }
            {
                json other = 555;
                json j = other;
                CHECK(j.m_type == json::value_t::number_integer);
                CHECK(j.m_value.number_integer == 555);
            }
        }
    }

    SECTION("object inspection")
    {
        json jp = 4294967295;
        json jn = -4294967295;

        SECTION("dump()")
        {
            CHECK(jp.dump() == "4294967295");
            CHECK(jn.dump(-1) == "-4294967295");
            CHECK(jp.dump(4) == "4294967295");
            CHECK(jn.dump() == "-4294967295");
            CHECK(jp.dump(-1) == "4294967295");
            CHECK(jn.dump(4) == "-4294967295");
        }

        SECTION("type()")
        {
            CHECK(jp.type() == jp.m_type);
            CHECK(jn.type() == jn.m_type);
        }

        SECTION("operator value_t()")
        {
            {
                json::value_t t = jp;
                CHECK(t == jp.m_type);
            }
            {
                json::value_t t = jn;
                CHECK(t == jn.m_type);
            }
        }
    }

    SECTION("value conversion")
    {
        json j = 1003;

        SECTION("get()/operator() for objects")
        {
            CHECK_THROWS_AS(auto o = j.get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json::object_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for arrays")
        {
            CHECK_THROWS_AS(auto o = j.get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json::array_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for strings")
        {
            CHECK_THROWS_AS(auto o = j.get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json::string_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for booleans")
        {
            CHECK_THROWS_AS(auto o = j.get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json::boolean_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for integer numbers")
        {
            {
                auto o = j.get<json::number_integer_t>();
                CHECK(o == 1003);
            }
            {
                json::number_integer_t o = j;
                CHECK(o == 1003);
            }
        }

        SECTION("get()/operator() for floating point numbers")
        {
            {
                auto o = j.get<json::number_float_t>();
                CHECK(o == 1003);
            }
            {
                json::number_float_t o = j;
                CHECK(o == 1003);
            }
        }
    }

    SECTION("element access")
    {
        json j = 119;
        const json jc = -65433;

        SECTION("operator[size_type]")
        {
            CHECK_THROWS_AS(auto o = j[0], std::runtime_error);
            CHECK_THROWS_AS(auto o = jc[0], std::runtime_error);
        }

        SECTION("at(size_type)")
        {
            CHECK_THROWS_AS(auto o = j.at(0), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at(0), std::runtime_error);
        }

        SECTION("operator[object_t::key_type]")
        {
            CHECK_THROWS_AS(j["key"], std::runtime_error);
            CHECK_THROWS_AS(j[std::string("key")], std::runtime_error);
        }

        SECTION("at(object_t::key_type)")
        {
            CHECK_THROWS_AS(auto o = j.at("key"), std::runtime_error);
            CHECK_THROWS_AS(auto o = j.at(std::string("key")), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at("key"), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at(std::string("key")), std::runtime_error);
        }
    }

    SECTION("iterators")
    {
        json j = 0;
        const json jc = 666;

        SECTION("begin()")
        {
            {
                json::iterator it = j.begin();
                CHECK(*it == j);
            }
            {
                json::const_iterator it = jc.begin();
                CHECK(*it == jc);
            }
        }

        SECTION("cbegin()")
        {
            {
                json::const_iterator it = j.cbegin();
                CHECK(*it == j);
            }
            {
                json::const_iterator it = jc.cbegin();
                CHECK(*it == jc);
            }
            {
                // check semantics definition of cbegin()
                CHECK(const_cast<json::const_reference>(j).begin() == j.cbegin());
                CHECK(const_cast<json::const_reference>(jc).begin() == jc.cbegin());
            }
        }

        SECTION("end()")
        {
            {
                json::iterator it = j.end();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                json::const_iterator it = jc.end();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
        }

        SECTION("cend()")
        {
            {
                json::const_iterator it = j.cend();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                json::const_iterator it = jc.cend();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                // check semantics definition of cend()
                CHECK(const_cast<json::const_reference>(j).end() == j.cend());
                CHECK(const_cast<json::const_reference>(jc).end() == jc.cend());
            }
        }
    }

    SECTION("capacity")
    {
        json j = 4344;
        const json jc = -255;

        SECTION("empty()")
        {
            // null values are empty
            CHECK(not j.empty());
            CHECK(not jc.empty());

            // check semantics definition of empty()
            CHECK(j.begin() != j.end());
            CHECK(j.cbegin() != j.cend());
        }

        SECTION("size()")
        {
            // number values have size 1
            CHECK(j.size() == 1);
            CHECK(jc.size() == 1);

            // check semantics definition of size()
            CHECK(std::distance(j.begin(), j.end()) == 1);
            CHECK(std::distance(j.cbegin(), j.cend()) == 1);
        }

        SECTION("max_size()")
        {
            // null values have max_size 0
            CHECK(j.max_size() == 1);
            CHECK(jc.max_size() == 1);
        }
    }

    SECTION("modifiers")
    {
        json j = 1119;

        SECTION("clear()")
        {
            j.clear();
            CHECK(not j.empty());
            CHECK(j.m_value.number_integer == 0);
        }

        SECTION("push_back")
        {
            SECTION("const json&")
            {
                const json v = 6;
                CHECK_THROWS_AS(j.push_back(v), std::runtime_error);
            }

            SECTION("json&&")
            {
                CHECK_THROWS_AS(j.push_back(56), std::runtime_error);
            }

            SECTION("object_t::value_type&")
            {
                json::object_t::value_type v { "foo", 12 };
                CHECK_THROWS_AS(j.push_back(v), std::runtime_error);
            }
        }

        SECTION("emplace_back")
        {
            CHECK_THROWS_AS(j.emplace_back(-42), std::runtime_error);
        }

        /*
        SECTION("operator+=")
        {
            SECTION("const json&")
            {
                const json v = 8;
                CHECK_THROWS_AS(j += v, std::runtime_error);
            }

            SECTION("json&&")
            {
                CHECK_THROWS_AS(j += 0, std::runtime_error);
            }

            SECTION("object_t::value_type&")
            {
                json::object_t::value_type v { "foo", 42 };
                CHECK_THROWS_AS(j += v, std::runtime_error);
            }
        }
        */

        SECTION("swap")
        {
            SECTION("array_t&")
            {
                json::array_t other = {11, 2};
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }

            SECTION("object_t&")
            {
                json::object_t other = {{"key1", 4}, {"key2", 33}};
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }

            SECTION("string_t&")
            {
                json::string_t other = "string";
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }
        }
    }

    SECTION("lexicographical comparison operators")
    {
        json j1 = -100;
        json j2 = 100;

        CHECK(j1 == j1);
        CHECK(not(j1 != j1));
        CHECK(not(j1 < j1));
        CHECK(j1 <= j1);
        CHECK(not(j1 > j1));
        CHECK(j1 >= j1);

        CHECK(j2 == j2);
        CHECK(not(j2 != j2));
        CHECK(not(j2 < j2));
        CHECK(j2 <= j2);
        CHECK(not(j2 > j2));
        CHECK(j2 >= j2);

        CHECK(not(j1 == j2));
        CHECK(j1 != j2);
        CHECK(j1 < j2);
        CHECK(j1 <= j2);
        CHECK(not(j1 > j2));
        CHECK(not(j1 >= j2));
    }

    SECTION("serialization")
    {
        json j1 = 42;
        json j2 = 66;

        SECTION("operator<<")
        {
            std::stringstream s;
            s << j1 << " " << j2;
            CHECK(s.str() == "42 66");
        }

        SECTION("operator>>")
        {
            std::stringstream s;
            j1 >> s;
            j2 >> s;
            CHECK(s.str() == "4266");
        }
    }

    SECTION("convenience functions")
    {
        json j = 2354;

        SECTION("type_name")
        {
            CHECK(j.type_name() == "number");
        }
    }

    SECTION("nonmember functions")
    {
        json j1 = 23;
        json j2 = 32;

        SECTION("swap")
        {
            std::swap(j1, j2);
            CHECK(j1 == json(32));
            CHECK(j2 == json(23));
        }

        SECTION("hash")
        {
            std::hash<json> hash_fn;
            auto h1 = hash_fn(j1);
            auto h2 = hash_fn(j2);
            CHECK(h1 != h2);
        }
    }
}

TEST_CASE("number (floating point)")
{
    SECTION("constructors")
    {
        SECTION("number_float_t argument")
        {
            {
                json j(17.23);
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == 17.23);
            }
            {
                json j(0.0);
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == 0.0);
            }
            {
                json j(-42.1211);
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == -42.1211);
            }
        }

        SECTION("floating type argument")
        {
            {
                float v = 3.14159265359;
                json j(v);
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == v);
            }
            {
                double v = 2.71828182846;
                json j(v);
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == v);
            }
            {
                long double v = 1.57079632679;
                json j(v);
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == v);
            }
        }

        SECTION("value_t::number_float argument")
        {
            {
                json j(json::value_t::number_float);
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == 0.0);
            }
        }

        SECTION("copy constructor")
        {
            {
                json other(117.1);
                json j(other);
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == 117.1);
            }
            {
                json other(-49.00);
                json j(other);
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == -49.00);
            }
            {
                json j = 110.22;
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == 110.22);
            }
            {
                json j = 112.5;
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == 112.5);
            }
        }

        SECTION("move constructor")
        {
            {
                json other = 7653434.99999;
                json j(std::move(other));
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == 7653434.99999);
                CHECK(other.m_type == json::value_t::null);
            }
        }

        SECTION("copy assignment")
        {
            {
                json other = 333.444;
                json j = other;
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == 333.444);
            }
            {
                json other = 555.333;
                json j = other;
                CHECK(j.m_type == json::value_t::number_float);
                CHECK(j.m_value.number_float == 555.333);
            }
        }
    }

    SECTION("object inspection")
    {
        json jp = 4294967295.333;
        json jn = -4294967249.222;

        SECTION("dump()")
        {
            CHECK(jp.dump() == "4294967295.333000");
            CHECK(jn.dump(-1) == "-4294967249.222000");
            CHECK(jp.dump(4) == "4294967295.333000");
            CHECK(jn.dump() == "-4294967249.222000");
            CHECK(jp.dump(-1) == "4294967295.333000");
            CHECK(jn.dump(4) == "-4294967249.222000");
        }

        SECTION("type()")
        {
            CHECK(jp.type() == jp.m_type);
            CHECK(jn.type() == jn.m_type);
        }

        SECTION("operator value_t()")
        {
            {
                json::value_t t = jp;
                CHECK(t == jp.m_type);
            }
            {
                json::value_t t = jn;
                CHECK(t == jn.m_type);
            }
        }
    }

    SECTION("value conversion")
    {
        json j = 10203.444344;

        SECTION("get()/operator() for objects")
        {
            CHECK_THROWS_AS(auto o = j.get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json::object_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for arrays")
        {
            CHECK_THROWS_AS(auto o = j.get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json::array_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for strings")
        {
            CHECK_THROWS_AS(auto o = j.get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json::string_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for booleans")
        {
            CHECK_THROWS_AS(auto o = j.get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json::boolean_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for integer numbers")
        {
            {
                auto o = j.get<json::number_integer_t>();
                CHECK(o == 10203);
            }
            {
                json::number_integer_t o = j;
                CHECK(o == 10203);
            }
        }

        SECTION("get()/operator() for floating point numbers")
        {
            {
                auto o = j.get<json::number_float_t>();
                CHECK(o == 10203.444344);
            }
            {
                json::number_float_t o = j;
                CHECK(o == 10203.444344);
            }
        }
    }

    SECTION("element access")
    {
        json j = 119.3333;
        const json jc = -65433.55343;

        SECTION("operator[size_type]")
        {
            CHECK_THROWS_AS(auto o = j[0], std::runtime_error);
            CHECK_THROWS_AS(auto o = jc[0], std::runtime_error);
        }

        SECTION("at(size_type)")
        {
            CHECK_THROWS_AS(auto o = j.at(0), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at(0), std::runtime_error);
        }

        SECTION("operator[object_t::key_type]")
        {
            CHECK_THROWS_AS(j["key"], std::runtime_error);
            CHECK_THROWS_AS(j[std::string("key")], std::runtime_error);
        }

        SECTION("at(object_t::key_type)")
        {
            CHECK_THROWS_AS(auto o = j.at("key"), std::runtime_error);
            CHECK_THROWS_AS(auto o = j.at(std::string("key")), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at("key"), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at(std::string("key")), std::runtime_error);
        }
    }

    SECTION("iterators")
    {
        json j = 0.0;
        const json jc = -666.22233322;

        SECTION("begin()")
        {
            {
                json::iterator it = j.begin();
                CHECK(*it == j);
            }
            {
                json::const_iterator it = jc.begin();
                CHECK(*it == jc);
            }
        }

        SECTION("cbegin()")
        {
            {
                json::const_iterator it = j.cbegin();
                CHECK(*it == j);
            }
            {
                json::const_iterator it = jc.cbegin();
                CHECK(*it == jc);
            }
            {
                // check semantics definition of cbegin()
                CHECK(const_cast<json::const_reference>(j).begin() == j.cbegin());
                CHECK(const_cast<json::const_reference>(jc).begin() == jc.cbegin());
            }
        }

        SECTION("end()")
        {
            {
                json::iterator it = j.end();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                json::const_iterator it = jc.end();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
        }

        SECTION("cend()")
        {
            {
                json::const_iterator it = j.cend();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                json::const_iterator it = jc.cend();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                // check semantics definition of cend()
                CHECK(const_cast<json::const_reference>(j).end() == j.cend());
                CHECK(const_cast<json::const_reference>(jc).end() == jc.cend());
            }
        }
    }

    SECTION("capacity")
    {
        json j = 4344.0;
        const json jc = -255.1;

        SECTION("empty()")
        {
            // null values are empty
            CHECK(not j.empty());
            CHECK(not jc.empty());

            // check semantics definition of empty()
            CHECK(j.begin() != j.end());
            CHECK(j.cbegin() != j.cend());
        }

        SECTION("size()")
        {
            // number values have size 1
            CHECK(j.size() == 1);
            CHECK(jc.size() == 1);

            // check semantics definition of size()
            CHECK(std::distance(j.begin(), j.end()) == 1);
            CHECK(std::distance(j.cbegin(), j.cend()) == 1);
        }

        SECTION("max_size()")
        {
            // null values have max_size 0
            CHECK(j.max_size() == 1);
            CHECK(jc.max_size() == 1);
        }
    }

    SECTION("modifiers")
    {
        json j = 1119.12;

        SECTION("clear()")
        {
            j.clear();
            CHECK(not j.empty());
            CHECK(j.m_value.number_float == 0.0);
        }

        SECTION("push_back")
        {
            SECTION("const json&")
            {
                const json v = 6.2;
                CHECK_THROWS_AS(j.push_back(v), std::runtime_error);
            }

            SECTION("json&&")
            {
                CHECK_THROWS_AS(j.push_back(56.11), std::runtime_error);
            }

            SECTION("object_t::value_type&")
            {
                json::object_t::value_type v { "foo", 12.2 };
                CHECK_THROWS_AS(j.push_back(v), std::runtime_error);
            }
        }

        SECTION("emplace_back")
        {
            CHECK_THROWS_AS(j.emplace_back(-42.55), std::runtime_error);
        }

        /*
        SECTION("operator+=")
        {
            SECTION("const json&")
            {
                const json v = 8.4;
                CHECK_THROWS_AS(j += v, std::runtime_error);
            }

            SECTION("json&&")
            {
                CHECK_THROWS_AS(j += 0, std::runtime_error);
            }

            SECTION("object_t::value_type&")
            {
                json::object_t::value_type v { "foo", 4.42 };
                CHECK_THROWS_AS(j += v, std::runtime_error);
            }
        }
        */

        SECTION("swap")
        {
            SECTION("array_t&")
            {
                json::array_t other = {11.2, 2.4};
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }

            SECTION("object_t&")
            {
                json::object_t other = {{"key1", 44.4}, {"key2", 23.2}};
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }

            SECTION("string_t&")
            {
                json::string_t other = "string";
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }
        }
    }

    SECTION("lexicographical comparison operators")
    {
        json j1 = -100.55;
        json j2 = 100.4;

        CHECK(j1 == j1);
        CHECK(not(j1 != j1));
        CHECK(not(j1 < j1));
        CHECK(j1 <= j1);
        CHECK(not(j1 > j1));
        CHECK(j1 >= j1);

        CHECK(j2 == j2);
        CHECK(not(j2 != j2));
        CHECK(not(j2 < j2));
        CHECK(j2 <= j2);
        CHECK(not(j2 > j2));
        CHECK(j2 >= j2);

        CHECK(not(j1 == j2));
        CHECK(j1 != j2);
        CHECK(j1 < j2);
        CHECK(j1 <= j2);
        CHECK(not(j1 > j2));
        CHECK(not(j1 >= j2));
    }

    SECTION("serialization")
    {
        json j1 = 42.23;
        json j2 = 66.66;

        SECTION("operator<<")
        {
            std::stringstream s;
            s << j1 << " " << j2;
            auto res = s.str();
            CHECK(res.find("42.23") != std::string::npos);
            CHECK(res.find("66.66") != std::string::npos);
        }

        SECTION("operator>>")
        {
            std::stringstream s;
            j1 >> s;
            j2 >> s;
            auto res = s.str();
            CHECK(res.find("42.23") != std::string::npos);
            CHECK(res.find("66.66") != std::string::npos);
        }
    }

    SECTION("convenience functions")
    {
        json j = 2354.222;

        SECTION("type_name")
        {
            CHECK(j.type_name() == "number");
        }
    }

    SECTION("nonmember functions")
    {
        json j1 = 23.44;
        json j2 = 32.44;

        SECTION("swap")
        {
            std::swap(j1, j2);
            CHECK(j1 == json(32.44));
            CHECK(j2 == json(23.44));
        }

        SECTION("hash")
        {
            std::hash<json> hash_fn;
            auto h1 = hash_fn(j1);
            auto h2 = hash_fn(j2);
            CHECK(h1 != h2);
        }
    }
}

TEST_CASE("string")
{
    SECTION("constructors")
    {
        SECTION("string_t argument")
        {
            {
                json j("hello");
                CHECK(j.m_type == json::value_t::string);
                CHECK(*(j.m_value.string) == "hello");
            }
            {
                json j("world");
                CHECK(j.m_type == json::value_t::string);
                CHECK(*(j.m_value.string) == "world");
            }
            {
                json j("this");
                CHECK(j.m_type == json::value_t::string);
                CHECK(*(j.m_value.string) == "this");
            }
        }

        SECTION("string type argument")
        {
            {
                std::string v = "3.14159265359";
                json j(v);
                CHECK(j.m_type == json::value_t::string);
                CHECK(*(j.m_value.string) == v);
            }
            {
                const char* v = "3.14159265359";
                json j(v);
                CHECK(j.m_type == json::value_t::string);
                CHECK(*(j.m_value.string) == v);
            }
            {
                char v[14] = "3.14159265359";
                json j(v);
                CHECK(j.m_type == json::value_t::string);
                CHECK(*(j.m_value.string) == v);
            }
            {
                const char v[14] = "3.14159265359";
                json j(v);
                CHECK(j.m_type == json::value_t::string);
                CHECK(*(j.m_value.string) == v);
            }
        }

        SECTION("value_t::string argument")
        {
            {
                json j(json::value_t::string);
                CHECK(j.m_type == json::value_t::string);
                CHECK(*(j.m_value.string) == "");
            }
        }

        SECTION("copy constructor")
        {
            {
                json other("foo");
                json j(other);
                CHECK(j.m_type == json::value_t::string);
                CHECK(*(j.m_value.string) == "foo");
            }
            {
                json j = "baz";
                CHECK(j.m_type == json::value_t::string);
                CHECK(*(j.m_value.string) == "baz");
            }
        }

        SECTION("move constructor")
        {
            {
                json other = "ß";
                json j(std::move(other));
                CHECK(j.m_type == json::value_t::string);
                CHECK(*(j.m_value.string) == "ß");
                CHECK(other.m_type == json::value_t::null);
            }
        }

        SECTION("copy assignment")
        {
            {
                json other = "a string";
                json j = other;
                CHECK(j.m_type == json::value_t::string);
                CHECK(*(j.m_value.string) == "a string");
            }
        }
    }

    SECTION("object inspection")
    {
        json j = "This is a string.";

        SECTION("dump()")
        {
            CHECK(j.dump() == "\"This is a string.\"");
            CHECK(j.dump(-1) == "\"This is a string.\"");
            CHECK(j.dump(4) == "\"This is a string.\"");
        }

        SECTION("type()")
        {
            CHECK(j.type() == j.m_type);
        }

        SECTION("operator value_t()")
        {
            {
                json::value_t t = j;
                CHECK(t == j.m_type);
            }
        }
    }

    SECTION("value conversion")
    {
        json j = "another example string";

        SECTION("get()/operator() for objects")
        {
            CHECK_THROWS_AS(auto o = j.get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json::object_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for arrays")
        {
            CHECK_THROWS_AS(auto o = j.get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json::array_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for strings")
        {
            {
                auto o = j.get<json::string_t>();
                CHECK(o == "another example string");
            }
            {
                json::string_t o = j;
                CHECK(o == "another example string");
            }
        }

        SECTION("get()/operator() for booleans")
        {
            CHECK_THROWS_AS(auto o = j.get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json::boolean_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for integer numbers")
        {
            CHECK_THROWS_AS(auto o = j.get<json::number_integer_t>(), std::logic_error);
            CHECK_THROWS_AS(json::number_integer_t o = j, std::logic_error);
        }

        SECTION("get()/operator() for floating point numbers")
        {
            CHECK_THROWS_AS(auto o = j.get<json::number_float_t>(), std::logic_error);
            CHECK_THROWS_AS(json::number_float_t o = j, std::logic_error);
        }
    }

    SECTION("element access")
    {
        json j = "!§$&/()=";
        const json jc = "!§$&/()=";

        SECTION("operator[size_type]")
        {
            CHECK_THROWS_AS(auto o = j[0], std::runtime_error);
            CHECK_THROWS_AS(auto o = jc[0], std::runtime_error);
        }

        SECTION("at(size_type)")
        {
            CHECK_THROWS_AS(auto o = j.at(0), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at(0), std::runtime_error);
        }

        SECTION("operator[object_t::key_type]")
        {
            CHECK_THROWS_AS(j["key"], std::runtime_error);
            CHECK_THROWS_AS(j[std::string("key")], std::runtime_error);
        }

        SECTION("at(object_t::key_type)")
        {
            CHECK_THROWS_AS(auto o = j.at("key"), std::runtime_error);
            CHECK_THROWS_AS(auto o = j.at(std::string("key")), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at("key"), std::runtime_error);
            CHECK_THROWS_AS(auto o = jc.at(std::string("key")), std::runtime_error);
        }
    }

    SECTION("iterators")
    {
        json j = "@";
        const json jc = "€";

        SECTION("begin()")
        {
            {
                json::iterator it = j.begin();
                CHECK(*it == j);
            }
            {
                json::const_iterator it = jc.begin();
                CHECK(*it == jc);
            }
        }

        SECTION("cbegin()")
        {
            {
                json::const_iterator it = j.cbegin();
                CHECK(*it == j);
            }
            {
                json::const_iterator it = jc.cbegin();
                CHECK(*it == jc);
            }
            {
                // check semantics definition of cbegin()
                CHECK(const_cast<json::const_reference>(j).begin() == j.cbegin());
                CHECK(const_cast<json::const_reference>(jc).begin() == jc.cbegin());
            }
        }

        SECTION("end()")
        {
            {
                json::iterator it = j.end();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                json::const_iterator it = jc.end();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
        }

        SECTION("cend()")
        {
            {
                json::const_iterator it = j.cend();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                json::const_iterator it = jc.cend();
                CHECK_THROWS_AS(*it, std::out_of_range);
            }
            {
                // check semantics definition of cend()
                CHECK(const_cast<json::const_reference>(j).end() == j.cend());
                CHECK(const_cast<json::const_reference>(jc).end() == jc.cend());
            }
        }
    }

    SECTION("capacity")
    {
        json j = "Franz jagt im komplett verwahrlosten Taxi quer durch Bayern.";
        const json jc = "The quick brown fox jumps over the lazy dog.";

        SECTION("empty()")
        {
            // null values are empty
            CHECK(not j.empty());
            CHECK(not jc.empty());

            // check semantics definition of empty()
            CHECK(j.begin() != j.end());
            CHECK(j.cbegin() != j.cend());
        }

        SECTION("size()")
        {
            // string values have size 1
            CHECK(j.size() == 1);
            CHECK(jc.size() == 1);

            // check semantics definition of size()
            CHECK(std::distance(j.begin(), j.end()) == 1);
            CHECK(std::distance(j.cbegin(), j.cend()) == 1);
        }

        SECTION("max_size()")
        {
            // null values have max_size 0
            CHECK(j.max_size() == 1);
            CHECK(jc.max_size() == 1);
        }
    }

    SECTION("modifiers")
    {
        json j = "YOLO";

        SECTION("clear()")
        {
            j.clear();
            CHECK(not j.empty());
            CHECK(*(j.m_value.string) == "");
        }

        SECTION("push_back")
        {
            SECTION("const json&")
            {
                const json v = 6.2;
                CHECK_THROWS_AS(j.push_back(v), std::runtime_error);
            }

            SECTION("json&&")
            {
                CHECK_THROWS_AS(j.push_back(56.11), std::runtime_error);
            }

            SECTION("object_t::value_type&")
            {
                json::object_t::value_type v { "foo", 12.2 };
                CHECK_THROWS_AS(j.push_back(v), std::runtime_error);
            }
        }

        SECTION("emplace_back")
        {
            CHECK_THROWS_AS(j.emplace_back(-42.55), std::runtime_error);
        }

        /*
        SECTION("operator+=")
        {
            SECTION("const json&")
            {
                const json v = 8.4;
                CHECK_THROWS_AS(j += v, std::runtime_error);
            }

            SECTION("json&&")
            {
                CHECK_THROWS_AS(j += 0, std::runtime_error);
            }

            SECTION("object_t::value_type&")
            {
                json::object_t::value_type v { "foo", 4.42 };
                CHECK_THROWS_AS(j += v, std::runtime_error);
            }
        }
        */

        SECTION("swap")
        {
            SECTION("array_t&")
            {
                json::array_t other = {11.2, 2.4};
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }

            SECTION("object_t&")
            {
                json::object_t other = {{"key1", 44.4}, {"key2", 23.2}};
                CHECK_THROWS_AS(j.swap(other), std::runtime_error);
            }

            SECTION("string_t&")
            {
                json::string_t other = "string";
                j.swap(other);
                CHECK(other == json("YOLO"));
                CHECK(j == json("string"));
            }
        }
    }

    SECTION("lexicographical comparison operators")
    {
        json j1 = "Alpha";
        json j2 = "Omega";

        CHECK(j1 == j1);
        CHECK(not(j1 != j1));
        CHECK(not(j1 < j1));
        CHECK(j1 <= j1);
        CHECK(not(j1 > j1));
        CHECK(j1 >= j1);

        CHECK(j2 == j2);
        CHECK(not(j2 != j2));
        CHECK(not(j2 < j2));
        CHECK(j2 <= j2);
        CHECK(not(j2 > j2));
        CHECK(j2 >= j2);

        CHECK(not(j1 == j2));
        CHECK(j1 != j2);
        CHECK(j1 < j2);
        CHECK(j1 <= j2);
        CHECK(not(j1 > j2));
        CHECK(not(j1 >= j2));
    }

    SECTION("serialization")
    {
        json j1 = "flip";
        json j2 = "flop";

        SECTION("operator<<")
        {
            std::stringstream s;
            s << j1 << " " << j2;
            CHECK(s.str() == "\"flip\" \"flop\"");
        }

        SECTION("operator>>")
        {
            std::stringstream s;
            j1 >> s;
            j2 >> s;
            CHECK(s.str() == "\"flip\"\"flop\"");
        }
    }

    SECTION("convenience functions")
    {
        json j = "I am a string, believe me!";

        SECTION("type_name")
        {
            CHECK(j.type_name() == "string");
        }
    }

    SECTION("nonmember functions")
    {
        json j1 = "A";
        json j2 = "B";

        SECTION("swap")
        {
            std::swap(j1, j2);
            CHECK(j1 == json("B"));
            CHECK(j2 == json("A"));
        }

        SECTION("hash")
        {
            std::hash<json> hash_fn;
            auto h1 = hash_fn(j1);
            auto h2 = hash_fn(j2);
            CHECK(h1 != h2);
        }
    }
}
