#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "json.hpp"
using nlohmann::json;

#include <array>
#include <deque>
#include <forward_list>
#include <list>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

TEST_CASE("constructors")
{
    SECTION("create an empty value with a given type")
    {
        SECTION("null")
        {
            auto t = json::value_t::null;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("object")
        {
            auto t = json::value_t::object;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("array")
        {
            auto t = json::value_t::array;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("boolean")
        {
            auto t = json::value_t::boolean;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("string")
        {
            auto t = json::value_t::string;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("number_integer")
        {
            auto t = json::value_t::number_integer;
            json j(t);
            CHECK(j.type() == t);
        }

        SECTION("number_float")
        {
            auto t = json::value_t::number_float;
            json j(t);
            CHECK(j.type() == t);
        }
    }

    SECTION("create a null object (implicitly)")
    {
        SECTION("no parameter")
        {
            json j{};
            CHECK(j.type() == json::value_t::null);
        }
    }

    SECTION("create a null object (explicitly)")
    {
        SECTION("parameter")
        {
            json j(nullptr);
            CHECK(j.type() == json::value_t::null);
        }
    }

    SECTION("create an object (explicit)")
    {
        SECTION("empty object")
        {
            json::object_t o;
            json j(o);
            CHECK(j.type() == json::value_t::object);
        }

        SECTION("filled object")
        {
            json::object_t o {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
        }
    }

    SECTION("create an object (implicit)")
    {
        // reference object
        json::object_t o_reference {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
        json j_reference(o_reference);

        SECTION("std::map<std::string, json>")
        {
            std::map<std::string, json> o {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::map<const char*, json>")
        {
            std::map<const char*, json> o {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::multimap<std::string, json>")
        {
            std::multimap<std::string, json> o {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::unordered_map<std::string, json>")
        {
            std::unordered_map<std::string, json> o {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("std::unordered_multimap<std::string, json>")
        {
            std::unordered_multimap<std::string, json> o {{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}};
            json j(o);
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }

        SECTION("associative container literal")
        {
            json j({{"a", json(1)}, {"b", json(2.2)}, {"c", json(false)}, {"d", json("string")}, {"e", json()}});
            CHECK(j.type() == json::value_t::object);
            CHECK(j == j_reference);
        }
    }

    SECTION("create an array (explicit)")
    {
        SECTION("empty array")
        {
            json::array_t a;
            json j(a);
            CHECK(j.type() == json::value_t::array);
        }

        SECTION("filled array")
        {
            json::array_t a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
        }
    }

    SECTION("create an array (implicit)")
    {
        // reference array
        json::array_t a_reference {json(1), json(2.2), json(false), json("string"), json()};
        json j_reference(a_reference);

        SECTION("std::list<json>")
        {
            std::list<json> a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::forward_list<json>")
        {
            std::forward_list<json> a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::array<json, 5>")
        {
            std::array<json, 5> a {{json(1), json(2.2), json(false), json("string"), json()}};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::vector<json>")
        {
            std::vector<json> a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::deque<json>")
        {
            std::deque<json> a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }

        SECTION("std::set<json>")
        {
            std::set<json> a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            // we cannot really check for equality here
        }

        SECTION("std::unordered_set<json>")
        {
            std::unordered_set<json> a {json(1), json(2.2), json(false), json("string"), json()};
            json j(a);
            CHECK(j.type() == json::value_t::array);
            // we cannot really check for equality here
        }

        SECTION("sequence container literal")
        {
            json j({json(1), json(2.2), json(false), json("string"), json()});
            CHECK(j.type() == json::value_t::array);
            CHECK(j == j_reference);
        }
    }

    SECTION("create a string (explicit)")
    {
        SECTION("empty string")
        {
            json::string_t s;
            json j(s);
            CHECK(j.type() == json::value_t::string);
        }

        SECTION("filled string")
        {
            json::string_t s {"Hello world"};
            json j(s);
            CHECK(j.type() == json::value_t::string);
        }
    }

    SECTION("create a string (implicit)")
    {
        // reference string
        json::string_t s_reference {"Hello world"};
        json j_reference(s_reference);

        SECTION("std::string")
        {
            std::string s {"Hello world"};
            json j(s);
            CHECK(j.type() == json::value_t::string);
            CHECK(j == j_reference);
        }

        SECTION("char[]")
        {
            char s[] {"Hello world"};
            json j(s);
            CHECK(j.type() == json::value_t::string);
            CHECK(j == j_reference);
        }

        SECTION("const char*")
        {
            const char* s {"Hello world"};
            json j(s);
            CHECK(j.type() == json::value_t::string);
            CHECK(j == j_reference);
        }

        SECTION("string literal")
        {
            json j("Hello world");
            CHECK(j.type() == json::value_t::string);
            CHECK(j == j_reference);
        }
    }

    SECTION("create a boolean (explicit)")
    {
        SECTION("empty boolean")
        {
            json::boolean_t b{};
            json j(b);
            CHECK(j.type() == json::value_t::boolean);
        }

        SECTION("filled boolean (true)")
        {
            json j(true);
            CHECK(j.type() == json::value_t::boolean);
        }

        SECTION("filled boolean (false)")
        {
            json j(false);
            CHECK(j.type() == json::value_t::boolean);
        }
    }

    SECTION("create an integer number (explicit)")
    {
        SECTION("uninitialized value")
        {
            json::number_integer_t n{};
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
        }

        SECTION("initialized value")
        {
            json::number_integer_t n(42);
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
        }
    }

    SECTION("create an integer number (implicit)")
    {
        // reference object
        json::number_integer_t n_reference = 42;
        json j_reference(n_reference);

        SECTION("short")
        {
            short n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("unsigned short")
        {
            unsigned short n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int")
        {
            int n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("unsigned int")
        {
            unsigned int n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("long")
        {
            long n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("unsigned long")
        {
            short n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("long long")
        {
            long long n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("unsigned long long")
        {
            unsigned long long n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int8_t")
        {
            int8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int16_t")
        {
            int16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int32_t")
        {
            int32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int64_t")
        {
            int64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_fast8_t")
        {
            int_fast8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_fast16_t")
        {
            int_fast16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_fast32_t")
        {
            int_fast32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_fast64_t")
        {
            int_fast64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_least8_t")
        {
            int_least8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_least16_t")
        {
            int_least16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_least32_t")
        {
            int_least32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("int_least64_t")
        {
            int_least64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint8_t")
        {
            uint8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint16_t")
        {
            uint16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint32_t")
        {
            uint32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint64_t")
        {
            uint64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_fast8_t")
        {
            uint_fast8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_fast16_t")
        {
            uint_fast16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_fast32_t")
        {
            uint_fast32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_fast64_t")
        {
            uint_fast64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_least8_t")
        {
            uint_least8_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_least16_t")
        {
            uint_least16_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_least32_t")
        {
            uint_least32_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("uint_least64_t")
        {
            uint_least64_t n = 42;
            json j(n);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("integer literal without suffix")
        {
            json j(42);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("integer literal with u suffix")
        {
            json j(42u);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("integer literal with l suffix")
        {
            json j(42l);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("integer literal with ul suffix")
        {
            json j(42ul);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("integer literal with ll suffix")
        {
            json j(42ll);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }

        SECTION("integer literal with ull suffix")
        {
            json j(42ull);
            CHECK(j.type() == json::value_t::number_integer);
            CHECK(j == j_reference);
        }
    }

    SECTION("create a floating-point number (explicit)")
    {
        SECTION("uninitialized value")
        {
            json::number_float_t n{};
            json j(n);
            CHECK(j.type() == json::value_t::number_float);
        }

        SECTION("initialized value")
        {
            json::number_float_t n(42.23);
            json j(n);
            CHECK(j.type() == json::value_t::number_float);
        }
    }

    SECTION("create a floating-point number (implicit)")
    {
        // reference object
        json::number_float_t n_reference = 42.23;
        json j_reference(n_reference);

        SECTION("float")
        {
            float n = 42.23;
            json j(n);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_value.number_float == Approx(j_reference.m_value.number_float));
        }

        SECTION("double")
        {
            double n = 42.23;
            json j(n);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_value.number_float == Approx(j_reference.m_value.number_float));
        }

        SECTION("long double")
        {
            long double n = 42.23;
            json j(n);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_value.number_float == Approx(j_reference.m_value.number_float));
        }

        SECTION("floating-point literal without suffix")
        {
            json j(42.23);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_value.number_float == Approx(j_reference.m_value.number_float));
        }

        SECTION("integer literal with f suffix")
        {
            json j(42.23f);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_value.number_float == Approx(j_reference.m_value.number_float));
        }

        SECTION("integer literal with l suffix")
        {
            json j(42.23l);
            CHECK(j.type() == json::value_t::number_float);
            CHECK(j.m_value.number_float == Approx(j_reference.m_value.number_float));
        }
    }

    SECTION("create a container (array or object) from an initializer list")
    {
        SECTION("empty initializer list")
        {
            SECTION("explicit")
            {
                std::initializer_list<json> l;
                json j(l);
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("implicit")
            {
                json j {};
                CHECK(j.type() == json::value_t::null);
            }
        }

        SECTION("one element")
        {
            SECTION("array")
            {
                SECTION("explicit")
                {
                    std::initializer_list<json> l = {json(json::array_t())};
                    json j(l);
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {json::array_t()};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("object")
            {
                SECTION("explicit")
                {
                    std::initializer_list<json> l = {json(json::object_t())};
                    json j(l);
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {json::object_t()};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("string")
            {
                SECTION("explicit")
                {
                    std::initializer_list<json> l = {json("Hello world")};
                    json j(l);
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {"Hello world"};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("boolean")
            {
                SECTION("explicit")
                {
                    std::initializer_list<json> l = {json(true)};
                    json j(l);
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {true};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("number (integer)")
            {
                SECTION("explicit")
                {
                    std::initializer_list<json> l = {json(1)};
                    json j(l);
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {1};
                    CHECK(j.type() == json::value_t::array);
                }
            }

            SECTION("number (floating-point)")
            {
                SECTION("explicit")
                {
                    std::initializer_list<json> l = {json(42.23)};
                    json j(l);
                    CHECK(j.type() == json::value_t::array);
                }

                SECTION("implicit")
                {
                    json j {42.23};
                    CHECK(j.type() == json::value_t::array);
                }
            }
        }

        SECTION("more elements")
        {
            SECTION("explicit")
            {
                std::initializer_list<json> l = {1, 42.23, true, nullptr, json::object_t(), json::array_t()};
                json j(l);
                CHECK(j.type() == json::value_t::array);
            }

            SECTION("implicit")
            {
                json j {1, 42.23, true, nullptr, json::object_t(), json::array_t()};
                CHECK(j.type() == json::value_t::array);
            }
        }

        SECTION("implicit type deduction")
        {
            SECTION("object")
            {
                json j { {"one", 1}, {"two", 2.2}, {"three", false} };
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("array")
            {
                json j { {"one", 1}, {"two", 2.2}, {"three", false}, 13 };
                CHECK(j.type() == json::value_t::array);
            }
        }

        SECTION("explicit type deduction")
        {
            SECTION("empty object")
            {
                json j = json::object();
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("object")
            {
                json j = json::object({ {"one", 1}, {"two", 2.2}, {"three", false} });
                CHECK(j.type() == json::value_t::object);
            }

            SECTION("object with error")
            {
                CHECK_THROWS_AS(json::object({ {"one", 1}, {"two", 2.2}, {"three", false}, 13 }), std::logic_error);
            }

            SECTION("empty array")
            {
                json j = json::array();
                CHECK(j.type() == json::value_t::array);
            }

            SECTION("array")
            {
                json j = json::array({ {"one", 1}, {"two", 2.2}, {"three", false} });
                CHECK(j.type() == json::value_t::array);
            }
        }
    }
}

TEST_CASE("other constructors and destructor")
{
    SECTION("copy constructor")
    {
        SECTION("object")
        {
            json j {{"foo", 1}, {"bar", false}};
            json k(j);
            CHECK(j == k);
        }

        SECTION("array")
        {
            json j {"foo", 1, 42.23, false};
            json k(j);
            CHECK(j == k);
        }

        SECTION("null")
        {
            json j(nullptr);
            json k(j);
            CHECK(j == k);
        }

        SECTION("boolean")
        {
            json j(true);
            json k(j);
            CHECK(j == k);
        }

        SECTION("string")
        {
            json j("Hello world");
            json k(j);
            CHECK(j == k);
        }

        SECTION("number (integer)")
        {
            json j(42);
            json k(j);
            CHECK(j == k);
        }

        SECTION("number (floating-point)")
        {
            json j(42.23);
            json k(j);
            CHECK(j == k);
        }
    }

    SECTION("move constructor")
    {
        json j {{"foo", "bar"}, {"baz", {1, 2, 3, 4}}, {"a", 42.23}, {"b", nullptr}};
        CHECK(j.type() == json::value_t::object);
        json k(std::move(j));
        CHECK(k.type() == json::value_t::object);
        CHECK(j.type() == json::value_t::null);
    }

    SECTION("copy assignment")
    {
        SECTION("object")
        {
            json j {{"foo", 1}, {"bar", false}};
            json k = j;
            CHECK(j == k);
        }

        SECTION("array")
        {
            json j {"foo", 1, 42.23, false};
            json k = j;
            CHECK(j == k);
        }

        SECTION("null")
        {
            json j(nullptr);
            json k = j;
            CHECK(j == k);
        }

        SECTION("boolean")
        {
            json j(true);
            json k = j;
            CHECK(j == k);
        }

        SECTION("string")
        {
            json j("Hello world");
            json k = j;
            CHECK(j == k);
        }

        SECTION("number (integer)")
        {
            json j(42);
            json k = j;
            CHECK(j == k);
        }

        SECTION("number (floating-point)")
        {
            json j(42.23);
            json k = j;
            CHECK(j == k);
        }
    }

    SECTION("destructor")
    {
        SECTION("object")
        {
            auto j = new json {{"foo", 1}, {"bar", false}};
            delete j;
        }

        SECTION("array")
        {
            auto j = new json {"foo", 1, false, 23.42};
            delete j;
        }

        SECTION("string")
        {
            auto j = new json("Hello world");
            delete j;
        }
    }
}

TEST_CASE("object inspection")
{
    SECTION("serialization")
    {
        json j {{"object", json::object()}, {"array", {1, 2, 3, 4}}, {"number", 42}, {"boolean", false}, {"null", nullptr}, {"string", "Hello world"} };

        SECTION("no indent")
        {
            CHECK(j.dump() ==
                  "{\"array\":[1,2,3,4],\"boolean\":false,\"null\":null,\"number\":42,\"object\":{},\"string\":\"Hello world\"}");
        }

        SECTION("indent=0")
        {
            CHECK(j.dump(0) ==
                  "{\n\"array\": [\n1,\n2,\n3,\n4\n],\n\"boolean\": false,\n\"null\": null,\n\"number\": 42,\n\"object\": {},\n\"string\": \"Hello world\"\n}");
        }

        SECTION("indent=4")
        {
            CHECK(j.dump(4) ==
                  "{\n    \"array\": [\n        1,\n        2,\n        3,\n        4\n    ],\n    \"boolean\": false,\n    \"null\": null,\n    \"number\": 42,\n    \"object\": {},\n    \"string\": \"Hello world\"\n}");
        }

        SECTION("dump and floating-point numbers")
        {
            auto s = json(42.23).dump();
            CHECK(s.find("42.23") != std::string::npos);
        }
    }

    SECTION("return the type of the object (explicit)")
    {
        SECTION("null")
        {
            json j = nullptr;
            CHECK(j.type() == json::value_t::null);
        }

        SECTION("object")
        {
            json j = {{"foo", "bar"}};
            CHECK(j.type() == json::value_t::object);
        }

        SECTION("array")
        {
            json j = {1, 2, 3, 4};
            CHECK(j.type() == json::value_t::array);
        }

        SECTION("boolean")
        {
            json j = true;
            CHECK(j.type() == json::value_t::boolean);
        }

        SECTION("string")
        {
            json j = "Hello world";
            CHECK(j.type() == json::value_t::string);
        }

        SECTION("number (integer)")
        {
            json j = 23;
            CHECK(j.type() == json::value_t::number_integer);
        }

        SECTION("number (floating-point)")
        {
            json j = 42.23;
            CHECK(j.type() == json::value_t::number_float);
        }
    }

    SECTION("return the type of the object (implicit)")
    {
        SECTION("null")
        {
            json j = nullptr;
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("object")
        {
            json j = {{"foo", "bar"}};
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("array")
        {
            json j = {1, 2, 3, 4};
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("boolean")
        {
            json j = true;
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("string")
        {
            json j = "Hello world";
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("number (integer)")
        {
            json j = 23;
            json::value_t t = j;
            CHECK(t == j.type());
        }

        SECTION("number (floating-point)")
        {
            json j = 42.23;
            json::value_t t = j;
            CHECK(t == j.type());
        }
    }
}

TEST_CASE("value conversion")
{
    SECTION("get an object (explicit)")
    {
        json::object_t o_reference = {{"object", json::object()}, {"array", {1, 2, 3, 4}}, {"number", 42}, {"boolean", false}, {"null", nullptr}, {"string", "Hello world"} };
        json j(o_reference);

        SECTION("json::object_t")
        {
            json::object_t o = j.get<json::object_t>();
            CHECK(json(o) == j);
        }

        SECTION("std::map<std::string, json>")
        {
            std::map<std::string, json> o = j.get<std::map<std::string, json>>();
            CHECK(json(o) == j);
        }

        SECTION("std::multimap<std::string, json>")
        {
            std::multimap<std::string, json> o = j.get<std::multimap<std::string, json>>();
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_map<std::string, json>")
        {
            std::unordered_map<std::string, json> o = j.get<std::unordered_map<std::string, json>>();
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_multimap<std::string, json>")
        {
            std::unordered_multimap<std::string, json> o = j.get<std::unordered_multimap<std::string, json>>();
            CHECK(json(o) == j);
        }

        SECTION("exception in case of a non-object type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_integer).get<json::object_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::object_t>(), std::logic_error);
        }
    }

    SECTION("get an object (implicit)")
    {
        json::object_t o_reference = {{"object", json::object()}, {"array", {1, 2, 3, 4}}, {"number", 42}, {"boolean", false}, {"null", nullptr}, {"string", "Hello world"} };
        json j(o_reference);

        SECTION("json::object_t")
        {
            json::object_t o = j;
            CHECK(json(o) == j);
        }

        SECTION("std::map<std::string, json>")
        {
            std::map<std::string, json> o = j;
            CHECK(json(o) == j);
        }

        SECTION("std::multimap<std::string, json>")
        {
            std::multimap<std::string, json> o = j;
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_map<std::string, json>")
        {
            std::unordered_map<std::string, json> o = j;
            CHECK(json(o) == j);
        }

        SECTION("std::unordered_multimap<std::string, json>")
        {
            std::unordered_multimap<std::string, json> o = j;
            CHECK(json(o) == j);
        }
    }

    SECTION("get an array (explicit)")
    {
        json::array_t a_reference {json(1), json(2.2), json(false), json("string"), json()};
        json j(a_reference);

        SECTION("json::array_t")
        {
            json::array_t a = j.get<json::array_t>();
            CHECK(json(a) == j);
        }

        SECTION("std::list<json>")
        {
            std::list<json> a = j.get<std::list<json>>();
            CHECK(json(a) == j);
        }

        SECTION("std::forward_list<json>")
        {
            std::forward_list<json> a = j.get<std::forward_list<json>>();
            CHECK(json(a) == j);
        }

        SECTION("std::vector<json>")
        {
            std::vector<json> a = j.get<std::vector<json>>();
            CHECK(json(a) == j);
        }

        SECTION("std::deque<json>")
        {
            std::deque<json> a = j.get<std::deque<json>>();
            CHECK(json(a) == j);
        }

        SECTION("exception in case of a non-array type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_integer).get<json::array_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::array_t>(), std::logic_error);
        }
    }

    SECTION("get an array (implicit)")
    {
        json::array_t a_reference {json(1), json(2.2), json(false), json("string"), json()};
        json j(a_reference);

        SECTION("json::array_t")
        {
            json::array_t a = j;
            CHECK(json(a) == j);
        }

        SECTION("std::list<json>")
        {
            std::list<json> a = j;
            CHECK(json(a) == j);
        }

        SECTION("std::forward_list<json>")
        {
            std::forward_list<json> a = j;
            CHECK(json(a) == j);
        }

        SECTION("std::vector<json>")
        {
            std::vector<json> a = j;
            CHECK(json(a) == j);
        }

        SECTION("std::deque<json>")
        {
            std::deque<json> a = j;
            CHECK(json(a) == j);
        }
    }

    SECTION("get a string (explicit)")
    {
        json::string_t s_reference {"Hello world"};
        json j(s_reference);

        SECTION("string_t")
        {
            json::string_t s = j.get<json::string_t>();
            CHECK(json(s) == j);
        }

        SECTION("std::string")
        {
            std::string s = j.get<std::string>();
            CHECK(json(s) == j);
        }

        SECTION("exception in case of a non-string type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_integer).get<json::string_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::string_t>(), std::logic_error);
        }
    }

    SECTION("get a string (implicit)")
    {
        json::string_t s_reference {"Hello world"};
        json j(s_reference);

        SECTION("string_t")
        {
            json::string_t s = j;
            CHECK(json(s) == j);
        }

        SECTION("std::string")
        {
            std::string s = j;
            CHECK(json(s) == j);
        }
    }

    SECTION("get a boolean (explicit)")
    {
        json::boolean_t b_reference {true};
        json j(b_reference);

        SECTION("boolean_t")
        {
            json::boolean_t b = j.get<json::boolean_t>();
            CHECK(json(b) == j);
        }

        SECTION("bool")
        {
            bool b = j.get<bool>();
            CHECK(json(b) == j);
        }

        SECTION("exception in case of a non-string type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_integer).get<json::boolean_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::number_float).get<json::boolean_t>(), std::logic_error);
        }
    }

    SECTION("get a boolean (implicit)")
    {
        json::boolean_t b_reference {true};
        json j(b_reference);

        SECTION("boolean_t")
        {
            json::boolean_t b = j;
            CHECK(json(b) == j);
        }

        SECTION("bool")
        {
            bool b = j;
            CHECK(json(b) == j);
        }
    }

    SECTION("get an integer number (explicit)")
    {
        json::number_integer_t n_reference {42};
        json j(n_reference);

        SECTION("number_integer_t")
        {
            json::number_integer_t n = j.get<json::number_integer_t>();
            CHECK(json(n) == j);
        }

        SECTION("short")
        {
            short n = j.get<short>();
            CHECK(json(n) == j);
        }

        SECTION("unsigned short")
        {
            unsigned short n = j.get<unsigned short>();
            CHECK(json(n) == j);
        }

        SECTION("int")
        {
            int n = j.get<int>();
            CHECK(json(n) == j);
        }

        SECTION("unsigned int")
        {
            unsigned int n = j.get<unsigned int>();
            CHECK(json(n) == j);
        }

        SECTION("long")
        {
            long n = j.get<long>();
            CHECK(json(n) == j);
        }

        SECTION("unsigned long")
        {
            unsigned long n = j.get<unsigned long>();
            CHECK(json(n) == j);
        }

        SECTION("long long")
        {
            long long n = j.get<long long>();
            CHECK(json(n) == j);
        }

        SECTION("unsigned long long")
        {
            unsigned long long n = j.get<unsigned long long>();
            CHECK(json(n) == j);
        }

        SECTION("int8_t")
        {
            int8_t n = j.get<int8_t>();
            CHECK(json(n) == j);
        }

        SECTION("int16_t")
        {
            int16_t n = j.get<int16_t>();
            CHECK(json(n) == j);
        }

        SECTION("int32_t")
        {
            int32_t n = j.get<int32_t>();
            CHECK(json(n) == j);
        }

        SECTION("int64_t")
        {
            int64_t n = j.get<int64_t>();
            CHECK(json(n) == j);
        }

        SECTION("int8_fast_t")
        {
            int_fast8_t n = j.get<int_fast8_t>();
            CHECK(json(n) == j);
        }

        SECTION("int16_fast_t")
        {
            int_fast16_t n = j.get<int_fast16_t>();
            CHECK(json(n) == j);
        }

        SECTION("int32_fast_t")
        {
            int_fast32_t n = j.get<int_fast32_t>();
            CHECK(json(n) == j);
        }

        SECTION("int64_fast_t")
        {
            int_fast64_t n = j.get<int_fast64_t>();
            CHECK(json(n) == j);
        }

        SECTION("int8_least_t")
        {
            int_least8_t n = j.get<int_least8_t>();
            CHECK(json(n) == j);
        }

        SECTION("int16_least_t")
        {
            int_least16_t n = j.get<int_least16_t>();
            CHECK(json(n) == j);
        }

        SECTION("int32_least_t")
        {
            int_least32_t n = j.get<int_least32_t>();
            CHECK(json(n) == j);
        }

        SECTION("int64_least_t")
        {
            int_least64_t n = j.get<int_least64_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint8_t")
        {
            uint8_t n = j.get<uint8_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint16_t")
        {
            uint16_t n = j.get<uint16_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint32_t")
        {
            uint32_t n = j.get<uint32_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint64_t")
        {
            uint64_t n = j.get<uint64_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint8_fast_t")
        {
            uint_fast8_t n = j.get<uint_fast8_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint16_fast_t")
        {
            uint_fast16_t n = j.get<uint_fast16_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint32_fast_t")
        {
            uint_fast32_t n = j.get<uint_fast32_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint64_fast_t")
        {
            uint_fast64_t n = j.get<uint_fast64_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint8_least_t")
        {
            uint_least8_t n = j.get<uint_least8_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint16_least_t")
        {
            uint_least16_t n = j.get<uint_least16_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint32_least_t")
        {
            uint_least32_t n = j.get<uint_least32_t>();
            CHECK(json(n) == j);
        }

        SECTION("uint64_least_t")
        {
            uint_least64_t n = j.get<uint_least64_t>();
            CHECK(json(n) == j);
        }

        SECTION("exception in case of a non-number type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::number_integer_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::number_integer_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::number_integer_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::number_integer_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::number_integer_t>(), std::logic_error);
            CHECK_NOTHROW(json(json::value_t::number_float).get<json::number_integer_t>());
        }
    }

    SECTION("get an integer number (implicit)")
    {
        json::number_integer_t n_reference {42};
        json j(n_reference);

        SECTION("number_integer_t")
        {
            json::number_integer_t n = j.get<json::number_integer_t>();
            CHECK(json(n) == j);
        }

        SECTION("short")
        {
            short n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned short")
        {
            unsigned short n = j;
            CHECK(json(n) == j);
        }

        SECTION("int")
        {
            int n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned int")
        {
            unsigned int n = j;
            CHECK(json(n) == j);
        }

        SECTION("long")
        {
            long n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned long")
        {
            unsigned long n = j;
            CHECK(json(n) == j);
        }

        SECTION("long long")
        {
            long long n = j;
            CHECK(json(n) == j);
        }

        SECTION("unsigned long long")
        {
            unsigned long long n = j;
            CHECK(json(n) == j);
        }

        SECTION("int8_t")
        {
            int8_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int16_t")
        {
            int16_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int32_t")
        {
            int32_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int64_t")
        {
            int64_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int8_fast_t")
        {
            int_fast8_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int16_fast_t")
        {
            int_fast16_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int32_fast_t")
        {
            int_fast32_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int64_fast_t")
        {
            int_fast64_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int8_least_t")
        {
            int_least8_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int16_least_t")
        {
            int_least16_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int32_least_t")
        {
            int_least32_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("int64_least_t")
        {
            int_least64_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint8_t")
        {
            uint8_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint16_t")
        {
            uint16_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint32_t")
        {
            uint32_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint64_t")
        {
            uint64_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint8_fast_t")
        {
            uint_fast8_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint16_fast_t")
        {
            uint_fast16_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint32_fast_t")
        {
            uint_fast32_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint64_fast_t")
        {
            uint_fast64_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint8_least_t")
        {
            uint_least8_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint16_least_t")
        {
            uint_least16_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint32_least_t")
        {
            uint_least32_t n = j;
            CHECK(json(n) == j);
        }

        SECTION("uint64_least_t")
        {
            uint_least64_t n = j;
            CHECK(json(n) == j);
        }
    }

    SECTION("get a floating-point number (explicit)")
    {
        json::number_float_t n_reference {42.23};
        json j(n_reference);

        SECTION("number_float_t")
        {
            json::number_float_t n = j.get<json::number_float_t>();
            CHECK(json(n).m_value.number_float == Approx(j.m_value.number_float));
        }

        SECTION("float")
        {
            float n = j.get<float>();
            CHECK(json(n).m_value.number_float == Approx(j.m_value.number_float));
        }

        SECTION("double")
        {
            double n = j.get<double>();
            CHECK(json(n).m_value.number_float == Approx(j.m_value.number_float));
        }

        SECTION("exception in case of a non-string type")
        {
            CHECK_THROWS_AS(json(json::value_t::null).get<json::number_float_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::object).get<json::number_float_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::array).get<json::number_float_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::string).get<json::number_float_t>(), std::logic_error);
            CHECK_THROWS_AS(json(json::value_t::boolean).get<json::number_float_t>(), std::logic_error);
            CHECK_NOTHROW(json(json::value_t::number_integer).get<json::number_float_t>());
        }
    }

    SECTION("get a floating-point number (implicit)")
    {
        json::number_float_t n_reference {42.23};
        json j(n_reference);

        SECTION("number_float_t")
        {
            json::number_float_t n = j;
            CHECK(json(n).m_value.number_float == Approx(j.m_value.number_float));
        }

        SECTION("float")
        {
            float n = j;
            CHECK(json(n).m_value.number_float == Approx(j.m_value.number_float));
        }

        SECTION("double")
        {
            double n = j;
            CHECK(json(n).m_value.number_float == Approx(j.m_value.number_float));
        }
    }
}

TEST_CASE("element access")
{
    SECTION("array")
    {
        json j = {1, true, nullptr, "string", 42.23, json::object(), {1, 2, 3}};
        const json j_const = j;

        SECTION("access specified element with bounds checking")
        {
            SECTION("access within bounds")
            {
                CHECK(j.at(0) == json(1));
                CHECK(j.at(1) == json(true));
                CHECK(j.at(2) == json(nullptr));
                CHECK(j.at(3) == json("string"));
                CHECK(j.at(4) == json(42.23));
                CHECK(j.at(5) == json(json::object()));
                CHECK(j.at(6) == json({1, 2, 3}));

                CHECK(j_const.at(0) == json(1));
                CHECK(j_const.at(1) == json(true));
                CHECK(j_const.at(2) == json(nullptr));
                CHECK(j_const.at(3) == json("string"));
                CHECK(j_const.at(4) == json(42.23));
                CHECK(j_const.at(5) == json(json::object()));
                CHECK(j_const.at(6) == json({1, 2, 3}));
            }

            SECTION("access outside bounds")
            {
                CHECK_THROWS_AS(j.at(7), std::out_of_range);
                CHECK_THROWS_AS(j_const.at(7), std::out_of_range);
            }

            SECTION("access on non-array type")
            {
                SECTION("null")
                {
                    json j_nonarray(json::value_t::null);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::runtime_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::runtime_error);
                }

                SECTION("boolean")
                {
                    json j_nonarray(json::value_t::boolean);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::runtime_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::runtime_error);
                }

                SECTION("string")
                {
                    json j_nonarray(json::value_t::string);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::runtime_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::runtime_error);
                }

                SECTION("object")
                {
                    json j_nonarray(json::value_t::object);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::runtime_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::runtime_error);
                }

                SECTION("number (integer)")
                {
                    json j_nonarray(json::value_t::number_integer);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::runtime_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::runtime_error);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonarray(json::value_t::number_float);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray.at(0), std::runtime_error);
                    CHECK_THROWS_AS(j_nonarray_const.at(0), std::runtime_error);
                }
            }
        }

        SECTION("access specified element")
        {
            SECTION("access within bounds")
            {
                CHECK(j[0] == json(1));
                CHECK(j[1] == json(true));
                CHECK(j[2] == json(nullptr));
                CHECK(j[3] == json("string"));
                CHECK(j[4] == json(42.23));
                CHECK(j[5] == json(json::object()));
                CHECK(j[6] == json({1, 2, 3}));

                CHECK(j_const[0] == json(1));
                CHECK(j_const[1] == json(true));
                CHECK(j_const[2] == json(nullptr));
                CHECK(j_const[3] == json("string"));
                CHECK(j_const[4] == json(42.23));
                CHECK(j_const[5] == json(json::object()));
                CHECK(j_const[6] == json({1, 2, 3}));
            }

            SECTION("access on non-array type")
            {
                SECTION("null")
                {
                    json j_nonarray(json::value_t::null);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::runtime_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::runtime_error);
                }

                SECTION("boolean")
                {
                    json j_nonarray(json::value_t::boolean);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::runtime_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::runtime_error);
                }

                SECTION("string")
                {
                    json j_nonarray(json::value_t::string);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::runtime_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::runtime_error);
                }

                SECTION("object")
                {
                    json j_nonarray(json::value_t::object);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::runtime_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::runtime_error);
                }

                SECTION("number (integer)")
                {
                    json j_nonarray(json::value_t::number_integer);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::runtime_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::runtime_error);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonarray(json::value_t::number_float);
                    const json j_nonarray_const(j_nonarray);
                    CHECK_THROWS_AS(j_nonarray[0], std::runtime_error);
                    CHECK_THROWS_AS(j_nonarray_const[0], std::runtime_error);
                }
            }
        }
    }

    SECTION("object")
    {
        json j = {{"integer", 1}, {"floating", 42.23}, {"null", nullptr}, {"string", "hello world"}, {"boolean", true}, {"object", json::object()}, {"array", {1, 2, 3}}};
        const json j_const = j;

        SECTION("access specified element with bounds checking")
        {
            SECTION("access within bounds")
            {
                CHECK(j.at("integer") == json(1));
                CHECK(j.at("boolean") == json(true));
                CHECK(j.at("null") == json(nullptr));
                CHECK(j.at("string") == json("hello world"));
                CHECK(j.at("floating") == json(42.23));
                CHECK(j.at("object") == json(json::object()));
                CHECK(j.at("array") == json({1, 2, 3}));

                CHECK(j_const.at("integer") == json(1));
                CHECK(j_const.at("boolean") == json(true));
                CHECK(j_const.at("null") == json(nullptr));
                CHECK(j_const.at("string") == json("hello world"));
                CHECK(j_const.at("floating") == json(42.23));
                CHECK(j_const.at("object") == json(json::object()));
                CHECK(j_const.at("array") == json({1, 2, 3}));
            }

            SECTION("access outside bounds")
            {
                CHECK_THROWS_AS(j.at("foo"), std::out_of_range);
                CHECK_THROWS_AS(j_const.at("foo"), std::out_of_range);
            }

            SECTION("access on non-object type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::runtime_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::runtime_error);
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::runtime_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::runtime_error);
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::runtime_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::runtime_error);
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::runtime_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::runtime_error);
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::runtime_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::runtime_error);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    const json j_nonobject_const(j_nonobject);
                    CHECK_THROWS_AS(j_nonobject.at("foo"), std::runtime_error);
                    CHECK_THROWS_AS(j_nonobject_const.at("foo"), std::runtime_error);
                }
            }
        }

        SECTION("access specified element")
        {
            SECTION("access within bounds")
            {
                CHECK(j["integer"] == json(1));
                CHECK(j["boolean"] == json(true));
                CHECK(j["null"] == json(nullptr));
                CHECK(j["string"] == json("hello world"));
                CHECK(j["floating"] == json(42.23));
                CHECK(j["object"] == json(json::object()));
                CHECK(j["array"] == json({1, 2, 3}));
            }

            SECTION("access on non-object type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::runtime_error);
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::runtime_error);
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::runtime_error);
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::runtime_error);
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::runtime_error);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::runtime_error);
                }
            }
        }

        SECTION("find an element in an object")
        {
            SECTION("existing element")
            {
                for (auto key :
                        {"integer", "floating", "null", "string", "boolean", "object", "array"
                        })
                {
                    CHECK(j.find(key) != j.end());
                    CHECK(*j.find(key) == j.at(key));
                    CHECK(j_const.find(key) != j_const.end());
                    CHECK(*j_const.find(key) == j_const.at(key));
                }
            }

            SECTION("nonexisting element")
            {
                CHECK(j.find("foo") == j.end());
                CHECK(j_const.find("foo") == j_const.end());
            }

            SECTION("all types")
            {
                SECTION("null")
                {
                    json j_nonarray(json::value_t::null);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("string")
                {
                    json j_nonarray(json::value_t::string);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("object")
                {
                    json j_nonarray(json::value_t::object);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("array")
                {
                    json j_nonarray(json::value_t::array);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("boolean")
                {
                    json j_nonarray(json::value_t::boolean);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("number (integer)")
                {
                    json j_nonarray(json::value_t::number_integer);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }

                SECTION("number (floating-point)")
                {
                    json j_nonarray(json::value_t::number_float);
                    const json j_nonarray_const(j_nonarray);
                    CHECK(j_nonarray.find("foo") == j_nonarray.end());
                    CHECK(j_nonarray_const.find("foo") == j_nonarray_const.end());
                }
            }
        }
    }
}

TEST_CASE("iterators")
{
    SECTION("boolean")
    {
        json j = true;
        json j_const(j);

        SECTION("json + begin/end")
        {
            auto it = j.begin();
            CHECK(it != j.end());
            CHECK(*it == j);

            it++;
            CHECK(it != j.begin());
            CHECK(it == j.end());

            it--;
            CHECK(it == j.begin());
            CHECK(it != j.end());
            CHECK(*it == j);

            ++it;
            CHECK(it != j.begin());
            CHECK(it == j.end());

            --it;
            CHECK(it == j.begin());
            CHECK(it != j.end());
            CHECK(*it == j);
        }

        SECTION("const json + begin/end")
        {
            auto it = j_const.begin();
            CHECK(it != j_const.end());
            CHECK(*it == j_const);

            it++;
            CHECK(it != j_const.begin());
            CHECK(it == j_const.end());

            it--;
            CHECK(it == j_const.begin());
            CHECK(it != j_const.end());
            CHECK(*it == j_const);

            ++it;
            CHECK(it != j_const.begin());
            CHECK(it == j_const.end());

            --it;
            CHECK(it == j_const.begin());
            CHECK(it != j_const.end());
            CHECK(*it == j_const);
        }

        SECTION("json + cbegin/cend")
        {
            auto it = j.cbegin();
            CHECK(it != j.cend());
            CHECK(*it == j);

            it++;
            CHECK(it != j.cbegin());
            CHECK(it == j.cend());

            it--;
            CHECK(it == j.cbegin());
            CHECK(it != j.cend());
            CHECK(*it == j);

            ++it;
            CHECK(it != j.cbegin());
            CHECK(it == j.cend());

            --it;
            CHECK(it == j.cbegin());
            CHECK(it != j.cend());
            CHECK(*it == j);
        }

        SECTION("const json + cbegin/cend")
        {
            auto it = j_const.cbegin();
            CHECK(it != j_const.cend());
            CHECK(*it == j_const);

            it++;
            CHECK(it != j_const.cbegin());
            CHECK(it == j_const.cend());

            it--;
            CHECK(it == j_const.cbegin());
            CHECK(it != j_const.cend());
            CHECK(*it == j_const);

            ++it;
            CHECK(it != j_const.cbegin());
            CHECK(it == j_const.cend());

            --it;
            CHECK(it == j_const.cbegin());
            CHECK(it != j_const.cend());
            CHECK(*it == j_const);
        }
    }

    SECTION("string")
    {
        json j = "hello world";
        json j_const(j);

        SECTION("json + begin/end")
        {
            auto it = j.begin();
            CHECK(it != j.end());
            CHECK(*it == j);

            it++;
            CHECK(it != j.begin());
            CHECK(it == j.end());

            it--;
            CHECK(it == j.begin());
            CHECK(it != j.end());
            CHECK(*it == j);

            ++it;
            CHECK(it != j.begin());
            CHECK(it == j.end());

            --it;
            CHECK(it == j.begin());
            CHECK(it != j.end());
            CHECK(*it == j);
        }

        SECTION("const json + begin/end")
        {
            auto it = j_const.begin();
            CHECK(it != j_const.end());
            CHECK(*it == j_const);

            it++;
            CHECK(it != j_const.begin());
            CHECK(it == j_const.end());

            it--;
            CHECK(it == j_const.begin());
            CHECK(it != j_const.end());
            CHECK(*it == j_const);

            ++it;
            CHECK(it != j_const.begin());
            CHECK(it == j_const.end());

            --it;
            CHECK(it == j_const.begin());
            CHECK(it != j_const.end());
            CHECK(*it == j_const);
        }

        SECTION("json + cbegin/cend")
        {
            auto it = j.cbegin();
            CHECK(it != j.cend());
            CHECK(*it == j);

            it++;
            CHECK(it != j.cbegin());
            CHECK(it == j.cend());

            it--;
            CHECK(it == j.cbegin());
            CHECK(it != j.cend());
            CHECK(*it == j);

            ++it;
            CHECK(it != j.cbegin());
            CHECK(it == j.cend());

            --it;
            CHECK(it == j.cbegin());
            CHECK(it != j.cend());
            CHECK(*it == j);
        }

        SECTION("const json + cbegin/cend")
        {
            auto it = j_const.cbegin();
            CHECK(it != j_const.cend());
            CHECK(*it == j_const);

            it++;
            CHECK(it != j_const.cbegin());
            CHECK(it == j_const.cend());

            it--;
            CHECK(it == j_const.cbegin());
            CHECK(it != j_const.cend());
            CHECK(*it == j_const);

            ++it;
            CHECK(it != j_const.cbegin());
            CHECK(it == j_const.cend());

            --it;
            CHECK(it == j_const.cbegin());
            CHECK(it != j_const.cend());
            CHECK(*it == j_const);
        }
    }

    SECTION("array")
    {
        json j = {1, 2, 3, 4};
        json j_const(j);
    }

    SECTION("object")
    {
        json j = {{"one", 1}, {"two", 2}, {"three", 3}};
        json j_const(j);
    }

    SECTION("number (integer)")
    {
        json j = 23;
        json j_const(j);

        SECTION("json + begin/end")
        {
            auto it = j.begin();
            CHECK(it != j.end());
            CHECK(*it == j);

            it++;
            CHECK(it != j.begin());
            CHECK(it == j.end());

            it--;
            CHECK(it == j.begin());
            CHECK(it != j.end());
            CHECK(*it == j);

            ++it;
            CHECK(it != j.begin());
            CHECK(it == j.end());

            --it;
            CHECK(it == j.begin());
            CHECK(it != j.end());
            CHECK(*it == j);
        }

        SECTION("const json + begin/end")
        {
            auto it = j_const.begin();
            CHECK(it != j_const.end());
            CHECK(*it == j_const);

            it++;
            CHECK(it != j_const.begin());
            CHECK(it == j_const.end());

            it--;
            CHECK(it == j_const.begin());
            CHECK(it != j_const.end());
            CHECK(*it == j_const);

            ++it;
            CHECK(it != j_const.begin());
            CHECK(it == j_const.end());

            --it;
            CHECK(it == j_const.begin());
            CHECK(it != j_const.end());
            CHECK(*it == j_const);
        }

        SECTION("json + cbegin/cend")
        {
            auto it = j.cbegin();
            CHECK(it != j.cend());
            CHECK(*it == j);

            it++;
            CHECK(it != j.cbegin());
            CHECK(it == j.cend());

            it--;
            CHECK(it == j.cbegin());
            CHECK(it != j.cend());
            CHECK(*it == j);

            ++it;
            CHECK(it != j.cbegin());
            CHECK(it == j.cend());

            --it;
            CHECK(it == j.cbegin());
            CHECK(it != j.cend());
            CHECK(*it == j);
        }

        SECTION("const json + cbegin/cend")
        {
            auto it = j_const.cbegin();
            CHECK(it != j_const.cend());
            CHECK(*it == j_const);

            it++;
            CHECK(it != j_const.cbegin());
            CHECK(it == j_const.cend());

            it--;
            CHECK(it == j_const.cbegin());
            CHECK(it != j_const.cend());
            CHECK(*it == j_const);

            ++it;
            CHECK(it != j_const.cbegin());
            CHECK(it == j_const.cend());

            --it;
            CHECK(it == j_const.cbegin());
            CHECK(it != j_const.cend());
            CHECK(*it == j_const);
        }
    }

    SECTION("number (float)")
    {
        json j = 23.42;
        json j_const(j);

        SECTION("json + begin/end")
        {
            auto it = j.begin();
            CHECK(it != j.end());
            CHECK(*it == j);

            it++;
            CHECK(it != j.begin());
            CHECK(it == j.end());

            it--;
            CHECK(it == j.begin());
            CHECK(it != j.end());
            CHECK(*it == j);

            ++it;
            CHECK(it != j.begin());
            CHECK(it == j.end());

            --it;
            CHECK(it == j.begin());
            CHECK(it != j.end());
            CHECK(*it == j);
        }

        SECTION("const json + begin/end")
        {
            auto it = j_const.begin();
            CHECK(it != j_const.end());
            CHECK(*it == j_const);

            it++;
            CHECK(it != j_const.begin());
            CHECK(it == j_const.end());

            it--;
            CHECK(it == j_const.begin());
            CHECK(it != j_const.end());
            CHECK(*it == j_const);

            ++it;
            CHECK(it != j_const.begin());
            CHECK(it == j_const.end());

            --it;
            CHECK(it == j_const.begin());
            CHECK(it != j_const.end());
            CHECK(*it == j_const);
        }

        SECTION("json + cbegin/cend")
        {
            auto it = j.cbegin();
            CHECK(it != j.cend());
            CHECK(*it == j);

            it++;
            CHECK(it != j.cbegin());
            CHECK(it == j.cend());

            it--;
            CHECK(it == j.cbegin());
            CHECK(it != j.cend());
            CHECK(*it == j);

            ++it;
            CHECK(it != j.cbegin());
            CHECK(it == j.cend());

            --it;
            CHECK(it == j.cbegin());
            CHECK(it != j.cend());
            CHECK(*it == j);
        }

        SECTION("const json + cbegin/cend")
        {
            auto it = j_const.cbegin();
            CHECK(it != j_const.cend());
            CHECK(*it == j_const);

            it++;
            CHECK(it != j_const.cbegin());
            CHECK(it == j_const.cend());

            it--;
            CHECK(it == j_const.cbegin());
            CHECK(it != j_const.cend());
            CHECK(*it == j_const);

            ++it;
            CHECK(it != j_const.cbegin());
            CHECK(it == j_const.cend());

            --it;
            CHECK(it == j_const.cbegin());
            CHECK(it != j_const.cend());
            CHECK(*it == j_const);
        }
    }

    SECTION("null")
    {
        json j = nullptr;
        json j_const(j);

        SECTION("json + begin/end")
        {
            auto it = j.begin();
            CHECK(it == j.end());
        }

        SECTION("const json + begin/end")
        {
            auto it = j_const.begin();
            CHECK(it == j_const.end());
        }

        SECTION("json + cbegin/cend")
        {
            auto it = j.cbegin();
            CHECK(it == j.cend());
        }

        SECTION("const json + cbegin/cend")
        {
            auto it = j_const.cbegin();
            CHECK(it == j_const.cend());
        }
    }
}
