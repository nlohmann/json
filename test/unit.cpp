#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "json.hpp"
using nlohmann::json;

#include <array>
#include <deque>
#include <forward_list>
#include <iomanip>
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
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("array")
        {
            json j {"foo", 1, 42.23, false};
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("null")
        {
            json j(nullptr);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("boolean")
        {
            json j(true);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("string")
        {
            json j("Hello world");
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("number (integer)")
        {
            json j(42);
            json k;
            k = j;
            CHECK(j == k);
        }

        SECTION("number (floating-point)")
        {
            json j(42.23);
            json k;
            k = j;
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

        SECTION("no indent / indent=-1")
        {
            CHECK(j.dump() ==
                  "{\"array\":[1,2,3,4],\"boolean\":false,\"null\":null,\"number\":42,\"object\":{},\"string\":\"Hello world\"}");

            CHECK(j.dump() == j.dump(-1));
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
                CHECK(j[json::object_t::key_type("integer")] == j["integer"]);

                CHECK(j["boolean"] == json(true));
                CHECK(j[json::object_t::key_type("boolean")] == j["boolean"]);

                CHECK(j["null"] == json(nullptr));
                CHECK(j[json::object_t::key_type("null")] == j["null"]);

                CHECK(j["string"] == json("hello world"));
                CHECK(j[json::object_t::key_type("string")] == j["string"]);

                CHECK(j["floating"] == json(42.23));
                CHECK(j[json::object_t::key_type("floating")] == j["floating"]);

                CHECK(j["object"] == json(json::object()));
                CHECK(j[json::object_t::key_type("object")] == j["object"]);

                CHECK(j["array"] == json({1, 2, 3}));
                CHECK(j[json::object_t::key_type("array")] == j["array"]);
            }

            SECTION("access on non-object type")
            {
                SECTION("null")
                {
                    json j_nonobject(json::value_t::null);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::runtime_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::runtime_error);
                }

                SECTION("boolean")
                {
                    json j_nonobject(json::value_t::boolean);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::runtime_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::runtime_error);
                }

                SECTION("string")
                {
                    json j_nonobject(json::value_t::string);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::runtime_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::runtime_error);
                }

                SECTION("array")
                {
                    json j_nonobject(json::value_t::array);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::runtime_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::runtime_error);
                }

                SECTION("number (integer)")
                {
                    json j_nonobject(json::value_t::number_integer);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::runtime_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::runtime_error);
                }

                SECTION("number (floating-point)")
                {
                    json j_nonobject(json::value_t::number_float);
                    CHECK_THROWS_AS(j_nonobject["foo"], std::runtime_error);
                    CHECK_THROWS_AS(j_nonobject[json::object_t::key_type("foo")], std::runtime_error);
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
            json::iterator it = j.begin();
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
            json::const_iterator it = j_const.begin();
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
            json::const_iterator it = j.cbegin();
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
            json::const_iterator it = j_const.cbegin();
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
            json::iterator it = j.begin();
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
            json::const_iterator it = j_const.begin();
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
            json::const_iterator it = j.cbegin();
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
            json::const_iterator it = j_const.cbegin();
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
        json j = {1, 2, 3};
        json j_const(j);

        SECTION("json + begin/end")
        {
            json::iterator it_begin = j.begin();
            json::iterator it_end = j.end();

            auto it = it_begin;
            CHECK(it != it_end);

            it++;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it == it_end);
        }

        SECTION("const json + begin/end")
        {
            json::const_iterator it_begin = j_const.begin();
            json::const_iterator it_end = j_const.end();

            auto it = it_begin;
            CHECK(it != it_end);

            it++;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it == it_end);
        }

        SECTION("json + cbegin/cend")
        {
            json::const_iterator it_begin = j.cbegin();
            json::const_iterator it_end = j.cend();

            auto it = it_begin;
            CHECK(it != it_end);

            it++;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it == it_end);
        }

        SECTION("const json + cbegin/cend")
        {
            json::const_iterator it_begin = j.cbegin();
            json::const_iterator it_end = j.cend();

            auto it = it_begin;
            CHECK(it != it_end);

            it++;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it == it_end);
        }
    }

    SECTION("object")
    {
        json j = {{"one", 1}, {"two", 2}, {"three", 3}};
        json j_const(j);

        SECTION("json + begin/end")
        {
            json::iterator it_begin = j.begin();
            json::iterator it_end = j.end();

            auto it = it_begin;
            CHECK(it != it_end);

            it++;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it == it_end);
        }

        SECTION("const json + begin/end")
        {
            json::const_iterator it_begin = j_const.begin();
            json::const_iterator it_end = j_const.end();

            auto it = it_begin;
            CHECK(it != it_end);

            it++;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it == it_end);
        }

        SECTION("json + cbegin/cend")
        {
            json::const_iterator it_begin = j.cbegin();
            json::const_iterator it_end = j.cend();

            auto it = it_begin;
            CHECK(it != it_end);

            it++;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it == it_end);
        }

        SECTION("const json + cbegin/cend")
        {
            json::const_iterator it_begin = j.cbegin();
            json::const_iterator it_end = j.cend();

            auto it = it_begin;
            CHECK(it != it_end);

            it++;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it != it_end);

            ++it;
            CHECK(it != it_begin);
            CHECK(it == it_end);
        }
    }

    SECTION("number (integer)")
    {
        json j = 23;
        json j_const(j);

        SECTION("json + begin/end")
        {
            json::iterator it = j.begin();
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
            json::const_iterator it = j_const.begin();
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
            json::const_iterator it = j.cbegin();
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
            json::const_iterator it = j_const.cbegin();
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
            json::iterator it = j.begin();
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
            json::const_iterator it = j_const.begin();
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
            json::const_iterator it = j.cbegin();
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
            json::const_iterator it = j_const.cbegin();
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
            json::iterator it = j.begin();
            CHECK(it == j.end());
        }

        SECTION("const json + begin/end")
        {
            json::const_iterator it_begin = j_const.begin();
            json::const_iterator it_end = j_const.end();
            CHECK(it_begin == it_end);
        }

        SECTION("json + cbegin/cend")
        {
            json::const_iterator it_begin = j.cbegin();
            json::const_iterator it_end = j.cend();
            CHECK(it_begin == it_end);
        }

        SECTION("const json + cbegin/cend")
        {
            json::const_iterator it_begin = j_const.cbegin();
            json::const_iterator it_end = j_const.cend();
            CHECK(it_begin == it_end);
        }
    }
}

TEST_CASE("capacity")
{
    SECTION("empty()")
    {
        SECTION("boolean")
        {
            json j = true;
            json j_const(j);

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.begin() != j.end());
                CHECK(j_const.begin() != j_const.end());
            }
        }

        SECTION("string")
        {
            json j = "hello world";
            json j_const(j);

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.begin() != j.end());
                CHECK(j_const.begin() != j_const.end());
            }
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                json j = json::array();
                json j_const(j);

                SECTION("result of empty")
                {
                    CHECK(j.empty() == true);
                    CHECK(j_const.empty() == true);
                }

                SECTION("definition of empty")
                {
                    CHECK(j.begin() == j.end());
                    CHECK(j_const.begin() == j_const.end());
                }
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3};
                json j_const(j);

                SECTION("result of empty")
                {
                    CHECK(j.empty() == false);
                    CHECK(j_const.empty() == false);
                }

                SECTION("definition of empty")
                {
                    CHECK(j.begin() != j.end());
                    CHECK(j_const.begin() != j_const.end());
                }
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                json j = json::object();
                json j_const(j);

                SECTION("result of empty")
                {
                    CHECK(j.empty() == true);
                    CHECK(j_const.empty() == true);
                }

                SECTION("definition of empty")
                {
                    CHECK(j.begin() == j.end());
                    CHECK(j_const.begin() == j_const.end());
                }
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}};
                json j_const(j);

                SECTION("result of empty")
                {
                    CHECK(j.empty() == false);
                    CHECK(j_const.empty() == false);
                }

                SECTION("definition of empty")
                {
                    CHECK(j.begin() != j.end());
                    CHECK(j_const.begin() != j_const.end());
                }
            }
        }

        SECTION("number (integer)")
        {
            json j = 23;
            json j_const(j);

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.begin() != j.end());
                CHECK(j_const.begin() != j_const.end());
            }
        }

        SECTION("number (float)")
        {
            json j = 23.42;
            json j_const(j);

            SECTION("result of empty")
            {
                CHECK(j.empty() == false);
                CHECK(j_const.empty() == false);
            }

            SECTION("definition of empty")
            {
                CHECK(j.begin() != j.end());
                CHECK(j_const.begin() != j_const.end());
            }
        }

        SECTION("null")
        {
            json j = nullptr;
            json j_const(j);

            SECTION("result of empty")
            {
                CHECK(j.empty() == true);
                CHECK(j_const.empty() == true);
            }

            SECTION("definition of empty")
            {
                CHECK(j.begin() == j.end());
                CHECK(j_const.begin() == j_const.end());
            }
        }
    }

    SECTION("size()")
    {
        SECTION("boolean")
        {
            json j = true;
            json j_const(j);

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
            }
        }

        SECTION("string")
        {
            json j = "hello world";
            json j_const(j);

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
            }
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                json j = json::array();
                json j_const(j);

                SECTION("result of size")
                {
                    CHECK(j.size() == 0);
                    CHECK(j_const.size() == 0);
                }

                SECTION("definition of size")
                {
                    CHECK(std::distance(j.begin(), j.end()) == j.size());
                    CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                }
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3};
                json j_const(j);

                SECTION("result of size")
                {
                    CHECK(j.size() == 3);
                    CHECK(j_const.size() == 3);
                }

                SECTION("definition of size")
                {
                    CHECK(std::distance(j.begin(), j.end()) == j.size());
                    CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                }
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                json j = json::object();
                json j_const(j);

                SECTION("result of size")
                {
                    CHECK(j.size() == 0);
                    CHECK(j_const.size() == 0);
                }

                SECTION("definition of size")
                {
                    CHECK(std::distance(j.begin(), j.end()) == j.size());
                    CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                }
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}};
                json j_const(j);

                SECTION("result of size")
                {
                    CHECK(j.size() == 3);
                    CHECK(j_const.size() == 3);
                }

                SECTION("definition of size")
                {
                    CHECK(std::distance(j.begin(), j.end()) == j.size());
                    CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
                }
            }
        }

        SECTION("number (integer)")
        {
            json j = 23;
            json j_const(j);

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
            }
        }

        SECTION("number (float)")
        {
            json j = 23.42;
            json j_const(j);

            SECTION("result of size")
            {
                CHECK(j.size() == 1);
                CHECK(j_const.size() == 1);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
            }
        }

        SECTION("null")
        {
            json j = nullptr;
            json j_const(j);

            SECTION("result of size")
            {
                CHECK(j.size() == 0);
                CHECK(j_const.size() == 0);
            }

            SECTION("definition of size")
            {
                CHECK(std::distance(j.begin(), j.end()) == j.size());
                CHECK(std::distance(j_const.begin(), j_const.end()) == j_const.size());
            }
        }
    }

    SECTION("max_size()")
    {
        SECTION("boolean")
        {
            json j = true;
            json j_const(j);

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("string")
        {
            json j = "hello world";
            json j_const(j);

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
                json j_const(j);

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3};
                json j_const(j);

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
                json j_const(j);

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}};
                json j_const(j);

                SECTION("result of max_size")
                {
                    CHECK(j.max_size() >= j.size());
                    CHECK(j_const.max_size() >= j_const.size());
                }
            }
        }

        SECTION("number (integer)")
        {
            json j = 23;
            json j_const(j);

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("number (float)")
        {
            json j = 23.42;
            json j_const(j);

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 1);
                CHECK(j_const.max_size() == 1);
            }
        }

        SECTION("null")
        {
            json j = nullptr;
            json j_const(j);

            SECTION("result of max_size")
            {
                CHECK(j.max_size() == 0);
                CHECK(j_const.max_size() == 0);
            }
        }
    }
}

TEST_CASE("modifiers")
{
    SECTION("clear()")
    {
        SECTION("boolean")
        {
            json j = true;

            j.clear();
            CHECK(j == json(json::value_t::boolean));
        }

        SECTION("string")
        {
            json j = "hello world";

            j.clear();
            CHECK(j == json(json::value_t::string));
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                json j = json::array();

                j.clear();
                CHECK(j.empty());
                CHECK(j == json(json::value_t::array));
            }

            SECTION("filled array")
            {
                json j = {1, 2, 3};

                j.clear();
                CHECK(j.empty());
                CHECK(j == json(json::value_t::array));
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                json j = json::object();

                j.clear();
                CHECK(j.empty());
                CHECK(j == json(json::value_t::object));
            }

            SECTION("filled object")
            {
                json j = {{"one", 1}, {"two", 2}, {"three", 3}};

                j.clear();
                CHECK(j.empty());
                CHECK(j == json(json::value_t::object));
            }
        }

        SECTION("number (integer)")
        {
            json j = 23;

            j.clear();
            CHECK(j == json(json::value_t::number_integer));
        }

        SECTION("number (float)")
        {
            json j = 23.42;

            j.clear();
            CHECK(j == json(json::value_t::number_float));
        }

        SECTION("null")
        {
            json j = nullptr;

            j.clear();
            CHECK(j == json(json::value_t::null));
        }
    }

    SECTION("push_back()")
    {
        SECTION("to array")
        {
            SECTION("json&&")
            {
                SECTION("null")
                {
                    json j;
                    j.push_back(1);
                    j.push_back(2);
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2}));
                }

                SECTION("array")
                {
                    json j = {1, 2, 3};
                    j.push_back("Hello");
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2, 3, "Hello"}));
                }

                SECTION("other type")
                {
                    json j = 1;
                    CHECK_THROWS_AS(j.push_back("Hello"), std::runtime_error);
                }
            }

            SECTION("const json&")
            {
                SECTION("null")
                {
                    json j;
                    json k(1);
                    j.push_back(k);
                    j.push_back(k);
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 1}));
                }

                SECTION("array")
                {
                    json j = {1, 2, 3};
                    json k("Hello");
                    j.push_back(k);
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2, 3, "Hello"}));
                }

                SECTION("other type")
                {
                    json j = 1;
                    json k("Hello");
                    CHECK_THROWS_AS(j.push_back(k), std::runtime_error);
                }
            }
        }
    }

    SECTION("operator+=")
    {
        SECTION("to array")
        {
            SECTION("json&&")
            {
                SECTION("null")
                {
                    json j;
                    j += 1;
                    j += 2;
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2}));
                }

                SECTION("array")
                {
                    json j = {1, 2, 3};
                    j += "Hello";
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2, 3, "Hello"}));
                }

                SECTION("other type")
                {
                    json j = 1;
                    CHECK_THROWS_AS(j += "Hello", std::runtime_error);
                }
            }

            SECTION("const json&")
            {
                SECTION("null")
                {
                    json j;
                    json k(1);
                    j += k;
                    j += k;
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 1}));
                }

                SECTION("array")
                {
                    json j = {1, 2, 3};
                    json k("Hello");
                    j += k;
                    CHECK(j.type() == json::value_t::array);
                    CHECK(j == json({1, 2, 3, "Hello"}));
                }

                SECTION("other type")
                {
                    json j = 1;
                    json k("Hello");
                    CHECK_THROWS_AS(j += k, std::runtime_error);
                }
            }
        }
    }

    SECTION("swap()")
    {
        SECTION("json")
        {
            SECTION("member swap")
            {
                json j("hello world");
                json k(42.23);

                j.swap(k);

                CHECK(j == json(42.23));
                CHECK(k == json("hello world"));
            }

            SECTION("nonmember swap")
            {
                json j("hello world");
                json k(42.23);

                std::swap(j, k);

                CHECK(j == json(42.23));
                CHECK(k == json("hello world"));
            }
        }

        SECTION("array_t")
        {
            SECTION("array_t type")
            {
                json j = {1, 2, 3, 4};
                json::array_t a = {"foo", "bar", "baz"};

                j.swap(a);

                CHECK(j == json({"foo", "bar", "baz"}));

                j.swap(a);

                CHECK(j == json({1, 2, 3, 4}));
            }

            SECTION("non-array_t type")
            {
                json j = 17;
                json::array_t a = {"foo", "bar", "baz"};

                CHECK_THROWS_AS(j.swap(a), std::runtime_error);
            }
        }

        SECTION("object_t")
        {
            SECTION("object_t type")
            {
                json j = {{"one", 1}, {"two", 2}};
                json::object_t o = {{"cow", "Kuh"}, {"chicken", "Huhn"}};

                j.swap(o);

                CHECK(j == json({{"cow", "Kuh"}, {"chicken", "Huhn"}}));

                j.swap(o);

                CHECK(j == json({{"one", 1}, {"two", 2}}));
            }

            SECTION("non-object_t type")
            {
                json j = 17;
                json::object_t o = {{"cow", "Kuh"}, {"chicken", "Huhn"}};

                CHECK_THROWS_AS(j.swap(o), std::runtime_error);
            }
        }

        SECTION("string_t")
        {
            SECTION("string_t type")
            {
                json j = "Hello world";
                json::string_t s = "Hallo Welt";

                j.swap(s);

                CHECK(j == json("Hallo Welt"));

                j.swap(s);

                CHECK(j == json("Hello world"));
            }

            SECTION("non-string_t type")
            {
                json j = 17;
                json::string_t s = "Hallo Welt";

                CHECK_THROWS_AS(j.swap(s), std::runtime_error);
            }
        }
    }
}

TEST_CASE("lexicographical comparison operators")
{
    json j_values =
    {
        nullptr, nullptr,
        17, 42,
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
            {true, true, false, false, false, false, false, false, false, false, false, false, false, false},
            {true, true, false, false, false, false, false, false, false, false, false, false, false, false},
            {false, false, true, false, false, false, false, false, false, false, false, false, false, false},
            {false, false, false, true, false, false, false, false, false, false, false, false, false, false},
            {false, false, false, false, true, false, false, false, false, false, false, false, false, false},
            {false, false, false, false, false, true, false, false, false, false, false, false, false, false},
            {false, false, false, false, false, false, true, false, false, false, false, false, false, false},
            {false, false, false, false, false, false, false, true, false, false, false, false, false, false},
            {false, false, false, false, false, false, false, false, true, false, false, false, false, false},
            {false, false, false, false, false, false, false, false, false, true, false, false, false, false},
            {false, false, false, false, false, false, false, false, false, false, true, false, false, false},
            {false, false, false, false, false, false, false, false, false, false, false, true, false, false},
            {false, false, false, false, false, false, false, false, false, false, false, false, true, false},
            {false, false, false, false, false, false, false, false, false, false, false, false, false, true}
        };

        for (size_t i = 0; i < j_values.size(); ++i)
        {
            for (size_t j = 0; j < j_values.size(); ++j)
            {
                // check precomputed values
                CHECK( (j_values[i] == j_values[j]) == expected[i][j] );
            }
        }
    }

    SECTION("comparison: not equal")
    {
        for (size_t i = 0; i < j_values.size(); ++i)
        {
            for (size_t j = 0; j < j_values.size(); ++j)
            {
                // check definition
                CHECK( (j_values[i] != j_values[j]) == not(j_values[i] == j_values[j]) );
            }
        }
    }

    SECTION("comparison: less")
    {
        std::vector<std::vector<bool>> expected =
        {
            {false, false, false, false, false, false, false, false, false, false, false, false, false, false},
            {false, false, false, false, false, false, false, false, false, false, false, false, false, false},
            {false, false, false, true, false, true, false, false, false, false, false, false, false, false},
            {false, false, false, false, false, false, false, false, false, false, false, false, false, false},
            {false, false, true, true, false, true, false, false, false, false, false, false, false, false},
            {false, false, false, true, false, false, false, false, false, false, false, false, false, false},
            {false, false, false, false, false, false, false, false, false, false, false, false, false, false},
            {false, false, false, false, false, false, true, false, false, false, false, false, false, false},
            {false, false, false, false, false, false, false, false, false, false, false, false, false, false},
            {false, false, false, false, false, false, false, false, true, false, false, false, false, false},
            {false, false, false, false, false, false, false, false, false, false, false, false, false, false},
            {false, false, false, false, false, false, false, false, false, false, false, false, false, false},
            {false, false, false, false, false, false, false, false, false, false, false, false, false, false},
            {false, false, false, false, false, false, false, false, false, false, false, false, true, false}
        };

        for (size_t i = 0; i < j_values.size(); ++i)
        {
            for (size_t j = 0; j < j_values.size(); ++j)
            {
                // check precomputed values
                CHECK( (j_values[i] < j_values[j]) == expected[i][j] );
            }
        }
    }

    SECTION("comparison: less than or equal equal")
    {
        for (size_t i = 0; i < j_values.size(); ++i)
        {
            for (size_t j = 0; j < j_values.size(); ++j)
            {
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
                // check definition
                CHECK( (j_values[i] >= j_values[j]) == not(j_values[i] < j_values[j]) );
            }
        }
    }
}

TEST_CASE("serialization")
{
    SECTION("operator<<")
    {
        SECTION("no given width")
        {
            std::stringstream ss;
            json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            ss << j;
            CHECK(ss.str() == "[\"foo\",1,2,3,false,{\"one\":1}]");
        }

        SECTION("given width")
        {
            std::stringstream ss;
            json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            ss << std::setw(4) << j;
            CHECK(ss.str() ==
                  "[\n    \"foo\",\n    1,\n    2,\n    3,\n    false,\n    {\n        \"one\": 1\n    }\n]");
        }
    }

    SECTION("operator>>")
    {
        SECTION("no given width")
        {
            std::stringstream ss;
            json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            j >> ss;
            CHECK(ss.str() == "[\"foo\",1,2,3,false,{\"one\":1}]");
        }

        SECTION("given width")
        {
            std::stringstream ss;
            json j = {"foo", 1, 2, 3, false, {{"one", 1}}};
            ss.width(4);
            j >> ss;
            CHECK(ss.str() ==
                  "[\n    \"foo\",\n    1,\n    2,\n    3,\n    false,\n    {\n        \"one\": 1\n    }\n]");
        }
    }
}

TEST_CASE("deserialization")
{
    SECTION("string")
    {
        auto s = "[\"foo\",1,2,3,false,{\"one\":1}]";
        json j = json::parse(s);
        CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
    }

    SECTION("operator<<")
    {
        std::stringstream ss;
        ss << "[\"foo\",1,2,3,false,{\"one\":1}]";
        json j;
        j << ss;
        CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
    }

    SECTION("operator>>")
    {
        std::stringstream ss;
        ss << "[\"foo\",1,2,3,false,{\"one\":1}]";
        json j;
        ss >> j;
        CHECK(j == json({"foo", 1, 2, 3, false, {{"one", 1}}}));
    }
}


TEST_CASE("convenience functions")
{
    SECTION("type name as string")
    {
        CHECK(json(json::value_t::null).type_name() == "null");
        CHECK(json(json::value_t::object).type_name() == "object");
        CHECK(json(json::value_t::array).type_name() == "array");
        CHECK(json(json::value_t::number_integer).type_name() == "number");
        CHECK(json(json::value_t::number_float).type_name() == "number");
        CHECK(json(json::value_t::boolean).type_name() == "boolean");
        CHECK(json(json::value_t::string).type_name() == "string");
    }

    SECTION("string escape")
    {
        CHECK(json::escape_string("\"") == "\\\"");
        CHECK(json::escape_string("\\") == "\\\\");
        CHECK(json::escape_string("\b") == "\\b");
        CHECK(json::escape_string("\f") == "\\f");
        CHECK(json::escape_string("\n") == "\\n");
        CHECK(json::escape_string("\r") == "\\r");
        CHECK(json::escape_string("\t") == "\\t");

        CHECK(json::escape_string("\x01") == "\\u0001");
        CHECK(json::escape_string("\x02") == "\\u0002");
        CHECK(json::escape_string("\x03") == "\\u0003");
        CHECK(json::escape_string("\x04") == "\\u0004");
        CHECK(json::escape_string("\x05") == "\\u0005");
        CHECK(json::escape_string("\x06") == "\\u0006");
        CHECK(json::escape_string("\x07") == "\\u0007");
        CHECK(json::escape_string("\x08") == "\\b");
        CHECK(json::escape_string("\x09") == "\\t");
        CHECK(json::escape_string("\x0a") == "\\n");
        CHECK(json::escape_string("\x0b") == "\\u000b");
        CHECK(json::escape_string("\x0c") == "\\f");
        CHECK(json::escape_string("\x0d") == "\\r");
        CHECK(json::escape_string("\x0e") == "\\u000e");
        CHECK(json::escape_string("\x0f") == "\\u000f");
        CHECK(json::escape_string("\x10") == "\\u0010");
        CHECK(json::escape_string("\x11") == "\\u0011");
        CHECK(json::escape_string("\x12") == "\\u0012");
        CHECK(json::escape_string("\x13") == "\\u0013");
        CHECK(json::escape_string("\x14") == "\\u0014");
        CHECK(json::escape_string("\x15") == "\\u0015");
        CHECK(json::escape_string("\x16") == "\\u0016");
        CHECK(json::escape_string("\x17") == "\\u0017");
        CHECK(json::escape_string("\x18") == "\\u0018");
        CHECK(json::escape_string("\x19") == "\\u0019");
        CHECK(json::escape_string("\x1a") == "\\u001a");
        CHECK(json::escape_string("\x1b") == "\\u001b");
        CHECK(json::escape_string("\x1c") == "\\u001c");
        CHECK(json::escape_string("\x1d") == "\\u001d");
        CHECK(json::escape_string("\x1e") == "\\u001e");
        CHECK(json::escape_string("\x1f") == "\\u001f");
    }
}

TEST_CASE("lexer class")
{
    SECTION("scan")
    {
        SECTION("structural characters")
        {
            CHECK(json::lexer("[").scan() == json::lexer::token_type::begin_array);
            CHECK(json::lexer("]").scan() == json::lexer::token_type::end_array);
            CHECK(json::lexer("{").scan() == json::lexer::token_type::begin_object);
            CHECK(json::lexer("}").scan() == json::lexer::token_type::end_object);
            CHECK(json::lexer(",").scan() == json::lexer::token_type::value_separator);
            CHECK(json::lexer(":").scan() == json::lexer::token_type::name_separator);
        }

        SECTION("literal names")
        {
            CHECK(json::lexer("null").scan() == json::lexer::token_type::literal_null);
            CHECK(json::lexer("true").scan() == json::lexer::token_type::literal_true);
            CHECK(json::lexer("false").scan() == json::lexer::token_type::literal_false);
        }

        SECTION("numbers")
        {
            CHECK(json::lexer("0").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("1").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("2").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("3").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("4").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("5").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("6").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("7").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("8").scan() == json::lexer::token_type::value_number);
            CHECK(json::lexer("9").scan() == json::lexer::token_type::value_number);
        }

        SECTION("whitespace")
        {
            // result is end_of_input, because not token is following
            CHECK(json::lexer(" ").scan() == json::lexer::token_type::end_of_input);
            CHECK(json::lexer("\t").scan() == json::lexer::token_type::end_of_input);
            CHECK(json::lexer("\n").scan() == json::lexer::token_type::end_of_input);
            CHECK(json::lexer("\r").scan() == json::lexer::token_type::end_of_input);
            CHECK(json::lexer(" \t\n\r\n\t ").scan() == json::lexer::token_type::end_of_input);
        }
    }

    SECTION("token_type_name")
    {
        CHECK(json::lexer::token_type_name(json::lexer::token_type::uninitialized) == "<uninitialized>");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::literal_true) == "true literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::literal_false) == "false literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::literal_null) == "null literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::value_string) == "string literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::value_number) == "number literal");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::begin_array) == "[");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::begin_object) == "{");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::end_array) == "]");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::end_object) == "}");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::name_separator) == ":");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::value_separator) == ",");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::parse_error) == "<parse error>");
        CHECK(json::lexer::token_type_name(json::lexer::token_type::end_of_input) == "<end of input>");
    }

    SECTION("parse errors on first character")
    {
        for (int c = 1; c < 128; ++c)
        {
            auto s = std::string(1, c);

            switch (c)
            {
                // characters that are prefixes of reasonable json
                case ('['):
                case (']'):
                case ('{'):
                case ('}'):
                case (','):
                case (':'):
                case ('0'):
                case ('1'):
                case ('2'):
                case ('3'):
                case ('4'):
                case ('5'):
                case ('6'):
                case ('7'):
                case ('8'):
                case ('9'):
                {
                    CHECK(json::lexer(s.c_str()).scan() != json::lexer::token_type::parse_error);
                    break;
                }

                case ('"'):
                {
                    // no idea what to do here
                    break;
                }

                // whitespace
                case (' '):
                case ('\t'):
                case ('\n'):
                case ('\r'):
                {
                    CHECK(json::lexer(s.c_str()).scan() == json::lexer::token_type::end_of_input);
                    break;
                }

                // anything else is not expected
                default:
                {
                    CHECK(json::lexer(s.c_str()).scan() == json::lexer::token_type::parse_error);
                    break;
                }
            }
        }
    }
}

TEST_CASE("parser class")
{
    SECTION("parse")
    {
        SECTION("null")
        {
            CHECK(json::parser("null").parse() == json(nullptr));
        }

        SECTION("true")
        {
            CHECK(json::parser("true").parse() == json(true));
        }

        SECTION("false")
        {
            CHECK(json::parser("false").parse() == json(false));
        }

        SECTION("array")
        {
            SECTION("empty array")
            {
                CHECK(json::parser("[]").parse() == json(json::value_t::array));
                CHECK(json::parser("[ ]").parse() == json(json::value_t::array));
            }

            SECTION("nonempty array")
            {
                CHECK(json::parser("[true, false, null]").parse() == json({true, false, nullptr}));
            }
        }

        SECTION("object")
        {
            SECTION("empty object")
            {
                CHECK(json::parser("{}").parse() == json(json::value_t::object));
                CHECK(json::parser("{ }").parse() == json(json::value_t::object));
            }
        }

        SECTION("number")
        {
            SECTION("integers")
            {
                SECTION("without exponent")
                {
                    CHECK(json::parser("-128").parse() == json(-128));
                    CHECK(json::parser("0").parse() == json(0));
                    CHECK(json::parser("128").parse() == json(128));
                }

                SECTION("with exponent")
                {
                    CHECK(json::parser("10000E-4").parse() == json(10000e-4));
                    CHECK(json::parser("10000E-3").parse() == json(10000e-3));
                    CHECK(json::parser("10000E-2").parse() == json(10000e-2));
                    CHECK(json::parser("10000E-1").parse() == json(10000e-1));
                    CHECK(json::parser("10000E0").parse() == json(10000e0));
                    CHECK(json::parser("10000E1").parse() == json(10000e1));
                    CHECK(json::parser("10000E2").parse() == json(10000e2));
                    CHECK(json::parser("10000E3").parse() == json(10000e3));
                    CHECK(json::parser("10000E4").parse() == json(10000e4));
                }
            }

            SECTION("invalid numbers")
            {
                CHECK_THROWS_AS(json::parser("01").parse(), std::invalid_argument);
            }
        }
    }
}
