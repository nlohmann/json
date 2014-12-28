#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include "JSON.h"

TEST_CASE("array")
{
    SECTION("Basics")
    {
        // construction with given type
        JSON j(JSON::value_type::array);
        CHECK(j.type() == JSON::value_type::array);

        // string representation of default value
        CHECK(j.toString() == "[]");

        // check payload
        CHECK(*(j.data().array) == JSON::array_t());

        // container members
        CHECK(j.size() == 0);
        CHECK(j.empty() == true);

        // implicit conversions
        CHECK_NOTHROW(JSON::array_t v = j);
        CHECK_THROWS_AS(JSON::object_t v = j, std::logic_error);
        CHECK_THROWS_AS(std::string v = j, std::logic_error);
        CHECK_THROWS_AS(bool v = j, std::logic_error);
        CHECK_THROWS_AS(int v = j, std::logic_error);
        CHECK_THROWS_AS(double v = j, std::logic_error);

        // explicit conversions
        CHECK_NOTHROW(auto v = j.get<JSON::array_t>());
        CHECK_THROWS_AS(auto v = j.get<JSON::object_t>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<std::string>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<bool>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<int>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<double>(), std::logic_error);

        // transparent usage
        auto id = [](JSON::array_t v)
        {
            return v;
        };
        CHECK(id(j) == j.get<JSON::array_t>());

        // copy constructor
        JSON k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        JSON l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        JSON::array_t v1 = {"string", 1, 1.0, false, nullptr};
        JSON j1 = v1;
        CHECK(j1.get<JSON::array_t>() == v1);

        JSON j2 = {"string", 1, 1.0, false, nullptr};
        JSON::array_t v2 = j2;
        CHECK(j2.get<JSON::array_t>() == v1);
        CHECK(j2.get<JSON::array_t>() == v2);

        // special tests to make sure construction from initializer list works

        // case 1: there is an element that is not an array
        JSON j3 = { {"foo", "bar"}, 3 };
        CHECK(j3.type() == JSON::value_type::array);

        // case 2: there is an element with more than two elements
        JSON j4 = { {"foo", "bar"}, {"one", "two", "three"} };
        CHECK(j4.type() == JSON::value_type::array);

        // case 3: there is an element whose first element is not a string
        JSON j5 = { {"foo", "bar"}, {true, "baz"} };
        CHECK(j5.type() == JSON::value_type::array);

        // check if nested arrays work and are recognized as arrays
        JSON j6 = { {{"foo", "bar"}} };
        CHECK(j6.type() == JSON::value_type::array);
        CHECK(j6.size() == 1);
        CHECK(j6[0].type() == JSON::value_type::object);

        // move constructor
        JSON j7(std::move(v1));
        CHECK(j7 == j1);
    }

    SECTION("Array operators")
    {
        JSON j = {0, 1, 2, 3, 4, 5, 6};

        // read
        const int v1 = j[3];
        CHECK(v1 == 3);

        // write
        j[4] = 9;
        int v2 = j[4];
        CHECK(v2 == 9);

        // size
        CHECK (j.size() == 7);

        // push_back for different value types
        j.push_back(7);
        j.push_back("const char*");
        j.push_back(42.23);
        std::string s = "std::string";
        j.push_back(s);
        j.push_back(false);
        j.push_back(nullptr);
        j.push_back(j);

        CHECK (j.size() == 14);

        // operator+= for different value types
        j += 7;
        j += "const char*";
        j += 42.23;
        j += s;
        j += false;
        j += nullptr;
        j += j;

        CHECK (j.size() == 21);
        
        // implicit transformation into an array
        JSON empty1, empty2;
        empty1 += "foo";
        empty2.push_back("foo");
        CHECK(empty1.type() == JSON::value_type::array);
        CHECK(empty2.type() == JSON::value_type::array);
        CHECK(empty1 == empty2);

        // exceptions
        JSON nonarray = 1;
        CHECK_THROWS_AS(const int i = nonarray[0], std::domain_error);
        CHECK_NOTHROW(j[21]);
        CHECK_THROWS_AS(const int i = j.at(21), std::out_of_range);
        CHECK_THROWS_AS(nonarray[0] = 10, std::domain_error);
        CHECK_NOTHROW(j[21] = 5);
        CHECK_THROWS_AS(j.at(21) = 5, std::out_of_range);
        CHECK_THROWS_AS(nonarray += 2, std::runtime_error);

        const JSON k = j;
        CHECK_NOTHROW(k[21]);
        CHECK_THROWS_AS(const int i = k.at(21), std::out_of_range);

        // add initializer list
        j.push_back({"a", "b", "c"});
        CHECK (j.size() == 24);
    }

    SECTION("Iterators")
    {
        std::vector<int> vec = {0, 1, 2, 3, 4, 5, 6};
        JSON j1 = {0, 1, 2, 3, 4, 5, 6};
        const JSON j2 = {0, 1, 2, 3, 4, 5, 6};

        {
            // const_iterator
            for (JSON::const_iterator cit = j1.begin(); cit != j1.end(); ++cit)
            {
                int v = *cit;
                CHECK(v == vec[static_cast<size_t>(v)]);

                if (cit == j1.begin())
                {
                    CHECK(v == 0);
                }
            }
        }
        {
            // const_iterator with cbegin/cend
            for (JSON::const_iterator cit = j1.cbegin(); cit != j1.cend(); ++cit)
            {
                int v = *cit;
                CHECK(v == vec[static_cast<size_t>(v)]);

                if (cit == j1.cbegin())
                {
                    CHECK(v == 0);
                }
            }
        }

        {
            // range based for
            for (auto el : j1)
            {
                int v = el;
                CHECK(v == vec[static_cast<size_t>(v)]);
            }
        }

        {
            // iterator
            for (JSON::iterator cit = j1.begin(); cit != j1.end(); ++cit)
            {
                int v_old = *cit;
                *cit = cit->get<int>() * 2;
                int v = *cit;
                CHECK(v == vec[static_cast<size_t>(v_old)] * 2);

                if (cit == j1.begin())
                {
                    CHECK(v == 0);
                }
            }
        }

        {
            // const_iterator (on const object)
            for (JSON::const_iterator cit = j2.begin(); cit != j2.end(); ++cit)
            {
                int v = *cit;
                CHECK(v == vec[static_cast<size_t>(v)]);

                if (cit == j2.begin())
                {
                    CHECK(v == 0);
                }
            }
        }

        {
            // const_iterator with cbegin/cend (on const object)
            for (JSON::const_iterator cit = j2.cbegin(); cit != j2.cend(); ++cit)
            {
                int v = *cit;
                CHECK(v == vec[static_cast<size_t>(v)]);

                if (cit == j2.cbegin())
                {
                    CHECK(v == 0);
                }
            }
        }

        {
            // range based for (on const object)
            for (auto el : j2)
            {
                int v = el;
                CHECK(v == vec[static_cast<size_t>(v)]);
            }
        }

    }
}

TEST_CASE("object")
{
    SECTION("Basics")
    {
        // construction with given type
        JSON j(JSON::value_type::object);
        CHECK(j.type() == JSON::value_type::object);

        // string representation of default value
        CHECK(j.toString() == "{}");

        // check payload
        CHECK(*(j.data().object) == JSON::object_t());

        // container members
        CHECK(j.size() == 0);
        CHECK(j.empty() == true);

        // implicit conversions
        CHECK_THROWS_AS(JSON::array_t v = j, std::logic_error);
        CHECK_NOTHROW(JSON::object_t v = j);
        CHECK_THROWS_AS(std::string v = j, std::logic_error);
        CHECK_THROWS_AS(bool v = j, std::logic_error);
        CHECK_THROWS_AS(int v = j, std::logic_error);
        CHECK_THROWS_AS(double v = j, std::logic_error);

        // explicit conversions
        CHECK_THROWS_AS(auto v = j.get<JSON::array_t>(), std::logic_error);
        CHECK_NOTHROW(auto v = j.get<JSON::object_t>());
        CHECK_THROWS_AS(auto v = j.get<std::string>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<bool>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<int>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<double>(), std::logic_error);

        // transparent usage
        auto id = [](JSON::object_t v)
        {
            return v;
        };
        CHECK(id(j) == j.get<JSON::object_t>());

        // copy constructor
        JSON k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        JSON l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        JSON::object_t v1 = { {"v1", "string"}, {"v2", 1}, {"v3", 1.0}, {"v4", false} };
        JSON j1 = v1;
        CHECK(j1.get<JSON::object_t>() == v1);

        JSON j2 = { {"v1", "string"}, {"v2", 1}, {"v3", 1.0}, {"v4", false} };
        JSON::object_t v2 = j2;
        CHECK(j2.get<JSON::object_t>() == v1);
        CHECK(j2.get<JSON::object_t>() == v2);

        // check if multiple keys are ignored
        JSON j3 = { {"key", "value"}, {"key", 1} };
        CHECK(j3.size() == 1);

        // move constructor
        JSON j7(std::move(v1));
        CHECK(j7 == j1);
    }

    SECTION("Object operators")
    {
        JSON j = {{"k0", "v0"}, {"k1", nullptr}, {"k2", 42}, {"k3", 3.141}, {"k4", true}};
        const JSON k = j;

        // read
        const std::string v0 = j["k0"];
        CHECK(v0 == "v0");
        auto v1 = j["k1"];
        CHECK(v1 == nullptr);
        int v2 = j["k2"];
        CHECK(v2 == 42);
        double v3 = j["k3"];
        CHECK(v3 == 3.141);
        bool v4 = j["k4"];
        CHECK(v4 == true);

        // write (replace)
        j["k0"] = "new v0";
        CHECK(j["k0"] == "new v0");

        // write (add)
        j["k5"] = false;

        // size
        CHECK(j.size() == 6);

        // find
        CHECK(j.find("k0") != j.end());
        CHECK(j.find("v0") == j.end());
        JSON::const_iterator i1 = j.find("k0");
        JSON::iterator i2 = j.find("k0");

        // at
        CHECK_THROWS_AS(j.at("foo"), std::out_of_range);
        CHECK_THROWS_AS(k.at("foo"), std::out_of_range);

        // add pair
        j.push_back(JSON::object_t::value_type {"int_key", 42});
        CHECK(j["int_key"].get<int>() == 42);
        j += JSON::object_t::value_type {"int_key2", 23};
        CHECK(j["int_key2"].get<int>() == 23);
        {
            // make sure null objects are transformed
            JSON je;
            CHECK_NOTHROW(je.push_back(JSON::object_t::value_type {"int_key", 42}));
            CHECK(je["int_key"].get<int>() == 42);
        }
        {
            // make sure null objects are transformed
            JSON je;
            CHECK_NOTHROW((je += JSON::object_t::value_type {"int_key", 42}));
            CHECK(je["int_key"].get<int>() == 42);
        }

        // add initializer list (of pairs)
        {
            JSON je;
            je.push_back({ {"one", 1}, {"two", false}, {"three", {1,2,3}} });
            CHECK(je["one"].get<int>() == 1);
            CHECK(je["two"].get<bool>() == false);
            CHECK(je["three"].size() == 3);
        }
        {
            JSON je;
            je += { {"one", 1}, {"two", false}, {"three", {1,2,3}} };
            CHECK(je["one"].get<int>() == 1);
            CHECK(je["two"].get<bool>() == false);
            CHECK(je["three"].size() == 3);
        }

        // key/value for non-end iterator
        CHECK(i1.key() == "k0");
        CHECK(i1.value() == j["k0"]);
        CHECK(i2.key() == "k0");
        CHECK(i2.value() == j["k0"]);

        // key/value for uninitialzed iterator
        JSON::const_iterator i3;
        JSON::iterator i4;
        CHECK_THROWS_AS(i3.key(), std::out_of_range);
        CHECK_THROWS_AS(i3.value(), std::out_of_range);
        CHECK_THROWS_AS(i4.key(), std::out_of_range);
        CHECK_THROWS_AS(i4.value(), std::out_of_range);

        // key/value for end-iterator
        JSON::const_iterator i5 = j.find("v0");
        JSON::iterator i6 = j.find("v0");
        CHECK_THROWS_AS(i5.key(), std::out_of_range);
        CHECK_THROWS_AS(i5.value(), std::out_of_range);
        CHECK_THROWS_AS(i6.key(), std::out_of_range);
        CHECK_THROWS_AS(i6.value(), std::out_of_range);

        // implicit transformation into an object
        JSON empty;
        empty["foo"] = "bar";
        CHECK(empty.type() == JSON::value_type::object);
        CHECK(empty["foo"] == "bar");

        // exceptions
        JSON nonarray = 1;
        CHECK_THROWS_AS(const int i = nonarray["v1"], std::domain_error);
        CHECK_THROWS_AS(nonarray["v1"] = 10, std::domain_error);
    }

    SECTION("Iterators")
    {
        JSON j1 = {{"k0", 0}, {"k1", 1}, {"k2", 2}, {"k3", 3}};
        const JSON j2 = {{"k0", 0}, {"k1", 1}, {"k2", 2}, {"k3", 3}};

        // iterator
        for (JSON::iterator it = j1.begin(); it != j1.end(); ++it)
        {
            switch (static_cast<int>(it.value()))
            {
                case (0):
                    CHECK(it.key() == "k0");
                    break;
                case (1):
                    CHECK(it.key() == "k1");
                    break;
                case (2):
                    CHECK(it.key() == "k2");
                    break;
                case (3):
                    CHECK(it.key() == "k3");
                    break;
                default:
                    CHECK(false);
            }

            CHECK((*it).type() == JSON::value_type::number);
            CHECK(it->type() == JSON::value_type::number);
        }

        // range-based for
        for (auto& element : j1)
        {
            element = 2 * element.get<int>();
        }

        // const_iterator
        for (JSON::const_iterator it = j1.begin(); it != j1.end(); ++it)
        {
            switch (static_cast<int>(it.value()))
            {
                case (0):
                    CHECK(it.key() == "k0");
                    break;
                case (2):
                    CHECK(it.key() == "k1");
                    break;
                case (4):
                    CHECK(it.key() == "k2");
                    break;
                case (6):
                    CHECK(it.key() == "k3");
                    break;
                default:
                    CHECK(false);
            }

            CHECK((*it).type() == JSON::value_type::number);
            CHECK(it->type() == JSON::value_type::number);
        }

        // const_iterator using cbegin/cend
        for (JSON::const_iterator it = j1.cbegin(); it != j1.cend(); ++it)
        {
            switch (static_cast<int>(it.value()))
            {
                case (0):
                    CHECK(it.key() == "k0");
                    break;
                case (2):
                    CHECK(it.key() == "k1");
                    break;
                case (4):
                    CHECK(it.key() == "k2");
                    break;
                case (6):
                    CHECK(it.key() == "k3");
                    break;
                default:
                    CHECK(false);
            }

            CHECK((*it).type() == JSON::value_type::number);
            CHECK(it->type() == JSON::value_type::number);
        }

        // const_iterator (on const object)
        for (JSON::const_iterator it = j2.begin(); it != j2.end(); ++it)
        {
            switch (static_cast<int>(it.value()))
            {
                case (0):
                    CHECK(it.key() == "k0");
                    break;
                case (1):
                    CHECK(it.key() == "k1");
                    break;
                case (2):
                    CHECK(it.key() == "k2");
                    break;
                case (3):
                    CHECK(it.key() == "k3");
                    break;
                default:
                    CHECK(false);
            }

            CHECK((*it).type() == JSON::value_type::number);
            CHECK(it->type() == JSON::value_type::number);
        }

        // const_iterator using cbegin/cend (on const object)
        for (JSON::const_iterator it = j2.cbegin(); it != j2.cend(); ++it)
        {
            switch (static_cast<int>(it.value()))
            {
                case (0):
                    CHECK(it.key() == "k0");
                    break;
                case (1):
                    CHECK(it.key() == "k1");
                    break;
                case (2):
                    CHECK(it.key() == "k2");
                    break;
                case (3):
                    CHECK(it.key() == "k3");
                    break;
                default:
                    CHECK(false);
            }

            CHECK((*it).type() == JSON::value_type::number);
            CHECK(it->type() == JSON::value_type::number);
        }

        // range-based for (on const object)
        for (auto element : j1)
        {
            CHECK(element.get<int>() >= 0);
        }
    }
}

TEST_CASE("null")
{
    SECTION("Basics")
    {
        // construction with given type
        JSON j;
        CHECK(j.type() == JSON::value_type::null);

        // string representation of default value
        CHECK(j.toString() == "null");

        // container members
        CHECK(j.size() == 0);
        CHECK(j.empty() == true);

        // implicit conversions
        CHECK_NOTHROW(JSON::array_t v = j);
        CHECK_THROWS_AS(JSON::object_t v = j, std::logic_error);
        CHECK_THROWS_AS(std::string v = j, std::logic_error);
        CHECK_THROWS_AS(bool v = j, std::logic_error);
        CHECK_THROWS_AS(int v = j, std::logic_error);
        CHECK_THROWS_AS(double v = j, std::logic_error);

        // explicit conversions
        CHECK_NOTHROW(auto v = j.get<JSON::array_t>());
        CHECK_THROWS_AS(auto v = j.get<JSON::object_t>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<std::string>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<bool>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<int>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<double>(), std::logic_error);

        // copy constructor
        JSON k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        JSON l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        JSON j1 = nullptr;
        CHECK(j1.type() == JSON::value_type::null);
    }
}

TEST_CASE("string")
{
    SECTION("Basics")
    {
        // construction with given type
        JSON j(JSON::value_type::string);
        CHECK(j.type() == JSON::value_type::string);

        // string representation of default value
        CHECK(j.toString() == "\"\"");

        // check payload
        CHECK(*(j.data().string) == JSON::string_t());

        // container members
        CHECK(j.size() == 1);
        CHECK(j.empty() == false);

        // implicit conversions
        CHECK_NOTHROW(JSON::array_t v = j);
        CHECK_THROWS_AS(JSON::object_t v = j, std::logic_error);
        CHECK_NOTHROW(std::string v = j);
        CHECK_THROWS_AS(bool v = j, std::logic_error);
        CHECK_THROWS_AS(int v = j, std::logic_error);
        CHECK_THROWS_AS(double v = j, std::logic_error);

        // explicit conversions
        CHECK_NOTHROW(auto v = j.get<JSON::array_t>());
        CHECK_THROWS_AS(auto v = j.get<JSON::object_t>(), std::logic_error);
        CHECK_NOTHROW(auto v = j.get<std::string>());
        CHECK_THROWS_AS(auto v = j.get<bool>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<int>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<double>(), std::logic_error);

        // transparent usage
        auto id = [](std::string v)
        {
            return v;
        };
        CHECK(id(j) == j.get<std::string>());

        // copy constructor
        JSON k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        JSON l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        JSON j1 = std::string("Hello, world");
        std::string v1 = j1;
        CHECK(j1.get<std::string>() == v1);

        JSON j2 = "Hello, world";
        CHECK(j2.get<std::string>() == "Hello, world");

        std::string v3 = "Hello, world";
        JSON j3 = std::move(v3);
        CHECK(j3.get<std::string>() == "Hello, world");
    }
}

TEST_CASE("boolean")
{
    SECTION("Basics")
    {
        // construction with given type
        JSON j(JSON::value_type::boolean);
        CHECK(j.type() == JSON::value_type::boolean);

        // string representation of default value
        CHECK(j.toString() == "false");

        // check payload
        CHECK(j.data().boolean == JSON::boolean_t());

        // container members
        CHECK(j.size() == 1);
        CHECK(j.empty() == false);

        // implicit conversions
        CHECK_NOTHROW(JSON::array_t v = j);
        CHECK_THROWS_AS(JSON::object_t v = j, std::logic_error);
        CHECK_THROWS_AS(std::string v = j, std::logic_error);
        CHECK_NOTHROW(bool v = j);
        CHECK_THROWS_AS(int v = j, std::logic_error);
        CHECK_THROWS_AS(double v = j, std::logic_error);

        // explicit conversions
        CHECK_NOTHROW(auto v = j.get<JSON::array_t>());
        CHECK_THROWS_AS(auto v = j.get<JSON::object_t>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<std::string>(), std::logic_error);
        CHECK_NOTHROW(auto v = j.get<bool>());
        CHECK_THROWS_AS(auto v = j.get<int>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<double>(), std::logic_error);

        // transparent usage
        auto id = [](bool v)
        {
            return v;
        };
        CHECK(id(j) == j.get<bool>());

        // copy constructor
        JSON k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        JSON l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        JSON j1 = true;
        bool v1 = j1;
        CHECK(j1.get<bool>() == v1);

        JSON j2 = false;
        bool v2 = j2;
        CHECK(j2.get<bool>() == v2);
    }
}

TEST_CASE("number (int)")
{
    SECTION("Basics")
    {
        // construction with given type
        JSON j(JSON::value_type::number);
        CHECK(j.type() == JSON::value_type::number);

        // string representation of default value
        CHECK(j.toString() == "0");

        // check payload
        CHECK(j.data().number == JSON::number_t());

        // container members
        CHECK(j.size() == 1);
        CHECK(j.empty() == false);

        // implicit conversions
        CHECK_NOTHROW(JSON::array_t v = j);
        CHECK_THROWS_AS(JSON::object_t v = j, std::logic_error);
        CHECK_THROWS_AS(std::string v = j, std::logic_error);
        CHECK_THROWS_AS(bool v = j, std::logic_error);
        CHECK_NOTHROW(int v = j);
        CHECK_NOTHROW(double v = j);

        // explicit conversions
        CHECK_NOTHROW(auto v = j.get<JSON::array_t>());
        CHECK_THROWS_AS(auto v = j.get<JSON::object_t>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<std::string>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<bool>(), std::logic_error);
        CHECK_NOTHROW(auto v = j.get<int>());
        CHECK_NOTHROW(auto v = j.get<double>());

        // transparent usage
        auto id = [](int v)
        {
            return v;
        };
        CHECK(id(j) == j.get<int>());

        // copy constructor
        JSON k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        JSON l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        JSON j1 = 23;
        int v1 = j1;
        CHECK(j1.get<int>() == v1);

        JSON j2 = 42;
        int v2 = j2;
        CHECK(j2.get<int>() == v2);
    }
}

TEST_CASE("number (float)")
{
    SECTION("Basics")
    {
        // construction with given type
        JSON j(JSON::value_type::number_float);
        CHECK(j.type() == JSON::value_type::number_float);

        // string representation of default value
        CHECK(j.toString() == "0.000000");

        // check payload
        CHECK(j.data().number_float == JSON::number_float_t());

        // container members
        CHECK(j.size() == 1);
        CHECK(j.empty() == false);

        // implicit conversions
        CHECK_NOTHROW(JSON::array_t v = j);
        CHECK_THROWS_AS(JSON::object_t v = j, std::logic_error);
        CHECK_THROWS_AS(std::string v = j, std::logic_error);
        CHECK_THROWS_AS(bool v = j, std::logic_error);
        CHECK_NOTHROW(int v = j);
        CHECK_NOTHROW(double v = j);

        // explicit conversions
        CHECK_NOTHROW(auto v = j.get<JSON::array_t>());
        CHECK_THROWS_AS(auto v = j.get<JSON::object_t>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<std::string>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<bool>(), std::logic_error);
        CHECK_NOTHROW(auto v = j.get<int>());
        CHECK_NOTHROW(auto v = j.get<double>());

        // transparent usage
        auto id = [](double v)
        {
            return v;
        };
        CHECK(id(j) == j.get<double>());

        // copy constructor
        JSON k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        JSON l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        JSON j1 = 3.1415926;
        double v1 = j1;
        CHECK(j1.get<double>() == v1);

        JSON j2 = 2.7182818;
        double v2 = j2;
        CHECK(j2.get<double>() == v2);
    }
}

TEST_CASE("Parser")
{
    SECTION("null")
    {
        // accept the exact values
        CHECK(JSON::parse("null") == JSON(nullptr));

        // ignore whitespace
        CHECK(JSON::parse(" null ") == JSON(nullptr));
        CHECK(JSON::parse("\tnull\n") == JSON(nullptr));

        // respect capitalization
        CHECK_THROWS_AS(JSON::parse("Null"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("NULL"), std::invalid_argument);

        // do not accept prefixes
        CHECK_THROWS_AS(JSON::parse("n"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("nu"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("nul"), std::invalid_argument);
    }

    SECTION("string")
    {
        // accept some values
        CHECK(JSON::parse("\"\"") == JSON(""));
        CHECK(JSON::parse("\"foo\"") == JSON("foo"));

        // quotes must be closed
        CHECK_THROWS_AS(JSON::parse("\""), std::invalid_argument);
    }

    SECTION("boolean")
    {
        // accept the exact values
        CHECK(JSON::parse("true") == JSON(true));
        CHECK(JSON::parse("false") == JSON(false));

        // ignore whitespace
        CHECK(JSON::parse(" true ") == JSON(true));
        CHECK(JSON::parse("\tfalse\n") == JSON(false));

        // respect capitalization
        CHECK_THROWS_AS(JSON::parse("True"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("False"), std::invalid_argument);

        // do not accept prefixes
        CHECK_THROWS_AS(JSON::parse("t"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("tr"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("tru"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("f"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("fa"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("fal"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("fals"), std::invalid_argument);
    }

    SECTION("number (int)")
    {
        // accept the exact values
        CHECK(JSON::parse("0") == JSON(0));
        CHECK(JSON::parse("-0") == JSON(0));
        CHECK(JSON::parse("1") == JSON(1));
        CHECK(JSON::parse("-1") == JSON(-1));
        CHECK(JSON::parse("12345678") == JSON(12345678));
        CHECK(JSON::parse("-12345678") == JSON(-12345678));

        CHECK(JSON::parse("0.0") == JSON(0));
        CHECK(JSON::parse("-0.0") == JSON(0));
        CHECK(JSON::parse("1.0") == JSON(1));
        CHECK(JSON::parse("-1.0") == JSON(-1));
        CHECK(JSON::parse("12345678.0") == JSON(12345678));
        CHECK(JSON::parse("-12345678.0") == JSON(-12345678));

        CHECK(JSON::parse("17e0") == JSON(17));
        CHECK(JSON::parse("17e1") == JSON(170));
        CHECK(JSON::parse("17e3") == JSON(17000));
        CHECK(JSON::parse("17e+0") == JSON(17));
        CHECK(JSON::parse("17e+1") == JSON(170));
        CHECK(JSON::parse("17e+3") == JSON(17000));
        CHECK(JSON::parse("17E0") == JSON(17));
        CHECK(JSON::parse("17E1") == JSON(170));
        CHECK(JSON::parse("17E3") == JSON(17000));
        CHECK(JSON::parse("17E+0") == JSON(17));
        CHECK(JSON::parse("17E+1") == JSON(170));
        CHECK(JSON::parse("17E+3") == JSON(17000));
        CHECK(JSON::parse("10000e-0") == JSON(10000));
        CHECK(JSON::parse("10000e-1") == JSON(1000));
        CHECK(JSON::parse("10000e-4") == JSON(1));
        CHECK(JSON::parse("10000E-0") == JSON(10000));
        CHECK(JSON::parse("10000E-1") == JSON(1000));
        CHECK(JSON::parse("10000E-4") == JSON(1));

        CHECK(JSON::parse("17.0e0") == JSON(17));
        CHECK(JSON::parse("17.0e1") == JSON(170));
        CHECK(JSON::parse("17.0e3") == JSON(17000));
        CHECK(JSON::parse("17.0e+0") == JSON(17));
        CHECK(JSON::parse("17.0e+1") == JSON(170));
        CHECK(JSON::parse("17.0e+3") == JSON(17000));
        CHECK(JSON::parse("17.0E0") == JSON(17));
        CHECK(JSON::parse("17.0E1") == JSON(170));
        CHECK(JSON::parse("17.0E3") == JSON(17000));
        CHECK(JSON::parse("17.0E+0") == JSON(17));
        CHECK(JSON::parse("17.0E+1") == JSON(170));
        CHECK(JSON::parse("17.0E+3") == JSON(17000));
        CHECK(JSON::parse("10000.0e-0") == JSON(10000));
        CHECK(JSON::parse("10000.0e-1") == JSON(1000));
        CHECK(JSON::parse("10000.0e-4") == JSON(1));
        CHECK(JSON::parse("10000.0E-0") == JSON(10000));
        CHECK(JSON::parse("10000.0E-1") == JSON(1000));
        CHECK(JSON::parse("10000.0E-4") == JSON(1));

        // trailing zero is not allowed
        //CHECK_THROWS_AS(JSON::parse("01"), std::invalid_argument);

        // whitespace inbetween is an error
        //CHECK_THROWS_AS(JSON::parse("1 0"), std::invalid_argument);

        // only one minus is allowd
        CHECK_THROWS_AS(JSON::parse("--1"), std::invalid_argument);

        // string representations are not allowed
        CHECK_THROWS_AS(JSON::parse("NAN"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("nan"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("INF"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("inf"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("INFINITY"), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("infinity"), std::invalid_argument);
    }

    SECTION("user-defined string literal operator")
    {
        auto j1 = "[1,2,3]"_json;
        JSON j2 = {1, 2, 3};
        CHECK(j1 == j2);

        auto j3 = "{\"key\": \"value\"}"_json;
        CHECK(j3["key"] == "value");
    }
}
