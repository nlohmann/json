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

        // const object
        const JSON j_const (j);

        // string representation of default value
        CHECK(j.toString() == "[]");

        // iterators
        CHECK(j.begin() != j.end());
        CHECK(j.cbegin() != j.cend());

        // check payload
        //CHECK(*(j.data().array) == JSON::array_t());
        //CHECK(*(j_const.data().array) == JSON::array_t());

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
        CHECK_THROWS_AS(nonarray.at(0), std::domain_error);
        CHECK_THROWS_AS(const int i = nonarray[0], std::domain_error);
        CHECK_NOTHROW(j[21]);
        CHECK_THROWS_AS(const int i = j.at(21), std::out_of_range);
        CHECK_THROWS_AS(nonarray[0] = 10, std::domain_error);
        CHECK_NOTHROW(j[21] = 5);
        CHECK_THROWS_AS(j.at(21) = 5, std::out_of_range);
        CHECK_THROWS_AS(nonarray += 2, std::runtime_error);

        const JSON nonarray_const = nonarray;
        const JSON j_const = j;
        CHECK_THROWS_AS(nonarray_const.at(0), std::domain_error);
        CHECK_THROWS_AS(const int i = nonarray_const[0], std::domain_error);
        CHECK_NOTHROW(j_const[21]);
        CHECK_THROWS_AS(const int i = j.at(21), std::out_of_range);

        {
            JSON nonarray2 = JSON(1);
            JSON nonarray3 = JSON(2);
            JSON empty3 = JSON();
            CHECK_THROWS_AS(nonarray2.push_back(nonarray3), std::runtime_error);
            CHECK_NOTHROW(empty3.push_back(nonarray3));
            CHECK(empty3.type() == JSON::value_type::array);
        }

        const JSON k = j;
        CHECK_NOTHROW(k[21]);
        CHECK_THROWS_AS(const int i = k.at(21), std::out_of_range);

        // add initializer list
        j.push_back({"a", "b", "c"});
        CHECK (j.size() == 24);

        // clear()
        JSON j7 = {0, 1, 2, 3, 4, 5, 6};;
        CHECK(j7.size() == 7);
        j7.clear();
        CHECK(j7.size() == 0);
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

        // const object
        const JSON j_const = j;

        // string representation of default value
        CHECK(j.toString() == "{}");

        // iterators
        CHECK(j.begin() != j.end());
        CHECK(j.cbegin() != j.cend());

        // check payload
        //CHECK(*(j.data().object) == JSON::object_t());
        //CHECK(*(j_const.data().object) == JSON::object_t());

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
        {
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
        }
        {
            const std::string v0 = j[std::string("k0")];
            CHECK(v0 == "v0");
            auto v1 = j[std::string("k1")];
            CHECK(v1 == nullptr);
            int v2 = j[std::string("k2")];
            CHECK(v2 == 42);
            double v3 = j[std::string("k3")];
            CHECK(v3 == 3.141);
            bool v4 = j[std::string("k4")];
            CHECK(v4 == true);
        }
        {
            const std::string v0 = k[std::string("k0")];
            CHECK(v0 == "v0");
            auto v1 = k[std::string("k1")];
            CHECK(v1 == nullptr);
            int v2 = k[std::string("k2")];
            CHECK(v2 == 42);
            double v3 = k[std::string("k3")];
            CHECK(v3 == 3.141);
            bool v4 = k[std::string("k4")];
            CHECK(v4 == true);
        }

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
        CHECK(j.find(std::string("v0")) == j.end());
        JSON::const_iterator i1 = j.find("k0");
        JSON::iterator i2 = j.find("k0");
        CHECK(k.find("k0") != k.end());
        CHECK(k.find("v0") == k.end());
        CHECK(k.find(std::string("v0")) == k.end());
        JSON::const_iterator i22 = k.find("k0");

        // at
        CHECK_THROWS_AS(j.at("foo"), std::out_of_range);
        CHECK_THROWS_AS(k.at("foo"), std::out_of_range);
        CHECK_THROWS_AS(j.at(std::string("foo")), std::out_of_range);
        CHECK_THROWS_AS(k.at(std::string("foo")), std::out_of_range);
        CHECK_NOTHROW(j.at(std::string("k0")));
        CHECK_NOTHROW(k.at(std::string("k0")));
        {
            JSON noobject = 1;
            const JSON noobject_const = noobject;
            CHECK_THROWS_AS(noobject.at("foo"), std::domain_error);
            CHECK_THROWS_AS(noobject.at(std::string("foo")), std::domain_error);
            CHECK_THROWS_AS(noobject_const.at("foo"), std::domain_error);
            CHECK_THROWS_AS(noobject_const.at(std::string("foo")), std::domain_error);
            CHECK_THROWS_AS(noobject["foo"], std::domain_error);
            CHECK_THROWS_AS(noobject[std::string("foo")], std::domain_error);
            CHECK_THROWS_AS(noobject_const[std::string("foo")], std::domain_error);
        }

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
            je.push_back({ {"one", 1}, {"two", false}, {"three", {1, 2, 3}} });
            CHECK(je["one"].get<int>() == 1);
            CHECK(je["two"].get<bool>() == false);
            CHECK(je["three"].size() == 3);
        }
        {
            JSON je;
            je += { {"one", 1}, {"two", false}, {"three", {1, 2, 3}} };
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
        {
            const JSON c = {{"foo", "bar"}};
            CHECK_THROWS_AS(c[std::string("baz")], std::out_of_range);
        }

        // clear()
        JSON j7 = {{"k0", 0}, {"k1", 1}, {"k2", 2}, {"k3", 3}};
        CHECK(j7.size() == 4);
        j7.clear();
        CHECK(j7.size() == 0);
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

        // iterators
        CHECK(j.begin() != j.end());
        CHECK(j.cbegin() != j.cend());

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

    SECTION("Operators")
    {
        // clear()
        JSON j1 = nullptr;
        j1.clear();
        CHECK(j1 == JSON(nullptr));
    }
}

TEST_CASE("string")
{
    SECTION("Basics")
    {
        // construction with given type
        JSON j(JSON::value_type::string);
        CHECK(j.type() == JSON::value_type::string);

        // const object
        const JSON j_const = j;

        // iterators
        CHECK(j.begin() != j.end());
        CHECK(j.cbegin() != j.cend());

        // string representation of default value
        CHECK(j.toString() == "\"\"");

        // check payload
        CHECK(*(j.data().string) == JSON::string_t());
        CHECK(*(j_const.data().string) == JSON::string_t());

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

    SECTION("Operators")
    {
        // clear()
        JSON j1 = std::string("Hello, world");
        CHECK(j1.get<std::string>() == "Hello, world");
        j1.clear();
        CHECK(j1.get<std::string>() == "");
    }
}

TEST_CASE("boolean")
{
    SECTION("Basics")
    {
        // construction with given type
        JSON j(JSON::value_type::boolean);
        CHECK(j.type() == JSON::value_type::boolean);

        // const object
        const JSON j_const = j;

        // iterators
        CHECK(j.begin() != j.end());
        CHECK(j.cbegin() != j.cend());

        // string representation of default value
        CHECK(j.toString() == "false");

        // check payload
        CHECK(j.data().boolean == JSON::boolean_t());
        CHECK(j_const.data().boolean == JSON::boolean_t());

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

    SECTION("Operators")
    {
        // clear()
        JSON j1 = true;
        CHECK(j1.get<bool>() == true);
        j1.clear();
        CHECK(j1.get<bool>() == false);
    }
}

TEST_CASE("number (int)")
{
    SECTION("Basics")
    {
        // construction with given type
        JSON j(JSON::value_type::number);
        CHECK(j.type() == JSON::value_type::number);

        // const object
        const JSON j_const = j;

        // iterators
        CHECK(j.begin() != j.end());
        CHECK(j.cbegin() != j.cend());

        // string representation of default value
        CHECK(j.toString() == "0");

        // check payload
        CHECK(j.data().number == JSON::number_t());
        CHECK(j_const.data().number == JSON::number_t());

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

    SECTION("Operators")
    {
        // clear()
        JSON j1 = 42;
        CHECK(j1.get<int>() == 42);
        j1.clear();
        CHECK(j1.get<int>() == 0);

        // find()
        CHECK(j1.find("foo") == j1.end());
        CHECK(j1.find(std::string("foo")) == j1.end());
        const JSON j2 = j1;
        CHECK(j2.find("foo") == j2.end());
        CHECK(j2.find(std::string("foo")) == j2.end());
    }
}

TEST_CASE("number (float)")
{
    SECTION("Basics")
    {
        // construction with given type
        JSON j(JSON::value_type::number_float);
        CHECK(j.type() == JSON::value_type::number_float);

        // const object
        const JSON j_const = j;

        // iterators
        CHECK(j.begin() != j.end());
        CHECK(j.cbegin() != j.cend());

        // string representation of default value
        CHECK(j.toString() == "0.000000");

        // check payload
        CHECK(j.data().number_float == JSON::number_float_t());
        CHECK(j_const.data().number_float == JSON::number_float_t());

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

    SECTION("Operators")
    {
        // clear()
        JSON j1 = 3.1415926;
        CHECK(j1.get<double>() == 3.1415926);
        j1.clear();
        CHECK(j1.get<double>() == 0.0);
    }
}

TEST_CASE("Iterators")
{
    JSON j1 = {0, 1, 2, 3, 4};
    JSON j2 = {{"foo", "bar"}, {"baz", "bam"}};
    JSON j3 = true;
    JSON j4 = nullptr;
    JSON j5 = 42;
    JSON j6 = 23.42;
    JSON j7 = "hello";

    const JSON j1_const = {0, 1, 2, 3, 4};
    const JSON j2_const = {{"foo", "bar"}, {"baz", "bam"}};
    const JSON j3_const = true;
    const JSON j4_const = nullptr;
    const JSON j5_const = 42;
    const JSON j6_const = 23.42;
    const JSON j7_const = "hello";

    // operator *
    CHECK_THROWS_AS(* j1.end(), std::runtime_error);
    CHECK_THROWS_AS(* j1.cend(), std::runtime_error);
    CHECK_THROWS_AS(* j2.end(), std::runtime_error);
    CHECK_THROWS_AS(* j2.cend(), std::runtime_error);
    CHECK_THROWS_AS(* j3.end(), std::runtime_error);
    CHECK_THROWS_AS(* j3.cend(), std::runtime_error);
    CHECK_THROWS_AS(* j4.end(), std::runtime_error);
    CHECK_THROWS_AS(* j4.cend(), std::runtime_error);
    CHECK_THROWS_AS(* j5.end(), std::runtime_error);
    CHECK_THROWS_AS(* j5.cend(), std::runtime_error);
    CHECK_THROWS_AS(* j6.end(), std::runtime_error);
    CHECK_THROWS_AS(* j6.cend(), std::runtime_error);
    CHECK_THROWS_AS(* j7.end(), std::runtime_error);
    CHECK_THROWS_AS(* j7.cend(), std::runtime_error);

    CHECK_THROWS_AS(* j1_const.end(), std::runtime_error);
    CHECK_THROWS_AS(* j1_const.cend(), std::runtime_error);
    CHECK_THROWS_AS(* j2_const.end(), std::runtime_error);
    CHECK_THROWS_AS(* j2_const.cend(), std::runtime_error);
    CHECK_THROWS_AS(* j3_const.end(), std::runtime_error);
    CHECK_THROWS_AS(* j3_const.cend(), std::runtime_error);
    CHECK_THROWS_AS(* j4_const.end(), std::runtime_error);
    CHECK_THROWS_AS(* j4_const.cend(), std::runtime_error);
    CHECK_THROWS_AS(* j5_const.end(), std::runtime_error);
    CHECK_THROWS_AS(* j5_const.cend(), std::runtime_error);
    CHECK_THROWS_AS(* j6_const.end(), std::runtime_error);
    CHECK_THROWS_AS(* j6_const.cend(), std::runtime_error);
    CHECK_THROWS_AS(* j7_const.end(), std::runtime_error);
    CHECK_THROWS_AS(* j7_const.cend(), std::runtime_error);

    // operator ->
    CHECK(j1.begin()->type() == JSON::value_type::number);
    CHECK(j1.cbegin()->type() == JSON::value_type::number);
    CHECK(j2.begin()->type() == JSON::value_type::string);
    CHECK(j2.cbegin()->type() == JSON::value_type::string);
    CHECK(j3.begin()->type() == JSON::value_type::boolean);
    CHECK(j3.cbegin()->type() == JSON::value_type::boolean);
    CHECK(j4.begin()->type() == JSON::value_type::null);
    CHECK(j4.cbegin()->type() == JSON::value_type::null);
    CHECK(j5.begin()->type() == JSON::value_type::number);
    CHECK(j5.cbegin()->type() == JSON::value_type::number);
    CHECK(j6.begin()->type() == JSON::value_type::number_float);
    CHECK(j6.cbegin()->type() == JSON::value_type::number_float);
    CHECK(j7.begin()->type() == JSON::value_type::string);
    CHECK(j7.cbegin()->type() == JSON::value_type::string);

    CHECK(j1_const.begin()->type() == JSON::value_type::number);
    CHECK(j1_const.cbegin()->type() == JSON::value_type::number);
    CHECK(j2_const.begin()->type() == JSON::value_type::string);
    CHECK(j2_const.cbegin()->type() == JSON::value_type::string);
    CHECK(j3_const.begin()->type() == JSON::value_type::boolean);
    CHECK(j3_const.cbegin()->type() == JSON::value_type::boolean);
    CHECK(j4_const.begin()->type() == JSON::value_type::null);
    CHECK(j4_const.cbegin()->type() == JSON::value_type::null);
    CHECK(j5_const.begin()->type() == JSON::value_type::number);
    CHECK(j5_const.cbegin()->type() == JSON::value_type::number);
    CHECK(j6_const.begin()->type() == JSON::value_type::number_float);
    CHECK(j6_const.cbegin()->type() == JSON::value_type::number_float);
    CHECK(j7_const.begin()->type() == JSON::value_type::string);
    CHECK(j7_const.cbegin()->type() == JSON::value_type::string);

    CHECK_THROWS_AS(j1.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j1.cend()->type(), std::runtime_error);
    CHECK_THROWS_AS(j2.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j2.cend()->type(), std::runtime_error);
    CHECK_THROWS_AS(j3.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j3.cend()->type(), std::runtime_error);
    CHECK_THROWS_AS(j4.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j4.cend()->type(), std::runtime_error);
    CHECK_THROWS_AS(j5.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j5.cend()->type(), std::runtime_error);
    CHECK_THROWS_AS(j6.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j6.cend()->type(), std::runtime_error);
    CHECK_THROWS_AS(j7.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j7.cend()->type(), std::runtime_error);

    CHECK_THROWS_AS(j1_const.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j1_const.cend()->type(), std::runtime_error);
    CHECK_THROWS_AS(j2_const.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j2_const.cend()->type(), std::runtime_error);
    CHECK_THROWS_AS(j3_const.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j3_const.cend()->type(), std::runtime_error);
    CHECK_THROWS_AS(j4_const.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j4_const.cend()->type(), std::runtime_error);
    CHECK_THROWS_AS(j5_const.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j5_const.cend()->type(), std::runtime_error);
    CHECK_THROWS_AS(j6_const.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j6_const.cend()->type(), std::runtime_error);
    CHECK_THROWS_AS(j7_const.end()->type(), std::runtime_error);
    CHECK_THROWS_AS(j7_const.cend()->type(), std::runtime_error);

    // value
    CHECK(j1.begin().value().type() == JSON::value_type::number);
    CHECK(j1.cbegin().value().type() == JSON::value_type::number);
    CHECK(j2.begin().value().type() == JSON::value_type::string);
    CHECK(j2.cbegin().value().type() == JSON::value_type::string);
    CHECK(j3.begin().value().type() == JSON::value_type::boolean);
    CHECK(j3.cbegin().value().type() == JSON::value_type::boolean);
    CHECK(j4.begin().value().type() == JSON::value_type::null);
    CHECK(j4.cbegin().value().type() == JSON::value_type::null);
    CHECK(j5.begin().value().type() == JSON::value_type::number);
    CHECK(j5.cbegin().value().type() == JSON::value_type::number);
    CHECK(j6.begin().value().type() == JSON::value_type::number_float);
    CHECK(j6.cbegin().value().type() == JSON::value_type::number_float);
    CHECK(j7.begin().value().type() == JSON::value_type::string);
    CHECK(j7.cbegin().value().type() == JSON::value_type::string);

    CHECK(j1_const.begin().value().type() == JSON::value_type::number);
    CHECK(j1_const.cbegin().value().type() == JSON::value_type::number);
    CHECK(j2_const.begin().value().type() == JSON::value_type::string);
    CHECK(j2_const.cbegin().value().type() == JSON::value_type::string);
    CHECK(j3_const.begin().value().type() == JSON::value_type::boolean);
    CHECK(j3_const.cbegin().value().type() == JSON::value_type::boolean);
    CHECK(j4_const.begin().value().type() == JSON::value_type::null);
    CHECK(j4_const.cbegin().value().type() == JSON::value_type::null);
    CHECK(j5_const.begin().value().type() == JSON::value_type::number);
    CHECK(j5_const.cbegin().value().type() == JSON::value_type::number);
    CHECK(j6_const.begin().value().type() == JSON::value_type::number_float);
    CHECK(j6_const.cbegin().value().type() == JSON::value_type::number_float);
    CHECK(j7_const.begin().value().type() == JSON::value_type::string);
    CHECK(j7_const.cbegin().value().type() == JSON::value_type::string);

    CHECK_THROWS_AS(j1.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j1.cend().value(), std::out_of_range);
    CHECK_THROWS_AS(j2.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j2.cend().value(), std::out_of_range);
    CHECK_THROWS_AS(j3.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j3.cend().value(), std::out_of_range);
    CHECK_THROWS_AS(j4.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j4.cend().value(), std::out_of_range);
    CHECK_THROWS_AS(j5.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j5.cend().value(), std::out_of_range);
    CHECK_THROWS_AS(j6.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j6.cend().value(), std::out_of_range);
    CHECK_THROWS_AS(j7.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j7.cend().value(), std::out_of_range);

    CHECK_THROWS_AS(j1_const.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j1_const.cend().value(), std::out_of_range);
    CHECK_THROWS_AS(j2_const.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j2_const.cend().value(), std::out_of_range);
    CHECK_THROWS_AS(j3_const.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j3_const.cend().value(), std::out_of_range);
    CHECK_THROWS_AS(j4_const.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j4_const.cend().value(), std::out_of_range);
    CHECK_THROWS_AS(j5_const.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j5_const.cend().value(), std::out_of_range);
    CHECK_THROWS_AS(j6_const.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j6_const.cend().value(), std::out_of_range);
    CHECK_THROWS_AS(j7_const.end().value(), std::out_of_range);
    CHECK_THROWS_AS(j7_const.cend().value(), std::out_of_range);

    // iterator comparison
    CHECK(j1.begin() != j2.begin());
    CHECK(j1.begin() != j3.begin());
    CHECK(j1.begin() != j4.begin());
    CHECK(j1.begin() != j5.begin());
    CHECK(j1.begin() != j6.begin());
    CHECK(j1.begin() != j7.begin());

    CHECK(j1.cbegin() != j2.cbegin());
    CHECK(j1.cbegin() != j3.cbegin());
    CHECK(j1.cbegin() != j4.cbegin());
    CHECK(j1.cbegin() != j5.cbegin());
    CHECK(j1.cbegin() != j6.cbegin());
    CHECK(j1.cbegin() != j7.cbegin());

    CHECK(j2.begin() != j1.begin());
    CHECK(j2.begin() != j3.begin());
    CHECK(j2.begin() != j4.begin());
    CHECK(j2.begin() != j5.begin());
    CHECK(j2.begin() != j6.begin());
    CHECK(j2.begin() != j7.begin());

    CHECK(j2.cbegin() != j1.cbegin());
    CHECK(j2.cbegin() != j3.cbegin());
    CHECK(j2.cbegin() != j4.cbegin());
    CHECK(j2.cbegin() != j5.cbegin());
    CHECK(j2.cbegin() != j6.cbegin());
    CHECK(j2.cbegin() != j7.cbegin());

    CHECK(j3.begin() != j1.begin());
    CHECK(j3.begin() != j2.begin());
    CHECK(j3.begin() != j4.begin());
    CHECK(j3.begin() != j5.begin());
    CHECK(j3.begin() != j6.begin());
    CHECK(j3.begin() != j7.begin());

    CHECK(j3.cbegin() != j1.cbegin());
    CHECK(j3.cbegin() != j2.cbegin());
    CHECK(j3.cbegin() != j4.cbegin());
    CHECK(j3.cbegin() != j5.cbegin());
    CHECK(j3.cbegin() != j6.cbegin());
    CHECK(j3.cbegin() != j7.cbegin());

    CHECK(j4.begin() != j1.begin());
    CHECK(j4.begin() != j2.begin());
    CHECK(j4.begin() != j3.begin());
    CHECK(j4.begin() != j5.begin());
    CHECK(j4.begin() != j6.begin());
    CHECK(j4.begin() != j7.begin());

    CHECK(j4.cbegin() != j1.cbegin());
    CHECK(j4.cbegin() != j2.cbegin());
    CHECK(j4.cbegin() != j3.cbegin());
    CHECK(j4.cbegin() != j5.cbegin());
    CHECK(j4.cbegin() != j6.cbegin());
    CHECK(j4.cbegin() != j7.cbegin());

    CHECK(j5.begin() != j1.begin());
    CHECK(j5.begin() != j2.begin());
    CHECK(j5.begin() != j3.begin());
    CHECK(j5.begin() != j4.begin());
    CHECK(j5.begin() != j6.begin());
    CHECK(j5.begin() != j7.begin());

    CHECK(j5.cbegin() != j1.cbegin());
    CHECK(j5.cbegin() != j2.cbegin());
    CHECK(j5.cbegin() != j3.cbegin());
    CHECK(j5.cbegin() != j4.cbegin());
    CHECK(j5.cbegin() != j6.cbegin());
    CHECK(j5.cbegin() != j7.cbegin());

    CHECK(j6.begin() != j1.begin());
    CHECK(j6.begin() != j2.begin());
    CHECK(j6.begin() != j3.begin());
    CHECK(j6.begin() != j4.begin());
    CHECK(j6.begin() != j5.begin());
    CHECK(j6.begin() != j7.begin());

    CHECK(j6.cbegin() != j1.cbegin());
    CHECK(j6.cbegin() != j2.cbegin());
    CHECK(j6.cbegin() != j3.cbegin());
    CHECK(j6.cbegin() != j4.cbegin());
    CHECK(j6.cbegin() != j5.cbegin());
    CHECK(j6.cbegin() != j7.cbegin());

    CHECK(j7.begin() != j1.begin());
    CHECK(j7.begin() != j2.begin());
    CHECK(j7.begin() != j3.begin());
    CHECK(j7.begin() != j4.begin());
    CHECK(j7.begin() != j5.begin());
    CHECK(j7.begin() != j6.begin());

    CHECK(j7.cbegin() != j1.cbegin());
    CHECK(j7.cbegin() != j2.cbegin());
    CHECK(j7.cbegin() != j3.cbegin());
    CHECK(j7.cbegin() != j4.cbegin());
    CHECK(j7.cbegin() != j5.cbegin());
    CHECK(j7.cbegin() != j6.cbegin());

    // iterator copy constructors
    {
        JSON::iterator tmp1(j1.begin());
        JSON::const_iterator tmp2(j1.cbegin());
    }
    {
        JSON::iterator tmp1(j2.begin());
        JSON::const_iterator tmp2(j2.cbegin());
    }
    {
        JSON::iterator tmp1(j3.begin());
        JSON::const_iterator tmp2(j3.cbegin());
    }
    {
        JSON::iterator tmp1(j4.begin());
        JSON::const_iterator tmp2(j4.cbegin());
    }
    {
        JSON::iterator tmp1(j5.begin());
        JSON::const_iterator tmp2(j5.cbegin());
    }
    {
        JSON::iterator tmp1(j6.begin());
        JSON::const_iterator tmp2(j6.cbegin());
    }
    {
        JSON::iterator tmp1(j7.begin());
        JSON::const_iterator tmp2(j7.cbegin());
    }

}

TEST_CASE("Comparisons")
{
    JSON j1 = {0, 1, 2, 3, 4};
    JSON j2 = {{"foo", "bar"}, {"baz", "bam"}};
    JSON j3 = true;
    JSON j4 = nullptr;
    JSON j5 = 42;
    JSON j6 = 23.42;
    JSON j7 = "hello";

    CHECK((j1 == j1) == true);
    CHECK((j1 == j2) == false);
    CHECK((j1 == j3) == false);
    CHECK((j1 == j4) == false);
    CHECK((j1 == j5) == false);
    CHECK((j1 == j6) == false);
    CHECK((j1 == j7) == false);

    CHECK((j2 == j1) == false);
    CHECK((j2 == j2) == true);
    CHECK((j2 == j3) == false);
    CHECK((j2 == j4) == false);
    CHECK((j2 == j5) == false);
    CHECK((j2 == j6) == false);
    CHECK((j2 == j7) == false);

    CHECK((j3 == j1) == false);
    CHECK((j3 == j2) == false);
    CHECK((j3 == j3) == true);
    CHECK((j3 == j4) == false);
    CHECK((j3 == j5) == false);
    CHECK((j3 == j6) == false);
    CHECK((j3 == j7) == false);

    CHECK((j4 == j1) == false);
    CHECK((j4 == j2) == false);
    CHECK((j4 == j3) == false);
    CHECK((j4 == j4) == true);
    CHECK((j4 == j5) == false);
    CHECK((j4 == j6) == false);
    CHECK((j4 == j7) == false);

    CHECK((j5 == j1) == false);
    CHECK((j5 == j2) == false);
    CHECK((j5 == j3) == false);
    CHECK((j5 == j4) == false);
    CHECK((j5 == j5) == true);
    CHECK((j5 == j6) == false);
    CHECK((j5 == j7) == false);

    CHECK((j6 == j1) == false);
    CHECK((j6 == j2) == false);
    CHECK((j6 == j3) == false);
    CHECK((j6 == j4) == false);
    CHECK((j6 == j5) == false);
    CHECK((j6 == j6) == true);
    CHECK((j6 == j7) == false);

    CHECK((j7 == j1) == false);
    CHECK((j7 == j2) == false);
    CHECK((j7 == j3) == false);
    CHECK((j7 == j4) == false);
    CHECK((j7 == j5) == false);
    CHECK((j7 == j6) == false);
    CHECK((j7 == j7) == true);

    CHECK((j1 != j1) == false);
    CHECK((j1 != j2) == true);
    CHECK((j1 != j3) == true);
    CHECK((j1 != j4) == true);
    CHECK((j1 != j5) == true);
    CHECK((j1 != j6) == true);
    CHECK((j1 != j7) == true);

    CHECK((j2 != j1) == true);
    CHECK((j2 != j2) == false);
    CHECK((j2 != j3) == true);
    CHECK((j2 != j4) == true);
    CHECK((j2 != j5) == true);
    CHECK((j2 != j6) == true);
    CHECK((j2 != j7) == true);

    CHECK((j3 != j1) == true);
    CHECK((j3 != j2) == true);
    CHECK((j3 != j3) == false);
    CHECK((j3 != j4) == true);
    CHECK((j3 != j5) == true);
    CHECK((j3 != j6) == true);
    CHECK((j3 != j7) == true);

    CHECK((j4 != j1) == true);
    CHECK((j4 != j2) == true);
    CHECK((j4 != j3) == true);
    CHECK((j4 != j4) == false);
    CHECK((j4 != j5) == true);
    CHECK((j4 != j6) == true);
    CHECK((j4 != j7) == true);

    CHECK((j5 != j1) == true);
    CHECK((j5 != j2) == true);
    CHECK((j5 != j3) == true);
    CHECK((j5 != j4) == true);
    CHECK((j5 != j5) == false);
    CHECK((j5 != j6) == true);
    CHECK((j5 != j7) == true);

    CHECK((j6 != j1) == true);
    CHECK((j6 != j2) == true);
    CHECK((j6 != j3) == true);
    CHECK((j6 != j4) == true);
    CHECK((j6 != j5) == true);
    CHECK((j6 != j6) == false);
    CHECK((j6 != j7) == true);

    CHECK((j7 != j1) == true);
    CHECK((j7 != j2) == true);
    CHECK((j7 != j3) == true);
    CHECK((j7 != j4) == true);
    CHECK((j7 != j5) == true);
    CHECK((j7 != j6) == true);
    CHECK((j7 != j7) == false);
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

        // escape characters
        CHECK_THROWS_AS(JSON::parse("\"\\\""), std::invalid_argument);
        CHECK_NOTHROW(JSON::parse("\"\\\"\""));

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

    SECTION("number (float)")
    {
        // accept the exact values
        CHECK(JSON::parse("0.5") == JSON(0.5));
        CHECK(JSON::parse("-0.5") == JSON(-0.5));
        CHECK(JSON::parse("1.5") == JSON(1.5));
        CHECK(JSON::parse("-1.5") == JSON(-1.5));
        CHECK(JSON::parse("12345678.5") == JSON(12345678.5));
        CHECK(JSON::parse("-12345678.5") == JSON(-12345678.5));

        CHECK(JSON::parse("17.5e0") == JSON(17.5));
        CHECK(JSON::parse("17.5e1") == JSON(175));
        CHECK(JSON::parse("17.5e3") == JSON(17500));
        CHECK(JSON::parse("17.5e+0") == JSON(17.5));
        CHECK(JSON::parse("17.5e+1") == JSON(175));
        CHECK(JSON::parse("17.5e+3") == JSON(17500));
        CHECK(JSON::parse("17.5E0") == JSON(17.5));
        CHECK(JSON::parse("17.5E1") == JSON(175));
        CHECK(JSON::parse("17.5E3") == JSON(17500));
        CHECK(JSON::parse("17.5E+0") == JSON(17.5));
        CHECK(JSON::parse("17.5E+1") == JSON(175));
        CHECK(JSON::parse("17.5E+3") == JSON(17500));
        CHECK(JSON::parse("10000.5e-0") == JSON(10000.5));
        CHECK(JSON::parse("10000.5e-1") == JSON(1000.05));
        CHECK(JSON::parse("10000.5e-4") == JSON(1.00005));
        CHECK(JSON::parse("10000.5E-0") == JSON(10000.5));
        CHECK(JSON::parse("10000.5E-1") == JSON(1000.05));
        CHECK(JSON::parse("10000.5E-4") == JSON(1.00005));
    }

    SECTION("parse from C++ string")
    {
        std::string s = "{ \"foo\": [1,2,true] }";
        JSON j = JSON::parse(s);
        CHECK(j["foo"].size() == 3);
    }

    SECTION("parse from stream")
    {
        std::stringstream s;
        s << "{ \"foo\": [1,2,true] }";
        JSON j;
        j << s;
        CHECK(j["foo"].size() == 3);
    }

    SECTION("user-defined string literal operator")
    {
        auto j1 = "[1,2,3]"_json;
        JSON j2 = {1, 2, 3};
        CHECK(j1 == j2);

        auto j3 = "{\"key\": \"value\"}"_json;
        CHECK(j3["key"] == "value");
    }

    SECTION("Errors")
    {
        CHECK_THROWS_AS(JSON::parse(""), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse(std::string("")), std::invalid_argument);
        CHECK_THROWS_AS(JSON::parse("[1,2"), std::invalid_argument);
    }
}
