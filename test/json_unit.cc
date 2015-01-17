#define CATCH_CONFIG_MAIN
#define CATCH_CONFIG_CPP11_NULLPTR
#include "catch.hpp"

#include "json.h"

using json = nlohmann::json;

#if defined(_MSC_VER)
#define SKIP_FOR_VS(x)

#if _MSC_VER < 1900
#define LIST_INIT_T(...) json::list_init_t(__VA_ARGS__)
#else
#define LIST_INIT_T(...) __VA_ARGS__
#endif

#else
#define SKIP_FOR_VS(x) x
#define LIST_INIT_T(...) __VA_ARGS__
#endif

TEST_CASE("array")
{
    SECTION("Basics")
    {
        // construction with given type
        json j(json::value_type::array);
        CHECK(j.type() == json::value_type::array);

        // const object
        const json j_const (j);

        // string representation of default value
        CHECK(j.dump() == "[]");

        // iterators
        CHECK(j.begin() == j.end());
        CHECK(j.cbegin() == j.cend());

        // container members
        CHECK(j.size() == 0);
        CHECK(j.empty() == true);

        // implicit conversions
        CHECK_NOTHROW(json::array_t v = j);
        CHECK_THROWS_AS(json::object_t v = j, std::logic_error);
        CHECK_THROWS_AS(std::string v = j, std::logic_error);
        CHECK_THROWS_AS(bool v = j, std::logic_error);
        CHECK_THROWS_AS(int v = j, std::logic_error);
        CHECK_THROWS_AS(double v = j, std::logic_error);

        // explicit conversions
        CHECK_NOTHROW(auto v = j.get<json::array_t>());
        CHECK_THROWS_AS(auto v = j.get<json::object_t>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<std::string>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<bool>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<int>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<double>(), std::logic_error);

        // transparent usage
        auto id = [](json::array_t v)
        {
            return v;
        };
        CHECK(id(j) == j.get<json::array_t>());

        // copy constructor
        json k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        json l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        json::array_t v1 = {"string", 1, 1.0, false, nullptr};
        json j1 = v1;
        CHECK(j1.get<json::array_t>() == v1);

        json j2 = {"string", 1, 1.0, false, nullptr};
        json::array_t v2 = j2;
        CHECK(j2.get<json::array_t>() == v1);
        CHECK(j2.get<json::array_t>() == v2);

        // special tests to make sure construction from initializer list works

        // case 1: there is an element that is not an array
        json j3 = { {"foo", "bar"}, 3 };
        CHECK(j3.type() == json::value_type::array);

        // case 2: there is an element with more than two elements
        json j4 = { {"foo", "bar"}, {"one", "two", "three"} };
        CHECK(j4.type() == json::value_type::array);

        // case 3: there is an element whose first element is not a string
        json j5 = { {"foo", "bar"}, {true, "baz"} };
        CHECK(j5.type() == json::value_type::array);

        // check if nested arrays work and are recognized as arrays
        json j6 = { {{"foo", "bar"}} };
        CHECK(j6.type() == json::value_type::array);
        CHECK(j6.size() == 1);
        CHECK(j6[0].type() == json::value_type::object);

        // move constructor
        json j7(std::move(v1));
        CHECK(j7 == j1);
    }

    SECTION("Array operators")
    {
        json j = {0, 1, 2, 3, 4, 5, 6};

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
        json empty1, empty2;
        empty1 += "foo";
        empty2.push_back("foo");
        CHECK(empty1.type() == json::value_type::array);
        CHECK(empty2.type() == json::value_type::array);
        CHECK(empty1 == empty2);

        // exceptions
        json nonarray = 1;
        CHECK_THROWS_AS(nonarray.at(0), std::domain_error);
        CHECK_THROWS_AS(const int i = nonarray[0], std::domain_error);
		SKIP_FOR_VS(CHECK_NOTHROW(j[21]));
        CHECK_THROWS_AS(const int i = j.at(21), std::out_of_range);
        CHECK_THROWS_AS(nonarray[0] = 10, std::domain_error);
        // the next test is remove due to undefined behavior
        //CHECK_NOTHROW(j[21] = 5);
        CHECK_THROWS_AS(j.at(21) = 5, std::out_of_range);
        CHECK_THROWS_AS(nonarray += 2, std::runtime_error);

        const json nonarray_const = nonarray;
        const json j_const = j;
        CHECK_THROWS_AS(nonarray_const.at(0), std::domain_error);
        CHECK_THROWS_AS(const int i = nonarray_const[0], std::domain_error);
		SKIP_FOR_VS(CHECK_NOTHROW(j_const[21]));
        CHECK_THROWS_AS(const int i = j.at(21), std::out_of_range);

        {
            json nonarray2 = json(1);
            json nonarray3 = json(2);
            json empty3 = json();
            CHECK_THROWS_AS(nonarray2.push_back(nonarray3), std::runtime_error);
            CHECK_NOTHROW(empty3.push_back(nonarray3));
            CHECK(empty3.type() == json::value_type::array);
        }

        const json k = j;
		SKIP_FOR_VS(CHECK_NOTHROW(k[21]));
        CHECK_THROWS_AS(const int i = k.at(21), std::out_of_range);

        // add initializer list
        j.push_back(LIST_INIT_T({"a", "b", "c"}));
        CHECK (j.size() == 24);

        // clear()
        json j7 = {0, 1, 2, 3, 4, 5, 6};;
        CHECK(j7.size() == 7);
        j7.clear();
        CHECK(j7.size() == 0);
    }

    SECTION("Iterators")
    {
        std::vector<int> vec = {0, 1, 2, 3, 4, 5, 6};
        json j1 = {0, 1, 2, 3, 4, 5, 6};
        const json j2 = {0, 1, 2, 3, 4, 5, 6};

        {
            // const_iterator
            for (json::const_iterator cit = j1.begin(); cit != j1.end(); ++cit)
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
            for (json::const_iterator cit = j1.cbegin(); cit != j1.cend(); ++cit)
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
            for (json::iterator cit = j1.begin(); cit != j1.end(); ++cit)
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
            for (json::const_iterator cit = j2.begin(); cit != j2.end(); ++cit)
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
            for (json::const_iterator cit = j2.cbegin(); cit != j2.cend(); ++cit)
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


        // edge case: This should be an array with two elements which are in
        // turn arrays with two strings. However, this is treated like the
        // initializer list of an object.
        json j_should_be_an_array = { {"foo", "bar"}, {"baz", "bat"} };
        CHECK(j_should_be_an_array.type() == json::value_type::object);
    }

    SECTION("Iterators and empty arrays")
    {
        json empty_array(json::value_type::array);
        for (json::iterator it = empty_array.begin(); it != empty_array.end(); ++it) {}
        for (json::const_iterator it = empty_array.begin(); it != empty_array.end(); ++it) {}
        for (json::const_iterator it = empty_array.cbegin(); it != empty_array.cend(); ++it) {}
        for (auto el : empty_array) {}
        for (const auto el : empty_array) {}

        // create nonempty array, set iterators, clear array, and copy
        // existing iterators to cover copy constructor's code
        json array = {1, 2, 3};
        json::iterator i1 = array.begin();
        json::const_iterator i2 = array.cbegin();
        array.clear();
        json::iterator i3(i1);
        json::const_iterator i4(i1);
        json::const_iterator i5(i2);
    }
}

TEST_CASE("object")
{
    SECTION("Basics")
    {
        // construction with given type
        json j(json::value_type::object);
        CHECK(j.type() == json::value_type::object);

        // const object
        const json j_const = j;

        // string representation of default value
        CHECK(j.dump() == "{}");

        // iterators
        CHECK(j.begin() == j.end());
        CHECK(j.cbegin() == j.cend());

        // container members
        CHECK(j.size() == 0);
        CHECK(j.empty() == true);

        // implicit conversions
        CHECK_THROWS_AS(json::array_t v = j, std::logic_error);
        CHECK_NOTHROW(json::object_t v = j);
        CHECK_THROWS_AS(std::string v = j, std::logic_error);
        CHECK_THROWS_AS(bool v = j, std::logic_error);
        CHECK_THROWS_AS(int v = j, std::logic_error);
        CHECK_THROWS_AS(double v = j, std::logic_error);

        // explicit conversions
        CHECK_THROWS_AS(auto v = j.get<json::array_t>(), std::logic_error);
        CHECK_NOTHROW(auto v = j.get<json::object_t>());
        CHECK_THROWS_AS(auto v = j.get<std::string>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<bool>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<int>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<double>(), std::logic_error);

        // transparent usage
        auto id = [](json::object_t v)
        {
            return v;
        };
        CHECK(id(j) == j.get<json::object_t>());

        // copy constructor
        json k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        json l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        json::object_t v1 = { {"v1", "string"}, {"v2", 1}, {"v3", 1.0}, {"v4", false} };
        json j1 = v1;
        CHECK(j1.get<json::object_t>() == v1);

        json j2 = { {"v1", "string"}, {"v2", 1}, {"v3", 1.0}, {"v4", false} };
        json::object_t v2 = j2;
        CHECK(j2.get<json::object_t>() == v1);
        CHECK(j2.get<json::object_t>() == v2);

        // check if multiple keys are ignored
        json j3 = { {"key", "value"}, {"key", 1} };
        CHECK(j3.size() == 1);

        // move constructor
        json j7(std::move(v1));
        CHECK(j7 == j1);
    }

    SECTION("Object operators")
    {
        json j = {{"k0", "v0"}, {"k1", nullptr}, {"k2", 42}, {"k3", 3.141}, {"k4", true}};
        const json k = j;

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
        json::const_iterator i1 = j.find("k0");
        json::iterator i2 = j.find("k0");
        CHECK(k.find("k0") != k.end());
        CHECK(k.find("v0") == k.end());
        CHECK(k.find(std::string("v0")) == k.end());
        json::const_iterator i22 = k.find("k0");

        // at
        CHECK_THROWS_AS(j.at("foo"), std::out_of_range);
        CHECK_THROWS_AS(k.at("foo"), std::out_of_range);
        CHECK_THROWS_AS(j.at(std::string("foo")), std::out_of_range);
        CHECK_THROWS_AS(k.at(std::string("foo")), std::out_of_range);
        CHECK_NOTHROW(j.at(std::string("k0")));
        CHECK_NOTHROW(k.at(std::string("k0")));
        {
            json noobject = 1;
            const json noobject_const = noobject;
            CHECK_THROWS_AS(noobject.at("foo"), std::domain_error);
            CHECK_THROWS_AS(noobject.at(std::string("foo")), std::domain_error);
            CHECK_THROWS_AS(noobject_const.at("foo"), std::domain_error);
            CHECK_THROWS_AS(noobject_const.at(std::string("foo")), std::domain_error);
            CHECK_THROWS_AS(noobject["foo"], std::domain_error);
            CHECK_THROWS_AS(noobject[std::string("foo")], std::domain_error);
            CHECK_THROWS_AS(noobject_const[std::string("foo")], std::domain_error);
        }

        // add pair
        j.push_back(json::object_t::value_type {"int_key", 42});
        CHECK(j["int_key"].get<int>() == 42);
        j += json::object_t::value_type {"int_key2", 23};
        CHECK(j["int_key2"].get<int>() == 23);
        {
            // make sure null objects are transformed
            json je;
            CHECK_NOTHROW(je.push_back(json::object_t::value_type {"int_key", 42}));
            CHECK(je["int_key"].get<int>() == 42);
        }
        {
            // make sure null objects are transformed
            json je;
            CHECK_NOTHROW((je += json::object_t::value_type {"int_key", 42}));
            CHECK(je["int_key"].get<int>() == 42);
        }

        // add initializer list (of pairs)
        {
            json je;
            je.push_back(LIST_INIT_T({ {"one", 1}, {"two", false}, {"three", {1, 2, 3}} }));
            CHECK(je["one"].get<int>() == 1);
            CHECK(je["two"].get<bool>() == false);
            CHECK(je["three"].size() == 3);
        }
        {
            json je;
            je += LIST_INIT_T({ {"one", 1}, {"two", false}, {"three", {1, 2, 3}} });
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
        json::const_iterator i3;
        json::iterator i4;
        CHECK_THROWS_AS(i3.key(), std::out_of_range);
        CHECK_THROWS_AS(i3.value(), std::out_of_range);
        CHECK_THROWS_AS(i4.key(), std::out_of_range);
        CHECK_THROWS_AS(i4.value(), std::out_of_range);

        // key/value for end-iterator
        json::const_iterator i5 = j.find("v0");
        json::iterator i6 = j.find("v0");
        CHECK_THROWS_AS(i5.key(), std::out_of_range);
        CHECK_THROWS_AS(i5.value(), std::out_of_range);
        CHECK_THROWS_AS(i6.key(), std::out_of_range);
        CHECK_THROWS_AS(i6.value(), std::out_of_range);

        // implicit transformation into an object
        json empty;
        empty["foo"] = "bar";
        CHECK(empty.type() == json::value_type::object);
        CHECK(empty["foo"] == "bar");

        // exceptions
        json nonarray = 1;
        CHECK_THROWS_AS(const int i = nonarray["v1"], std::domain_error);
        CHECK_THROWS_AS(nonarray["v1"] = 10, std::domain_error);
        {
            const json c = {{"foo", "bar"}};
            CHECK_THROWS_AS(c[std::string("baz")], std::out_of_range);
        }

        // clear()
        json j7 = {{"k0", 0}, {"k1", 1}, {"k2", 2}, {"k3", 3}};
        CHECK(j7.size() == 4);
        j7.clear();
        CHECK(j7.size() == 0);
    }

    SECTION("Iterators")
    {
        json j1 = {{"k0", 0}, {"k1", 1}, {"k2", 2}, {"k3", 3}};
        const json j2 = {{"k0", 0}, {"k1", 1}, {"k2", 2}, {"k3", 3}};

        // iterator
        for (json::iterator it = j1.begin(); it != j1.end(); ++it)
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

            CHECK((*it).type() == json::value_type::number);
            CHECK(it->type() == json::value_type::number);
        }

        // range-based for
        for (auto& element : j1)
        {
            element = 2 * element.get<int>();
        }

        // const_iterator
        for (json::const_iterator it = j1.begin(); it != j1.end(); ++it)
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

            CHECK((*it).type() == json::value_type::number);
            CHECK(it->type() == json::value_type::number);
        }

        // const_iterator using cbegin/cend
        for (json::const_iterator it = j1.cbegin(); it != j1.cend(); ++it)
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

            CHECK((*it).type() == json::value_type::number);
            CHECK(it->type() == json::value_type::number);
        }

        // const_iterator (on const object)
        for (json::const_iterator it = j2.begin(); it != j2.end(); ++it)
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

            CHECK((*it).type() == json::value_type::number);
            CHECK(it->type() == json::value_type::number);
        }

        // const_iterator using cbegin/cend (on const object)
        for (json::const_iterator it = j2.cbegin(); it != j2.cend(); ++it)
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

            CHECK((*it).type() == json::value_type::number);
            CHECK(it->type() == json::value_type::number);
        }

        // range-based for (on const object)
        for (auto element : j1)
        {
            CHECK(element.get<int>() >= 0);
        }
    }

    SECTION("Iterators and empty objects")
    {
        json empty_object(json::value_type::object);
        for (json::iterator it = empty_object.begin(); it != empty_object.end(); ++it) {}
        for (json::const_iterator it = empty_object.begin(); it != empty_object.end(); ++it) {}
        for (json::const_iterator it = empty_object.cbegin(); it != empty_object.cend(); ++it) {}
        for (auto el : empty_object) {}
        for (const auto el : empty_object) {}

        // create nonempty object, set iterators, clear object, and copy
        // existing iterators to cover copy constructor's code
        json object = {{"foo", 1}};
        json::iterator i1 = object.begin();
        json::const_iterator i2 = object.cbegin();
        object.clear();
        json::iterator i3(i1);
        json::const_iterator i4(i1);
        json::const_iterator i5(i2);
    }
}

TEST_CASE("null")
{
    SECTION("Basics")
    {
        // construction with given type
        json j;
        CHECK(j.type() == json::value_type::null);

        // string representation of default value
        CHECK(j.dump() == "null");

        // iterators
        CHECK(j.begin() != j.end());
        CHECK(j.cbegin() != j.cend());

        // container members
        CHECK(j.size() == 0);
        CHECK(j.empty() == true);

        // implicit conversions
        CHECK_NOTHROW(json::array_t v = j);
        CHECK_THROWS_AS(json::object_t v = j, std::logic_error);
        CHECK_THROWS_AS(std::string v = j, std::logic_error);
        CHECK_THROWS_AS(bool v = j, std::logic_error);
        CHECK_THROWS_AS(int v = j, std::logic_error);
        CHECK_THROWS_AS(double v = j, std::logic_error);

        // explicit conversions
        CHECK_NOTHROW(auto v = j.get<json::array_t>());
        CHECK_THROWS_AS(auto v = j.get<json::object_t>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<std::string>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<bool>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<int>(), std::logic_error);
        CHECK_THROWS_AS(auto v = j.get<double>(), std::logic_error);

        // copy constructor
        json k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        json l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        json j1 = nullptr;
        CHECK(j1.type() == json::value_type::null);
    }

    SECTION("Operators")
    {
        // clear()
        json j1 = nullptr;
        j1.clear();
        CHECK(j1 == json(nullptr));
    }
}

TEST_CASE("string")
{
    SECTION("Basics")
    {
        // construction with given type
        json j(json::value_type::string);
        CHECK(j.type() == json::value_type::string);

        // const object
        const json j_const = j;

        // iterators
        CHECK(j.begin() != j.end());
        CHECK(j.cbegin() != j.cend());

        // string representation of default value
        CHECK(j.dump() == "\"\"");

        // container members
        CHECK(j.size() == 1);
        CHECK(j.empty() == false);

        // implicit conversions
        CHECK_NOTHROW(json::array_t v = j);
        CHECK_THROWS_AS(json::object_t v = j, std::logic_error);
        CHECK_NOTHROW(std::string v = j);
        CHECK_THROWS_AS(bool v = j, std::logic_error);
        CHECK_THROWS_AS(int v = j, std::logic_error);
        CHECK_THROWS_AS(double v = j, std::logic_error);

        // explicit conversions
        CHECK_NOTHROW(auto v = j.get<json::array_t>());
        CHECK_THROWS_AS(auto v = j.get<json::object_t>(), std::logic_error);
        CHECK_NOTHROW(auto v = j.get<std::string>());
        CHECK_NOTHROW(auto v = static_cast<std::string>(j));
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
        json k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        json l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        json j1 = std::string("Hello, world");
        std::string v1 = j1;
        CHECK(j1.get<std::string>() == v1);

        json j2 = "Hello, world";
        CHECK(j2.get<std::string>() == "Hello, world");

        std::string v3 = "Hello, world";
        json j3 = std::move(v3);
        CHECK(j3.get<std::string>() == "Hello, world");
    }

    SECTION("Operators")
    {
        // clear()
        json j1 = std::string("Hello, world");
        CHECK(j1.get<std::string>() == "Hello, world");
        j1.clear();
        CHECK(j1.get<std::string>() == "");
    }

    SECTION("Dumping")
    {
        CHECK(json("\"").dump(0) == "\"\\\"\"");
        SKIP_FOR_VS(CHECK(json("\\").dump(0) == "\"\\\\\""));
        CHECK(json("\n").dump(0) == "\"\\n\"");
        CHECK(json("\t").dump(0) == "\"\\t\"");
        CHECK(json("\b").dump(0) == "\"\\b\"");
        CHECK(json("\f").dump(0) == "\"\\f\"");
        CHECK(json("\r").dump(0) == "\"\\r\"");
    }
}

TEST_CASE("boolean")
{
    SECTION("Basics")
    {
        // construction with given type
        json j(json::value_type::boolean);
        CHECK(j.type() == json::value_type::boolean);

        // const object
        const json j_const = j;

        // iterators
        CHECK(j.begin() != j.end());
        CHECK(j.cbegin() != j.cend());

        // string representation of default value
        CHECK(j.dump() == "false");

        // container members
        CHECK(j.size() == 1);
        CHECK(j.empty() == false);

        // implicit conversions
        CHECK_NOTHROW(json::array_t v = j);
        CHECK_THROWS_AS(json::object_t v = j, std::logic_error);
        CHECK_THROWS_AS(std::string v = j, std::logic_error);
        CHECK_NOTHROW(bool v = j);
        CHECK_THROWS_AS(int v = j, std::logic_error);
        CHECK_THROWS_AS(double v = j, std::logic_error);

        // explicit conversions
        CHECK_NOTHROW(auto v = j.get<json::array_t>());
        CHECK_THROWS_AS(auto v = j.get<json::object_t>(), std::logic_error);
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
        json k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        json l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        json j1 = true;
        bool v1 = j1;
        CHECK(j1.get<bool>() == v1);

        json j2 = false;
        bool v2 = j2;
        CHECK(j2.get<bool>() == v2);
    }

    SECTION("Operators")
    {
        // clear()
        json j1 = true;
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
        json j(json::value_type::number);
        CHECK(j.type() == json::value_type::number);

        // const object
        const json j_const = j;

        // iterators
        CHECK(j.begin() != j.end());
        CHECK(j.cbegin() != j.cend());

        // string representation of default value
        CHECK(j.dump() == "0");

        // container members
        CHECK(j.size() == 1);
        CHECK(j.empty() == false);

        // implicit conversions
        CHECK_NOTHROW(json::array_t v = j);
        CHECK_THROWS_AS(json::object_t v = j, std::logic_error);
        CHECK_THROWS_AS(std::string v = j, std::logic_error);
        CHECK_THROWS_AS(bool v = j, std::logic_error);
        CHECK_NOTHROW(int v = j);
        CHECK_NOTHROW(double v = j);

        // explicit conversions
        CHECK_NOTHROW(auto v = j.get<json::array_t>());
        CHECK_THROWS_AS(auto v = j.get<json::object_t>(), std::logic_error);
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
        json k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        json l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        json j1 = 23;
        int v1 = j1;
        CHECK(j1.get<int>() == v1);

        json j2 = 42;
        int v2 = j2;
        CHECK(j2.get<int>() == v2);
    }

    SECTION("Operators")
    {
        // clear()
        json j1 = 42;
        CHECK(j1.get<int>() == 42);
        j1.clear();
        CHECK(j1.get<int>() == 0);

        // find()
        CHECK(j1.find("foo") == j1.end());
        CHECK(j1.find(std::string("foo")) == j1.end());
        const json j2 = j1;
        CHECK(j2.find("foo") == j2.end());
        CHECK(j2.find(std::string("foo")) == j2.end());
    }
}

TEST_CASE("number (float)")
{
    SECTION("Basics")
    {
        // construction with given type
        json j(json::value_type::number_float);
        CHECK(j.type() == json::value_type::number_float);

        // const object
        const json j_const = j;

        // iterators
        CHECK(j.begin() != j.end());
        CHECK(j.cbegin() != j.cend());

        // string representation of default value
        CHECK(j.dump() == "0.000000");

        // container members
        CHECK(j.size() == 1);
        CHECK(j.empty() == false);

        // implicit conversions
        CHECK_NOTHROW(json::array_t v = j);
        CHECK_THROWS_AS(json::object_t v = j, std::logic_error);
        CHECK_THROWS_AS(std::string v = j, std::logic_error);
        CHECK_THROWS_AS(bool v = j, std::logic_error);
        CHECK_NOTHROW(int v = j);
        CHECK_NOTHROW(double v = j);

        // explicit conversions
        CHECK_NOTHROW(auto v = j.get<json::array_t>());
        CHECK_THROWS_AS(auto v = j.get<json::object_t>(), std::logic_error);
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
        json k(j);
        CHECK(k == j);

        // copy assignment
        k = j;
        CHECK(k == j);

        // move constructor
        json l = std::move(k);
        CHECK(l == j);
    }

    SECTION("Create from value")
    {
        json j1 = 3.1415926;
        double v1 = j1;
        CHECK(j1.get<double>() == v1);

        json j2 = 2.7182818;
        double v2 = j2;
        CHECK(j2.get<double>() == v2);
    }

    SECTION("Operators")
    {
        // clear()
        json j1 = 3.1415926;
        CHECK(j1.get<double>() == 3.1415926);
        j1.clear();
        CHECK(j1.get<double>() == 0.0);
    }
}

TEST_CASE("Iterators")
{
    json j1 = {0, 1, 2, 3, 4};
    json j2 = {{"foo", "bar"}, {"baz", "bam"}};
    json j3 = true;
    json j4 = nullptr;
    json j5 = 42;
    json j6 = 23.42;
    json j7 = "hello";

    const json j1_const = {0, 1, 2, 3, 4};
    const json j2_const = {{"foo", "bar"}, {"baz", "bam"}};
    const json j3_const = true;
    const json j4_const = nullptr;
    const json j5_const = 42;
    const json j6_const = 23.42;
    const json j7_const = "hello";

    // operator *
    CHECK(* j1.begin() == json(0));
    CHECK(* j1_const.begin() == json(0));
    CHECK(* j2.begin() != json());
    CHECK(* j2_const.begin() != json());
    CHECK(* j3.begin() == json(true));
    CHECK(* j3_const.begin() == json(true));
    CHECK(* j4.begin() == json());
    CHECK(* j4_const.begin() == json());
    CHECK(* j5.begin() == json(42));
    CHECK(* j5_const.begin() == json(42));
    CHECK(* j6.begin() == json(23.42));
    CHECK(* j6_const.begin() == json(23.42));
    CHECK(* j7.begin() == json("hello"));
    CHECK(* j7_const.begin() == json("hello"));

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
    CHECK(j1.begin()->type() == json::value_type::number);
    CHECK(j1.cbegin()->type() == json::value_type::number);
    CHECK(j2.begin()->type() == json::value_type::string);
    CHECK(j2.cbegin()->type() == json::value_type::string);
    CHECK(j3.begin()->type() == json::value_type::boolean);
    CHECK(j3.cbegin()->type() == json::value_type::boolean);
    CHECK(j4.begin()->type() == json::value_type::null);
    CHECK(j4.cbegin()->type() == json::value_type::null);
    CHECK(j5.begin()->type() == json::value_type::number);
    CHECK(j5.cbegin()->type() == json::value_type::number);
    CHECK(j6.begin()->type() == json::value_type::number_float);
    CHECK(j6.cbegin()->type() == json::value_type::number_float);
    CHECK(j7.begin()->type() == json::value_type::string);
    CHECK(j7.cbegin()->type() == json::value_type::string);

    CHECK(j1_const.begin()->type() == json::value_type::number);
    CHECK(j1_const.cbegin()->type() == json::value_type::number);
    CHECK(j2_const.begin()->type() == json::value_type::string);
    CHECK(j2_const.cbegin()->type() == json::value_type::string);
    CHECK(j3_const.begin()->type() == json::value_type::boolean);
    CHECK(j3_const.cbegin()->type() == json::value_type::boolean);
    CHECK(j4_const.begin()->type() == json::value_type::null);
    CHECK(j4_const.cbegin()->type() == json::value_type::null);
    CHECK(j5_const.begin()->type() == json::value_type::number);
    CHECK(j5_const.cbegin()->type() == json::value_type::number);
    CHECK(j6_const.begin()->type() == json::value_type::number_float);
    CHECK(j6_const.cbegin()->type() == json::value_type::number_float);
    CHECK(j7_const.begin()->type() == json::value_type::string);
    CHECK(j7_const.cbegin()->type() == json::value_type::string);

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
    CHECK(j1.begin().value().type() == json::value_type::number);
    CHECK(j1.cbegin().value().type() == json::value_type::number);
    CHECK(j2.begin().value().type() == json::value_type::string);
    CHECK(j2.cbegin().value().type() == json::value_type::string);
    CHECK(j3.begin().value().type() == json::value_type::boolean);
    CHECK(j3.cbegin().value().type() == json::value_type::boolean);
    CHECK(j4.begin().value().type() == json::value_type::null);
    CHECK(j4.cbegin().value().type() == json::value_type::null);
    CHECK(j5.begin().value().type() == json::value_type::number);
    CHECK(j5.cbegin().value().type() == json::value_type::number);
    CHECK(j6.begin().value().type() == json::value_type::number_float);
    CHECK(j6.cbegin().value().type() == json::value_type::number_float);
    CHECK(j7.begin().value().type() == json::value_type::string);
    CHECK(j7.cbegin().value().type() == json::value_type::string);

    CHECK(j1_const.begin().value().type() == json::value_type::number);
    CHECK(j1_const.cbegin().value().type() == json::value_type::number);
    CHECK(j2_const.begin().value().type() == json::value_type::string);
    CHECK(j2_const.cbegin().value().type() == json::value_type::string);
    CHECK(j3_const.begin().value().type() == json::value_type::boolean);
    CHECK(j3_const.cbegin().value().type() == json::value_type::boolean);
    CHECK(j4_const.begin().value().type() == json::value_type::null);
    CHECK(j4_const.cbegin().value().type() == json::value_type::null);
    CHECK(j5_const.begin().value().type() == json::value_type::number);
    CHECK(j5_const.cbegin().value().type() == json::value_type::number);
    CHECK(j6_const.begin().value().type() == json::value_type::number_float);
    CHECK(j6_const.cbegin().value().type() == json::value_type::number_float);
    CHECK(j7_const.begin().value().type() == json::value_type::string);
    CHECK(j7_const.cbegin().value().type() == json::value_type::string);

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
        json::iterator tmp1(j1.begin());
        json::const_iterator tmp2(j1.cbegin());
    }
    {
        json::iterator tmp1(j2.begin());
        json::const_iterator tmp2(j2.cbegin());
    }
    {
        json::iterator tmp1(j3.begin());
        json::const_iterator tmp2(j3.cbegin());
    }
    {
        json::iterator tmp1(j4.begin());
        json::const_iterator tmp2(j4.cbegin());
    }
    {
        json::iterator tmp1(j5.begin());
        json::const_iterator tmp2(j5.cbegin());
    }
    {
        json::iterator tmp1(j6.begin());
        json::const_iterator tmp2(j6.cbegin());
    }
    {
        json::iterator tmp1(j7.begin());
        json::const_iterator tmp2(j7.cbegin());
    }
    {
        json j_array = {0, 1, 2, 3, 4, 5};

        json::iterator i1 = j_array.begin();
        ++i1;
        json::iterator i2(i1);
        json::iterator i3;
        i3 = i2;
        CHECK(i1 == i1);

        json::const_iterator i4 = j_array.begin();
        ++i4;
        json::const_iterator i5(i4);
        json::const_iterator i6;
        i6 = i5;
        CHECK(i4 == i4);
    }
    {
        json j_object = {{"1", 1}, {"2", 2}, {"3", 3}};

        json::iterator i1 = j_object.begin();
        ++i1;
        json::iterator i11 = j_object.begin();
        CHECK((i1 == i11) == false);
        json::iterator i2(i1);
        json::iterator i3;
        i3 = i2;
        CHECK(i1 == i1);

        json::const_iterator i4 = j_object.begin();
        ++i4;
        json::iterator i41 = j_object.begin();
        CHECK((i4 == i41) == false);
        json::const_iterator i5(i4);
        json::const_iterator i6;
        i6 = i5;
        CHECK(i4 == i4);
    }

    // iterator copy assignment
    {
        json::iterator i1 = j2.begin();
        json::const_iterator i2 = j2.cbegin();
        json::iterator i3 = i1;
        json::const_iterator i4 = i2;
    }

    // operator++
    {
        json j;
        const json j_const = j;
        {
            json::iterator i = j.begin();
            ++i;
            CHECK(i == j.end());
            ++i;
            CHECK(i == j.end());
        }
        {
            json::const_iterator i = j.begin();
            ++i;
            CHECK(i == j.end());
            ++i;
            CHECK(i == j.end());
        }
        {
            json::const_iterator i = j_const.begin();
            ++i;
            CHECK(i == j_const.end());
            ++i;
            CHECK(i == j_const.end());
        }
        {
            json::const_iterator i = j.cbegin();
            ++i;
            CHECK(i == j.cend());
            ++i;
            CHECK(i == j.cend());
        }
        {
            json::const_iterator i = j_const.cbegin();
            ++i;
            CHECK(i == j_const.cend());
            ++i;
            CHECK(i == j_const.cend());
        }
    }
}

TEST_CASE("Comparisons")
{
    json j1 = {0, 1, 2, 3, 4};
    json j2 = {{"foo", "bar"}, {"baz", "bam"}};
    json j3 = true;
    json j4 = nullptr;
    json j5 = 42;
    json j6 = 23.42;
    json j7 = "hello";

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
        CHECK(json::parse("null") == json(nullptr));

        // ignore whitespace
        CHECK(json::parse(" null ") == json(nullptr));
        CHECK(json::parse("\tnull\n") == json(nullptr));

        // respect capitalization
        CHECK_THROWS_AS(json::parse("Null"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("NULL"), std::invalid_argument);

        // do not accept prefixes
        CHECK_THROWS_AS(json::parse("n"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("nu"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("nul"), std::invalid_argument);
    }

    SECTION("string")
    {
        // accept some values
        CHECK(json::parse("\"\"") == json(""));
        CHECK(json::parse("\"foo\"") == json("foo"));

        // escaping quotes
        CHECK_THROWS_AS(json::parse("\"\\\""), std::invalid_argument);
        CHECK_NOTHROW(json::parse("\"\\\"\""));

        // escaping backslashes
        CHECK(json::parse("\"a\\\\z\"") == json("a\\z"));
        CHECK(json::parse("\"\\\\\"") == json("\\"));
        CHECK(json::parse("\"\\\\a\\\\\"") == json("\\a\\"));
        CHECK(json::parse("\"\\\\\\\\\"") == json("\\\\"));

        // escaping slash
        CHECK(json::parse("\"a\\/z\"") == json("a/z"));
        CHECK(json::parse("\"\\/\"") == json("/"));

        // escaping tabs
        CHECK(json::parse("\"a\\tz\"") == json("a\tz"));
        CHECK(json::parse("\"\\t\"") == json("\t"));

        // escaping formfeed
        CHECK(json::parse("\"a\\fz\"") == json("a\fz"));
        CHECK(json::parse("\"\\f\"") == json("\f"));

        // escaping carriage return
        CHECK(json::parse("\"a\\rz\"") == json("a\rz"));
        CHECK(json::parse("\"\\r\"") == json("\r"));

        // escaping backspace
        CHECK(json::parse("\"a\\bz\"") == json("a\bz"));
        CHECK(json::parse("\"\\b\"") == json("\b"));

        // escaping newline
        CHECK(json::parse("\"a\\nz\"") == json("a\nz"));
        CHECK(json::parse("\"\\n\"") == json("\n"));

        // escaping senseless stuff
        CHECK_THROWS_AS(json::parse("\"\\z\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\ \""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\9\""), std::invalid_argument);

        // quotes must be closed
        CHECK_THROWS_AS(json::parse("\""), std::invalid_argument);
    }

    SECTION("unicode_escaping")
    {
        // two tests for uppercase and lowercase hex

        // normal forward slash in ASCII range
        CHECK(json::parse("\"\\u002F\"") == json("/"));
        CHECK(json::parse("\"\\u002f\"") == json("/"));

        // german a umlaut
        SKIP_FOR_VS(CHECK(json::parse("\"\\u00E4\"") == json(u8"\u00E4")));
        SKIP_FOR_VS(CHECK(json::parse("\"\\u00e4\"") == json(u8"\u00E4")));
        // weird d
        SKIP_FOR_VS(CHECK(json::parse("\"\\u0111\"") == json(u8"\u0111")));
        // unicode arrow left
        SKIP_FOR_VS(CHECK(json::parse("\"\\u2190\"") == json(u8"\u2190")));
        // pleasing osiris by testing hieroglyph support
        SKIP_FOR_VS(CHECK(json::parse("\"\\uD80C\\uDC60\"") == json(u8"\U00013060")));
        SKIP_FOR_VS(CHECK(json::parse("\"\\ud80C\\udc60\"") == json(u8"\U00013060")));

        // no hex numbers behind the \u
        CHECK_THROWS_AS(json::parse("\"\\uD80v\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\uD80 A\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\uD8v\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\uDv\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\uv\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\u\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\u\\u\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"a\\uD80vAz\""), std::invalid_argument);
        // missing part of a surrogate pair
        CHECK_THROWS_AS(json::parse("\"bla \\uD80C bla\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\uD80C bla bla\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"bla bla \\uD80C bla bla\""), std::invalid_argument);
        // senseless surrogate pair
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\uD80C\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\u0000\""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("\"\\uD80C\\uFFFF\""), std::invalid_argument);

        // test private code point converter function
        CHECK_NOTHROW(json::parser("").codePointToUTF8(0x10FFFE));
        CHECK_NOTHROW(json::parser("").codePointToUTF8(0x10FFFF));
        CHECK_THROWS_AS(json::parser("").codePointToUTF8(0x110000), std::invalid_argument);
        CHECK_THROWS_AS(json::parser("").codePointToUTF8(0x110001), std::invalid_argument);
    }

    SECTION("boolean")
    {
        // accept the exact values
        CHECK(json::parse("true") == json(true));
        CHECK(json::parse("false") == json(false));

        // ignore whitespace
        CHECK(json::parse(" true ") == json(true));
        CHECK(json::parse("\tfalse\n") == json(false));

        // respect capitalization
        CHECK_THROWS_AS(json::parse("True"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("False"), std::invalid_argument);

        // do not accept prefixes
        CHECK_THROWS_AS(json::parse("t"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("tr"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("tru"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("f"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("fa"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("fal"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("fals"), std::invalid_argument);
    }

    SECTION("number (int)")
    {
        // accept the exact values
        CHECK(json::parse("0") == json(0));
        CHECK(json::parse("-0") == json(0));
        CHECK(json::parse("1") == json(1));
        CHECK(json::parse("-1") == json(-1));
        CHECK(json::parse("12345678") == json(12345678));
        CHECK(json::parse("-12345678") == json(-12345678));

        CHECK(json::parse("0.0") == json(0));
        CHECK(json::parse("-0.0") == json(0));
        CHECK(json::parse("1.0") == json(1));
        CHECK(json::parse("-1.0") == json(-1));
        CHECK(json::parse("12345678.0") == json(12345678));
        CHECK(json::parse("-12345678.0") == json(-12345678));

        CHECK(json::parse("17e0") == json(17));
        CHECK(json::parse("17e1") == json(170));
        CHECK(json::parse("17e3") == json(17000));
        CHECK(json::parse("17e+0") == json(17));
        CHECK(json::parse("17e+1") == json(170));
        CHECK(json::parse("17e+3") == json(17000));
        CHECK(json::parse("17E0") == json(17));
        CHECK(json::parse("17E1") == json(170));
        CHECK(json::parse("17E3") == json(17000));
        CHECK(json::parse("17E+0") == json(17));
        CHECK(json::parse("17E+1") == json(170));
        CHECK(json::parse("17E+3") == json(17000));
        CHECK(json::parse("10000e-0") == json(10000));
        CHECK(json::parse("10000e-1") == json(1000));
        CHECK(json::parse("10000e-4") == json(1));
        CHECK(json::parse("10000E-0") == json(10000));
        CHECK(json::parse("10000E-1") == json(1000));
        CHECK(json::parse("10000E-4") == json(1));

        CHECK(json::parse("17.0e0") == json(17));
        CHECK(json::parse("17.0e1") == json(170));
        CHECK(json::parse("17.0e3") == json(17000));
        CHECK(json::parse("17.0e+0") == json(17));
        CHECK(json::parse("17.0e+1") == json(170));
        CHECK(json::parse("17.0e+3") == json(17000));
        CHECK(json::parse("17.0E0") == json(17));
        CHECK(json::parse("17.0E1") == json(170));
        CHECK(json::parse("17.0E3") == json(17000));
        CHECK(json::parse("17.0E+0") == json(17));
        CHECK(json::parse("17.0E+1") == json(170));
        CHECK(json::parse("17.0E+3") == json(17000));
        CHECK(json::parse("10000.0e-0") == json(10000));
        CHECK(json::parse("10000.0e-1") == json(1000));
        CHECK(json::parse("10000.0e-4") == json(1));
        CHECK(json::parse("10000.0E-0") == json(10000));
        CHECK(json::parse("10000.0E-1") == json(1000));
        CHECK(json::parse("10000.0E-4") == json(1));

        // trailing zero is not allowed
        //CHECK_THROWS_AS(json::parse("01"), std::invalid_argument);

        // whitespace inbetween is an error
        //CHECK_THROWS_AS(json::parse("1 0"), std::invalid_argument);

        // only one minus is allowd
        CHECK_THROWS_AS(json::parse("--1"), std::invalid_argument);

        // string representations are not allowed
        CHECK_THROWS_AS(json::parse("NAN"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("nan"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("INF"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("inf"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("INFINITY"), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("infinity"), std::invalid_argument);
    }

    SECTION("number (float)")
    {
        // accept the exact values
        CHECK(json::parse("0.5") == json(0.5));
        CHECK(json::parse("-0.5") == json(-0.5));
        CHECK(json::parse("1.5") == json(1.5));
        CHECK(json::parse("-1.5") == json(-1.5));
        CHECK(json::parse("12345678.5") == json(12345678.5));
        CHECK(json::parse("-12345678.5") == json(-12345678.5));

        CHECK(json::parse("17.5e0") == json(17.5));
        CHECK(json::parse("17.5e1") == json(175));
        CHECK(json::parse("17.5e3") == json(17500));
        CHECK(json::parse("17.5e+0") == json(17.5));
        CHECK(json::parse("17.5e+1") == json(175));
        CHECK(json::parse("17.5e+3") == json(17500));
        CHECK(json::parse("17.5E0") == json(17.5));
        CHECK(json::parse("17.5E1") == json(175));
        CHECK(json::parse("17.5E3") == json(17500));
        CHECK(json::parse("17.5E+0") == json(17.5));
        CHECK(json::parse("17.5E+1") == json(175));
        CHECK(json::parse("17.5E+3") == json(17500));
        CHECK(json::parse("10000.5e-0") == json(10000.5));
        CHECK(json::parse("10000.5e-1") == json(1000.05));
        CHECK(json::parse("10000.5e-4") == json(1.00005));
        CHECK(json::parse("10000.5E-0") == json(10000.5));
        CHECK(json::parse("10000.5E-1") == json(1000.05));
        CHECK(json::parse("10000.5E-4") == json(1.00005));
    }

    SECTION("parse from C++ string")
    {
        std::string s = "{ \"foo\": [1,2,true] }";
        json j = json::parse(s);
        CHECK(j["foo"].size() == 3);
    }

    SECTION("parse from stream")
    {
        std::stringstream s;
        s << "{ \"foo\": [1,2,true] }";
        json j;
        j << s;
        CHECK(j["foo"].size() == 3);
    }

#ifdef JSON_USE_LITERALS
    SECTION("user-defined string literal operator")
    {
        auto j1 = "[1,2,3]"_json;
        json j2 = {1, 2, 3};
        CHECK(j1 == j2);

        auto j3 = "{\"key\": \"value\"}"_json;
        CHECK(j3["key"] == "value");

        auto j22 = R"({
            "pi": 3.141,
            "happy": true
        })"_json;
        auto j23 = "{ \"pi\": 3.141, \"happy\": true }"_json;
        CHECK(j22 == j23);
    }

    SECTION("serialization")
    {
        auto j23 = "{ \"a\": null, \"b\": true, \"c\": [1,2,3], \"d\": {\"a\": 0} }"_json;

        CHECK(j23.dump() == "{\"a\": null, \"b\": true, \"c\": [1, 2, 3], \"d\": {\"a\": 0}}");
        CHECK(j23.dump(-1) == "{\"a\": null, \"b\": true, \"c\": [1, 2, 3], \"d\": {\"a\": 0}}");
        CHECK(j23.dump(0) ==
              "{\n\"a\": null,\n\"b\": true,\n\"c\": [\n1,\n2,\n3\n],\n\"d\": {\n\"a\": 0\n}\n}");
        CHECK(j23.dump(4) ==
              "{\n    \"a\": null,\n    \"b\": true,\n    \"c\": [\n        1,\n        2,\n        3\n    ],\n    \"d\": {\n        \"a\": 0\n    }\n}");
    }
#endif

    SECTION("Errors")
    {
        CHECK_THROWS_AS(json::parse(""), std::invalid_argument);
        CHECK_THROWS_AS(json::parse(std::string("")), std::invalid_argument);
        CHECK_THROWS_AS(json::parse("[1,2"), std::invalid_argument);
    }
}
