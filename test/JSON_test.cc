#include <iostream>
#include <fstream>
#include <cstdio>
#include <cassert>
#include <JSON.h>
#include <sstream>

void test_null() {
    std::cerr << "entering test_null()\n";

    /* a null object */

    // construct
    JSON a, b;

    // copy assign
    b = JSON();

    // copy construct
    JSON c(a);

    // copy construct
    JSON d = a;

    // assign operator
    JSON e = JSON();

    // compare
    assert(a == b);

    // type
    assert(a.type() == JSON::null);

    // empty and size
    assert(a.size() == 0);
    assert(a.empty() == true);

    // output
    std::cout << a << '\n';

    // string represetations
    assert(a.toString() == std::string("null"));

    // invalid conversion to int
    try {
        int i = 0;
        i = a;
        assert(false);
    } catch (const std::exception& ex) {
        assert(ex.what() == std::string("cannot cast null to JSON number"));
    }

    // invalid conversion to double
    try {
        double f = 0;
        f = a;
        assert(false);
    } catch (const std::exception& ex) {
        assert(ex.what() == std::string("cannot cast null to JSON number"));
    }

    // invalid conversion to bool
    try {
        bool b = a;
        assert(false);
    } catch (const std::exception& ex) {
        assert(ex.what() == std::string("cannot cast null to JSON Boolean"));
    }

    // invalid conversion to string
    try {
        std::string s = a;
        assert(false);
    } catch (const std::exception& ex) {
        assert(ex.what() == std::string("cannot cast null to JSON string"));
    }

    std::cerr << "leaving test_null()\n";
}

void test_bool() {
    std::cerr << "entering test_bool()\n";

    JSON True = true;
    JSON False = false;

    bool x = True;

    std::cerr << "leaving test_bool()\n";
}

void test_string() {
    std::cerr << "entering test_string()\n";

    /* a string object */

    // construct
    JSON a = "object a";
    JSON b;

    // copy assign
    b = JSON("object a");

    // copy construct
    JSON c(a);

    // copy construct
    JSON d = a;

    // assign operator
    JSON e = JSON("");

    // compare
    assert(a == b);

    // type
    assert(a.type() == JSON::string);

    // empty and size
    assert(a.size() == 1);
    assert(a.empty() == false);

    // output
    std::cout << a << '\n';

    // string represetations
    assert(a.toString() == std::string("\"object a\""));

    // invalid conversion to int
    try {
        int i = 0;
        i = a;
        assert(false);
    } catch (const std::exception& ex) {
        assert(ex.what() == std::string("cannot cast string to JSON number"));
    }

    // invalid conversion to double
    try {
        double f = 0;
        f = a;
        assert(false);
    } catch (const std::exception& ex) {
        assert(ex.what() == std::string("cannot cast string to JSON number"));
    }

    // invalid conversion to bool
    try {
        bool b = false;
        b = a;
        assert(false);
    } catch (const std::exception& ex) {
        assert(ex.what() == std::string("cannot cast string to JSON Boolean"));
    }

    {
        // get payload
        std::string* s1 = a.data().string;
        std::string s2 = a;
        assert(*s1 == s2);
    }

    std::cerr << "leaving test_string()\n";
}

void test_array() {
    std::cerr << "entering test_array()\n";

    JSON a;
    a += JSON();
    a += 1;
    a += 1.0;
    a += true;
    a += "string";

    // type
    assert(a.type() == JSON::array);

    // empty and size
    assert(a.size() == 5);
    assert(a.empty() == false);

    // output
    std::cout << a << '\n';

    // check for elements
    assert(a[1] == JSON(1));
    assert(a[2] == JSON(1.0));
    assert(a[3] == JSON(true));
    assert(a[4] == JSON("string"));

    // invalid access to element
    try {
        a[5] = 1;
        assert(false);
    } catch (const std::exception& ex) {
        assert(ex.what() == std::string("cannot access element at index 5"));
    }

    // get elements
    {
        int i = a[1];
        double d = a[2];
        bool b = a[3];
        std::string s = a[4];
    }

    // set elements
    a[1] = 2;

#ifdef __cplusplus11
    // construction from initializer list
    JSON b = {JSON(), 2, 1.0, true, "string"};
    assert(a == b);
#endif

    // iterators
    {
        size_t count = 0;
        for (JSON::iterator i = a.begin(); i != a.end(); ++i) {
            std::cerr << *i << '\n';
            count++;
        }
        assert(count == a.size());
    }

    {
        size_t count = 0;
        for (JSON::const_iterator i = a.begin(); i != a.end(); ++i) {
            std::cerr << *i << '\n';
            count++;
        }
        assert(count == a.size());
    }

    {
        size_t count = 0;
        for (JSON::const_iterator i = a.cbegin(); i != a.cend(); ++i) {
            std::cerr << *i << '\n';
            count++;
        }
        assert(count == a.size());
    }

#ifdef __cplusplus11
    {
        size_t count = 0;
        for (auto element : a) {
            std::cerr << element << '\n';
            count++;
        }
        assert(count == a.size());
    }
#endif

    {
        JSON::iterator i;
        size_t count = 0;
        for (i = a.begin(); i != a.end(); ++i) {
            std::cerr << *i << '\n';
            count++;
        }
        assert(count == a.size());
    }

    {
        JSON::const_iterator i;
        size_t count = 0;
        for (i = a.begin(); i != a.end(); ++i) {
            std::cerr << *i << '\n';
            count++;
        }
        assert(count == a.size());
    }

    {
        JSON::const_iterator i;
        size_t count = 0;
        for (i = a.cbegin(); i != a.cend(); ++i) {
            std::cerr << *i << '\n';
            count++;
        }
        assert(count == a.size());
    }

    {
        // get payload
        std::vector<JSON>* array = a.data().array;
        assert(array->size() == a.size());
        assert(array->empty() == a.empty());
    }

    std::cerr << "leaving test_array()\n";
}

void test_object() {
    std::cerr << "entering test_object()\n";

    // check find()
    {
        JSON o;
        o["foo"] = "bar";

        JSON::iterator i1 = o.find("foo");
        assert(i1 != o.end());
        assert(i1.value() == "bar");
        assert(i1.key() == "foo");
        assert(*i1 == "bar");

        JSON::iterator i2 = o.find("baz");
        assert(i2 == o.end());
        
        JSON a;
        a += "foo";
        a += "bar";
        JSON::iterator i;
        i = a.find("foo");
        assert(i == a.end());
    }

    std::cerr << "leaving test_object()\n";
}

void test_streaming() {
    std::cerr << "entering test_streaming()\n";
    
    // stream text representation into stream
    std::stringstream i;
    i << "{ \"foo\": true, \"baz\": [1,2,3,4] }";

    // create JSON from stream
    {
        JSON j, k;
        i >> j;
        k << i;
        assert(j.toString() == k.toString());
    }

    // roundtrip
    {
        std::stringstream o;
        JSON j, k;
        i >> j;
        j >> o;
        o >> k;
        assert(j.toString() == k.toString());
    }

    // check numbers
    {
        std::stringstream number_stream;
        number_stream << "[0, -1, 1, 1.0, -1.0, 1.0e+1, 1.0e-1, 1.0E+1, 1.0E-1, -1.2345678e-12345678]";
        JSON j;
        j << number_stream;
    }

    // check Unicode
    {
        std::stringstream unicode_stream;
        unicode_stream << "[\"öäüÖÄÜß\", \"ÀÁÂÃĀĂȦ\", \"★☆→➠♥︎♦︎☁︎\"]";
        JSON j;
        j << unicode_stream;
    }

    // check escaped strings
    {
        std::stringstream escaped_stream;
        escaped_stream << "[\"\\\"Hallo\\\"\", \"\u0123\"]";
        JSON j;
        j << escaped_stream;
    }

    std::cerr << "leaving test_streaming()\n";
}

int main() {
    test_null();
    test_bool();
    test_string();
    test_array();
    test_object();
    test_streaming();

    return 0;
}
