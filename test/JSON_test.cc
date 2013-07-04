#include <iostream>
#include <fstream>
#include <cstdio>
#include <cassert>
#include <JSON.h>
#include <sstream>

void test_null() {
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
}


void test_bool() {
    JSON True = true;
    JSON False = false;

    bool x = True;
}

void test_string() {
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
        std::string* s1 = static_cast<std::string*>(a.data());
        std::string s2 = a;
        assert(*s1 == s2);
    }
}

void test_array() {
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
    for (JSON::iterator i = a.begin(); i != a.end(); ++i) {
        std::cerr << *i << '\n';
    }

    for (JSON::const_iterator i = a.cbegin(); i != a.cend(); ++i) {
        std::cerr << *i << '\n';
    }

#ifdef __cplusplus11
    for (auto element : a) {
        std::cerr << element << '\n';
    }
#endif

    {
        // get payload
        std::vector<JSON>* array = static_cast<std::vector<JSON>*>(a.data());
        assert(array->size() == a.size());
        assert(array->empty() == a.empty());
    }
}

void test_streaming() {
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
}

int main() {
    test_null();
    test_bool();
    test_string();
    test_array();
    test_streaming();

    return 0;
}
