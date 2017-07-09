#include <iostream>
#include <deque>
#include <list>
#include <forward_list>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include "json.hpp"

using json = nlohmann::json;

int main()
{
    // ============
    // object types
    // ============

    // create an object from an object_t value
    json::object_t object_value = { {"one", 1}, {"two", 2} };
    json j_object_t(object_value);

    // create an object from std::map
    std::map<std::string, int> c_map
    {
        {"one", 1}, {"two", 2}, {"three", 3}
    };
    json j_map(c_map);

    // create an object from std::unordered_map
    std::unordered_map<const char*, double> c_umap
    {
        {"one", 1.2}, {"two", 2.3}, {"three", 3.4}
    };
    json j_umap(c_umap);

    // create an object from std::multimap
    std::multimap<std::string, bool> c_mmap
    {
        {"one", true}, {"two", true}, {"three", false}, {"three", true}
    };
    json j_mmap(c_mmap); // only one entry for key "three" is used

    // create an object from std::unordered_multimap
    std::unordered_multimap<std::string, bool> c_ummap
    {
        {"one", true}, {"two", true}, {"three", false}, {"three", true}
    };
    json j_ummap(c_ummap); // only one entry for key "three" is used

    // serialize the JSON objects
    std::cout << j_object_t << '\n';
    std::cout << j_map << '\n';
    std::cout << j_umap << '\n';
    std::cout << j_mmap << '\n';
    std::cout << j_ummap << "\n\n";


    // ===========
    // array types
    // ===========

    // create an array from an array_t value
    json::array_t array_value = {"one", "two", 3, 4.5, false};
    json j_array_t(array_value);

    // create an array from std::vector
    std::vector<int> c_vector {1, 2, 3, 4};
    json j_vec(c_vector);

    // create an array from std::deque
    std::deque<double> c_deque {1.2, 2.3, 3.4, 5.6};
    json j_deque(c_deque);

    // create an array from std::list
    std::list<bool> c_list {true, true, false, true};
    json j_list(c_list);

    // create an array from std::forward_list
    std::forward_list<int64_t> c_flist {12345678909876, 23456789098765, 34567890987654, 45678909876543};
    json j_flist(c_flist);

    // create an array from std::array
    std::array<unsigned long, 4> c_array {{1, 2, 3, 4}};
    json j_array(c_array);

    // create an array from std::set
    std::set<std::string> c_set {"one", "two", "three", "four", "one"};
    json j_set(c_set); // only one entry for "one" is used

    // create an array from std::unordered_set
    std::unordered_set<std::string> c_uset {"one", "two", "three", "four", "one"};
    json j_uset(c_uset); // only one entry for "one" is used

    // create an array from std::multiset
    std::multiset<std::string> c_mset {"one", "two", "one", "four"};
    json j_mset(c_mset); // both entries for "one" are used

    // create an array from std::unordered_multiset
    std::unordered_multiset<std::string> c_umset {"one", "two", "one", "four"};
    json j_umset(c_umset); // both entries for "one" are used

    // serialize the JSON arrays
    std::cout << j_array_t << '\n';
    std::cout << j_vec << '\n';
    std::cout << j_deque << '\n';
    std::cout << j_list << '\n';
    std::cout << j_flist << '\n';
    std::cout << j_array << '\n';
    std::cout << j_set << '\n';
    std::cout << j_uset << '\n';
    std::cout << j_mset << '\n';
    std::cout << j_umset << "\n\n";


    // ============
    // string types
    // ============

    // create string from a string_t value
    json::string_t string_value = "The quick brown fox jumps over the lazy dog.";
    json j_string_t(string_value);

    // create a JSON string directly from a string literal
    json j_string_literal("The quick brown fox jumps over the lazy dog.");

    // create string from std::string
    std::string s_stdstring = "The quick brown fox jumps over the lazy dog.";
    json j_stdstring(s_stdstring);

    // serialize the JSON strings
    std::cout << j_string_t << '\n';
    std::cout << j_string_literal << '\n';
    std::cout << j_stdstring << "\n\n";


    // ============
    // number types
    // ============

    // create a JSON number from number_integer_t
    json::number_integer_t value_integer_t = -42;
    json j_integer_t(value_integer_t);

    // create a JSON number from number_unsigned_t
    json::number_integer_t value_unsigned_t = 17;
    json j_unsigned_t(value_unsigned_t);

    // create a JSON number from an anonymous enum
    enum { enum_value = 17 };
    json j_enum(enum_value);

    // create values of different integer types
    short n_short = 42;
    int n_int = -23;
    long n_long = 1024;
    int_least32_t n_int_least32_t = -17;
    uint8_t n_uint8_t = 8;

    // create (integer) JSON numbers
    json j_short(n_short);
    json j_int(n_int);
    json j_long(n_long);
    json j_int_least32_t(n_int_least32_t);
    json j_uint8_t(n_uint8_t);

    // create values of different floating-point types
    json::number_float_t v_ok = 3.141592653589793;
    json::number_float_t v_nan = NAN;
    json::number_float_t v_infinity = INFINITY;

    // create values of different floating-point types
    float n_float = 42.23;
    float n_float_nan = 1.0f / 0.0f;
    double n_double = 23.42;

    // create (floating point) JSON numbers
    json j_ok(v_ok);
    json j_nan(v_nan);
    json j_infinity(v_infinity);
    json j_float(n_float);
    json j_float_nan(n_float_nan);
    json j_double(n_double);

    // serialize the JSON numbers
    std::cout << j_integer_t << '\n';
    std::cout << j_unsigned_t << '\n';
    std::cout << j_enum << '\n';
    std::cout << j_short << '\n';
    std::cout << j_int << '\n';
    std::cout << j_long << '\n';
    std::cout << j_int_least32_t << '\n';
    std::cout << j_uint8_t << '\n';
    std::cout << j_ok << '\n';
    std::cout << j_nan << '\n';
    std::cout << j_infinity << '\n';
    std::cout << j_float << '\n';
    std::cout << j_float_nan << '\n';
    std::cout << j_double << "\n\n";


    // =============
    // boolean types
    // =============

    // create boolean values
    json j_truth = true;
    json j_falsity = false;

    // serialize the JSON booleans
    std::cout << j_truth << '\n';
    std::cout << j_falsity << '\n';
}
