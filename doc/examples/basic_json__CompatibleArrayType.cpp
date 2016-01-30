#include <json.hpp>
#include <deque>
#include <list>
#include <forward_list>
#include <set>
#include <unordered_set>

using json = nlohmann::json;

int main()
{
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
    json j_mset(c_mset); // only one entry for "one" is used

    // create an array from std::unordered_multiset
    std::unordered_multiset<std::string> c_umset {"one", "two", "one", "four"};
    json j_umset(c_umset); // both entries for "one" are used

    // serialize the JSON arrays
    std::cout << j_vec << '\n';
    std::cout << j_deque << '\n';
    std::cout << j_list << '\n';
    std::cout << j_flist << '\n';
    std::cout << j_array << '\n';
    std::cout << j_set << '\n';
    std::cout << j_uset << '\n';
    std::cout << j_mset << '\n';
    std::cout << j_umset << '\n';
}
