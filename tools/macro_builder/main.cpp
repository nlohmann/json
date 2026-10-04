#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>

using namespace std;

// Builds NLOHMANN_JSON_EXPAND, NLOHMANN_JSON_GET_MACRO, and the
// NLOHMANN_JSON_PASTE / NLOHMANN_JSON_PASTE2..PASTE<max_args> dispatch table
// and recursive definitions.
string build_paste_code(int max_args)
{
    stringstream ss;
    ss << "#define NLOHMANN_JSON_EXPAND( x ) x" << endl;
    ss << "#define NLOHMANN_JSON_GET_MACRO(";
    for (int i = 0 ; i < max_args ; i++)
        ss << "_" << i + 1 << ", ";
    ss << "NAME,...) NAME" << endl;

    ss << "#define NLOHMANN_JSON_PASTE(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_GET_MACRO(__VA_ARGS__, \\" << endl;
    for (int i = max_args ; i > 1 ; i--)
        ss << "NLOHMANN_JSON_PASTE" << i << ", \\" << endl;
    ss << "NLOHMANN_JSON_PASTE1)(__VA_ARGS__))" << endl;

    ss << "#define NLOHMANN_JSON_PASTE2(func, v1) func(v1)" << endl;
    for (int i = 3 ; i <= max_args ; i++)
    {
        ss << "#define NLOHMANN_JSON_PASTE" << i << "(func, ";
        for (int j = 1 ; j < i -1 ; j++)
            ss << "v" << j << ", ";
        ss << "v" << i-1 << ") NLOHMANN_JSON_PASTE2(func, v1) NLOHMANN_JSON_PASTE" << i-1 << "(func, ";
        for (int j = 2 ; j < i-1 ; j++)
            ss << "v" << j << ", ";
        ss << "v" << i-1 << ")" << endl;
    }

    return ss.str();
}

// Builds the NLOHMANN_JSON_DOUBLE_PASTE dispatch table and recursive
// definitions used by the *_WITH_NAMES macros. Its GET_MACRO dispatch reuses
// the same max_args slots as NLOHMANN_JSON_PASTE, but DOUBLE_PASTE consumes
// its arguments two at a time (name, member), so an even slot count falls
// back to the next lower odd NLOHMANN_JSON_DOUBLE_PASTE<N>.
string build_double_paste_code(int max_args)
{
    stringstream ss;
    ss << "#define NLOHMANN_JSON_DOUBLE_PASTE(...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_GET_MACRO(__VA_ARGS__, \\" << endl;
    for (int i = max_args ; i > 1 ; i--)
    {
        int k = (i % 2 == 1) ? i : i - 1;
        ss << "NLOHMANN_JSON_DOUBLE_PASTE" << k << ", \\" << endl;
    }
    ss << "NLOHMANN_JSON_DOUBLE_PASTE1)(__VA_ARGS__))" << endl;

    ss << "#define NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) func(v1, v2)" << endl;
    for (int k = 5 ; k <= max_args - 1 ; k += 2)
    {
        ss << "#define NLOHMANN_JSON_DOUBLE_PASTE" << k << "(func, ";
        for (int j = 1 ; j < k - 1 ; j++)
            ss << "v" << j << ", ";
        ss << "v" << k - 1 << ") NLOHMANN_JSON_DOUBLE_PASTE3(func, v1, v2) NLOHMANN_JSON_DOUBLE_PASTE" << k - 2 << "(func, ";
        for (int j = 3 ; j < k - 1 ; j++)
            ss << "v" << j << ", ";
        ss << "v" << k - 1 << ")" << endl;
    }

    return ss.str();
}

// Builds the NLOHMANN_JSON_TYPE_BODY dispatch table: max_args - 1 slots
// selecting the *_MEMBERS implementation and a final slot selecting
// *_EMPTY, so NLOHMANN_DEFINE_TYPE_*(Type) with no further arguments still
// resolves (issue #4041).
string build_type_body_table(int max_args)
{
    stringstream ss;
    ss << "#define NLOHMANN_JSON_TYPE_BODY(Prefix, ...) NLOHMANN_JSON_EXPAND(NLOHMANN_JSON_GET_MACRO(__VA_ARGS__, \\" << endl;
    const int per_line = 8;
    for (int i = 1 ; i <= max_args ; i++)
    {
        ss << (i == max_args ? "Prefix ## EMPTY" : "Prefix ## MEMBERS") << ", ";
        if (i % per_line == 0)
            ss << "\\" << endl;
    }
    ss << "NLOHMANN_JSON_TYPE_BODY_SENTINEL))" << endl;

    return ss.str();
}

int main(int argc, char** argv)
{
    int max_args = 64;

    // With "type_body", print only the NLOHMANN_JSON_TYPE_BODY dispatch
    // table (a separate insertion point in macro_scope.hpp); otherwise
    // print the EXPAND/GET_MACRO/PASTE/DOUBLE_PASTE block that precedes it.
    if (argc > 1 && string(argv[1]) == "type_body")
    {
        cout << build_type_body_table(max_args);
    }
    else
    {
        cout << build_paste_code(max_args) << build_double_paste_code(max_args);
    }

    return 0;
}
