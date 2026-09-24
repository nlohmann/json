#include <cstdlib>
#include <iostream>
#include <sstream>

using namespace std;

void build_code(int max_args)
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
    
    cout << ss.str() << endl;
}

int main(int argc, char** argv) 
{
    int max_args = 64;
    build_code(max_args);
       
    return 0;
}

