#include <iostream>
#include <fstream>
#include <JSON.h>

int main(int argc, char** argv) {
    JSON json;
    std::ifstream infile(argv[1]);

    json << infile;

    std::cout << json.size() << "\n";

    return 0;
}
