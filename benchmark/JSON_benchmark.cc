#include <iostream>
#include <fstream>
#include <ctime>
#include <JSON.h>

int main(int argc, char** argv) {
    time_t timer1, timer2;

    JSON json;
    std::ifstream infile(argv[1]);
    time(&timer1);
    json << infile;
    time(&timer2);
    std::cout << "Parsing from std::ifstream: " << difftime(timer2, timer1) << " sec\n";

    return 0;
}
