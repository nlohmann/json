// 
// benchmarks_simple.cpp -- a less complex version of benchmarks.cpp, that better reflects actual performance
// 
//     For some reason, the complexity of benchmarks.cpp doesn't allow
// the compiler to optimize code using json.hpp effectively.  The
// exact same tests, with the use of benchpress and cxxopts produces
// much faster code, at least under g++.
// 
#include <fstream>
#include <iostream>
#include <chrono>
#include <list>
#include <tuple>

#include <json.hpp>

using json = nlohmann::json;

enum class EMode { input, output, indent };

static double bench(const EMode mode, size_t iters, const std::string& in_path )
{
    // using string streams for benchmarking to factor-out cold-cache disk
    // access.  Define FROMFILE to use file I/O instead.
#if defined( FROMFILE )
    std::ifstream istr;
    {
        istr.open( in_path, std::ifstream::in );

        // read the stream once
        json j;
        istr >> j;
        // clear flags and rewind
        istr.clear();
        istr.seekg(0);
    }
#else
    std::stringstream istr;
    {
        // read file into string stream
        std::ifstream input_file(in_path);
        istr << input_file.rdbuf();
        input_file.close();

        // read the stream once
        json j;
        istr >> j;
        // clear flags and rewind
        istr.clear();
        istr.seekg(0);
    }
#endif
    double tps = 0;
    switch (mode)
    {
        // benchmarking input
        case EMode::input:
        {
	    auto start = std::chrono::system_clock::now();
            for (size_t i = 0; i < iters; ++i)
            {
                // clear flags and rewind
                istr.clear();
                istr.seekg(0);
                json j;
                istr >> j;
            }
	    auto ended = std::chrono::system_clock::now();
	    tps = 1.0 / std::chrono::duration<double>( ended - start ).count();
            break;
        }

        // benchmarking output
        case EMode::output:
        case EMode::indent:
        {
            // create JSON value from input
            json j;
            istr >> j;
            std::stringstream ostr;

	    auto start = std::chrono::system_clock::now();
            for (size_t i = 0; i < iters; ++i)
            {
                if (mode == EMode::indent)
                {
                    ostr << j;
                }
                else
                {
                    ostr << std::setw(4) << j;
                }

                // reset data
                ostr.str(std::string());
            }
	    auto ended = std::chrono::system_clock::now();
	    tps = 1.0 / std::chrono::duration<double>( ended - start ).count();

            break;
        }
    }
    return tps;
}

template <typename T>
struct average {
    T _sum { 0 };
    size_t _count { 0 };
    T operator+=( const T &val_ ) { _sum += val_; +_count++; return val_; }
    operator T() { return _sum / _count; }
};

// Execute each test approximately enough times to get near 1
// transaction per second, and compute the average; a single aggregate
// number that gives a performance metric representing both parsing
// and output.

int main( int, char ** )
{
    std::list<std::tuple<std::string, EMode, size_t, std::string>> tests {
	{ "parse jeopardy.json",	EMode::input,   2, "files/jeopardy/jeopardy.json" },
	{ "parse canada.json",		EMode::input,  30, "files/nativejson-benchmark/canada.json" },
	{ "parse citm_catalog.json",	EMode::input, 120, "files/nativejson-benchmark/citm_catalog.json" },
	{ "parse twitter.json",		EMode::input, 225, "files/nativejson-benchmark/twitter.json" },
	{ "parse floats.json",		EMode::input,   5, "files/numbers/floats.json" },
	{ "parse signed_ints.json",	EMode::input,   6, "files/numbers/signed_ints.json" },
	{ "parse unsigned_ints.json",	EMode::input,   6, "files/numbers/unsigned_ints.json" },
	{ "dump jeopardy.json",		EMode::output,  5, "files/jeopardy/jeopardy.json" },
	{ "dump jeopardy.json w/ind.",	EMode::indent,  5, "files/jeopardy/jeopardy.json" },
	{ "dump floats.json",		EMode::output,  2, "files/numbers/floats.json" },
	{ "dump signed_ints.json",	EMode::output, 20, "files/numbers/signed_ints.json" },
    };
    
    average<double> avg;
    for ( auto t : tests ) {
	std::string name, path;
	EMode mode;
	size_t iters;
	std::tie(name, mode, iters, path) = t;
	auto tps = bench( mode, iters, path );
	avg += tps;
	std::cout
	    << std::left 
	    << std::setw( 30 ) << name
	    << std::right	    
	    << " x " 	<< std::setw(  3 ) << iters
	    << std::left
	    << " == " 	<< std::setw( 10 ) << tps
	    << std::right
	    << " TPS, "	<< std::setw(  8 ) << std::round( tps * 1e6 / iters )
	    << " ms/op"
	    << std::endl;
    }
    std::cout << std::setw( 40 ) << "" << std::string( 10, '-' ) << std::endl;
    std::cout << std::setw( 40 ) << "" << std::setw( 10 ) << std::left << avg << " TPS Average" << std::endl;
    return 0;
}
