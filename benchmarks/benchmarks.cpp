#define BENCHPRESS_CONFIG_MAIN

#include <fstream>
#include <sstream>
#include <benchpress.hpp>
#include <json.hpp>
#include <pthread.h>
#include <thread>

using json = nlohmann::json;

struct StartUp
{
    StartUp()
    {
#ifndef __llvm__
        // pin thread to a single CPU
        cpu_set_t cpuset;
        pthread_t thread;
        thread = pthread_self();
        CPU_ZERO(&cpuset);
        CPU_SET(std::thread::hardware_concurrency() - 1, &cpuset);
        pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
#endif
    }
};
StartUp startup;

enum class EMode { input, output_no_indent, output_with_indent };

static void bench(benchpress::context& ctx,
                  const std::string& in_path,
                  const EMode mode)
{
    // using string streams for benchmarking to factor-out cold-cache disk
    // access.
    std::stringstream istr;
    {
        // read file into string stream
        std::ifstream input_file(in_path);
        istr << input_file.rdbuf();
        input_file.close();

        // read the stream once
        json j;
        j << istr;
        // clear flags and rewind
        istr.clear();
        istr.seekg(0);
    }

    switch (mode)
    {
        // benchmarking input
        case EMode::input:
        {
            ctx.reset_timer();

            for (size_t i = 0; i < ctx.num_iterations(); ++i)
            {
                // clear flags and rewind
                istr.clear();
                istr.seekg(0);
                json j;
                j << istr;
            }

            break;
        }

        // benchmarking output
        case EMode::output_no_indent:
        case EMode::output_with_indent:
        {
            // create JSON value from input
            json j;
            j << istr;
            std::stringstream ostr;

            ctx.reset_timer();
            for (size_t i = 0; i < ctx.num_iterations(); ++i)
            {
                if (mode == EMode::output_no_indent)
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

            break;
        }
    }
}

#define BENCHMARK_I(mode, title, in_path)           \
    BENCHMARK((title), [](benchpress::context* ctx) \
    {                                               \
        bench(*ctx, (in_path), (mode));             \
    })

BENCHMARK_I(EMode::input, "parse jeopardy.json",              "benchmarks/files/jeopardy/jeopardy.json");
BENCHMARK_I(EMode::input, "parse canada.json",                "benchmarks/files/nativejson-benchmark/canada.json");
BENCHMARK_I(EMode::input, "parse citm_catalog.json",          "benchmarks/files/nativejson-benchmark/citm_catalog.json");
BENCHMARK_I(EMode::input, "parse twitter.json",               "benchmarks/files/nativejson-benchmark/twitter.json");
BENCHMARK_I(EMode::input, "parse numbers/floats.json",        "benchmarks/files/numbers/floats.json");
BENCHMARK_I(EMode::input, "parse numbers/signed_ints.json",   "benchmarks/files/numbers/signed_ints.json");
BENCHMARK_I(EMode::input, "parse numbers/unsigned_ints.json", "benchmarks/files/numbers/unsigned_ints.json");

BENCHMARK_I(EMode::output_no_indent,   "dump jeopardy.json",             "benchmarks/files/jeopardy/jeopardy.json");
BENCHMARK_I(EMode::output_with_indent, "dump jeopardy.json with indent", "benchmarks/files/jeopardy/jeopardy.json");
BENCHMARK_I(EMode::output_no_indent,   "dump numbers/floats.json",       "benchmarks/files/numbers/floats.json");
BENCHMARK_I(EMode::output_no_indent,   "dump numbers/signed_ints.json",  "benchmarks/files/numbers/signed_ints.json");
