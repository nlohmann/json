#define BENCHPRESS_CONFIG_MAIN

#include <fstream>
#include <benchpress.hpp>
#include <json.hpp>
#include <pthread.h>
#include <thread>

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

BENCHMARK("parse jeopardy.json", [](benchpress::context* ctx)
{
    for (size_t i = 0; i < ctx->num_iterations(); ++i)
    {
        ctx->stop_timer();
        std::ifstream input_file("benchmarks/files/jeopardy/jeopardy.json");
        nlohmann::json j;
        ctx->start_timer();
        j << input_file;
        ctx->stop_timer();
    }
})

BENCHMARK("parse canada.json", [](benchpress::context* ctx)
{
    for (size_t i = 0; i < ctx->num_iterations(); ++i)
    {
        ctx->stop_timer();
        std::ifstream input_file("benchmarks/files/nativejson-benchmark/canada.json");
        nlohmann::json j;
        ctx->start_timer();
        j << input_file;
        ctx->stop_timer();
    }
})

BENCHMARK("parse citm_catalog.json", [](benchpress::context* ctx)
{
    for (size_t i = 0; i < ctx->num_iterations(); ++i)
    {
        ctx->stop_timer();
        std::ifstream input_file("benchmarks/files/nativejson-benchmark/citm_catalog.json");
        nlohmann::json j;
        ctx->start_timer();
        j << input_file;
        ctx->stop_timer();
    }
})

BENCHMARK("parse twitter.json", [](benchpress::context* ctx)
{
    for (size_t i = 0; i < ctx->num_iterations(); ++i)
    {
        ctx->stop_timer();
        std::ifstream input_file("benchmarks/files/nativejson-benchmark/twitter.json");
        nlohmann::json j;
        ctx->start_timer();
        j << input_file;
        ctx->stop_timer();
    }
})

BENCHMARK("parse numbers/floats.json", [](benchpress::context* ctx)
{
    for (size_t i = 0; i < ctx->num_iterations(); ++i)
    {
        ctx->stop_timer();
        std::ifstream input_file("benchmarks/files/numbers/floats.json");
        nlohmann::json j;
        ctx->start_timer();
        j << input_file;
        ctx->stop_timer();
    }
})

BENCHMARK("parse numbers/signed_ints.json", [](benchpress::context* ctx)
{
    for (size_t i = 0; i < ctx->num_iterations(); ++i)
    {
        ctx->stop_timer();
        std::ifstream input_file("benchmarks/files/numbers/signed_ints.json");
        nlohmann::json j;
        ctx->start_timer();
        j << input_file;
        ctx->stop_timer();
    }
})

BENCHMARK("parse numbers/unsigned_ints.json", [](benchpress::context* ctx)
{
    for (size_t i = 0; i < ctx->num_iterations(); ++i)
    {
        ctx->stop_timer();
        std::ifstream input_file("benchmarks/files/numbers/unsigned_ints.json");
        nlohmann::json j;
        ctx->start_timer();
        j << input_file;
        ctx->stop_timer();
    }
})

BENCHMARK("dump jeopardy.json", [](benchpress::context* ctx)
{
    std::ifstream input_file("benchmarks/files/jeopardy/jeopardy.json");
    nlohmann::json j;
    j << input_file;
    std::ofstream output_file("jeopardy.dump.json");

    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i)
    {
        ctx->start_timer();
        output_file << j;
        ctx->stop_timer();
    }

    std::remove("jeopardy.dump.json");
})

BENCHMARK("dump jeopardy.json with indent", [](benchpress::context* ctx)
{
    std::ifstream input_file("benchmarks/files/jeopardy/jeopardy.json");
    nlohmann::json j;
    j << input_file;
    std::ofstream output_file("jeopardy.dump.json");

    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i)
    {
        ctx->start_timer();
        output_file << std::setw(4) << j;
        ctx->stop_timer();
    }

    std::remove("jeopardy.dump.json");
})
