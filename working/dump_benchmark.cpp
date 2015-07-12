#define BENCHPRESS_CONFIG_MAIN

#include <fstream>
#include <benchpress.hpp>
#include <json.hpp>

BENCHMARK("dump jeopardy.json", [](benchpress::context* ctx)
{
    std::ifstream input_file("files/jeopardy/jeopardy.json");
    std::ofstream output_file("output.tmp");
    nlohmann::json j;
    j << input_file;
    
    for (size_t i = 0; i < ctx->num_iterations(); ++i)
    {
        output_file << j.dump();
    }
})
