/**
 * We use quotes per the doc's recommendation:
 * https://docs.bazel.build/versions/master/bazel-and-cpp.html#include-paths
 */
#include "nlohmann/json.hpp"

int main(int argc, char **argv)
{
    nlohmann::json j;

    return 0;
}
