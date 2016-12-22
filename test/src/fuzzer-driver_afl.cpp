/*
    __ _____ _____ _____
 __|  |   __|     |   | |  JSON for Modern C++ (fuzz test support)
|  |  |__   |  |  | | | |  version 2.0.9
|_____|_____|_____|_|___|  https://github.com/nlohmann/json

This file implements a driver for American Fuzzy Lop (afl-fuzz). It relies on
an implementation of the `LLVMFuzzerTestOneInput` function which processes a
passed byte array.

Licensed under the MIT License <http://opensource.org/licenses/MIT>.
*/

#include <sstream>
#include <cstdint>
#include <iostream>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main()
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    while (__AFL_LOOP(1000))
    {
#endif
        // copy stdin to stringstream to pass it to fuzzer as byte array
        std::stringstream ss;
        ss << std::cin.rdbuf();
        LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(ss.str().c_str()), ss.str().size());
#ifdef __AFL_HAVE_MANUAL_CONTROL
    }
#endif
}
