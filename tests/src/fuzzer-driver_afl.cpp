//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.11.2
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2022 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

/*
This file implements a driver for American Fuzzy Lop (afl-fuzz). It relies on
an implementation of the `LLVMFuzzerTestOneInput` function which processes a
passed byte array.
*/

#include <vector>    // for vector
#include <cstdint>   // for uint8_t
#include <iostream>  // for cin

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

int main()
{
#ifdef __AFL_HAVE_MANUAL_CONTROL
    while (__AFL_LOOP(1000))
    {
#endif
        // copy stdin to byte vector
        std::vector<uint8_t> vec;
        char c;
        while (std::cin.get(c))
        {
            vec.push_back(static_cast<uint8_t>(c));
        }

        LLVMFuzzerTestOneInput(vec.data(), vec.size());
#ifdef __AFL_HAVE_MANUAL_CONTROL
    }
#endif
}
