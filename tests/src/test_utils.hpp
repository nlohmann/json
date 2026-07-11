//     __ _____ _____ _____
//  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
// |  |  |__   |  |  | | | |  version 3.12.0
// |_____|_____|_____|_|___|  https://github.com/nlohmann/json
//
// SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
// SPDX-License-Identifier: MIT

#pragma once

#include <cstdint> // uint8_t
#include <fstream> // ifstream, istreambuf_iterator, ios
#include <vector> // vector

namespace utils
{

inline std::vector<std::uint8_t> read_binary_file(const std::string& filename)
{
    std::ifstream file(filename, std::ios::binary);
    file.unsetf(std::ios::skipws);

    file.seekg(0, std::ios::end);
    const auto size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<std::uint8_t> byte_vector;
    byte_vector.reserve(static_cast<std::size_t>(size));
    byte_vector.insert(byte_vector.begin(), std::istream_iterator<std::uint8_t>(file), std::istream_iterator<std::uint8_t>());
    return byte_vector;
}

// sentinel for istreambuf_iterator; compares != true until EOF is reached
// lets tests read a file directly via the new iterator+sentinel overloads
// instead of buffering the whole file into a vector first.
// Only the iterator-first direction (it != sentinel) is ever evaluated by
// the library's parse loop, so no reversed-order overload is needed.
struct istreambuf_sentinel
{
    friend bool operator!=(const std::istreambuf_iterator<char>& it, const istreambuf_sentinel& /*unused*/) noexcept
    {
        return it != std::istreambuf_iterator<char>();
    }
};

} // namespace utils
