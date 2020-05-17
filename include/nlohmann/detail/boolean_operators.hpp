#pragma once

// Header <ciso646> is removed in C++20.
// See <https://github.com/nlohmann/json/issues/2089> for more information.

#if __cplusplus <= 201703L
    #include <ciso646> // and, not, or
#endif
