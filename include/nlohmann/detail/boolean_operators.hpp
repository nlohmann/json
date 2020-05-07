#pragma once

#include <nlohmann/detail/macro_scope.hpp>

// Header <ciso646> is needed for older MSVC versions to allow to use the
// alternative operator representations "and", "or", and "not". As the header
// is removed in C++20, we must only include it for old MSVC versions.
// See <https://github.com/nlohmann/json/issues/2089> for more information.

#if !JSON_HEDLEY_MSVC_VERSION_CHECK(15,5,0)
    #include <ciso646> // and, not, or
#endif
