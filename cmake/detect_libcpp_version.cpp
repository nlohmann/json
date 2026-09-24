/*
 * Detect used C++ Standard Library
 *
 * This file is compiled and run via try_run in download_test_data.cmake.
 */

#include <cstdio>

// see https://en.cppreference.com/w/cpp/header/ciso646
#if __cplusplus >= 202002L
    #include <version>
#else
    #include <ciso646>
#endif

int main()
{
#if defined(_LIBCPP_VERSION)
    std::printf("LLVM C++ Standard Library (libc++), _LIBCPP_VERSION=%d", _LIBCPP_VERSION);
#elif defined(__GLIBCXX__)
    std::printf("GNU C++ Standard Library (libstdc++), __GLIBCXX__=%d", __GLIBCXX__);
#elif defined(_MSVC_STL_VERSION)
    std::printf("Microsoft C++ Standard Library (MSVC STL), _MSVC_STL_VERSION=%d", _MSVC_STL_VERSION);
#elif defined(_LIBCUDACXX_VERSION)
    std::printf("NVIDIA C++ Standard Library (libcudacxx), _LIBCUDACXX_VERSION=%d", _LIBCUDACXX_VERSION);
#elif defined(EASTL_VERSION)
    std::printf("Electronic Arts Standard Template Library (EASTL), EASTL_VERSION=%d", EASTL_VERSION);
#else
    std::printf("unknown");
#endif
}
