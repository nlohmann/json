cmake_minimum_required(VERSION 3.18)
project(json_cuda LANGUAGES CUDA)

add_executable(json_cuda json_cuda.cu)
target_include_directories(json_cuda PRIVATE ../../include)

# nvcc added C++20 support in CUDA 12.0 and C++17 in CUDA 11.0; pick the
# newest standard the detected compiler actually supports (see #3907)
# instead of hard-requiring one standard for every CUDA version.
if(CMAKE_CUDA_COMPILER_VERSION VERSION_GREATER_EQUAL 12.0)
    set(json_cuda_std 20)
elseif(CMAKE_CUDA_COMPILER_VERSION VERSION_GREATER_EQUAL 11.0)
    set(json_cuda_std 17)
else()
    set(json_cuda_std 11)
endif()
target_compile_features(json_cuda PUBLIC cuda_std_${json_cuda_std})
set_target_properties(json_cuda PROPERTIES
    CUDA_EXTENSIONS OFF
    CUDA_STANDARD_REQUIRED ON
)
