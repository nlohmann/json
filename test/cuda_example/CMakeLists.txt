cmake_minimum_required(VERSION 3.8)
project(json_cuda LANGUAGES CXX CUDA)

add_executable(json_cuda json_cuda.cpp)
set_source_files_properties(json_cuda.cpp PROPERTIES LANGUAGE CUDA)
target_include_directories(json_cuda PRIVATE ../../include)
target_compile_features(json_cuda PUBLIC cuda_std_11)
set_target_properties(json_cuda PROPERTIES
    CUDA_EXTENSIONS OFF
    CUDA_STANDARD_REQUIRED ON
    CUDA_SEPARABLE_COMPILATION ON  # Just needed if we need separable compilation; this adds -dc
)
