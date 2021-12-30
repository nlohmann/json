cmake_minimum_required(VERSION 3.18)
project(json_cuda LANGUAGES CUDA)

add_executable(json_cuda json_cuda.cu)
target_include_directories(json_cuda PRIVATE ../../include)
target_compile_features(json_cuda PUBLIC cuda_std_11)
set_target_properties(json_cuda PROPERTIES
    CUDA_EXTENSIONS OFF
    CUDA_STANDARD_REQUIRED ON
)
