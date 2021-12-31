#pragma once

// restore clang diagnostic settings
#if defined(__clang__)
    #pragma clang diagnostic pop
#endif

// clean up
#undef JSON_ASSERT
#undef JSON_INTERNAL_CATCH
#undef JSON_CATCH
#undef JSON_THROW
#undef JSON_TRY
#undef JSON_PRIVATE_UNLESS_TESTED
#undef JSON_HAS_CPP_11
#undef JSON_HAS_CPP_14
#undef JSON_HAS_CPP_17
#undef JSON_HAS_CPP_20
#undef JSON_HAS_FILESYSTEM
#undef JSON_HAS_EXPERIMENTAL_FILESYSTEM
#undef NLOHMANN_BASIC_JSON_TPL_DECLARATION
#undef NLOHMANN_BASIC_JSON_TPL
#undef JSON_EXPLICIT
#undef NLOHMANN_CAN_CALL_STD_FUNC_IMPL

#include <nlohmann/thirdparty/hedley/hedley_undef.hpp>
