include(CheckCXXCompilerFlag)
function(add_cxx_flag_if_supported_to_targets flagname targets)
    check_cxx_compiler_flag("${flagname}" HAVE_FLAG_${flagname})

    if (HAVE_FLAG_${flagname})
        foreach(target ${targets})
            target_compile_options(${target} PUBLIC ${flagname})
        endforeach()
    endif()
endfunction()

# Assumes that it is only called for development builds, where warnings
# and Werror is desired, so it also enables Werror.
function(add_warnings_to_targets targets)
    LIST(LENGTH targets TARGETS_LEN)
    # For now we just assume 2 possibilities: msvc and msvc-like compilers,
    # and other.
    if (MSVC)
        foreach(target ${targets})
            # Force MSVC to consider everything as encoded in utf-8
            target_compile_options( ${target} PRIVATE /utf-8 )
            # Enable Werror equivalent
            if (CATCH_ENABLE_WERROR)
                target_compile_options( ${target} PRIVATE /WX )
            endif()

            # MSVC is currently handled specially
            if ( CMAKE_CXX_COMPILER_ID MATCHES "MSVC" )
                STRING(REGEX REPLACE "/W[0-9]" "/W4" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS}) # override default warning level
                target_compile_options( ${target} PRIVATE /w44265 /w44061 /w44062 /w45038 )
            endif()
        endforeach()

    endif()

    if (NOT MSVC)
        set(CHECKED_WARNING_FLAGS
          "-Wall"
          "-Wextra"
          "-Wpedantic"
          "-Wweak-vtables"
          "-Wunreachable-code"
          "-Wmissing-declarations"
          "-Wexit-time-destructors"
          "-Wglobal-constructors"
          "-Wmissing-noreturn"
          "-Wparentheses"
          "-Wextra-semi-stmt"
          "-Wunreachable-code"
          "-Wstrict-aliasing"
          "-Wreturn-std-move"
          "-Wmissing-braces"
          "-Wdeprecated"
          "-Wvla"
          "-Wundef"
          "-Wmisleading-indentation"
          "-Wcatch-value"
          "-Wabsolute-value"
          "-Wreturn-std-move"
          "-Wunused-parameter"
          "-Wunused-function"
          "-Wcall-to-pure-virtual-from-ctor-dtor"
          "-Wdeprecated-register"
          "-Wsuggest-override"
          "-Wshadow"
        )
        foreach(warning ${CHECKED_WARNING_FLAGS})
            add_cxx_flag_if_supported_to_targets(${warning} "${targets}")
        endforeach()

        if (CATCH_ENABLE_WERROR)
            foreach(target ${targets})
                # Enable Werror equivalent
                target_compile_options( ${target} PRIVATE -Werror )
            endforeach()
        endif()
    endif()
endfunction()
