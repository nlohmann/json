project('nlohmann_json',
    'cpp',
    version : '3.12.0',
    license : 'MIT',
    meson_version : '>= 0.64',
    default_options: ['cpp_std=c++11'],
)

if get_option('MultipleHeaders')
    incdir = 'include'
else
    incdir = 'single_include'
endif

# The same compile definitions as the CMake target (see target_compile_definitions
# in CMakeLists.txt): only an option that differs from its default adds one.
json_defines = []
if not get_option('GlobalUDLs')
    json_defines += 'JSON_USE_GLOBAL_UDLS=0'
endif
if not get_option('ImplicitConversions')
    json_defines += 'JSON_USE_IMPLICIT_CONVERSIONS=0'
endif
if get_option('DisableEnumSerialization')
    json_defines += 'JSON_DISABLE_ENUM_SERIALIZATION=1'
endif
if get_option('DisableTupleReferenceConversion')
    json_defines += 'JSON_DISABLE_TUPLE_REFERENCE_CONVERSION=1'
endif
if get_option('Diagnostics')
    json_defines += 'JSON_DIAGNOSTICS=1'
endif
if get_option('Diagnostic_Positions')
    json_defines += 'JSON_DIAGNOSTIC_POSITIONS=1'
endif
if get_option('LegacyDiscardedValueComparison')
    json_defines += 'JSON_USE_LEGACY_DISCARDED_VALUE_COMPARISON=1'
endif
if get_option('StrictNulHandling')
    json_defines += 'JSON_STRICT_NUL_HANDLING=1'
endif

cpp_args = []
foreach define : json_defines
    cpp_args += '-D' + define
endforeach

nlohmann_json_dep = declare_dependency(
    compile_args: cpp_args,
    include_directories: include_directories(incdir)
)
meson.override_dependency('nlohmann_json', nlohmann_json_dep)

# The multi-header version under the name earlier versions of this file used
nlohmann_json_multiple_headers = declare_dependency(
    compile_args: cpp_args,
    include_directories: include_directories('include')
)

if not meson.is_subproject()
    install_subdir(
        incdir / 'nlohmann',
        install_dir: get_option('includedir'),
        install_tag: 'devel',
    )

    pkgc = import('pkgconfig')
    pkgc.generate(name: 'nlohmann_json',
        version: meson.project_version(),
        description: 'JSON for Modern C++',
        extra_cflags: cpp_args,
        install_dir: get_option('datadir') / 'pkgconfig',
    )

    # CMake package config files, so that find_package(nlohmann_json) works. The
    # include directory is given relative to the config files, so that the
    # installation can be relocated. This is not possible if includedir or datadir
    # is an absolute path outside the prefix (e.g., with the separate outputs of
    # Nix); then the absolute include directory is used, as CMake does.
    fs = import('fs')
    cmake_install_dir = get_option('datadir') / 'cmake' / meson.project_name()
    cmake_to_prefix = []
    if fs.is_absolute(get_option('includedir')) or fs.is_absolute(cmake_install_dir)
        cmake_include_dir = (get_option('prefix') / get_option('includedir')).replace('\\', '/')
    else
        foreach component : cmake_install_dir.split('/')
            cmake_to_prefix += '..'
        endforeach
        cmake_include_dir = '${_IMPORT_PREFIX}/' + get_option('includedir')
    endif

    cmake_conf = configuration_data()
    cmake_conf.set('PROJECT_NAME', meson.project_name())
    cmake_conf.set('PROJECT_VERSION', meson.project_version())
    cmake_conf.set('PROJECT_VERSION_MAJOR', meson.project_version().split('.')[0])
    cmake_conf.set('NLOHMANN_JSON_TARGET_NAME', meson.project_name())
    cmake_conf.set('NLOHMANN_JSON_TARGETS_EXPORT_NAME', meson.project_name() + 'Targets')
    cmake_conf.set('NLOHMANN_JSON_INCLUDE_DIR', cmake_include_dir)
    cmake_conf.set('NLOHMANN_JSON_CONFIG_TO_PREFIX', '/'.join(cmake_to_prefix))
    cmake_conf.set('NLOHMANN_JSON_COMPILE_DEFINITIONS', ';'.join(json_defines))

    foreach cmake_file : [
        ['cmake/config.cmake.in', 'nlohmann_jsonConfig.cmake'],
        ['cmake/nlohmann_jsonConfigVersion.cmake.in', 'nlohmann_jsonConfigVersion.cmake'],
        ['cmake/nlohmann_jsonTargets.cmake.in', 'nlohmann_jsonTargets.cmake'],
    ]
        configure_file(
            input: cmake_file[0],
            output: cmake_file[1],
            configuration: cmake_conf,
            format: 'cmake@',
            install_dir: cmake_install_dir,
        )
    endforeach
endif
