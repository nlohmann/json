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

cpp_args = [
    '-DJSON_USE_GLOBAL_UDLS=@0@'.format(
        (not get_option('GlobalUDLs')).to_int()),
    '-DJSON_USE_IMPLICIT_CONVERSIONS=@0@'.format(
        (not get_option('ImplicitConversions')).to_int()),
]

nlohmann_json_dep = declare_dependency(
    compile_args: cpp_args,
    include_directories: include_directories(incdir)
)
meson.override_dependency('nlohmann_json', nlohmann_json_dep)

if not meson.is_subproject()
    install_subdir(
        incdir / 'nlohmann',
        install_dir: get_option('includedir'),
        install_tag: 'devel',
    )

    pkgc = import('pkgconfig')
    pkgc.generate(name: 'nlohmann_json',
        version: meson.project_version(),
        description: 'JSON for Modern C++'
    )

    # CMake package config files, so that find_package(nlohmann_json) works
    cmake_install_dir = get_option('datadir') / 'cmake' / meson.project_name()
    cmake_to_prefix = []
    foreach component : cmake_install_dir.split('/')
        cmake_to_prefix += '..'
    endforeach

    cmake_conf = configuration_data()
    cmake_conf.set('PROJECT_NAME', meson.project_name())
    cmake_conf.set('PROJECT_VERSION', meson.project_version())
    cmake_conf.set('PROJECT_VERSION_MAJOR', meson.project_version().split('.')[0])
    cmake_conf.set('NLOHMANN_JSON_TARGET_NAME', meson.project_name())
    cmake_conf.set('NLOHMANN_JSON_TARGETS_EXPORT_NAME', meson.project_name() + 'Targets')
    cmake_conf.set('NLOHMANN_JSON_INCLUDE_INSTALL_DIR', get_option('includedir'))
    cmake_conf.set('NLOHMANN_JSON_CONFIG_TO_PREFIX', '/'.join(cmake_to_prefix))

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
