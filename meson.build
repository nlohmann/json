project('nlohmann_json',
    'cpp',
    version : '3.12.0',
    license : 'MIT',
)

nlohmann_json_dep = declare_dependency(
    include_directories: include_directories('single_include')
)

nlohmann_json_multiple_headers = declare_dependency(
    include_directories: include_directories('include')
)

if not meson.is_subproject()
install_headers('single_include/nlohmann/json.hpp', subdir: 'nlohmann')
install_headers('single_include/nlohmann/json_fwd.hpp', subdir: 'nlohmann')

pkgc = import('pkgconfig')
pkgc.generate(name: 'nlohmann_json',
    version: meson.project_version(),
    description: 'JSON for Modern C++'
)

cmake_dir = get_option('datadir') / 'cmake' / meson.project_name()
version_parts = meson.project_version().split('.')

cmake_conf = configuration_data()
cmake_conf.set('PROJECT_NAME', meson.project_name())
cmake_conf.set('NLOHMANN_JSON_TARGET_NAME', meson.project_name())
cmake_conf.set('NLOHMANN_JSON_TARGETS_EXPORT_NAME', meson.project_name() + 'Targets')
cmake_conf.set('PROJECT_VERSION', meson.project_version())
cmake_conf.set('PROJECT_VERSION_MAJOR', version_parts[0])

configure_file(
    input: 'cmake/config.cmake.in',
    output: meson.project_name() + 'Config.cmake',
    configuration: cmake_conf,
    install: true,
    install_dir: cmake_dir,
)

configure_file(
    input: 'cmake/nlohmann_jsonConfigVersion.cmake.in',
    output: meson.project_name() + 'ConfigVersion.cmake',
    configuration: cmake_conf,
    install: true,
    install_dir: cmake_dir,
)

install_data(
    'cmake/nlohmann_jsonTargets.cmake',
    install_dir: cmake_dir,
)
endif
