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

# CMake package files, so that find_package(nlohmann_json) works after a Meson
# install just like it does after a CMake install.
cmake_config_dir = get_option('datadir') / 'cmake' / meson.project_name()

# Number of directory levels between the config file and the install prefix,
# used to make the generated target file relocatable.
import_prefix_steps = []
foreach component : cmake_config_dir.split('/')
    import_prefix_steps += 'get_filename_component(_IMPORT_PREFIX "${_IMPORT_PREFIX}" PATH)'
endforeach

version_parts = meson.project_version().split('.')

cmake_conf = configuration_data()
cmake_conf.set('PROJECT_NAME', meson.project_name())
cmake_conf.set('PROJECT_VERSION', meson.project_version())
cmake_conf.set('PROJECT_VERSION_MAJOR', version_parts[0])
cmake_conf.set('NLOHMANN_JSON_TARGET_NAME', 'nlohmann_json')
cmake_conf.set('NLOHMANN_JSON_EXPORTED_TARGET_NAME', 'nlohmann_json::nlohmann_json')
cmake_conf.set('NLOHMANN_JSON_TARGETS_EXPORT_NAME', meson.project_name() + 'Targets')
cmake_conf.set('NLOHMANN_JSON_INCLUDE_INSTALL_DIR', get_option('includedir'))
cmake_conf.set('NLOHMANN_JSON_IMPORT_PREFIX_STEPS', '\n'.join(import_prefix_steps))

configure_file(
    input: 'cmake/config.cmake.in',
    output: meson.project_name() + 'Config.cmake',
    configuration: cmake_conf,
    install_dir: cmake_config_dir,
)
configure_file(
    input: 'cmake/nlohmann_jsonConfigVersion.cmake.in',
    output: meson.project_name() + 'ConfigVersion.cmake',
    configuration: cmake_conf,
    install_dir: cmake_config_dir,
)
configure_file(
    input: 'cmake/nlohmann_jsonTargets.cmake.in',
    output: meson.project_name() + 'Targets.cmake',
    configuration: cmake_conf,
    install_dir: cmake_config_dir,
)
endif
