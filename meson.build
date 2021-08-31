project('nlohmann_json',
    'cpp',
    version : '3.10.2',
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

pkgc = import('pkgconfig')
pkgc.generate(name: 'nlohmann_json',
    version: meson.project_version(),
    description: 'JSON for Modern C++'
)
endif
