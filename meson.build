project('nlohmann_json',
    'cpp',
    version : '3.12.0',
    license : 'MIT',
    meson_version : '>= 0.64',
    default_options: ['cpp_std=c++11'],
)

nlohmann_json_dep = declare_dependency(
    include_directories: include_directories('single_include')
)
meson.override_dependency('nlohmann_json', nlohmann_json_dep)

nlohmann_json_multiple_headers = declare_dependency(
    include_directories: include_directories('include')
)
meson.override_dependency('nlohmann_json_multiple_headers', nlohmann_json_multiple_headers)

if not meson.is_subproject()
    install_subdir(
        'single_include/nlohmann',
        install_dir: get_option('includedir'),
        install_tag: 'devel',
    )

    pkgc = import('pkgconfig')
    pkgc.generate(name: 'nlohmann_json',
        version: meson.project_version(),
        description: 'JSON for Modern C++'
    )
endif
