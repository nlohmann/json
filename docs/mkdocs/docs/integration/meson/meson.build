project('json_example', 'cpp',
  version: '1.0',
  default_options: ['cpp_std=c++11']
)

dependency_json = dependency('nlohmann_json', required: true)

executable('json_example',
  sources: ['example.cpp'],
  dependencies: [dependency_json],
  install: true
)
