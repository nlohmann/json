#!/usr/bin/env python3
"""Check that the Meson build and the pkg-config files offer the CMake options.

The compile definitions of the CMake target (target_compile_definitions in
CMakeLists.txt) are the reference. For every option used there, the script
checks that

- the CMake pkg-config file adds the same definition under the same condition,
- meson_options.txt has a boolean option of the same name without the "JSON_"
  prefix and with the same default,
- meson.build adds the same definition under the same condition, and
- the Meson section of the package manager documentation lists the option.

Meson's MultipleHeaders option selects the include directory and adds no
definition; it is the only Meson option without a definition.
"""

import argparse
import os
import re
import sys

REPO_ROOT = os.path.normpath(os.path.join(sys.path[0], '..', '..'))
DOCS = os.path.join('docs', 'mkdocs', 'docs', 'integration', 'package_managers.md')

# Meson options that add no compile definition, with their default
MESON_ONLY = {'MultipleHeaders': 'false'}


def read(root, path):
    with open(os.path.join(root, path), encoding='utf-8') as f:
        return f.read()


def cmake_target_definitions(cmake):
    """Return {option: (definition, add_if_on)} from target_compile_definitions."""
    block = re.search(r'target_compile_definitions\(\s*\$\{NLOHMANN_JSON_TARGET_NAME\}\s*INTERFACE(.*?)\n\)', cmake, re.S)
    if not block:
        sys.exit('CMakeLists.txt: target_compile_definitions of the target not found')
    result = {}
    for line in block.group(1).split('\n'):
        line = line.strip()
        if not line:
            continue
        m = re.fullmatch(r'\$<\$<NOT:\$<BOOL:\$\{JSON_(\w+)\}>>:(\w+=\w+)>', line)
        if m:
            result[m.group(1)] = (m.group(2), False)
            continue
        m = re.fullmatch(r'\$<\$<BOOL:\$\{JSON_(\w+)\}>:(\w+=\w+)>', line)
        if m:
            result[m.group(1)] = (m.group(2), True)
            continue
        sys.exit(f'CMakeLists.txt: unexpected line in target_compile_definitions: {line}')
    return result


def cmake_defaults(cmake):
    """Return {option: 'true'/'false'} for the option() calls of the form JSON_<name>."""
    return {m.group(1): 'true' if m.group(2) == 'ON' else 'false'
            for m in re.finditer(r'^option\(JSON_(\w+)\s+"[^"]*"\s+(ON|OFF)\)', cmake, re.M)}


def cmake_pkgconfig_definitions(cmake):
    """Return {option: (definition, add_if_on)} from the pkg-config block."""
    return {m.group(2): (m.group(3), m.group(1) is None)
            for m in re.finditer(r'if \((NOT )?JSON_(\w+)\)\s*\n\s*string\(APPEND NLOHMANN_JSON_PKGCONFIG_CFLAGS " -D(\w+=\w+)"\)', cmake)}


def meson_options(options):
    """Return {option: default} for the boolean options in meson_options.txt."""
    result = {}
    for block in re.findall(r'option\((.*?)\)', options, re.S):
        name = re.search(r"'(\w+)'", block).group(1)
        kind = re.search(r"type\s*:\s*'(\w+)'", block)
        value = re.search(r'value\s*:\s*(\w+)', block)
        result[name] = value.group(1) if kind and kind.group(1) == 'boolean' and value else None
    return result


def meson_definitions(meson):
    """Return {option: (definition, add_if_on)} from meson.build."""
    return {m.group(2): (m.group(3), m.group(1) is None)
            for m in re.finditer(r"if (not )?get_option\('(\w+)'\)\s*\n\s*json_defines \+= '(\w+=\w+)'", meson)}


def describe(definition):
    name, add_if_on = definition
    return f'{name} if {"enabled" if add_if_on else "disabled"}'


def compare(errors, where, expected, actual):
    for option, definition in expected.items():
        if option not in actual:
            errors.append(f'{where}: no definition for option {option} (expected {describe(definition)})')
        elif actual[option] != definition:
            errors.append(f'{where}: option {option} adds {describe(actual[option])}, expected {describe(definition)}')
    for option in actual.keys() - expected.keys():
        errors.append(f'{where}: definition for option {option}, which the CMake target does not have')


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('root', nargs='?', default=REPO_ROOT, help='repository root (default: %(default)s)')
    root = parser.parse_args().root

    cmake = read(root, 'CMakeLists.txt')
    reference = cmake_target_definitions(cmake)
    defaults = cmake_defaults(cmake)
    errors = []

    compare(errors, 'CMakeLists.txt (pkg-config)', reference, cmake_pkgconfig_definitions(cmake))
    compare(errors, 'meson.build', reference, meson_definitions(read(root, 'meson.build')))

    options = meson_options(read(root, 'meson_options.txt'))
    for option in reference:
        if option not in defaults:
            errors.append(f'CMakeLists.txt: no option(JSON_{option} ... ON|OFF)')
        elif option not in options:
            errors.append(f'meson_options.txt: option {option} missing')
        elif options[option] != defaults[option]:
            errors.append(f'meson_options.txt: option {option} must be boolean with value {defaults[option]} as in CMake')
    for option, default in MESON_ONLY.items():
        if options.get(option) != default:
            errors.append(f'meson_options.txt: option {option} must be boolean with value {default}')
    for option in options.keys() - reference.keys() - MESON_ONLY.keys():
        errors.append(f'meson_options.txt: option {option} has no counterpart in the CMake target')

    docs = read(root, DOCS)
    for option in sorted(set(options) & (reference.keys() | MESON_ONLY.keys())):
        if f'`{option}`' not in docs:
            errors.append(f'{DOCS}: Meson option {option} not listed')

    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        print('The Meson build and the pkg-config files must offer the options of the CMake target; see '
              'tools/check_build_options/README.md.', file=sys.stderr)
        return 1
    print(f'OK: {len(reference)} options with compile definitions agree between CMake, pkg-config, and Meson.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
