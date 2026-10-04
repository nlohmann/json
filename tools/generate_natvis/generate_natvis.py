#!/usr/bin/env python3

import argparse
import itertools
import jinja2
import os
import re
import sys

# Directory of the repository, assuming this script stays at
# tools/generate_natvis/generate_natvis.py. Used only as the default value
# for the "output" argument below.
REPO_ROOT = os.path.normpath(os.path.join(sys.path[0], '..', '..'))


def semver(v):
    if not re.fullmatch(r'\d+\.\d+\.\d+', v):
        raise ValueError
    return v


def abi_info(repo_root):
    """Derive the ABI tag list (in NLOHMANN_JSON_ABI_TAGS_CONCAT order) and the
    library version from <repo_root>/include/nlohmann/detail/abi_macros.hpp,
    so this script cannot drift from the header it visualizes."""
    abi_macros_hpp = os.path.join(repo_root, 'include', 'nlohmann', 'detail', 'abi_macros.hpp')
    with open(abi_macros_hpp) as f:
        content = f.read()

    # find the NLOHMANN_JSON_ABI_TAGS_CONCAT(...) invocation that lists the
    # NLOHMANN_JSON_ABI_TAG_* identifiers in order (not its own #define, which
    # only names its formal parameters a, b, c, ...)
    tag_idents = None
    for args in re.findall(r'NLOHMANN_JSON_ABI_TAGS_CONCAT\(\s*(.*?)\)', content, re.S):
        idents = re.findall(r'NLOHMANN_JSON_ABI_TAG_\w+', args)
        if idents:
            tag_idents = idents
            break
    if not tag_idents:
        raise ValueError(f'could not find NLOHMANN_JSON_ABI_TAGS_CONCAT(...) in {abi_macros_hpp}')

    abi_tags = []
    for ident in tag_idents:
        # each tag is #define'd to its suffix (e.g. _diag) when the matching
        # JSON_* option is enabled, and to nothing in the #else branch; only
        # the non-empty definition matches here
        match = re.search(r'#define\s+' + re.escape(ident) + r'\s+(_\w+)\s*\n', content)
        if not match:
            raise ValueError(f'could not find a non-empty #define for {ident} in {abi_macros_hpp}')
        abi_tags.append(match.group(1))

    version = {}
    for part in ('MAJOR', 'MINOR', 'PATCH'):
        match = re.search(r'#define\s+NLOHMANN_JSON_VERSION_' + part + r'\s+(\d+)', content)
        if not match:
            raise ValueError(f'could not find NLOHMANN_JSON_VERSION_{part} in {abi_macros_hpp}')
        version[part] = match.group(1)

    return abi_tags, '{MAJOR}.{MINOR}.{PATCH}'.format(**version)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', type=semver,
                         help='Library version number (default: parsed from '
                              'include/nlohmann/detail/abi_macros.hpp below "output")')
    parser.add_argument('output', nargs='?', default=REPO_ROOT,
                         help='Repository root: where include/nlohmann/detail/abi_macros.hpp is '
                              'read from and where nlohmann_json.natvis is written '
                              '(default: the repository root this script lives in)')
    args = parser.parse_args()

    derived_tags, derived_version = abi_info(args.output)

    namespaces = ['nlohmann']
    abi_prefix = 'json_abi'
    abi_tags = derived_tags
    version = '_v' + (args.version or derived_version).replace('.', '_')
    inline_namespaces = []

    # generate all combinations of inline namespace names
    for n in range(0, len(abi_tags) + 1):
        for tags in itertools.combinations(abi_tags, n):
            ns = abi_prefix + ''.join(tags)
            inline_namespaces += [ns, ns + version]

    namespaces += [f'{namespaces[0]}::{ns}' for ns in inline_namespaces]

    env = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath=sys.path[0]), autoescape=True, trim_blocks=True,
                                                            lstrip_blocks=True, keep_trailing_newline=True)
    template = env.get_template('nlohmann_json.natvis.j2')
    natvis = template.render(namespaces=namespaces)

    with open(os.path.join(args.output, 'nlohmann_json.natvis'), 'w') as f:
        f.write(natvis)
