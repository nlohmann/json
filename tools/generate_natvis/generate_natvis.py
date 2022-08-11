#!/usr/bin/env python3

import argparse
import itertools
import jinja2
import os
import re
import sys

def semver(v):
    if not re.fullmatch(r'\d+\.\d+\.\d+', v):
        raise ValueError
    return v

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', required=True, type=semver, help='Library version number')
    parser.add_argument('output', help='Output directory for nlohmann_json.natvis')
    args = parser.parse_args()

    namespaces = ['nlohmann']
    abi_prefix = 'json_abi'
    abi_tags = ['_diag', '_ldvcmp']
    version = '_v' + args.version.replace('.', '_')
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
