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
    """Derive the ABI tags (in NLOHMANN_JSON_ABI_TAGS_CONCAT order) and the
    library version from <repo_root>/include/nlohmann/detail/abi_macros.hpp,
    so this script cannot drift from the header it visualizes. Each tag is
    returned as a (suffix, configuration macro, tag macro) tuple, for example
    ('_diag', 'JSON_DIAGNOSTICS', 'NLOHMANN_JSON_ABI_TAG_DIAGNOSTICS')."""
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
        # the option that enables the tag is the #if/#ifdef right above it
        option = re.search(r'#\s*(?:if|ifdef)\s+(\w+)\s*\n\s*#define\s+' + re.escape(ident) + r'\s+_', content)
        abi_tags.append((match.group(1), option.group(1) if option else '?', ident))

    version = {}
    for part in ('MAJOR', 'MINOR', 'PATCH'):
        match = re.search(r'#define\s+NLOHMANN_JSON_VERSION_' + part + r'\s+(\d+)', content)
        if not match:
            raise ValueError(f'could not find NLOHMANN_JSON_VERSION_{part} in {abi_macros_hpp}')
        version[part] = match.group(1)

    return abi_tags, '{MAJOR}.{MINOR}.{PATCH}'.format(**version)


def parse_tag_list(value, abi_tags):
    """Turn one --abi-tags value ("_diag,dp") into the tuple of suffixes it
    names, in namespace order; unknown tags and empty lists are errors."""
    known = [suffix for suffix, _, _ in abi_tags]
    requested = set()
    for tag in value.split(','):
        tag = tag.strip()
        if not tag:
            continue
        if not tag.startswith('_'):
            tag = '_' + tag
        if tag not in known:
            raise ValueError(f'unknown ABI tag {tag!r}; valid tags: {", ".join(known)} (see --list-tags)')
        requested.add(tag)
    if not requested:
        raise ValueError(f'empty ABI tag list {value!r}; the namespace without tags is always generated')
    return tuple(tag for tag in known if tag in requested)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generate nlohmann_json.natvis. By default, it covers the namespaces with up to two ABI tags; '
                    'use --abi-tags or --all for other configurations.')
    parser.add_argument('--version', type=semver,
                         help='Library version number (default: parsed from '
                              'include/nlohmann/detail/abi_macros.hpp below "repo_root")')
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--abi-tags', action='append', default=[], metavar='TAGS',
                           help='Comma-separated list of ABI tags (e.g. "_diag,_dp,_ns", leading underscores are '
                                'optional) of one configuration to add to the default namespaces; can be repeated')
    selection.add_argument('--all', action='store_true',
                           help='Generate the namespaces for every combination of ABI tags; the file size doubles '
                                'with each ABI tag (about 60 MB for 12 tags)')
    parser.add_argument('--list-tags', action='store_true',
                        help='List the ABI tags with the macros that enable them, and exit')
    parser.add_argument('--output', metavar='FILE',
                        help='Where to write the Natvis file (default: nlohmann_json.natvis below "repo_root")')
    parser.add_argument('repo_root', nargs='?', default=REPO_ROOT,
                         help='Repository root: where include/nlohmann/detail/abi_macros.hpp is read from '
                              '(default: the repository root this script lives in)')
    args = parser.parse_args()

    abi_tags, derived_version = abi_info(args.repo_root)

    if args.list_tags:
        width = max(len(suffix) for suffix, _, _ in abi_tags)
        option_width = max(len(option) for _, option, _ in abi_tags)
        for suffix, option, ident in abi_tags:
            print(f'{suffix:<{width}}  {option:<{option_width}}  {ident}')
        sys.exit(0)

    try:
        extra_combinations = [parse_tag_list(value, abi_tags) for value in args.abi_tags]
    except ValueError as e:
        parser.error(str(e))

    namespaces = ['nlohmann']
    abi_prefix = 'json_abi'
    suffixes = [suffix for suffix, _, _ in abi_tags]
    version = '_v' + (args.version or derived_version).replace('.', '_')

    # by default, generate the namespace names for up to two ABI tags, plus
    # the combinations requested with --abi-tags
    max_tags = len(suffixes) if args.all else min(len(suffixes), 2)
    combinations = [tags for n in range(0, max_tags + 1) for tags in itertools.combinations(suffixes, n)]
    for tags in extra_combinations:
        if tags not in combinations:
            combinations.append(tags)

    inline_namespaces = []
    for tags in combinations:
        ns = abi_prefix + ''.join(tags)
        inline_namespaces += [ns, ns + version]

    namespaces += [f'{namespaces[0]}::{ns}' for ns in inline_namespaces]

    # The template renders a local XML file, not a web response, and autoescape is enabled.
    # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath=sys.path[0]), autoescape=True, trim_blocks=True,
                                                            lstrip_blocks=True, keep_trailing_newline=True)
    template = env.get_template('nlohmann_json.natvis.j2')
    # nosemgrep: python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2
    natvis = template.render(namespaces=namespaces)

    output = args.output or os.path.join(args.repo_root, 'nlohmann_json.natvis')
    with open(output, 'w') as f:
        f.write(natvis)

    if args.all:
        print(f'wrote {len(namespaces)} namespaces ({os.path.getsize(output) / 1e6:.1f} MB) to {output}',
              file=sys.stderr)
