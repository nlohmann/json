#!/usr/bin/env python3
"""Check the path filters of the compiler workflows.

ubuntu.yml, macos.yml and windows.yml skip pull requests that change only files
no compiler job reads (documentation, Markdown files, GitHub metadata, license
files). The filter starts with '**' and excludes these files explicitly, so a
new file runs the workflows unless it is excluded on purpose.

The script checks that

- each of the three workflows has exactly the filter defined in PATHS below,
  with its own workflow file included, and
- no tracked file that the filter keeps (sources, tests, build files, tools,
  workflows) mentions a file the filter excludes, unless the mention is listed
  in KNOWN_REFERENCES with the reason why it does not matter.

A mention found this way must either be added to PATHS as an included path
(the file is read by a compiler job) or to KNOWN_REFERENCES (it is not).

With --changed FILE..., the script prints instead which workflows a pull
request changing these files would run.
"""

import argparse
import os
import re
import subprocess  # nosec B404
import sys

REPO_ROOT = os.path.normpath(os.path.join(sys.path[0], '..', '..'))
SELF = 'tools/check_path_filters/check_path_filters.py'

WORKFLOWS = ['.github/workflows/ubuntu.yml', '.github/workflows/macos.yml', '.github/workflows/windows.yml']

# The pull_request paths filter of the workflows above; '{workflow}' is replaced
# with the workflow's own file. GitHub applies the patterns in order: a file
# matching a later pattern is included ('pattern') or excluded ('!pattern').
PATHS = [
    '**',
    '!docs/**',
    '!**.md',
    '!.github/*',
    '!.github/ISSUE_TEMPLATE/**',
    '!.github/external_ci/**',
    '!.github/workflows/**',
    '!.reuse/**',
    '!LICENSES/**',
    '!CITATION.cff',
    '!REUSE.toml',
    # read by tools/check_build_options in the ci_meson_install job (ubuntu.yml)
    'docs/mkdocs/docs/integration/package_managers.md',
    # built by the swiftpm job (macos.yml)
    'docs/mkdocs/docs/integration/swift/**',
    '{workflow}',
]

# Mentions of excluded files that no job of the three workflows depends on:
# (file that mentions it, the mention, reason)
KNOWN_REFERENCES = [
    ('cmake/ci.cmake', 'docs/', 'ci_test_examples; runs in repository_checks.yml, which has no path filter'),
    ('cmake/ci.cmake', 'docs/mkdocs/', 'ci_test_build_documentation and ci_test_documentation_mermaid; they run in '
                                       'repository_checks.yml, which has no path filter'),
    ('cmake/ci.cmake', 'docs/mkdocs/docs/examples/', 'indentation check of ci_test_amalgamation; the same check runs in '
                                                     'check_amalgamation.yml, which has no path filter'),
    ('Makefile', 'docs/mkdocs/docs/examples/', 'make pretty; runs in check_amalgamation.yml, which has no path filter'),
    ('Makefile', 'ChangeLog.md', 'make ChangeLog.md writes the file; no CI job runs it'),
    ('Makefile', 'tests/fuzzing.md', 'help text'),
    ('Makefile', 'tools/generate_natvis/README.md', 'help text'),
    ('tests/src/make_test_data_available.hpp', 'README.md', 'a file of the external test data repository'),
    ('tools/check_build_options/check_build_options.py', 'docs/', 'builds the path of package_managers.md, which '
                                                                  'PATHS includes'),
]


# CI targets that read excluded files; they must run in a workflow without a path filter
UNFILTERED_TARGETS = ['ci_test_examples', 'ci_test_build_documentation', 'ci_test_documentation_mermaid',
                      'ci_test_amalgamation', 'ci_reuse_compliance']


def git_files(root):
    # fixed command, no user input; includes new files not yet added, so a local run
    # sees what CI sees after the commit
    out = subprocess.check_output(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'], cwd=root)  # nosec B603, B607
    return [f for f in out.decode('utf-8').split('\0') if f]


def glob_to_regex(pattern):
    """Translate a GitHub Actions path pattern to a regular expression."""
    regex = ''
    i = 0
    while i < len(pattern):
        if pattern.startswith('**', i):
            regex += '.*'
            i += 2
        elif pattern[i] == '*':
            regex += '[^/]*'
            i += 1
        elif pattern[i] == '?':
            regex += '[^/]'
            i += 1
        else:
            regex += re.escape(pattern[i])
            i += 1
    return re.compile(regex + r'\Z')


def compile_filter(paths, workflow):
    return [(p.startswith('!'), glob_to_regex(p.lstrip('!').replace('{workflow}', workflow))) for p in paths]


def included(compiled, path):
    result = False
    for negated, regex in compiled:
        if regex.match(path):
            result = not negated
    return result


def read_filter(root, workflow):
    """Return the pull_request paths list of a workflow file."""
    with open(os.path.join(root, workflow), encoding='utf-8') as f:
        lines = f.read().splitlines()
    paths = None
    in_pull_request = False
    for line in lines:
        if re.match(r'^  pull_request:', line):
            in_pull_request = True
            continue
        if in_pull_request:
            if re.match(r'^  \S', line) or re.match(r'^\S', line):
                break
            if re.match(r'^    paths:\s*$', line):
                paths = []
                continue
            m = re.match(r"^      - '(.*)'\s*(#.*)?$", line)
            if paths is not None and m:
                paths.append(m.group(1))
            elif paths is not None and line.strip() and not line.strip().startswith('#'):
                break
    return paths


TOKEN = re.compile(r'(["\'/]?)([\w.-]+(?:/[\w.-]+)*)')


COMMENT_LINE = re.compile(r'^[ \t]*(//|#|/?\*|--).*$', re.MULTILINE)


class Mentions:
    """Finds the words and paths in a text that name an excluded file or directory."""

    def __init__(self, files, excluded, is_excluded):
        self.files = set(files)
        self.excluded = excluded
        self.dirs = {'/'.join(f.split('/')[:n]) for f in files for n in range(1, f.count('/') + 1)}
        # an excluded directory: a new file in it would be excluded
        self.excluded_dirs = {d for d in self.dirs if is_excluded(d + '/new_file')}
        # base names that only excluded files have, e.g. 'ChangeLog.md' but not 'CMakeLists.txt'
        self.names = {os.path.basename(f) for f in excluded} - {os.path.basename(f) for f in files if f not in excluded}

    def find(self, text):
        """Yield (offset, mention) for every word or path in text that names an excluded file or directory."""
        for m in TOKEN.finditer(text):
            parts = m.group(2).rstrip('/').split('/')
            # a single word names a directory only in a path context, e.g. 'docs' in os.path.join('docs', ...)
            path_context = len(parts) > 1 or m.group(1)
            for i in range(len(parts)):
                path = '/'.join(parts[i:])
                if path in self.files:
                    if path in self.excluded:
                        yield m.start(2), path
                    break
                if path in self.dirs and path_context:
                    if path in self.excluded_dirs:
                        yield m.start(2), path + '/'
                    break
            else:
                if parts[-1] in self.names and '.' in parts[-1]:
                    yield m.start(2), parts[-1]


def known(path, mention):
    return any(path == file and mention == known_mention for file, known_mention, _ in KNOWN_REFERENCES)


def check(root):
    errors = []
    for workflow in WORKFLOWS:
        expected = [p.replace('{workflow}', workflow) for p in PATHS]
        actual = read_filter(root, workflow)
        if actual != expected:
            errors.append('{}: the pull_request paths filter differs from tools/check_path_filters/check_path_filters.py\n'
                          '  expected: {}\n  actual:   {}'.format(workflow, expected, actual))
        with open(os.path.join(root, workflow), encoding='utf-8') as f:
            text = f.read()
        for target in UNFILTERED_TARGETS:
            if re.search(r'\b' + target + r'\b', text):
                errors.append('{}: runs {}, which reads excluded files; run it in repository_checks.yml'.format(workflow, target))

    files = git_files(root)
    union = [compile_filter(PATHS, w) for w in WORKFLOWS]
    def is_excluded(path):
        return not any(included(c, path) for c in union)

    excluded = {f for f in files if is_excluded(f)}
    finder = Mentions(files, excluded, is_excluded)

    for path in sorted(set(files) - excluded):
        # third-party code and Markdown files read nothing; this script lists the excluded files
        if path.startswith('tests/thirdparty/') or path.endswith('.md') or path == SELF:
            continue
        try:
            with open(os.path.join(root, path), encoding='utf-8') as f:
                # a mention in a comment line reads nothing; keep the line numbers
                text = COMMENT_LINE.sub('', f.read())
        except (UnicodeDecodeError, OSError):
            continue
        if path in WORKFLOWS:
            # the filter itself lists the excluded files
            for p in PATHS:
                text = text.replace("      - '{}'".format(p.replace('{workflow}', path)), '')
        reported = set()
        for offset, mention in finder.find(text):
            if mention not in reported and not known(path, mention):
                reported.add(mention)
                line = text.count('\n', 0, offset) + 1
                errors.append('{}:{}: mentions excluded {}; include it in PATHS if a compiler job reads it, '
                              'or add it to KNOWN_REFERENCES'.format(path, line, mention))

    for e in errors:
        print(e)
    if not errors:
        print('path filters OK: {} of {} tracked files skip the compiler workflows'.format(len(excluded), len(files)))
    return 1 if errors else 0


def explain(changed):
    for workflow in WORKFLOWS:
        compiled = compile_filter(PATHS, workflow)
        hits = [f for f in changed if included(compiled, f)]
        print('{}: {}'.format(workflow, 'runs ({})'.format(', '.join(hits[:3]) + (' ...' if len(hits) > 3 else ''))
                                       if hits else 'skipped'))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--root', default=REPO_ROOT, help='repository root')
    parser.add_argument('--changed', nargs='+', metavar='FILE', help='show which workflows these changed files run')
    args = parser.parse_args()
    return explain(args.changed) if args.changed else check(args.root)


if __name__ == '__main__':
    sys.exit(main())
