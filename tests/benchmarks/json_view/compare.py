#!/usr/bin/env python3
#     __ _____ _____ _____
#  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
# |  |  |__   |  |  | | | |  version 3.12.0
# |_____|_____|_____|_|___|  https://github.com/nlohmann/json
#
# SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
# SPDX-License-Identifier: MIT

"""Compare json_view with yyjson, simdjson, Boost.JSON, and json::parse.

Builds bench_view.cpp, bench_corpus.cpp, and bench_edit.cpp against the include/ directory of
this checkout, runs them, and writes the results with everything needed to
reproduce them (date, commit, CPU, OS, compiler, library versions, flags) to
results/<date>-<host>.md and .csv next to this script.

The other libraries come from the system (--system, the default: pkg-config
or Homebrew) or are downloaded as pinned releases and checked against their
SHA-256 (--download). Boost.JSON is optional: without Boost headers, its
columns are skipped, and the results say so.

Only the Python 3 standard library is used; a C++17 compiler is needed.
"""

import argparse
import datetime
import hashlib
import os
import platform
import re
import shlex
import shutil
# runs only the compilers and benchmark binaries this script builds
import subprocess  # nosec B404
import sys
import tarfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..'))

# pinned releases for --download; the hashes are those of the archives
PINNED = {
    'yyjson': {
        'version': '0.13.0',
        'url': 'https://github.com/ibireme/yyjson/archive/refs/tags/0.13.0.tar.gz',
        'sha256': '34e0f62a2bc11ab20d601e8ca1cc2b2079503aa45119a19133d89d19b94a0fae',
        'dir': 'yyjson-0.13.0',
    },
    'simdjson': {
        'version': '4.6.11',
        'url': 'https://github.com/simdjson/simdjson/archive/refs/tags/v4.6.11.tar.gz',
        'sha256': '61d948fc24f0d793829ad658058e7597d064988a89b4607ea02e401a82df98ff',
        'dir': 'simdjson-4.6.11',
    },
    'boost': {
        'version': '1.92.0',
        'url': 'https://archives.boost.io/release/1.92.0/source/boost_1_92_0.tar.gz',
        'sha256': 'c4a3b310ddd2472416e091067166b0713be97c63f38c212c484ada022fd296ce',
        'dir': 'boost_1_92_0',
    },
}

# the documents of bench_view.cpp, relative to the json_test_data directory
DEFAULT_CORPUS = [
    'nativejson-benchmark/twitter.json',
    'nativejson-benchmark/citm_catalog.json',
    'nativejson-benchmark/canada.json',
    'jeopardy/jeopardy.json',
]


def run(cmd, **kwargs):
    print('+ ' + ' '.join(shlex.quote(c) for c in cmd), flush=True)
    # cmd is an argument list built by this script, never a shell string
    return subprocess.run(cmd, check=True, **kwargs)  # nosec B603


def output(cmd):
    try:
        # cmd is an argument list built by this script, never a shell string
        return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()  # nosec B603
    except (OSError, subprocess.CalledProcessError):
        return ''


# ---------------------------------------------------------------------------
# libraries
# ---------------------------------------------------------------------------

class Library:
    """include directories, sources to compile, and linker flags of a library"""

    def __init__(self, name, include=None, sources=None, link=None, version=''):
        self.name = name
        self.include = include or []
        self.sources = sources or []
        self.link = link or []
        self.version = version


def header_version(path, pattern):
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            m = re.search(pattern, f.read())
        return m.group(1) if m else ''
    except OSError:
        return ''


def library_version(name, include_dirs):
    patterns = {
        'yyjson': ('yyjson.h', r'#define\s+YYJSON_VERSION_STRING\s+"([^"]+)"'),
        'simdjson': ('simdjson.h', r'#define\s+SIMDJSON_VERSION\s+"?([0-9.]+)"?'),
        'boost': (os.path.join('boost', 'version.hpp'), r'#define\s+BOOST_LIB_VERSION\s+"([^"]+)"'),
    }
    header, pattern = patterns[name]
    for d in include_dirs:
        v = header_version(os.path.join(d, header), pattern)
        if v:
            return v.replace('_', '.')
    return ''


def system_library(name):
    """a library found with pkg-config or Homebrew, or None"""
    flags = output(['pkg-config', '--cflags', '--libs', name]).split()
    if flags:
        include = [f[2:] for f in flags if f.startswith('-I')]
        link = [f for f in flags if f.startswith('-L') or f.startswith('-l')]
        libdirs = [f[2:] for f in link if f.startswith('-L')]
        link += ['-Wl,-rpath,' + d for d in libdirs]
        return Library(name, include, [], link, library_version(name, include))
    prefix = output(['brew', '--prefix', name]) if shutil.which('brew') else ''
    if prefix and os.path.isdir(os.path.join(prefix, 'include')):
        include = [os.path.join(prefix, 'include')]
        link = []
        if name != 'boost':
            lib = os.path.join(prefix, 'lib')
            link = ['-L' + lib, '-l' + name, '-Wl,-rpath,' + lib]
        return Library(name, include, [], link, library_version(name, include))
    if name == 'boost':
        for d in ['/usr/include', '/usr/local/include']:
            if os.path.isfile(os.path.join(d, 'boost', 'json.hpp')):
                return Library(name, [d], [], [], library_version(name, [d]))
    return None


def download_library(name, work):
    """a pinned release, downloaded and checked, or an error"""
    pin = PINNED[name]
    archive = os.path.join(work, 'download', os.path.basename(pin['url']))
    os.makedirs(os.path.dirname(archive), exist_ok=True)
    if not os.path.isfile(archive):
        print(f'downloading {pin["url"]}', flush=True)
        # the URLs are the https constants in PINNED, and the SHA-256 is checked below
        # (into a .part file first, so that an interrupted download is not kept)
        urllib.request.urlretrieve(pin['url'], archive + '.part')  # nosec B310
        os.replace(archive + '.part', archive)
    with open(archive, 'rb') as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    if digest != pin['sha256']:
        os.remove(archive)  # downloaded again by the next run
        sys.exit(f'error: SHA-256 of {archive} is {digest}, expected {pin["sha256"]} (removed)')
    src = os.path.join(work, 'download', pin['dir'])
    if not os.path.isdir(src):
        with tarfile.open(archive) as t:
            # (the 'data' filter rejects links and paths outside the target where Python has it)
            kwargs = {'filter': 'data'} if hasattr(tarfile, 'data_filter') else {}
            t.extractall(os.path.join(work, 'download'), **kwargs)  # noqa: S202 (checked archive)  # nosec B202
    if name == 'yyjson':
        return Library(name, [os.path.join(src, 'src')], [os.path.join(src, 'src', 'yyjson.c')], [], pin['version'])
    if name == 'simdjson':
        single = os.path.join(src, 'singleheader')
        return Library(name, [single], [os.path.join(single, 'simdjson.cpp')], [], pin['version'])
    return Library(name, [src], [], [], pin['version'])


# ---------------------------------------------------------------------------
# machine description
# ---------------------------------------------------------------------------

def cpu_model():
    if sys.platform == 'darwin':
        return output(['sysctl', '-n', 'machdep.cpu.brand_string'])
    try:
        with open('/proc/cpuinfo', encoding='utf-8') as f:
            for line in f:
                if line.startswith('model name') or line.startswith('Model'):
                    return line.split(':', 1)[1].strip()
    except OSError:
        pass
    # (AArch64 Linux: /proc/cpuinfo has no model name, lscpu knows it)
    for line in output(['lscpu']).splitlines():
        if line.startswith('Model name:'):
            return line.split(':', 1)[1].strip()
    return platform.processor() or platform.machine()


def git_commit():
    commit = output(['git', '-C', REPO, 'rev-parse', '--short=12', 'HEAD'])
    dirty = output(['git', '-C', REPO, 'status', '--porcelain', '--untracked-files=no'])
    return commit + (' (with local changes)' if dirty else '')


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--data', required=True, help='json_test_data directory (with nativejson-benchmark/ and jeopardy/)')
    ap.add_argument('--download', action='store_true', help='use pinned downloads instead of system libraries')
    ap.add_argument('--no-boost', action='store_true', help='skip Boost.JSON')
    ap.add_argument('--native', action='store_true', help='compile for this CPU (-march=native / -mcpu=native)')
    ap.add_argument('--rounds', type=int, default=30, help='rounds of bench_view (default: 30)')
    ap.add_argument('--corpus', nargs='*', default=[], help='more files for bench_corpus')
    ap.add_argument('--build-dir', default=os.path.join(HERE, 'build'), help='where to build (default: build/ next to this script)')
    args = ap.parse_args()
    # the benchmarks run in the build directory: make the paths absolute
    args.data = os.path.abspath(args.data)
    args.corpus = [os.path.abspath(f) for f in args.corpus]
    args.build_dir = os.path.abspath(args.build_dir)

    cxx = os.environ.get('CXX', 'c++')
    cc = os.environ.get('CC', 'cc')
    os.makedirs(args.build_dir, exist_ok=True)

    libs = {}
    for name in ['yyjson', 'simdjson', 'boost']:
        if name == 'boost' and args.no_boost:
            continue
        lib = download_library(name, args.build_dir) if args.download else system_library(name)
        if lib is None and name != 'boost':
            sys.exit(f'error: {name} not found; install it, or use --download')
        if lib is not None:
            libs[name] = lib
    with_boost = 'boost' in libs
    if not with_boost:
        print('Boost.JSON not found: its columns are skipped', flush=True)

    flags = ['-std=c++17', '-O3', '-DNDEBUG', f'-DJSON_VIEW_BENCH_BOOST={1 if with_boost else 0}']
    if args.native:
        flags.append('-mcpu=native' if platform.machine().lower() in ('arm64', 'aarch64') else '-march=native')
    include = ['-I' + os.path.join(REPO, 'include')] + ['-I' + d for lib in libs.values() for d in lib.include]
    link = [f for lib in libs.values() for f in lib.link]

    # C sources of downloaded libraries are compiled once
    objects = []
    for lib in libs.values():
        for src in lib.sources:
            obj = os.path.join(args.build_dir, os.path.basename(src) + '.o')
            compiler = cc if src.endswith('.c') else cxx
            run([compiler] + (['-std=c++17'] if compiler == cxx else []) + ['-O3', '-DNDEBUG', '-c', src, '-o', obj]
                + ['-I' + d for d in lib.include])
            objects.append(obj)

    binaries = {}
    for bench in ['bench_view', 'bench_corpus', 'bench_edit']:
        exe = os.path.join(args.build_dir, bench)
        run([cxx] + flags + include + [os.path.join(HERE, bench + '.cpp')] + objects + link + ['-o', exe])
        binaries[bench] = exe

    # run: bench_view on its documents, bench_corpus on those and the given files
    corpus = [os.path.join(args.data, f) for f in DEFAULT_CORPUS] + args.corpus
    outputs = {}
    outputs['bench_view'] = run([binaries['bench_view'], args.data, str(args.rounds)], cwd=args.build_dir,
                                capture_output=True, text=True).stdout
    outputs['bench_corpus'] = run([binaries['bench_corpus']] + corpus, cwd=args.build_dir,
                                  capture_output=True, text=True).stdout
    outputs['bench_edit'] = run([binaries['bench_edit'], args.data, str(max(1, args.rounds // 2))], cwd=args.build_dir,
                                capture_output=True, text=True).stdout
    for name, text in outputs.items():
        print(text)

    # results with their metadata
    now = datetime.datetime.now()
    host = re.sub(r'[^A-Za-z0-9-]+', '-', platform.node().split('.')[0]) or 'host'
    stem = os.path.join(HERE, 'results', f'{now:%Y-%m-%d}-{host}')
    os.makedirs(os.path.dirname(stem), exist_ok=True)
    meta = [
        ('date', f'{now:%Y-%m-%d %H:%M}'),
        ('commit', git_commit()),
        ('CPU', cpu_model()),
        ('OS', f'{platform.system()} {platform.release()} ({platform.machine()})'),
        ('compiler', output([cxx, '--version']).splitlines()[0] if output([cxx, '--version']) else cxx),
        ('flags', ' '.join(flags)),
        ('yyjson', libs['yyjson'].version),
        ('simdjson', libs['simdjson'].version),
        ('Boost.JSON', libs['boost'].version if with_boost else 'skipped (not found)'),
        ('libraries from', 'pinned downloads' if args.download else 'the system'),
        ('rounds', str(args.rounds)),
    ]
    with open(stem + '.md', 'w', encoding='utf-8') as f:
        f.write(f'# json_view comparison, {now:%Y-%m-%d}\n\n')
        f.write('Generated by `tests/benchmarks/json_view/compare.py`; best of the interleaved rounds.\n\n')
        f.write('| | |\n|---|---|\n')
        for key, value in meta:
            f.write(f'| {key} | {value} |\n')
        for name, text in outputs.items():
            f.write(f'\n## {name}\n\n```\n{text.rstrip()}\n```\n')
    with open(stem + '.csv', 'w', encoding='utf-8') as out:
        out.write(''.join(f'# {key}: {value}\n' for key, value in meta))
        for name in ['bench_view', 'bench_corpus', 'bench_edit']:
            path = os.path.join(args.build_dir, name + '.csv')
            if os.path.isfile(path):
                with open(path, encoding='utf-8') as f:
                    out.write(f'# {name}\n' + f.read())
    print(f'results: {stem}.md, {stem}.csv')


if __name__ == '__main__':
    main()
