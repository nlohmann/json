#!/usr/bin/env python3
"""
    Author: Bryan Gillespie

    Legacy version... supports versions 7.1.0 <= GCC < 9.0.0

    A massively parallel gcov wrapper for generating intermediate coverage formats fast

    The goal of fastcov is to generate code coverage intermediate formats as fast as possible
    (ideally < 1 second), even for large projects with hundreds of gcda objects. The intermediate
    formats may then be consumed by a report generator such as lcov's genhtml, or a dedicated front
    end such as coveralls.

    Sample Usage:
        $ cd build_dir
        $ ./fastcov.py --exclude-gcov /usr/include --lcov -o report.info
        $ genhtml -o code_coverage report.info
"""

import re
import os
import glob
import json
import argparse
import subprocess
import multiprocessing
from random import shuffle

MINIMUM_GCOV = (7,1,0)
MINIMUM_CHUNK_SIZE = 10

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

def getGcovVersion(gcov):
    p = subprocess.Popen([gcov, "-v"], stdout=subprocess.PIPE)
    output = p.communicate()[0].decode('UTF-8')
    p.wait()
    version_str = re.search(r'\s([\d.]+)\s', output.split("\n")[0]).group(1)
    version = tuple(map(int, version_str.split(".")))
    return version

def removeFiles(files):
    for file in files:
        os.remove(file)

def getFilteredGcdaFiles(gcda_files, exclude):
    def excludeGcda(gcda):
        for ex in exclude:
            if ex in gcda:
                return False
        return True
    return list(filter(excludeGcda, gcda_files))

def getGcdaFiles(cwd, gcda_files, exclude):
    if not gcda_files:
        gcda_files = glob.glob(os.path.join(cwd, "**/*.gcda"), recursive=True)
    if exclude:
        return getFilteredGcdaFiles(gcda_files, exclude)
    return gcda_files

def getGcovFiles(cwd):
    return glob.glob(os.path.join(cwd, "*.gcov"))

def filterGcovFiles(gcov):
    with open(gcov) as f:
        path = f.readline()[5:]
        for ex in args.exclude:
            if ex in path:
                return False
        return True

def processGcdasPre9(cwd, gcov, jobs, gcda_files):
    chunk_size = min(MINIMUM_CHUNK_SIZE, int(len(gcda_files) / jobs) + 1)

    processes = []
    # shuffle(gcda_files) # improves performance by preventing any one gcov from bottlenecking on a list of sequential, expensive gcdas (?)
    for chunk in chunks(gcda_files, chunk_size):
        processes.append(subprocess.Popen([gcov, "-i"] + chunk, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))

    for p in processes:
        p.wait()

def processGcdasPre9Accurate(cwd, gcov, gcda_files, exclude):
    intermediate_json_files = []
    for gcda in gcda_files:
        subprocess.Popen([gcov, "-i", gcda], cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).wait()
        gcov_files = getGcovFiles(cwd)
        intermediate_json_files += processGcovs(gcov_files, exclude)
        removeFiles(gcov_files)
    return intermediate_json_files

def processGcovLine(file, line):
    line_type, data = line.split(":", 1)
    if line_type == "lcount":
        num, count = data.split(",")
        hit = (count != 0)
        file["lines_hit"] += int(hit)
        file["lines"].append({
            "branches": [],
            "line_number": num,
            "count": count,
            "unexecuted_block": not hit
        })
    elif line_type == "function":
        num, count, name = data.split(",")
        hit = (count != 0)
        file["functions_hit"] += int(hit)
        file["functions"].append({
            "name": name,
            "execution_count": count,
            "start_line": num,
            "end_line": None,
            "blocks": None,
            "blocks_executed": None,
            "demangled_name": None
        })

def processGcov(files, gcov, exclude):
    with open(gcov) as f:
        path = f.readline()[5:].rstrip()
        for ex in exclude:
            if ex in path:
                return False
        file = {
            "file": path,
            "functions": [],
            "functions_hit": 0,
            "lines": [],
            "lines_hit": 0
        }
        for line in f:
            processGcovLine(file, line.rstrip())
    files.append(file)
    return True

def processGcovs(gcov_files, exclude):
    files = []
    filtered = 0
    for gcov in gcov_files:
        filtered += int(not processGcov(files, gcov, exclude))
    print("Skipped %d .gcov files" % filtered)
    return files

def dumpToLcovInfo(intermediate, output):
    with open(output, "w") as f:
        for file in intermediate:
            f.write("SF:%s\n" % file["file"])
            for function in file["functions"]:
                f.write("FN:%s,%s\n" % (function["start_line"], function["name"]))
                f.write("FNDA:%s,%s\n" % (function["execution_count"], function["name"]))
            f.write("FNF:%s\n" % len(file["functions"]))
            f.write("FNH:%s\n" % file["functions_hit"])
            for line in file["lines"]:
                f.write("DA:%s,%s\n" % (line["line_number"], line["count"]))
            f.write("LF:%s\n" % len(file["lines"]))
            f.write("LH:%s\n" % file["lines_hit"])
            f.write("end_of_record\n")

def dumpToGcovJson(intermediate, output):
    with open(output, "w") as f:
        json.dump(intermediate, f)

def main(args):
    # Need at least gcov 7.1.0 because of bug not allowing -i in conjunction with multiple files
    # See: https://github.com/gcc-mirror/gcc/commit/41da7513d5aaaff3a5651b40edeccc1e32ea785a
    current_gcov_version = getGcovVersion(args.gcov)
    if current_gcov_version < MINIMUM_GCOV:
        print("Minimum gcov version {} required, found {}".format(".".join(map(str, MINIMUM_GCOV)), ".".join(map(str, current_gcov_version))))
        exit(1)

    gcda_files = getGcdaFiles(args.directory, args.gcda_files, args.excludepre)
    print("Found %d .gcda files" % len(gcda_files))

    # We "zero" the "counters" by simply deleting all gcda files
    if args.zerocounters:
        removeFiles(gcda_files)
        print("Removed %d .gcda files" % len(gcda_files))
        return

    # If we are less than gcov 9.0.0, convert .gcov files to GCOV 9 JSON format
    processGcdasPre9(args.cdirectory, args.gcov, args.jobs, gcda_files)
    gcov_files = getGcovFiles(args.cdirectory)

    print("Found %d .gcov files" % len(gcov_files))

    intermediate_json_files = processGcovs(gcov_files, args.excludepost)
    removeFiles(gcov_files)

    intermediate_json_files += processGcdasPre9Accurate(args.cdirectory, args.gcov, args.gcda_files_accurate, args.excludepost)

    if args.lcov:
        dumpToLcovInfo(intermediate_json_files, args.output)
    else:
        dumpToGcovJson(intermediate_json_files, args.output)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A parallel gcov wrapper for fast coverage report generation')
    parser.add_argument('-z', '--zerocounters', dest='zerocounters', action="store_true", help='Recursively delete all gcda files')

    parser.add_argument('-f', '--gcda-files', dest='gcda_files', nargs="+", default=[], help='Specify exactly which gcda files should be processed instead of recursivly searching the search directory.')
    parser.add_argument('-F', '--gcda-files-accurate', dest='gcda_files_accurate', nargs="+", default=[], help='(< gcov 9.0.0) Get accurate header coverage information for just these. These files cannot be processed in parallel')
    parser.add_argument('-E', '--exclude-gcda', dest='excludepre', nargs="+", default=[], help='.gcda filter - Exclude gcda files from being processed via simple find matching (not regex)')
    parser.add_argument('-e', '--exclude-gcov', dest='excludepost', nargs="+", default=[], help='.gcov filter - Exclude gcov files from being processed via simple find matching (not regex)')

    parser.add_argument('-g', '--gcov', dest='gcov', default='gcov', help='which gcov binary to use')

    parser.add_argument('-d', '--search-directory', dest='directory', default=".", help='Base directory to recursively search for gcda files (default: .)')
    parser.add_argument('-c', '--compiler-directory', dest='cdirectory', default=".", help='Base directory compiler was invoked from (default: .)')
    parser.add_argument('-j', '--jobs', dest='jobs', type=int, default=multiprocessing.cpu_count(), help='Number of parallel gcov to spawn (default: %d).' % multiprocessing.cpu_count())


    parser.add_argument('-o', '--output', dest='output', default="coverage.json", help='Name of output file (default: coverage.json)')
    parser.add_argument('-i', '--lcov', dest='lcov', action="store_true", help='Output in lcov info format instead of gcov json')
    args = parser.parse_args()
    main(args)