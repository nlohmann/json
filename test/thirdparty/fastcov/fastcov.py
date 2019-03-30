#!/usr/bin/env python3
"""
    Author: Bryan Gillespie

    A massively parallel gcov wrapper for generating intermediate coverage formats fast

    The goal of fastcov is to generate code coverage intermediate formats as fast as possible
    (ideally < 1 second), even for large projects with hundreds of gcda objects. The intermediate
    formats may then be consumed by a report generator such as lcov's genhtml, or a dedicated front
    end such as coveralls.

    Sample Usage:
        $ cd build_dir
        $ ./fastcov.py --zerocounters
        $ <run unit tests>
        $ ./fastcov.py --exclude-gcov /usr/include --lcov -o report.info
        $ genhtml -o code_coverage report.info
"""

import re
import os
import sys
import glob
import json
import argparse
import threading
import subprocess
import multiprocessing

MINIMUM_GCOV = (9,0,0)
MINIMUM_CHUNK_SIZE = 10

# Interesting metrics
GCOVS_TOTAL = []
GCOVS_SKIPPED = []

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

def getGcdaFiles(cwd, gcda_files):
    if not gcda_files:
        gcda_files = glob.glob(os.path.join(cwd, "**/*.gcda"), recursive=True)
    return gcda_files

def gcovWorker(cwd, gcov, files, chunk, exclude):
    p = subprocess.Popen([gcov, "-it"] + chunk, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    for line in iter(p.stdout.readline, b''):
        intermediate_json = json.loads(line.decode(sys.stdout.encoding))
        intermediate_json_files = processGcovs(intermediate_json["files"], exclude)
        for f in intermediate_json_files:
            files.append(f) #thread safe, there might be a better way to do this though
        GCOVS_TOTAL.append(len(intermediate_json["files"]))
        GCOVS_SKIPPED.append(len(intermediate_json["files"])-len(intermediate_json_files))
    p.wait()

def processGcdas(cwd, gcov, jobs, gcda_files, exclude):
    chunk_size = max(MINIMUM_CHUNK_SIZE, int(len(gcda_files) / jobs) + 1)

    threads = []
    intermediate_json_files = []
    for chunk in chunks(gcda_files, chunk_size):
        t = threading.Thread(target=gcovWorker, args=(cwd, gcov, intermediate_json_files, chunk, exclude))
        threads.append(t)
        t.start()

    log("Spawned %d gcov processes each processing at most %d gcda files" % (len(threads), chunk_size))
    for t in threads:
        t.join()

    return intermediate_json_files

def processGcov(gcov, files, exclude):
    for ex in exclude:
        if ex in gcov["file"]:
            return
    files.append(gcov)

def processGcovs(gcov_files, exclude):
    files = []
    for gcov in gcov_files:
        processGcov(gcov, files, exclude)
    return files

def dumpToLcovInfo(cwd, intermediate, output):
    with open(output, "w") as f:
        for file in intermediate:
            #Convert to absolute path so it plays nice with genhtml
            sf = file["file"]
            if not os.path.isabs(file["file"]):
                sf = os.path.abspath(os.path.join(cwd, file["file"]))
            f.write("SF:%s\n" % sf)
            fn_miss = 0
            for function in file["functions"]:
                f.write("FN:%s,%s\n" % (function["start_line"], function["name"]))
                f.write("FNDA:%s,%s\n" % (function["execution_count"], function["name"]))
                fn_miss += int(not function["execution_count"] == 0)
            f.write("FNF:%s\n" % len(file["functions"]))
            f.write("FNH:%s\n" % (len(file["functions"]) - fn_miss))
            line_miss = 0
            for line in file["lines"]:
                f.write("DA:%s,%s\n" % (line["line_number"], line["count"]))
                line_miss += int(not line["count"] == 0)
            f.write("LF:%s\n" % len(file["lines"]))
            f.write("LH:%s\n" % (len(file["lines"]) - line_miss))
            f.write("end_of_record\n")

def dumpToGcovJson(intermediate, output):
    with open(output, "w") as f:
        json.dump(intermediate, f)

def log(line):
    if not args.quiet:
        print(line)

def main(args):
    # Need at least gcov 9.0.0 because that's when gcov JSON and stdout streaming was introduced
    current_gcov_version = getGcovVersion(args.gcov)
    if current_gcov_version < MINIMUM_GCOV:
        sys.stderr.write("Minimum gcov version {} required, found {}\n".format(".".join(map(str, MINIMUM_GCOV)), ".".join(map(str, current_gcov_version))))
        exit(1)

    gcda_files = getGcdaFiles(args.directory, args.gcda_files)
    log("%d .gcda files" % len(gcda_files))

    if args.excludepre:
        gcda_files = getFilteredGcdaFiles(gcda_files, args.excludepre)
        log("%d .gcda files after filtering" % len(gcda_files))

    # We "zero" the "counters" by simply deleting all gcda files
    if args.zerocounters:
        removeFiles(gcda_files)
        log("%d .gcda files removed" % len(gcda_files))
        return

    intermediate_json_files = processGcdas(args.cdirectory, args.gcov, args.jobs, gcda_files, args.excludepost)

    gcov_total = sum(GCOVS_TOTAL)
    gcov_skipped = sum(GCOVS_SKIPPED)
    log("%d .gcov files generated by gcov" % gcov_total)
    log("%d .gcov files processed by fastcov (%d skipped)" % (gcov_total - gcov_skipped, gcov_skipped))

    if args.lcov:
        dumpToLcovInfo(args.cdirectory, intermediate_json_files, args.output)
        log("Created lcov info file '%s'" % args.output)
    else:
        dumpToGcovJson(intermediate_json_files, args.output)
        log("Created gcov json file '%s'" % args.output)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A parallel gcov wrapper for fast coverage report generation')
    parser.add_argument('-z', '--zerocounters', dest='zerocounters', action="store_true", help='Recursively delete all gcda files')

    parser.add_argument('-f', '--gcda-files', dest='gcda_files', nargs="+", default=[], help='Specify exactly which gcda files should be processed instead of recursivly searching the search directory.')
    parser.add_argument('-E', '--exclude-gcda', dest='excludepre', nargs="+", default=[], help='.gcda filter - Exclude gcda files from being processed via simple find matching (not regex)')
    parser.add_argument('-e', '--exclude-gcov', dest='excludepost', nargs="+", default=[], help='.gcov filter - Exclude gcov files from being processed via simple find matching (not regex)')

    parser.add_argument('-g', '--gcov', dest='gcov', default='gcov', help='which gcov binary to use')

    parser.add_argument('-d', '--search-directory', dest='directory', default=".", help='Base directory to recursively search for gcda files (default: .)')
    parser.add_argument('-c', '--compiler-directory', dest='cdirectory', default=".", help='Base directory compiler was invoked from (default: .)')
    parser.add_argument('-j', '--jobs', dest='jobs', type=int, default=multiprocessing.cpu_count(), help='Number of parallel gcov to spawn (default: %d).' % multiprocessing.cpu_count())

    parser.add_argument('-o', '--output', dest='output', default="coverage.json", help='Name of output file (default: coverage.json)')
    parser.add_argument('-i', '--lcov', dest='lcov', action="store_true", help='Output in lcov info format instead of gcov json')
    parser.add_argument('-q', '--quiet', dest='quiet', action="store_true", help='Suppress output to stdout')
    args = parser.parse_args()
    main(args)