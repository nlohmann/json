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
        $ ./fastcov.py --exclude /usr/include test/ --lcov -o report.info
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
        gcda_files = glob.glob(os.path.join(os.path.abspath(cwd), "**/*.gcda"), recursive=True)
    return gcda_files

def gcovWorker(cwd, gcov, files, chunk, gcov_filter_options, branch_coverage):
    gcov_args = "-it"
    if branch_coverage:
        gcov_args += "b"

    p = subprocess.Popen([gcov, gcov_args] + chunk, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    for line in iter(p.stdout.readline, b''):
        intermediate_json = json.loads(line.decode(sys.stdout.encoding))
        intermediate_json_files = processGcovs(intermediate_json["files"], gcov_filter_options)
        for f in intermediate_json_files:
            files.append(f) #thread safe, there might be a better way to do this though
        GCOVS_TOTAL.append(len(intermediate_json["files"]))
        GCOVS_SKIPPED.append(len(intermediate_json["files"])-len(intermediate_json_files))
    p.wait()

def processGcdas(cwd, gcov, jobs, gcda_files, gcov_filter_options, branch_coverage):
    chunk_size = max(MINIMUM_CHUNK_SIZE, int(len(gcda_files) / jobs) + 1)

    threads = []
    intermediate_json_files = []
    for chunk in chunks(gcda_files, chunk_size):
        t = threading.Thread(target=gcovWorker, args=(cwd, gcov, intermediate_json_files, chunk, gcov_filter_options, branch_coverage))
        threads.append(t)
        t.start()

    log("Spawned %d gcov processes each processing at most %d gcda files" % (len(threads), chunk_size))
    for t in threads:
        t.join()

    return intermediate_json_files

def processGcov(gcov, files, gcov_filter_options):
    # If explicit sources were passed, check for match
    source_file = os.path.abspath(gcov["file"])
    if gcov_filter_options["sources"]:
        if source_file in gcov_filter_options["sources"]:
            files.append(gcov)
        return

    # Check include filter
    if gcov_filter_options["include"]:
        for ex in gcov_filter_options["include"]:
            if ex in gcov["file"]:
                files.append(gcov)
                break
        return

    # Check exclude filter
    for ex in gcov_filter_options["exclude"]:
        if ex in gcov["file"]:
            return

    files.append(gcov)

def processGcovs(gcov_files, gcov_filter_options):
    files = []
    for gcov in gcov_files:
        processGcov(gcov, files, gcov_filter_options)
    return files

def dumpBranchCoverageToLcovInfo(f, source):
    branch_miss  = 0
    branch_total = 0
    for line in source["lines"]:
        if not line["branches"]:
            continue
        branch_total += len(line["branches"])
        for i, branch in enumerate(line["branches"]):
            #Branch (<line number>, <block number>, <branch number>, <taken>)
            f.write("BRDA:%d,%d,%d,%d\n" % (line["line_number"], int(i/2), i, branch["count"]))
            branch_miss += int(branch["count"] == 0)
    f.write("BRF:%d\n" % branch_total)                 #Branches Found
    f.write("BRH:%d\n" % (branch_total - branch_miss)) #Branches Hit

def dumpToLcovInfo(cwd, intermediate, output, branch_coverage):
    with open(output, "w") as f:
        for source in intermediate:
            #Convert to absolute path so it plays nice with genhtml
            sf = source["file"]
            if not os.path.isabs(source["file"]):
                sf = os.path.abspath(os.path.join(cwd, source["file"]))
            f.write("SF:%s\n" % sf) #Source File

            fn_miss = 0
            for function in source["functions"]:
                f.write("FN:%d,%s\n" % (function["start_line"], function["name"]))          #Function Start Line
                f.write("FNDA:%d,%s\n" % (function["execution_count"], function["name"]))   #Function Hits
                fn_miss += int(function["execution_count"] == 0)
            f.write("FNF:%d\n" % len(source["functions"]))                #Functions Found
            f.write("FNH:%d\n" % (len(source["functions"]) - fn_miss))    #Functions Hit

            if branch_coverage:
                dumpBranchCoverageToLcovInfo(f, source)

            line_miss = 0
            for line in source["lines"]:
                f.write("DA:%d,%d\n" % (line["line_number"], line["count"])) #Line
                line_miss += int(line["count"] == 0)
            f.write("LF:%d\n" % len(source["lines"]))                 #Lines Found
            f.write("LH:%d\n" % (len(source["lines"]) - line_miss))   #Lines Hit
            f.write("end_of_record\n")

def dumpToGcovJson(intermediate, output):
    with open(output, "w") as f:
        json.dump(intermediate, f)

def log(line):
    if not args.quiet:
        print(line)

def getGcovFilterOptions(args):
    return {
        "sources": set([os.path.abspath(s) for s in args.sources]), #Make paths absolute
        "include": args.includepost,
        "exclude": args.excludepost,
    }

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

    gcov_filter_options = getGcovFilterOptions(args)
    intermediate_json_files = processGcdas(args.cdirectory, args.gcov, args.jobs, gcda_files, gcov_filter_options, args.branchcoverage)

    gcov_total = sum(GCOVS_TOTAL)
    gcov_skipped = sum(GCOVS_SKIPPED)
    log("%d .gcov files generated by gcov" % gcov_total)
    log("%d .gcov files processed by fastcov (%d skipped)" % (gcov_total - gcov_skipped, gcov_skipped))

    if args.lcov:
        dumpToLcovInfo(args.cdirectory, intermediate_json_files, args.output, args.branchcoverage)
        log("Created lcov info file '%s'" % args.output)
    else:
        dumpToGcovJson(intermediate_json_files, args.output)
        log("Created gcov json file '%s'" % args.output)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A parallel gcov wrapper for fast coverage report generation')
    parser.add_argument('-z', '--zerocounters', dest='zerocounters', action="store_true", help='Recursively delete all gcda files')

    # Enable Branch Coverage
    parser.add_argument('-b', '--branch-coverage', dest='branchcoverage', action="store_true", help='Include branch counts in the coverage report')

    # Filtering Options
    parser.add_argument('-s', '--source-files', dest='sources',     nargs="+", default=[], help='Filter: Specify exactly which source files should be included in the final report. Paths must be either absolute or relative to current directory.')
    parser.add_argument('-e', '--exclude',      dest='excludepost', nargs="+", default=[], help='Filter: Exclude source files from final report if they contain one of the provided substrings (i.e. /usr/include test/, etc.)')
    parser.add_argument('-i', '--include',      dest='includepost', nargs="+", default=[], help='Filter: Only include source files in final report that contain one of the provided substrings (i.e. src/ etc.)')
    parser.add_argument('-f', '--gcda-files',   dest='gcda_files',  nargs="+", default=[], help='Filter: Specify exactly which gcda files should be processed instead of recursively searching the search directory.')
    parser.add_argument('-E', '--exclude-gcda', dest='excludepre',  nargs="+", default=[], help='Filter: Exclude gcda files from being processed via simple find matching (not regex)')

    parser.add_argument('-g', '--gcov', dest='gcov', default='gcov', help='Which gcov binary to use')

    parser.add_argument('-d', '--search-directory', dest='directory', default=".", help='Base directory to recursively search for gcda files (default: .)')
    parser.add_argument('-c', '--compiler-directory', dest='cdirectory', default=".", help='Base directory compiler was invoked from (default: .)')
    parser.add_argument('-j', '--jobs', dest='jobs', type=int, default=multiprocessing.cpu_count(), help='Number of parallel gcov to spawn (default: %d).' % multiprocessing.cpu_count())

    parser.add_argument('-o', '--output', dest='output', default="coverage.json", help='Name of output file (default: coverage.json)')
    parser.add_argument('-l', '--lcov', dest='lcov', action="store_true", help='Output in lcov info format instead of gcov json')
    parser.add_argument('-q', '--quiet', dest='quiet', action="store_true", help='Suppress output to stdout')
    args = parser.parse_args()
    main(args)