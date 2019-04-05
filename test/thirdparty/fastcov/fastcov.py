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
import time
import argparse
import threading
import subprocess
import multiprocessing

MINIMUM_GCOV = (9,0,0)
MINIMUM_CHUNK_SIZE = 5

# Interesting metrics
START_TIME = time.time()
GCOVS_TOTAL = []
GCOVS_SKIPPED = []

def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

def stopwatch():
    """Return number of seconds since last time this was called"""
    global START_TIME
    end_time   = time.time()
    delta      = end_time - START_TIME
    START_TIME = end_time
    return delta

def parseVersionFromLine(version_str):
    """Given a string containing a dotted integer version, parse out integers and return as tuple"""
    version = re.search(r'(\d+\.\d+\.\d+)[^\.]', version_str)

    if not version:
        return (0,0,0)

    return tuple(map(int, version.group(1).split(".")))

def getGcovVersion(gcov):
    p = subprocess.Popen([gcov, "-v"], stdout=subprocess.PIPE)
    output = p.communicate()[0].decode('UTF-8')
    p.wait()
    return parseVersionFromLine(output.split("\n")[0])

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
        intermediate_json_files = processGcovs(cwd, intermediate_json["files"], gcov_filter_options)
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

    log("Spawned %d gcov threads, each processing at most %d gcda files" % (len(threads), chunk_size))
    for t in threads:
        t.join()

    return intermediate_json_files

def processGcov(cwd, gcov, files, gcov_filter_options):
    # Add absolute path
    gcov["file_abs"] = os.path.abspath(os.path.join(cwd, gcov["file"]))

    # If explicit sources were passed, check for match
    if gcov_filter_options["sources"]:
        if gcov["file_abs"] in gcov_filter_options["sources"]:
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

def processGcovs(cwd, gcov_files, gcov_filter_options):
    files = []
    for gcov in gcov_files:
        processGcov(cwd, gcov, files, gcov_filter_options)
    return files

def dumpBranchCoverageToLcovInfo(f, branches):
    branch_miss  = 0
    for line_num, branch_counts in branches.items():
        for i, count in enumerate(branch_counts):
            #Branch (<line number>, <block number>, <branch number>, <taken>)
            f.write("BRDA:%s,%d,%d,%d\n" % (line_num, int(i/2), i, count))
            branch_miss += int(count == 0)
    f.write("BRF:%d\n" % len(branches))                 #Branches Found
    f.write("BRH:%d\n" % (len(branches) - branch_miss)) #Branches Hit

def dumpToLcovInfo(fastcov_json, output):
    with open(output, "w") as f:
        for sf, data in fastcov_json["sources"].items():
            f.write("SF:%s\n" % sf) #Source File

            fn_miss = 0
            for function, fdata in data["functions"].items():
                f.write("FN:%d,%s\n" % (fdata["start_line"], function))          #Function Start Line
                f.write("FNDA:%d,%s\n" % (fdata["execution_count"], function))   #Function Hits
                fn_miss += int(fdata["execution_count"] == 0)
            f.write("FNF:%d\n" % len(data["functions"]))                #Functions Found
            f.write("FNH:%d\n" % (len(data["functions"]) - fn_miss))    #Functions Hit

            if data["branches"]:
                dumpBranchCoverageToLcovInfo(f, data["branches"])

            line_miss = 0
            for line_num, count in data["lines"].items():
                f.write("DA:%s,%d\n" % (line_num, count)) #Line
                line_miss += int(count == 0)
            f.write("LF:%d\n" % len(data["lines"]))                 #Lines Found
            f.write("LH:%d\n" % (len(data["lines"]) - line_miss))   #Lines Hit
            f.write("end_of_record\n")

def exclMarkerWorker(fastcov_sources, chunk):
    for source in chunk:
        # If there are no covered lines, skip
        if not fastcov_sources[source]["lines"]:
            continue

        start_line = 0
        end_line = 0
        with open(source) as f:
            for i, line in enumerate(f, 1): #Start enumeration at line 1
                if not "LCOV_EXCL" in line:
                    continue

                if "LCOV_EXCL_LINE" in line:
                    if str(i) in fastcov_sources[source]["lines"]:
                        del fastcov_sources[source]["lines"][str(i)]
                    if str(i) in fastcov_sources[source]["branches"]:
                        del fastcov_sources[source]["branches"][str(i)]
                elif "LCOV_EXCL_START" in line:
                    start_line = i
                elif "LCOV_EXCL_STOP" in line:
                    end_line = i

                    if not start_line:
                        end_line = 0
                        continue

                    for key in ["lines", "branches"]:
                        for line_num in list(fastcov_sources[source][key].keys()):
                            if int(line_num) <= end_line and int(line_num) >= start_line:
                                del fastcov_sources[source][key][line_num]

                    start_line = end_line = 0

def scanExclusionMarkers(fastcov_json, jobs):
    chunk_size = max(MINIMUM_CHUNK_SIZE, int(len(fastcov_json["sources"]) / jobs) + 1)

    threads = []
    for chunk in chunks(list(fastcov_json["sources"].keys()), chunk_size):
        t = threading.Thread(target=exclMarkerWorker, args=(fastcov_json["sources"], chunk))
        threads.append(t)
        t.start()

    log("Spawned %d threads each scanning at most %d source files" % (len(threads), chunk_size))
    for t in threads:
        t.join()

def distillFunction(function_raw, functions):
    function_name = function_raw["name"]
    if function_name not in functions:
        functions[function_name] = {
            "start_line": function_raw["start_line"],
            "execution_count": function_raw["execution_count"]
        }
    else:
        functions[function_name]["execution_count"] += function_raw["execution_count"]

def distillLine(line_raw, lines, branches):
    line_number = str(line_raw["line_number"])
    if line_number not in lines:
        lines[line_number] = line_raw["count"]
    else:
        lines[line_number] += line_raw["count"]

    for i, branch in enumerate(line_raw["branches"]):
        if line_number not in branches:
            branches[line_number] = []
        blen = len(branches[line_number])
        glen = len(line_raw["branches"])
        if blen < glen:
            branches[line_number] += [0] * (glen - blen)
        branches[line_number][i] += branch["count"]

def distillSource(source_raw, sources):
    source_name = source_raw["file_abs"]
    if source_name not in sources:
        sources[source_name] = {
            "functions": {},
            "branches": {},
            "lines": {},
        }

    for function in source_raw["functions"]:
        distillFunction(function, sources[source_name]["functions"])

    for line in source_raw["lines"]:
        distillLine(line, sources[source_name]["lines"], sources[source_name]["branches"])

def distillReport(report_raw):
    report_json = {
        "sources": {}
    }

    for source in report_raw:
        distillSource(source, report_json["sources"])

    return report_json

def dumpToJson(intermediate, output):
    with open(output, "w") as f:
        json.dump(intermediate, f)

def log(line):
    if not args.quiet:
        print("[{:.3f}s] {}".format(stopwatch(), line))

def getGcovFilterOptions(args):
    return {
        "sources": set([os.path.abspath(s) for s in args.sources]), #Make paths absolute, use set for fast lookups
        "include": args.includepost,
        "exclude": args.excludepost,
    }

def main(args):
    # Need at least gcov 9.0.0 because that's when gcov JSON and stdout streaming was introduced
    current_gcov_version = getGcovVersion(args.gcov)
    if current_gcov_version < MINIMUM_GCOV:
        sys.stderr.write("Minimum gcov version {} required, found {}\n".format(".".join(map(str, MINIMUM_GCOV)), ".".join(map(str, current_gcov_version))))
        exit(1)

    # Get list of gcda files to process
    gcda_files = getGcdaFiles(args.directory, args.gcda_files)
    log("Found {} .gcda files ".format(len(gcda_files)))

    # If gcda filtering is enabled, filter them out now
    if args.excludepre:
        gcda_files = getFilteredGcdaFiles(gcda_files, args.excludepre)
        log("{} .gcda files after filtering".format(len(gcda_files)))

    # We "zero" the "counters" by simply deleting all gcda files
    if args.zerocounters:
        removeFiles(gcda_files)
        log("{} .gcda files removed".format(len(gcda_files)))
        return

    # Fire up one gcov per cpu and start processing gcdas
    gcov_filter_options = getGcovFilterOptions(args)
    intermediate_json_files = processGcdas(args.cdirectory, args.gcov, args.jobs, gcda_files, gcov_filter_options, args.branchcoverage)

    # Summarize processing results
    gcov_total = sum(GCOVS_TOTAL)
    gcov_skipped = sum(GCOVS_SKIPPED)
    log("Processed {} .gcov files ({} total, {} skipped)".format(gcov_total - gcov_skipped, gcov_total, gcov_skipped))

    # Distill all the extraneous info gcov gives us down to the core report
    fastcov_json = distillReport(intermediate_json_files)
    log("Aggregated raw gcov JSON into fastcov JSON report")

    # Dump to desired file format
    if args.lcov:
        scanExclusionMarkers(fastcov_json, args.jobs)
        log("Scanned {} source files for exclusion markers".format(len(fastcov_json["sources"])))
        dumpToLcovInfo(fastcov_json, args.output)
        log("Created lcov info file '{}'".format(args.output))
    elif args.gcov_raw:
        dumpToJson(intermediate_json_files, args.output)
        log("Created gcov raw json file '{}'".format(args.output))
    else:
        dumpToJson(fastcov_json, args.output)
        log("Created fastcov json file '{}'".format(args.output))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='A parallel gcov wrapper for fast coverage report generation')
    parser.add_argument('-z', '--zerocounters', dest='zerocounters', action="store_true", help='Recursively delete all gcda files')

    # Enable Branch Coverage
    parser.add_argument('-b', '--branch-coverage', dest='branchcoverage', action="store_true", help='Include branch counts in the coverage report')

    # Filtering Options
    parser.add_argument('-s', '--source-files', dest='sources',     nargs="+", metavar='', default=[], help='Filter: Specify exactly which source files should be included in the final report. Paths must be either absolute or relative to current directory.')
    parser.add_argument('-e', '--exclude',      dest='excludepost', nargs="+", metavar='', default=[], help='Filter: Exclude source files from final report if they contain one of the provided substrings (i.e. /usr/include test/, etc.)')
    parser.add_argument('-i', '--include',      dest='includepost', nargs="+", metavar='', default=[], help='Filter: Only include source files in final report that contain one of the provided substrings (i.e. src/ etc.)')
    parser.add_argument('-f', '--gcda-files',   dest='gcda_files',  nargs="+", metavar='', default=[], help='Filter: Specify exactly which gcda files should be processed instead of recursively searching the search directory.')
    parser.add_argument('-E', '--exclude-gcda', dest='excludepre',  nargs="+", metavar='', default=[], help='Filter: Exclude gcda files from being processed via simple find matching (not regex)')

    parser.add_argument('-g', '--gcov', dest='gcov', default='gcov', help='Which gcov binary to use')

    parser.add_argument('-d', '--search-directory', dest='directory', default=".", help='Base directory to recursively search for gcda files (default: .)')
    parser.add_argument('-c', '--compiler-directory', dest='cdirectory', default=".", help='Base directory compiler was invoked from (default: .) \
                                                                                            This needs to be set if invoking fastcov from somewhere other than the base compiler directory.')

    parser.add_argument('-j', '--jobs', dest='jobs', type=int, default=multiprocessing.cpu_count(), help='Number of parallel gcov to spawn (default: %d).' % multiprocessing.cpu_count())
    parser.add_argument('-m', '--minimum-chunk-size', dest='minimum_chunk', type=int, default=5, help='Minimum number of files a thread should process (default: 5). \
                                                                                                       If you have only 4 gcda files but they are monstrously huge, you could change this value to a 1 so that each thread will only process 1 gcda. Otherise fastcov will spawn only 1 thread to process all of them.')

    parser.add_argument('-l', '--lcov',     dest='lcov',     action="store_true", help='Output in lcov info format instead of fastcov json')
    parser.add_argument('-r', '--gcov-raw', dest='gcov_raw', action="store_true", help='Output in gcov raw json instead of fastcov json')
    parser.add_argument('-o', '--output',  dest='output', default="coverage.json", help='Name of output file (default: coverage.json)')
    parser.add_argument('-q', '--quiet', dest='quiet', action="store_true", help='Suppress output to stdout')

    args = parser.parse_args()
    main(args)