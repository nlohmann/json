#!/usr/bin/env python
"""
compare_bench.py - Compare two benchmarks or their results and report the
                   difference.
"""
import argparse
from argparse import ArgumentParser
import sys
import gbench
from gbench import util, report
from gbench.util import *

def check_inputs(in1, in2, flags):
    """
    Perform checking on the user provided inputs and diagnose any abnormalities
    """
    in1_kind, in1_err = classify_input_file(in1)
    in2_kind, in2_err = classify_input_file(in2)
    output_file = find_benchmark_flag('--benchmark_out=', flags)
    output_type = find_benchmark_flag('--benchmark_out_format=', flags)
    if in1_kind == IT_Executable and in2_kind == IT_Executable and output_file:
        print(("WARNING: '--benchmark_out=%s' will be passed to both "
              "benchmarks causing it to be overwritten") % output_file)
    if in1_kind == IT_JSON and in2_kind == IT_JSON and len(flags) > 0:
        print("WARNING: passing --benchmark flags has no effect since both "
              "inputs are JSON")
    if output_type is not None and output_type != 'json':
        print(("ERROR: passing '--benchmark_out_format=%s' to 'compare_bench.py`"
              " is not supported.") % output_type)
        sys.exit(1)


def main():
    parser = ArgumentParser(
        description='compare the results of two benchmarks')
    parser.add_argument(
        'test1', metavar='test1', type=str, nargs=1,
        help='A benchmark executable or JSON output file')
    parser.add_argument(
        'test2', metavar='test2', type=str, nargs=1,
        help='A benchmark executable or JSON output file')
    parser.add_argument(
        'benchmark_options', metavar='benchmark_options', nargs=argparse.REMAINDER,
        help='Arguments to pass when running benchmark executables'
    )
    args, unknown_args = parser.parse_known_args()
    # Parse the command line flags
    test1 = args.test1[0]
    test2 = args.test2[0]
    if unknown_args:
        # should never happen
        print("Unrecognized positional argument arguments: '%s'"
              % unknown_args)
        exit(1)
    benchmark_options = args.benchmark_options
    check_inputs(test1, test2, benchmark_options)
    # Run the benchmarks and report the results
    json1 = gbench.util.run_or_load_benchmark(test1, benchmark_options)
    json2 = gbench.util.run_or_load_benchmark(test2, benchmark_options)
    output_lines = gbench.report.generate_difference_report(json1, json2)
    print('Comparing %s to %s' % (test1, test2))
    for ln in output_lines:
        print(ln)


if __name__ == '__main__':
    main()
