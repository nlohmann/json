#!/usr/bin/env python3
#
# ===- check_clang_tidy.py - ClangTidy Test Helper ------------*- python -*--===#
#
# Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
# See https://llvm.org/LICENSE.txt for license information.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#
# ===------------------------------------------------------------------------===#
#
# This file was taken from llvm-project and tweaked very slightly to
# add the ability to load a plugin so that it can be used for testing
# clang-tidy plugins.

"""
ClangTidy Test Helper
=====================

This script is used to simplify writing, running, and debugging tests compatible
with llvm-lit. By default it runs clang-tidy in fix mode and uses FileCheck to
verify messages and/or fixes.

For debugging, with --export-fixes, the tool simply exports fixes to a provided
file and does not run FileCheck.

Extra arguments, those after the first -- if any, are passed to either
clang-tidy or clang:
* Arguments between the first -- and second -- are clang-tidy arguments.
  * May be only whitespace if there are no clang-tidy arguments.
  * clang-tidy's --config would go here.
* Arguments after the second -- are clang arguments

Examples
--------

  // RUN: %check_clang_tidy %s llvm-include-order %t -- -- -isystem %S/Inputs

or

  // RUN: %check_clang_tidy %s llvm-include-order --export-fixes=fixes.yaml %t -std=c++20

Notes
-----
  -std=c++(98|11|14|17|20)-or-later:
    This flag will cause multiple runs within the same check_clang_tidy
    execution. Make sure you don't have shared state across these runs.
"""

import argparse
import os
import pathlib
import re
import subprocess
import sys


def write_file(file_name, text):
    with open(file_name, "w", encoding="utf-8") as f:
        f.write(text)
        f.truncate()


def try_run(args, raise_error=True):
    try:
        process_output = subprocess.check_output(args, stderr=subprocess.STDOUT).decode(
            errors="ignore"
        )
    except subprocess.CalledProcessError as e:
        process_output = e.output.decode(errors="ignore")
        print("%s failed:\n%s" % (" ".join(args), process_output))
        if raise_error:
            raise
    return process_output


# This class represents the appearance of a message prefix in a file.
class MessagePrefix:
    def __init__(self, label):
        self.has_message = False
        self.prefixes = []
        self.label = label

    def check(self, file_check_suffix, input_text):
        self.prefix = self.label + file_check_suffix
        self.has_message = self.prefix in input_text
        if self.has_message:
            self.prefixes.append(self.prefix)
        return self.has_message


class CheckRunner:
    def __init__(self, args, extra_args):
        self.resource_dir = args.resource_dir
        self.assume_file_name = args.assume_filename
        self.input_file_name = args.input_file_name
        self.check_name = args.check_name
        self.temp_file_name = args.temp_file_name
        self.original_file_name = self.temp_file_name + ".orig"
        self.expect_clang_tidy_error = args.expect_clang_tidy_error
        self.std = args.std
        self.plugin = args.plugin
        self.check_suffix = args.check_suffix
        self.input_text = ""
        self.has_check_fixes = False
        self.has_check_messages = False
        self.has_check_notes = False
        self.expect_no_diagnosis = False
        self.export_fixes = args.export_fixes
        self.fixes = MessagePrefix("CHECK-FIXES")
        self.messages = MessagePrefix("CHECK-MESSAGES")
        self.notes = MessagePrefix("CHECK-NOTES")

        file_name_with_extension = self.assume_file_name or self.input_file_name
        _, extension = os.path.splitext(file_name_with_extension)
        if extension not in [".c", ".hpp", ".m", ".mm"]:
            extension = ".cpp"
        self.temp_file_name = self.temp_file_name + extension

        self.clang_extra_args = []
        self.clang_tidy_extra_args = extra_args
        if "--" in extra_args:
            i = self.clang_tidy_extra_args.index("--")
            self.clang_extra_args = self.clang_tidy_extra_args[i + 1 :]
            self.clang_tidy_extra_args = self.clang_tidy_extra_args[:i]

        # If the test does not specify a config style, force an empty one; otherwise
        # auto-detection logic can discover a ".clang-tidy" file that is not related to
        # the test.
        if not any(
            [re.match("^-?-config(-file)?=", arg) for arg in self.clang_tidy_extra_args]
        ):
            self.clang_tidy_extra_args.append("--config={}")

        if extension in [".m", ".mm"]:
            self.clang_extra_args = [
                "-fobjc-abi-version=2",
                "-fobjc-arc",
                "-fblocks",
            ] + self.clang_extra_args

        if extension in [".cpp", ".hpp", ".mm"]:
            self.clang_extra_args.append("-std=" + self.std)

        # Tests should not rely on STL being available, and instead provide mock
        # implementations of relevant APIs.
        self.clang_extra_args.append("-nostdinc++")

        if self.resource_dir is not None:
            self.clang_extra_args.append("-resource-dir=%s" % self.resource_dir)

    def read_input(self):
        with open(self.input_file_name, "r", encoding="utf-8") as input_file:
            self.input_text = input_file.read()

    def get_prefixes(self):
        for suffix in self.check_suffix:
            if suffix and not re.match("^[A-Z0-9\\-]+$", suffix):
                sys.exit(
                    'Only A..Z, 0..9 and "-" are allowed in check suffixes list,'
                    + ' but "%s" was given' % suffix
                )

            file_check_suffix = ("-" + suffix) if suffix else ""

            has_check_fix = self.fixes.check(file_check_suffix, self.input_text)
            self.has_check_fixes = self.has_check_fixes or has_check_fix

            has_check_message = self.messages.check(file_check_suffix, self.input_text)
            self.has_check_messages = self.has_check_messages or has_check_message

            has_check_note = self.notes.check(file_check_suffix, self.input_text)
            self.has_check_notes = self.has_check_notes or has_check_note

            if has_check_note and has_check_message:
                sys.exit(
                    "Please use either %s or %s but not both"
                    % (self.notes.prefix, self.messages.prefix)
                )

            if not has_check_fix and not has_check_message and not has_check_note:
                self.expect_no_diagnosis = True

        expect_diagnosis = (
            self.has_check_fixes or self.has_check_messages or self.has_check_notes
        )
        if self.expect_no_diagnosis and expect_diagnosis:
            sys.exit(
                "%s, %s or %s not found in the input"
                % (
                    self.fixes.prefix,
                    self.messages.prefix,
                    self.notes.prefix,
                )
            )
        assert expect_diagnosis or self.expect_no_diagnosis

    def prepare_test_inputs(self):
        # Remove the contents of the CHECK lines to avoid CHECKs matching on
        # themselves.  We need to keep the comments to preserve line numbers while
        # avoiding empty lines which could potentially trigger formatting-related
        # checks.
        cleaned_test = re.sub("// *CHECK-[A-Z0-9\\-]*:[^\r\n]*", "//", self.input_text)
        write_file(self.temp_file_name, cleaned_test)
        write_file(self.original_file_name, cleaned_test)

    def run_clang_tidy(self):
        args = (
            [
                "clang-tidy",
                self.temp_file_name,
            ]
            + [
                (
                    "-fix"
                    if self.export_fixes is None
                    else "--export-fixes=" + self.export_fixes
                )
            ]
            + ([ "--load=%s" % self.plugin ] if self.plugin else [])
            + [
                "--checks=-*," + self.check_name,
            ]
            + self.clang_tidy_extra_args
            + ["--"]
            + self.clang_extra_args
        )
        if self.expect_clang_tidy_error:
            args.insert(0, "not")
        print("Running " + repr(args) + "...")
        clang_tidy_output = try_run(args)
        print("------------------------ clang-tidy output -----------------------")
        print(
            clang_tidy_output.encode(sys.stdout.encoding, errors="replace").decode(
                sys.stdout.encoding
            )
        )
        print("------------------------------------------------------------------")

        diff_output = try_run(
            ["diff", "-u", self.original_file_name, self.temp_file_name], False
        )
        print("------------------------------ Fixes -----------------------------")
        print(diff_output)
        print("------------------------------------------------------------------")
        return clang_tidy_output

    def check_no_diagnosis(self, clang_tidy_output):
        if clang_tidy_output != "":
            sys.exit("No diagnostics were expected, but found the ones above")

    def check_fixes(self):
        if self.has_check_fixes:
            try_run(
                [
                    "FileCheck",
                    "-input-file=" + self.temp_file_name,
                    self.input_file_name,
                    "-check-prefixes=" + ",".join(self.fixes.prefixes),
                    "-strict-whitespace",
                ]
            )

    def check_messages(self, clang_tidy_output):
        if self.has_check_messages:
            messages_file = self.temp_file_name + ".msg"
            write_file(messages_file, clang_tidy_output)
            try_run(
                [
                    "FileCheck",
                    "-input-file=" + messages_file,
                    self.input_file_name,
                    "-check-prefixes=" + ",".join(self.messages.prefixes),
                    "-implicit-check-not={{warning|error}}:",
                ]
            )

    def check_notes(self, clang_tidy_output):
        if self.has_check_notes:
            notes_file = self.temp_file_name + ".notes"
            filtered_output = [
                line
                for line in clang_tidy_output.splitlines()
                if not ("note: FIX-IT applied" in line)
            ]
            write_file(notes_file, "\n".join(filtered_output))
            try_run(
                [
                    "FileCheck",
                    "-input-file=" + notes_file,
                    self.input_file_name,
                    "-check-prefixes=" + ",".join(self.notes.prefixes),
                    "-implicit-check-not={{note|warning|error}}:",
                ]
            )

    def run(self):
        self.read_input()
        if self.export_fixes is None:
            self.get_prefixes()
        self.prepare_test_inputs()
        clang_tidy_output = self.run_clang_tidy()
        if self.expect_no_diagnosis:
            self.check_no_diagnosis(clang_tidy_output)
        elif self.export_fixes is None:
            self.check_fixes()
            self.check_messages(clang_tidy_output)
            self.check_notes(clang_tidy_output)


CPP_STANDARDS = [
    "c++98",
    "c++11",
    ("c++14", "c++1y"),
    ("c++17", "c++1z"),
    ("c++20", "c++2a"),
    ("c++23", "c++2b"),
    ("c++26", "c++2c"),
]
C_STANDARDS = ["c99", ("c11", "c1x"), "c17", ("c23", "c2x"), "c2y"]


def expand_std(std):
    split_std, or_later, _ = std.partition("-or-later")

    if not or_later:
        return [split_std]

    for standard_list in (CPP_STANDARDS, C_STANDARDS):
        item = next(
            (
                i
                for i, v in enumerate(standard_list)
                if (split_std in v if isinstance(v, (list, tuple)) else split_std == v)
            ),
            None,
        )
        if item is not None:
            return [split_std] + [
                x if isinstance(x, str) else x[0] for x in standard_list[item + 1 :]
            ]
    return [std]


def csv(string):
    return string.split(",")


def parse_arguments():
    parser = argparse.ArgumentParser(
        prog=pathlib.Path(__file__).stem,
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-expect-clang-tidy-error", action="store_true")
    parser.add_argument("-resource-dir")
    parser.add_argument("-assume-filename")
    parser.add_argument("input_file_name")
    parser.add_argument("check_name")
    parser.add_argument("temp_file_name")
    parser.add_argument(
        "-check-suffix",
        "-check-suffixes",
        default=[""],
        type=csv,
        help="comma-separated list of FileCheck suffixes",
    )
    parser.add_argument(
        "-export-fixes",
        default=None,
        type=str,
        metavar="file",
        help="A file to export fixes into instead of fixing.",
    )
    parser.add_argument(
        "-std",
        type=csv,
        default=["c++11-or-later"],
        help="Passed to clang. Special -or-later values are expanded.",
    )
    parser.add_argument(
      "-plugin",
    )
    return parser.parse_known_args()


def main():
    args, extra_args = parse_arguments()

    abbreviated_stds = args.std
    for abbreviated_std in abbreviated_stds:
        for std in expand_std(abbreviated_std):
            args.std = std
            CheckRunner(args, extra_args).run()


if __name__ == "__main__":
    main()
