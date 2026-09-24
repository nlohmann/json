#!/usr/bin/env python3
# coding=utf-8

# amalgamate.py - Amalgamate C source and header files.
# Copyright (c) 2012, Erik Edlund <erik.edlund@32767.se>
# 
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
# 
#  * Redistributions of source code must retain the above copyright notice,
#  this list of conditions and the following disclaimer.
# 
#  * Redistributions in binary form must reproduce the above copyright notice,
#  this list of conditions and the following disclaimer in the documentation
#  and/or other materials provided with the distribution.
# 
#  * Neither the name of Erik Edlund, nor the names of its contributors may
#  be used to endorse or promote products derived from this software without
#  specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import datetime
import json
import os
import re


class Amalgamation(object):

    # Prepends self.source_path to file_path if needed.
    def actual_path(self, file_path):
        if not os.path.isabs(file_path):
            file_path = os.path.join(self.source_path, file_path)
        return file_path

    # Search included file_path in self.include_paths and
    # in source_dir if specified.
    def find_included_file(self, file_path, source_dir):
        search_dirs = self.include_paths[:]
        if source_dir:
            search_dirs.insert(0, source_dir)

        for search_dir in search_dirs:
            search_path = os.path.join(search_dir, file_path)
            if os.path.isfile(self.actual_path(search_path)):
                return search_path
        return None

    def __init__(self, args):
        with open(args.config, 'r') as f:
            config = json.loads(f.read())
            for key in config:
                setattr(self, key, config[key])

            self.verbose = args.verbose == "yes"
            self.prologue = args.prologue
            self.source_path = args.source_path
            self.included_files = []

    # Generate the amalgamation and write it to the target file.
    def generate(self):
        amalgamation = ""

        if self.prologue:
            with open(self.prologue, 'r') as f:
                amalgamation += datetime.datetime.now().strftime(f.read())

        if self.verbose:
            print("Config:")
            print(" target        = {0}".format(self.target))
            print(" working_dir   = {0}".format(os.getcwd()))
            print(" include_paths = {0}".format(self.include_paths))
        print("Creating amalgamation:")
        for file_path in self.sources:
            # Do not check the include paths while processing the source
            # list, all given source paths must be correct.
            # actual_path = self.actual_path(file_path)
            print(" - processing \"{0}\"".format(file_path))
            t = TranslationUnit(file_path, self, True)
            amalgamation += t.content

        with open(self.target, 'w') as f:
            f.write(amalgamation)

        print("...done!\n")
        if self.verbose:
            print("Files processed: {0}".format(self.sources))
            print("Files included: {0}".format(self.included_files))
        print("")


def _is_within(match, matches):
    for m in matches:
        if match.start() > m.start() and \
                match.end() < m.end():
            return True
    return False


class TranslationUnit(object):
    # // C++ comment.
    cpp_comment_pattern = re.compile(r"//.*?\n")

    # /* C comment. */
    c_comment_pattern = re.compile(r"/\*.*?\*/", re.S)

    # "complex \"stri\\\ng\" value".
    string_pattern = re.compile("[^']" r'".*?(?<=[^\\])"', re.S)

    # Handle simple include directives. Support for advanced
    # directives where macros and defines needs to expanded is
    # not a concern right now.
    include_pattern = re.compile(
        r'#\s*include\s+(<|")(?P<path>.*?)("|>)', re.S)

    # #pragma once
    pragma_once_pattern = re.compile(r'#\s*pragma\s+once', re.S)

    # Search for pattern in self.content, add the match to
    # contexts if found and update the index accordingly.
    def _search_content(self, index, pattern, contexts):
        match = pattern.search(self.content, index)
        if match:
            contexts.append(match)
            return match.end()
        return index + 2

    # Return all the skippable contexts, i.e., comments and strings
    def _find_skippable_contexts(self):
        # Find contexts in the content in which a found include
        # directive should not be processed.
        skippable_contexts = []

        # Walk through the content char by char, and try to grab
        # skippable contexts using regular expressions when found.
        i = 1
        content_len = len(self.content)
        while i < content_len:
            j = i - 1
            current = self.content[i]
            previous = self.content[j]

            if current == '"':
                # String value.
                i = self._search_content(j, self.string_pattern,
                                         skippable_contexts)
            elif current == '*' and previous == '/':
                # C style comment.
                i = self._search_content(j, self.c_comment_pattern,
                                         skippable_contexts)
            elif current == '/' and previous == '/':
                # C++ style comment.
                i = self._search_content(j, self.cpp_comment_pattern,
                                         skippable_contexts)
            else:
                # Skip to the next char.
                i += 1

        return skippable_contexts

    # Returns True if the match is within list of other matches

    # Removes pragma once from content
    def _process_pragma_once(self):
        content_len = len(self.content)
        if content_len < len("#include <x>"):
            return 0

        # Find contexts in the content in which a found include
        # directive should not be processed.
        skippable_contexts = self._find_skippable_contexts()

        pragmas = []
        pragma_once_match = self.pragma_once_pattern.search(self.content)
        while pragma_once_match:
            if not _is_within(pragma_once_match, skippable_contexts):
                pragmas.append(pragma_once_match)

            pragma_once_match = self.pragma_once_pattern.search(self.content,
                                                                pragma_once_match.end())

        # Handle all collected pragma once directives.
        prev_end = 0
        tmp_content = ''
        for pragma_match in pragmas:
            tmp_content += self.content[prev_end:pragma_match.start()]
            prev_end = pragma_match.end()
        tmp_content += self.content[prev_end:]
        self.content = tmp_content

    # Include all trivial #include directives into self.content.
    def _process_includes(self):
        content_len = len(self.content)
        if content_len < len("#include <x>"):
            return 0

        # Find contexts in the content in which a found include
        # directive should not be processed.
        skippable_contexts = self._find_skippable_contexts()

        # Search for include directives in the content, collect those
        # which should be included into the content.
        includes = []
        include_match = self.include_pattern.search(self.content)
        while include_match:
            if not _is_within(include_match, skippable_contexts):
                include_path = include_match.group("path")
                search_same_dir = include_match.group(1) == '"'
                found_included_path = self.amalgamation.find_included_file(
                    include_path, self.file_dir if search_same_dir else None)
                if found_included_path:
                    includes.append((include_match, found_included_path))

            include_match = self.include_pattern.search(self.content,
                                                        include_match.end())

        # Handle all collected include directives.
        prev_end = 0
        tmp_content = ''
        for include in includes:
            include_match, found_included_path = include
            tmp_content += self.content[prev_end:include_match.start()]
            tmp_content += "// {0}\n".format(include_match.group(0))
            if found_included_path not in self.amalgamation.included_files:
                t = TranslationUnit(found_included_path, self.amalgamation, False)
                tmp_content += t.content
            prev_end = include_match.end()
        tmp_content += self.content[prev_end:]
        self.content = tmp_content

        return len(includes)

    # Make all content processing
    def _process(self):
        if not self.is_root:
            self._process_pragma_once()
        self._process_includes()

    def __init__(self, file_path, amalgamation, is_root):
        self.file_path = file_path
        self.file_dir = os.path.dirname(file_path)
        self.amalgamation = amalgamation
        self.is_root = is_root

        self.amalgamation.included_files.append(self.file_path)

        actual_path = self.amalgamation.actual_path(file_path)
        if not os.path.isfile(actual_path):
            raise IOError("File not found: \"{0}\"".format(file_path))
        with open(actual_path, 'r') as f:
            self.content = f.read()
            self._process()


def main():
    description = "Amalgamate C source and header files."
    usage = " ".join([
        "amalgamate.py",
        "[-v]",
        "-c path/to/config.json",
        "-s path/to/source/dir",
        "[-p path/to/prologue.(c|h)]"
    ])
    argsparser = argparse.ArgumentParser(
        description=description, usage=usage)

    argsparser.add_argument("-v", "--verbose", dest="verbose",
                            choices=["yes", "no"], metavar="", help="be verbose")

    argsparser.add_argument("-c", "--config", dest="config",
                            required=True, metavar="", help="path to a JSON config file")

    argsparser.add_argument("-s", "--source", dest="source_path",
                            required=True, metavar="", help="source code path")

    argsparser.add_argument("-p", "--prologue", dest="prologue",
                            required=False, metavar="", help="path to a C prologue file")

    amalgamation = Amalgamation(argsparser.parse_args())
    amalgamation.generate()


if __name__ == "__main__":
    main()
