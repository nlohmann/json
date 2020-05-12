#! /usr/bin/env python

# This script uploads a directory to Wandbox (http://melpon.org/wandbox),
# which is an online compiler environment, and prints a permalink to the
# uploaded code. We use this to provide a "Try it online" version of the
# library to make the barrier to entry as low as possible.
#
# This script was adapted from the script proposed in
# https://github.com/melpon/wandbox/issues/153.
#
# To know how to use this script: ./wandbox.py --help
#
# Copyright Louis Dionne 2015
# Distributed under the Boost Software License, Version 1.0.
# (See accompanying file LICENSE.md or copy at http://boost.org/LICENSE_1_0.txt)

import argparse
import fnmatch
import json
import os
import re
import urllib2


# Strips C and C++ comments from the given string.
#
# Copied from https://stackoverflow.com/a/241506/627587.
def strip_comments(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " " # note: a space and not an empty string
        else:
            return s
    pattern = re.compile(
        r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"',
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)


# Post the given JSON data to Wandbox's API, and return the result
# as a JSON object.
def upload(options):
    request = urllib2.Request('https://melpon.org/wandbox/api/compile.json')
    request.add_header('Content-Type', 'application/json')
    response = urllib2.urlopen(request, json.dumps(options))
    return json.loads(response.read())


# Returns a list of the '.hpp' headers in the given directory and in
# subdirectories.
#
# The path must be absolute, and the returned paths are all absolute too.
def headers(path):
    return [
        os.path.join(dir, file)
            for (dir, _, files) in os.walk(path)
                for file in fnmatch.filter(files, "*.hpp")
    ]


def main():
    parser = argparse.ArgumentParser(description=
        """Upload a directory to Wandbox (http://melpon.org/wandbox).

           On success, the program prints a permalink to the uploaded
           directory on Wandbox and returns 0. On error, it prints the
           response from the Wandbox API and returns 1.

           Note that the comments are stripped from all the headers in the
           uploaded directory.
        """
    )
    parser.add_argument('directory', type=str, help=
        """A directory to upload to Wandbox.

           The path may be either absolute or relative to the current directory.
           However, the names of the files uploaded to Wandbox will all be
           relative to this directory. This way, one can easily specify the
           directory to be '/some/project/include', and the uploaded files
           will be uploaded as-if they were rooted at '/some/project/include'
        """)
    parser.add_argument('main', type=str, help=
        """The main source file.

           The path may be either absolute or relative to the current directory.
        """
    )
    args = parser.parse_args()
    directory = os.path.abspath(args.directory)
    if not os.path.exists(directory):
        raise Exception("'%s' is not a valid directory" % args.directory)

    cpp = os.path.abspath(args.main)
    if not os.path.exists(cpp):
        raise Exception("'%s' is not a valid file name" % args.main)

    response = upload({
        'code': open(cpp).read(),
        'codes': [{
            'file': os.path.relpath(header, directory),
            #'code': strip_comments(open(header).read())
            'code': open(header).read()
        } for header in headers(directory)],
        'options': 'boost-nothing,c++11',
        'compiler': 'gcc-4.9.2',
        'save': True,
        'compiler-option-raw': '-I.'
    })

    if 'status' in response and response['status'] == '0':
        print response['url']
        return 0
    else:
        print response
        return 1


exit(main())
