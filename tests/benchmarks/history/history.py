#!/usr/bin/env python3
#     __ _____ _____ _____
#  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
# |  |  |__   |  |  | | | |  version 3.12.0
# |_____|_____|_____|_|___|  https://github.com/nlohmann/json
#
# SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
# SPDX-License-Identifier: MIT

"""Time one fixed benchmark against the json.hpp of every commit that changed it.

Usage:
  history.py build     --repo REPO --work DIR [--from v3.12.0] [--to origin/develop] [--extra INCLUDE_DIR]
  history.py run       --work DIR [--rounds 4]
  history.py summarize --work DIR [--repo REPO] > history.csv

build: lists the first-parent commits between --from and --to that changed single_include/nlohmann/json.hpp or
json_view.hpp, extracts single_include/ of each (and of --from itself), and compiles history.cpp against it into
DIR/bin/NNN, NNN being the line of the commit in DIR/commits.txt. --extra adds one more header directory at the end,
for example an amalgamation of develop with open pull requests merged in. It also writes the input files to DIR/data
(the nativejson-benchmark files from the test data, which must be in DIR/data already, plus a minified copy of
citm_catalog.json).

run: runs every binary once per round, in a new random order each round, and only while the 1-minute load average is
below 4. Output: DIR/res/NNN-R.txt.

summarize: the median over the rounds per binary and workload, as CSV with the commit, its date and its pull request.

Only the Python 3 standard library is used; a C++17 compiler (c++) and git are needed.
"""
import argparse
import concurrent.futures
import csv
import json
import os
import random
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
FLAGS = ["-std=c++17", "-O3", "-DNDEBUG", "-w"]


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


def build_one(work, idx, rev, repo):
    hdr = work / "hdr" / idx
    hdr.mkdir(parents=True, exist_ok=True)
    if rev.startswith("dir:"):
        subprocess.run(["cp", "-R", rev[4:] + "/nlohmann", str(hdr)], check=True)
    else:
        archive = subprocess.run(["git", "-C", str(repo), "archive", rev, "single_include/nlohmann"],
                                 check=True, capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", str(hdr), "--strip-components=1"], input=archive, check=True)
    out = work / "bin" / idx
    cmd = ["c++", *FLAGS, "-I", str(hdr), str(HERE / "history.cpp"), "-o", str(out)]
    # json_view.hpp of the first commits that had it may not compile with history.cpp: time json.hpp alone then
    if subprocess.run(cmd, capture_output=True).returncode != 0:
        if subprocess.run(cmd[:-4] + ["-DHISTORY_NO_VIEW"] + cmd[-4:], capture_output=True).returncode != 0:
            return "FAIL %s %s" % (idx, rev)
    return None


def build(a):
    work, repo = Path(a.work), Path(a.repo)
    (work / "bin").mkdir(parents=True, exist_ok=True)
    revs = [a.__dict__["from"]] + git(repo, "log", "--first-parent", "--reverse", "--format=%H",
                                      "%s..%s" % (a.__dict__["from"], a.to), "--",
                                      "single_include/nlohmann/json.hpp", "single_include/nlohmann/json_view.hpp").split()
    if a.extra:
        revs.append("dir:" + str(Path(a.extra).resolve()))
    (work / "commits.txt").write_text("\n".join(revs) + "\n")
    data = work / "data"
    citm = json.loads((data / "citm_catalog.json").read_text(encoding="utf-8"))
    (data / "citm_compact.json").write_text(json.dumps(citm, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as ex:
        for r in ex.map(lambda p: build_one(work, "%03d" % p[0], p[1], repo), enumerate(revs)):
            if r:
                print(r, file=sys.stderr)


def load():
    out = subprocess.run(["sysctl", "-n", "vm.loadavg"], capture_output=True, text=True).stdout
    return float(out.split()[1]) if out else os.getloadavg()[0]


def run(a):
    work = Path(a.work)
    (work / "res").mkdir(exist_ok=True)
    bins = sorted(p.name for p in (work / "bin").iterdir())
    for r in range(1, a.rounds + 1):
        random.shuffle(bins)
        for b in bins:
            while load() >= 4:
                time.sleep(15)
            out = subprocess.run([str(work / "bin" / b), str(work / "data")], check=True, capture_output=True, text=True)
            (work / "res" / ("%s-%d.txt" % (b, r))).write_text(out.stdout)
        print("round %d done" % r, file=sys.stderr)


def summarize(a):
    work = Path(a.work)
    revs = (work / "commits.txt").read_text().split()
    times, names = {}, []
    for f in sorted((work / "res").glob("*.txt")):
        idx = int(f.name.split("-")[0])
        for line in f.read_text().splitlines():
            name, us = line.split()
            if name not in names:
                names.append(name)
            times.setdefault((idx, name), []).append(float(us))
    w = csv.writer(sys.stdout, lineterminator="\n")
    w.writerow(["index", "commit", "date", "pr", "subject"] + names)
    for idx, rev in enumerate(revs):
        if rev.startswith("dir:"):
            sha, date, pr, subject = "candidate", "", "", "develop + open pull requests"
        else:
            sha, date, subject = git(a.repo, "log", "-1", "--format=%h%x09%cs%x09%s", rev).strip().split("\t")
            m = re.search(r"\(#(\d+)\)$", subject)
            pr = m.group(1) if m else ""
        w.writerow([idx, sha, date, pr, subject] +
                   ["%.3f" % statistics.median(times[(idx, n)]) if (idx, n) in times else "" for n in names])


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--repo", required=True)
    b.add_argument("--work", required=True)
    b.add_argument("--from", default="v3.12.0")
    b.add_argument("--to", default="origin/develop")
    b.add_argument("--extra")
    r = sub.add_parser("run")
    r.add_argument("--work", required=True)
    r.add_argument("--rounds", type=int, default=4)
    s = sub.add_parser("summarize")
    s.add_argument("--work", required=True)
    s.add_argument("--repo", default=str(HERE.parents[2]))
    a = p.parse_args()
    {"build": build, "run": run, "summarize": summarize}[a.cmd](a)


if __name__ == "__main__":
    main()
