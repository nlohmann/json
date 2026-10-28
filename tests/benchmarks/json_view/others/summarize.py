#!/usr/bin/env python3
#     __ _____ _____ _____
#  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
# |  |  |__   |  |  | | | |  version 3.12.0
# |_____|_____|_____|_|___|  https://github.com/nlohmann/json
#
# SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
# SPDX-License-Identifier: MIT

"""Summarize runs of bench_all and bench_rs: for every document and workload, the engines ordered by time, and the
fastest other engine relative to json_document (above 1: json_document is ahead).

Usage: summarize.py LOG... [--rust LOG...]

Several logs of the same program are combined by taking each cell's best time. Fresh documents are compared with
fresh ones: "json_view (reused)" and "simdjson DOM" (a reused parser) are left out of the "fastest other" column
and compared with each other instead.
"""
import re
import sys

REUSED = {"json_view (reused)", "simdjson DOM"}
DOCS = ["twitter", "citm_catalog", "canada", "jeopardy", "status"]
WORKLOADS = ["parse", "traverse", "select", "parse+dump"]


def parse(path, suffix=""):
    cells = {}
    for line in open(path):
        if line.startswith(("check", "info", "WARNING")):
            continue
        m = re.match(r"(\S+)\s+(\S+)\s+(.*)", line)
        if not m:
            continue
        for engine, us in re.findall(r"\s*(.+?) ([\d.]+)us(?: \([\d.]+x\))?", m[3]):
            cells[(m[1], m[2], engine.strip() + suffix)] = float(us)
    return cells


def best(paths, suffix=""):
    runs = [parse(p, suffix) for p in paths]
    keys = set(runs[0]).intersection(*runs[1:])
    return {k: min(r[k] for r in runs) for k in keys}


def main():
    args = sys.argv[1:]
    cpp = args[:args.index("--rust")] if "--rust" in args else args
    rust = args[args.index("--rust") + 1:] if "--rust" in args else []
    cells = best(cpp)
    if rust:
        cells.update(best(rust, " (Rust)"))
    for wl in WORKLOADS:
        print("\n== " + wl)
        for doc in DOCS:
            cell = {e: v for (d, w, e), v in cells.items() if d == doc and w == wl}
            if "json_view" not in cell:
                continue
            jv = cell["json_view"]
            order = sorted(cell.items(), key=lambda x: x[1])
            fresh = {e: v for e, v in cell.items() if e not in REUSED and e != "json_view"}
            other, t = min(fresh.items(), key=lambda x: x[1])
            line = "%-13s json_view %10.1f us  fastest other: %s %.2f" % (doc, jv, other, t / jv)
            if "json_view (reused)" in cell and "simdjson DOM" in cell:
                line += "  | reused: simdjson DOM %.2f" % (cell["simdjson DOM"] / cell["json_view (reused)"])
            print(line)
            print("    " + ", ".join("%s %.2f" % (e, v / jv) for e, v in order))


if __name__ == "__main__":
    main()
