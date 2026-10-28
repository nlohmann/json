#!/usr/bin/env python3
#     __ _____ _____ _____
#  __|  |   __|     |   | |  JSON for Modern C++ (supporting code)
# |  |  |__   |  |  | | | |  version 3.12.0
# |_____|_____|_____|_|___|  https://github.com/nlohmann/json
#
# SPDX-FileCopyrightText: 2013-2026 Niels Lohmann <https://nlohmann.me>
# SPDX-License-Identifier: MIT

"""Summarize runs of bench_all and bench_rs by use case.

Usage: summarize.py LOG... [--rust LOG...] [--json OUT.json]

Every variant carries a validation level from the malformed-input probes: "full" (rejects truncated input, a stray
comma and invalid UTF-8), "no UTF-8" (accepts only the invalid UTF-8), "partial" (accepts or crashes on a structural
error, or crashes on any probe), or "n/a" (write: no input to validate; counts as full). A variant's level is the
worst it got for any file. Prints, for every use case and file,
  (a) per library the best "full" variant and, if faster, the best variant at any level, with their ratios to the
      best "full" nlohmann json_document variant (variants named "(reused)" keep a parser or document across calls and
      are never chosen as a library's best),
  (b) all variants with their levels and times,
  (c) the variants below "full" with what the probes found, and the variants excluded for wrong results.
--json writes {use case: {file: {library: {"best": {"variant", "us", "level"} or null, "best_any": {...},
"variants": {variant: {"us", "level"}}, "excluded": {variant: reason}}}}} for the chart scripts; variant names there
omit the "<library>: " prefix.

Several logs are combined by taking each cell's best time. A variant excluded for one file (or in one log) is excluded
for every file of that use case. The reference values that bench_all and bench_rs print for sum and select are
compared, so both programs are known to have checked against the same numbers.
"""
import json
import re
import sys

USE_CASES = ["validate", "sum", "select", "edit", "minify", "write"]
DOCS = ["twitter", "citm_catalog", "canada", "jeopardy", "status"]
OURS = "nlohmann json_document"
RANK = {"full": 0, "n/a": 0, "no UTF-8": 1, "partial": 2}
CELL = re.compile(r"^(.+) \[(full|no UTF-8|partial|n/a)\] ([\d.]+)us(?: \(([\d.]+)x\))?$")
REF = re.compile(r"^check (\S+)\s+(\S+)\s+reference: (.*)$")


def library(name):
    return name.split(": ", 1)[0]


def variant(name):
    return name.split(": ", 1)[1] if ": " in name else name


def is_reused(name):
    return "(reused)" in name


def worse(a, b):
    return a if a is not None and (b is None or RANK[a] >= RANK[b]) else b


def parse(path, cells, levels, notes, excluded, refs):
    for line in open(path, encoding="utf-8"):
        line = line.rstrip("\n")
        if line.startswith(("excluded: ", "level: ")):
            kind, rest = line.split(": ", 1)
            fields = rest.split(" | ")
            doc, uc = fields[0].split()
            name = fields[1]
            target = excluded if kind == "excluded" else notes
            for why in fields[-1].split("; "):
                target.setdefault((uc, name), {}).setdefault(why, set()).add(doc)
            if kind == "level":
                levels[(uc, name)] = worse(levels.get((uc, name)), fields[2])
            continue
        m = REF.match(line)
        if m:
            refs.setdefault((m[1], m[2]), {})[path] = m[3]
            continue
        if line.startswith(("check", "done", "WARNING")) or " | " not in line:
            continue
        parts = line.split(" | ")
        head = parts[0].split()
        if len(head) != 2 or head[1] not in USE_CASES:
            continue
        for c in parts[1:]:
            m = CELL.match(c.strip())
            if m:
                key = (head[0], head[1], m[1])
                cells[key] = min(cells.get(key, float("inf")), float(m[3]))
                levels[(head[1], m[1])] = worse(levels.get((head[1], m[1])), m[2])


def check_refs(refs):
    """The sum and select references of all logs must agree (bench_rs prints Rust's float formatting)."""
    def numbers(text):
        return [float(x) for x in re.findall(r"[-+]?\d[\d.]*(?:e[-+]?\d+)?", text)]
    ok = True
    for (doc, uc), by_log in sorted(refs.items()):
        values = {tuple(numbers(t)) for t in by_log.values()}
        if len(values) > 1:
            ok = False
            print("WARNING: the %s %s references differ: %s" % (doc, uc, "; ".join("%s: %s" % kv for kv in by_log.items())))
    return ok


def is_full(level):
    return RANK[level] == 0


def main():
    args = sys.argv[1:]
    out_json = None
    if "--json" in args:
        i = args.index("--json")
        out_json = args[i + 1]
        del args[i:i + 2]
    cpp = args[:args.index("--rust")] if "--rust" in args else args
    rust = args[args.index("--rust") + 1:] if "--rust" in args else []
    if not cpp and not rust:
        sys.exit(__doc__)
    cells, levels, notes, excluded, refs = {}, {}, {}, {}, {}
    for p in cpp + rust:
        parse(p, cells, levels, notes, excluded, refs)
    check_refs(refs)
    result = {}

    def docs_of(uc):
        return [d for d in DOCS if any(k[0] == d and k[1] == uc for k in cells)]

    def cell_of(doc, uc):
        return {n: t for (d, u, n), t in cells.items() if d == doc and u == uc and (uc, n) not in excluded}

    def show(n, t, ours, uc):
        ratio = "%5.2f" % (t / ours) if ours else "    -"
        return "%-40s %-10s %11.1f us %s" % (variant(n), "[%s]" % levels[(uc, n)], t, ratio)

    print("# (a) Per library: the best full variant, and the best at any level if faster (ratio to the best full %s"
          " variant; below 1: faster)" % OURS)
    for uc in USE_CASES:
        if not docs_of(uc):
            continue
        print("\n== " + uc)
        for doc in docs_of(uc):
            cell = cell_of(doc, uc)
            libs = {}
            for n, t in cell.items():
                libs.setdefault(library(n), {})[n] = t
            entry = result.setdefault(uc, {}).setdefault(doc, {})
            rows = []
            for lib, vs in libs.items():
                fresh = {n: t for n, t in vs.items() if not is_reused(n)}
                full = {n: t for n, t in fresh.items() if is_full(levels[(uc, n)])}
                b = min(full.items(), key=lambda x: x[1]) if full else None
                a = min(fresh.items(), key=lambda x: x[1]) if fresh else None
                entry[lib] = {
                    "best": {"variant": variant(b[0]), "us": b[1], "level": levels[(uc, b[0])]} if b else None,
                    "best_any": {"variant": variant(a[0]), "us": a[1], "level": levels[(uc, a[0])]} if a else None,
                    "variants": {variant(n): {"us": t, "level": levels[(uc, n)]} for n, t in sorted(vs.items(), key=lambda x: x[1])},
                }
                rows.append((lib, b, a))
            for (u, n), whys in excluded.items():
                if u == uc:
                    lib = entry.setdefault(library(n), {"best": None, "best_any": None, "variants": {}})
                    lib.setdefault("excluded", {})[variant(n)] = "; ".join(sorted(whys))
            ours = next((b[1] for lib, b, a in rows if lib == OURS and b), None)
            print("%s%s" % (doc, "" if ours else "  (no full %s result)" % OURS))
            rows.sort(key=lambda r: (r[1] is None, r[1][1] if r[1] else r[2][1] if r[2] else 0))
            for lib, b, a in rows:
                line = "    %-24s %s" % (lib, show(*b, ours, uc) if b else "%-40s %-10s %14s %5s" % ("(none)", "", "", ""))
                if a and (not b or a[0] != b[0]):
                    line += "  | faster: %s" % show(*a, ours, uc)
                print(line)

    print("\n# (b) All variants")
    for uc in USE_CASES:
        if not docs_of(uc):
            continue
        print("\n== " + uc)
        for doc in docs_of(uc):
            cell = cell_of(doc, uc)
            ours = min((t for n, t in cell.items() if library(n) == OURS and not is_reused(n) and is_full(levels[(uc, n)])), default=None)
            print(doc)
            for n, t in sorted(cell.items(), key=lambda x: x[1]):
                ratio = "%5.2f" % (t / ours) if ours else "    -"
                print("    %-66s %-10s %11.1f us %s" % (n, "[%s]" % levels[(uc, n)], t, ratio))

    print("\n# (c) Variants below full, and excluded variants")
    for uc in USE_CASES:
        rows = sorted((n, whys) for (u, n), whys in notes.items() if u == uc)
        ex = sorted((n, whys) for (u, n), whys in excluded.items() if u == uc)
        if not rows and not ex:
            continue
        print("\n== " + uc)
        for n, whys in rows:
            for why, docs in sorted(whys.items()):
                print("    %-58s %-10s %s (%s)" % (n, "[%s]" % levels.get((uc, n), "?"), why, ", ".join(d for d in DOCS if d in docs)))
        for n, whys in ex:
            for why, docs in sorted(whys.items()):
                print("    %-58s %-10s %s (%s)" % (n, "excluded", why, ", ".join(d for d in DOCS if d in docs)))

    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
            f.write("\n")


if __name__ == "__main__":
    main()
