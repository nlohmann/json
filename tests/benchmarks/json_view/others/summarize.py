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
      best "full" nlohmann json_document variant (variants named "(reused)" or "(reused allocator)" keep a parser,
      document or allocator across calls and are never chosen as a library's best; neither are "(copy untimed)"
      variants, which copy their input before the timer starts), and in a "reused:" line the library's best reused
      variant in the same way,
  (b) all variants with their levels and times,
  (c) the variants below "full" with what the probes found, and the variants excluded for wrong results.
--json writes {use case: {file: {library: {"best": {"variant", "us", "level"} or null, "best_any": {...},
"best_reused": {...} or null, "best_reused_any": {...} or null, "variants": {variant: {"us", "level"}}, "excluded":
{variant: reason}}}}} for the chart scripts ("best_reused" is the best full reused variant, "best_reused_any" the best
reused variant at any level); variant names there omit the "<library>: " prefix.

Several logs are combined by taking each cell's best time. A variant excluded for one file (or in one log) is excluded
for every file of that use case. The reference values that bench_all and bench_rs print for sum and select are
compared, so both programs are known to have checked against the same numbers.
"""
import json
import re
import sys

USE_CASES = ["validate", "sum", "select", "edit", "minify", "write"]
DOCS = ["twitter", "citm_catalog", "canada", "jeopardy", "status", "twitter_min", "citm_catalog_min"]
OURS = "nlohmann json_document"
RANK = {"full": 0, "n/a": 0, "no UTF-8": 1, "partial": 2}
CELL = re.compile(r"^(.+) \[(full|no UTF-8|partial|n/a)\] ([\d.]+)us(?: \(([\d.]+)x\))?$")
REF = re.compile(r"^check (\S+)\s+(\S+)\s+reference: (.*)$")


def library(name):
    return name.split(": ", 1)[0]


def variant(name):
    return name.split(": ", 1)[1] if ": " in name else name


def is_reused(name):
    return re.search(r"\(reused[ )]", name) is not None


def is_untimed_copy(name):
    return "(copy untimed)" in name


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
                if head[0] not in DOCS:   # bench_all --files: the documents are the files of a directory
                    DOCS.append(head[0])
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
            def pick(vs):
                """the best full variant and the best variant at any level"""
                full = {n: t for n, t in vs.items() if is_full(levels[(uc, n)])}
                return (min(full.items(), key=lambda x: x[1]) if full else None,
                        min(vs.items(), key=lambda x: x[1]) if vs else None)

            def described(x):
                return {"variant": variant(x[0]), "us": x[1], "level": levels[(uc, x[0])]} if x else None

            for lib, vs in libs.items():
                b, a = pick({n: t for n, t in vs.items() if not is_reused(n) and not is_untimed_copy(n)})
                rb, ra = pick({n: t for n, t in vs.items() if is_reused(n)})
                entry[lib] = {
                    "best": described(b),
                    "best_any": described(a),
                    "best_reused": described(rb),
                    "best_reused_any": described(ra),
                    "variants": {variant(n): {"us": t, "level": levels[(uc, n)]} for n, t in sorted(vs.items(), key=lambda x: x[1])},
                }
                rows.append((lib, b, a, rb, ra))
            for (u, n), whys in excluded.items():
                if u == uc:
                    lib = entry.setdefault(library(n), {"best": None, "best_any": None, "best_reused": None, "best_reused_any": None, "variants": {}})
                    lib.setdefault("excluded", {})[variant(n)] = "; ".join(sorted(whys))
            ours = next((b[1] for lib, b, a, rb, ra in rows if lib == OURS and b), None)
            print("%s%s" % (doc, "" if ours else "  (no full %s result)" % OURS))
            rows.sort(key=lambda r: (r[1] is None, r[1][1] if r[1] else r[2][1] if r[2] else 0))
            for lib, b, a, rb, ra in rows:
                line = "    %-24s %s" % (lib, show(*b, ours, uc) if b else "%-40s %-10s %14s %5s" % ("(none)", "", "", ""))
                if a and (not b or a[0] != b[0]):
                    line += "  | faster: %s" % show(*a, ours, uc)
                print(line)
                if ra:
                    line = "      %-22s %s" % ("reused:", show(*rb, ours, uc) if rb else "%-40s %-10s %14s %5s" % ("(none)", "", "", ""))
                    if not rb or ra[0] != rb[0]:
                        line += "  | faster: %s" % show(*ra, ours, uc)
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
