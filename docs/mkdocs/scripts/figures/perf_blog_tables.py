"""Prints the tables of Appendix E of home/blog/how_3_13_0_got_faster.md (comparison with other libraries) as Markdown,
from data/perf_usecases_<platform>.json, which tests/benchmarks/json_view/others/summarize.py --json writes.

Usage: python3 scripts/figures/perf_blog_tables.py <platform> [title]
"""
import json
import sys
from pathlib import Path

from perf_blog import normalize_usecases

HERE = Path(__file__).resolve().parent
FILES = [("twitter", "`twitter.json`"), ("citm_catalog", "`citm_catalog.json`"), ("canada", "`canada.json`"),
         ("jeopardy", "`jeopardy.json`"), ("status", "one status (2.5 KB)")]
USE_CASES = [("validate", "validate"), ("sum", "sum"), ("select", "select"), ("edit", "edit"), ("minify", "minify"),
             ("write", "write")]
NAMES = {"nlohmann json_document": "nlohmann/json `json_document`", "nlohmann json": "nlohmann/json `json`",
         "sonic-rs": "sonic-rs (Rust)", "simd-json": "simd-json (Rust)", "serde_json": "serde_json (Rust)"}


def fmt(us):
    if us >= 10000:
        return "{:,.0f}".format(us)
    if us >= 100:
        return "{:,.0f}".format(us)
    return "%.1f" % us


def table(data, uc, indent):
    files = [f for f, _ in FILES if f in data.get(uc, {})]
    libs = list(data[uc][files[0]].keys())
    jd = lambda f: data[uc][f]["nlohmann json_document"]["best"]["us"]
    libs.sort(key=lambda l: sum(((data[uc][f][l]["best"] or data[uc][f][l]["best_any"])["us"] / jd(f)) for f in files))
    head = "| library | variant | " + " | ".join(n for f, n in FILES if f in files) + " |"
    rows = [head, "| --- | --- | " + " | ".join("--:" for _ in files) + " |"]
    for lib in libs:
        best = [data[uc][f][lib]["best"] for f in files]
        anyv = [data[uc][f][lib]["best_any"] for f in files]
        names = sorted({b["variant"] for b in best if b} | {a["variant"] + " [%s]" % a["mark"] for b, a in zip(best, anyv) if a["mark"] and (not b or a["us"] < b["us"])})
        cells = []
        for b, a in zip(best, anyv):
            c = fmt(b["us"]) if b else "–"
            if a["mark"] and (not b or a["us"] < b["us"] * 0.97):
                c += " (%s %s)" % (a["mark"], fmt(a["us"]))
            cells.append(c)
        bold = "**%s**" if lib == "nlohmann json_document" else "%s"
        rows.append("| %s | %s | %s |" % (bold % NAMES.get(lib, lib), ", ".join(names), " | ".join(cells)))
    return "\n".join(indent + r for r in rows)


def main():
    platform = sys.argv[1]
    data = json.load((HERE / "data" / ("perf_usecases_%s.json" % platform)).open())
    data = normalize_usecases(data)   # the same choices as the figure
    out = []
    for uc, label in USE_CASES:
        if uc not in data:
            continue
        out.append("**%s**\n" % label)
        out.append(table(data, uc, ""))
        out.append("")
    print("\n".join(out))


if __name__ == "__main__":
    main()
