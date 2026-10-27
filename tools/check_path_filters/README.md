# check_path_filters

The compiler workflows [`ubuntu.yml`](../../.github/workflows/ubuntu.yml),
[`macos.yml`](../../.github/workflows/macos.yml), and [`windows.yml`](../../.github/workflows/windows.yml) skip pull
requests that change only files no compiler job reads: the documentation, Markdown files, GitHub metadata, other
workflows, and the license files. Pushes to `develop`, `master`, and `release/*` always run them. The documentation,
license, and path-filter checks run in [`repository_checks.yml`](../../.github/workflows/repository_checks.yml), which
has no path filter.

The filter starts with `'**'` and excludes these files explicitly, so a new file runs the compiler workflows unless it
is excluded on purpose. [`check_path_filters.py`](check_path_filters.py) holds the filter (`PATHS`) and checks that

- each of the three workflows has exactly this filter, with its own workflow file included,
- the CI targets that read excluded files (`UNFILTERED_TARGETS`) do not run in these workflows, and
- no file the filter keeps (sources, tests, build files, tools, workflows) mentions an excluded file or directory
  outside a comment line, unless the mention is listed in `KNOWN_REFERENCES` with a reason.

When the check reports a mention, decide whether a compiler job reads that file:

- If it does, include the file in `PATHS` after the exclusions (as `package_managers.md` and the Swift example are) and
  copy the new filter into the three workflows.
- If it does not, add the mention to `KNOWN_REFERENCES` with the reason.

Run the check with

```shell
python3 tools/check_path_filters/check_path_filters.py
```

To see which workflows a pull request would run, pass the changed files:

```shell
python3 tools/check_path_filters/check_path_filters.py --changed $(git diff --name-only origin/develop)
```
