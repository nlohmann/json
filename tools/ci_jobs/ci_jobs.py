#!/usr/bin/env python3
"""List and check the jobs of the compiler workflows and the set each job belongs to.

The jobs of the compiler workflows belong to one of three sets, chosen by the
job's `if:` condition:

- PR set: every pull request push and every push,
- full set: after the PR set passed, on pushes and on pull requests with the
  "🚀 ready to merge" label,
- nightly set: nightly on develop, on pushes to master and release/*, and when
  started by hand.

The script checks that every job belongs to exactly one set, that the full set
of a workflow waits for its whole PR set, that the nightly report waits for the
whole nightly set, and that the job table in
docs/mkdocs/docs/community/quality_assurance.md is up to date.

  --markdown       print the job table for the documentation
  --compare REF    list the configurations (job and matrix values) added or
                   removed since the git revision REF; fails if one was removed
"""

import argparse
import collections
import itertools
import os
import re
import subprocess  # nosec B404
import sys

import yaml

REPO_ROOT = os.path.normpath(os.path.join(sys.path[0], '..', '..'))
DOCS = 'docs/mkdocs/docs/community/quality_assurance.md'
BEGIN, END = '<!-- ci_jobs: begin -->', '<!-- ci_jobs: end -->'

WORKFLOWS = ['.github/workflows/ubuntu.yml', '.github/workflows/macos.yml', '.github/workflows/windows.yml']
TIERED = WORKFLOWS
# --compare also counts the jobs of these workflows, so a job moved between workflows is not a removed one
COMPARED = WORKFLOWS + ['.github/workflows/repository_checks.yml', '.github/workflows/check_amalgamation.yml']

LABEL = '🚀 ready to merge'
SETS = collections.OrderedDict([
    ('PR set', "${{ github.event_name != 'schedule' && (github.event.action != 'labeled' || "
               "github.event.label.name == '" + LABEL + "') }}"),
    ('full set', "${{ github.event_name == 'push' || github.event_name == 'workflow_dispatch' || "
                 "contains(github.event.pull_request.labels.*.name, '" + LABEL + "') }}"),
    ('nightly set', "${{ github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || "
                    "(github.event_name == 'push' && github.ref != 'refs/heads/develop') }}"),
])
UNTIERED = 'every push and PR'
REPORT_JOB = 'nightly_report'

# a job split by set keeps its name and gets one of these suffixes
SUFFIXES = {'full set': '_full', 'nightly set': '_nightly'}


def read(root, path, ref=None):
    if ref is None:
        with open(os.path.join(root, path), encoding='utf-8') as f:
            return f.read()
    # fixed command; ref is a git revision given on the command line
    return subprocess.check_output(['git', 'show', '{}:{}'.format(ref, path)], cwd=root,  # nosec B603, B607
                                   stderr=subprocess.DEVNULL).decode('utf-8')


def add_include(combos, keys, inc):
    """Apply one include entry: extend the matching configurations, or add it as a new one."""
    matching = [c for c in combos if all(c[k] == v for k, v in inc.items() if k in keys)]
    for c in matching:
        c.update({k: v for k, v in inc.items() if k not in keys})
    if not matching:
        combos.append(dict(inc))


def expand(matrix):
    """Return the configurations of a job's strategy.matrix like GitHub Actions does."""
    if not matrix:
        return [{}]
    keys = [k for k in matrix if k not in ('include', 'exclude')]
    if not keys:
        # a matrix of only include entries runs each entry
        return [dict(inc) for inc in matrix.get('include') or []]
    combos = [dict(zip(keys, values)) for values in itertools.product(*(matrix[k] for k in keys))]
    for ex in matrix.get('exclude') or []:
        combos = [c for c in combos if any(c.get(k) != v for k, v in ex.items())]
    for inc in matrix.get('include') or []:
        add_include(combos, keys, inc)
    return combos


def jobs_of(root, workflow, ref=None):
    """Yield (job id, set, list of configurations) for every job of a workflow."""
    data = yaml.safe_load(read(root, workflow, ref))
    for job_id, job in data['jobs'].items():
        condition = job.get('if')
        job_set = UNTIERED if condition is None else next((s for s, c in SETS.items() if c == condition), None)
        matrix = (job.get('strategy') or {}).get('matrix')
        yield job_id, job_set, job, expand(matrix)


def base_id(job_id, job_set):
    suffix = SUFFIXES.get(job_set)
    return job_id[:-len(suffix)] if suffix and job_id.endswith(suffix) else job_id


def label(config):
    return ', '.join(str(v) for k, v in config.items() if k != 'os' or len(config) == 1)


def configurations(root, ref=None):
    """Return a Counter of (job name without set suffix, configuration) over the compared workflows."""
    result = collections.Counter()
    for workflow in COMPARED:
        try:
            jobs = list(jobs_of(root, workflow, ref))
        except (OSError, subprocess.CalledProcessError):
            continue  # the workflow does not exist in this revision
        for job_id, job_set, _, configs in jobs:
            if job_id == REPORT_JOB:
                continue
            for c in configs:
                result[(base_id(job_id, job_set), tuple(sorted((k, str(v)) for k, v in c.items())))] += 1
    return result


def markdown(root):
    rows = []
    order = list(SETS) + [UNTIERED]
    for workflow in WORKFLOWS:
        for job_id, job_set, _, configs in jobs_of(root, workflow):
            if job_id == REPORT_JOB:
                continue
            labels = [label(c) for c in configs if c]
            rows.append((order.index(job_set) if job_set in order else len(order), os.path.basename(workflow), job_id,
                         job_set or 'no set', '; '.join(labels) or '-'))
    rows.sort(key=lambda r: (r[0], r[1]))
    lines = ['| Set | Workflow | Job | Configurations |', '|-----|----------|-----|----------------|']
    lines += ['| {} | {} | `{}` | {} |'.format(s, w, j, c) for _, w, j, s, c in rows]
    return lines


def check_sets(workflow, jobs):
    """Return the errors in the sets of a tiered workflow's jobs and the jobs of each set."""
    errors = []
    by_set = collections.defaultdict(set)
    for job_id, job_set, _, _ in jobs:
        if job_id == REPORT_JOB:
            continue
        if job_set in SETS:
            by_set[job_set].add(job_id)
        else:
            errors.append('{}: job {} has an if: condition of no set; use one of the conditions in '
                          'tools/ci_jobs/ci_jobs.py'.format(workflow, job_id))
    return errors, by_set


def check_needs(workflow, jobs, by_set):
    """Return the errors in the needs: of a tiered workflow's jobs."""
    required = {'full set': by_set['PR set'], 'PR set': set(), 'nightly set': set()}
    errors = []
    for job_id, job_set, job, _ in jobs:
        needs = job.get('needs') or []
        needs = {needs} if isinstance(needs, str) else set(needs)
        expected = by_set['nightly set'] if job_id == REPORT_JOB else required.get(job_set, needs)
        if needs != expected:
            errors.append('{}: job {} must need exactly: {}'.format(workflow, job_id, ', '.join(sorted(expected)) or 'no job'))
    return errors


def check_docs(root):
    """Return an error if the job table in the documentation is not up to date."""
    text = read(root, DOCS)
    block = re.search(re.escape(BEGIN) + r'\n(.*?)\n[ \t]*' + re.escape(END), text, re.S)
    if not block:
        return ['{}: markers {} and {} not found'.format(DOCS, BEGIN, END)]
    indent = re.match(r'[ \t]*', block.group(1)).group(0)
    if block.group(1) != '\n'.join(indent + line for line in markdown(root)):
        return ['{}: the job table is out of date; replace it with the output of '
                'python3 tools/ci_jobs/ci_jobs.py --markdown'.format(DOCS)]
    return []


def check(root):
    errors = []
    for workflow in TIERED:
        jobs = list(jobs_of(root, workflow))
        set_errors, by_set = check_sets(workflow, jobs)
        errors += set_errors + check_needs(workflow, jobs, by_set)
    errors += check_docs(root)

    for e in errors:
        print(e)
    if not errors:
        counts = collections.Counter()
        for workflow in WORKFLOWS:
            for job_id, job_set, _, configs in jobs_of(root, workflow):
                if job_id != REPORT_JOB:
                    counts[job_set] += len(configs)
        print('CI jobs OK: ' + ', '.join('{} {}'.format(n, s) for s, n in counts.items()))
    return 1 if errors else 0


def compare(root, ref):
    before, after = configurations(root, ref), configurations(root)
    removed, added = before - after, after - before
    for title, diff in (('removed', removed), ('added', added)):
        for job, config in sorted(diff.elements()):
            print('{}: {} ({})'.format(title, job, ', '.join('{}={}'.format(k, v) for k, v in config)))
    print('{} configurations before, {} after; {} removed, {} added'.format(
        sum(before.values()), sum(after.values()), sum(removed.values()), sum(added.values())))
    return 1 if removed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--root', default=REPO_ROOT, help='repository root')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--markdown', action='store_true', help='print the job table for the documentation')
    group.add_argument('--compare', metavar='REF', help='list the configurations added or removed since REF')
    args = parser.parse_args()
    if args.markdown:
        print('\n'.join(markdown(args.root)))
        return 0
    if args.compare:
        return compare(args.root, args.compare)
    return check(args.root)


if __name__ == '__main__':
    sys.exit(main())
