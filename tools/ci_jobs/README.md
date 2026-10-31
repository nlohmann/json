# ci_jobs

The compiler jobs of [`ubuntu.yml`](../../.github/workflows/ubuntu.yml) are split into three sets, chosen by each job's
`if:` condition (see [How CI runs](https://json.nlohmann.me/community/quality_assurance/#how-ci-runs)):

- **PR set**: every push to a pull request, and every push to `develop`, `master`, and `release/*`;
- **full set**: after the PR set passed, on pull requests with the label "🚀 ready to merge" and on every push;
- **nightly set**: every night on `develop`, on every push to `master` and `release/*`, and when started by hand.

A matrix whose entries belong to different sets is split into one job per set: the full-set job gets the suffix
`_full`, the nightly-set job `_nightly`, and both share their steps with the PR-set job through YAML anchors.

[`ci_jobs.py`](ci_jobs.py) checks that

- every job of `ubuntu.yml` has the `if:` condition of exactly one set (the conditions are in `SETS`),
- every full-set job waits for (`needs:`) exactly the PR set, and `nightly_report` for exactly the nightly set, and
- the job table in [`quality_assurance.md`](../../docs/mkdocs/docs/community/quality_assurance.md) is up to date.

```shell
python3 -m venv venv && venv/bin/pip install -r tools/ci_jobs/requirements.txt
venv/bin/python tools/ci_jobs/ci_jobs.py                       # check
venv/bin/python tools/ci_jobs/ci_jobs.py --markdown            # print the job table for the documentation
venv/bin/python tools/ci_jobs/ci_jobs.py --compare origin/develop  # list configurations added or removed since develop
```

Use `--compare` when changing the workflows: a configuration that disappears fails it, so no compiler, version, or
standard is dropped by accident when jobs are split, merged, or moved between sets.
