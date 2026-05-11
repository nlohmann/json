# Supporting files

This file describes the source for supporting files; that is, files that are not part of the library, but define the infrastructure and other aspects of the project.

- [Continuous Integration](#continuous-integration)
- [GitHub](#github)
- [REUSE](#reuse)
- [Package Managers](#package-managers)

## Continuous Integration

### `.cirrus.yml`

Configuration file for the pipeline at [Cirrus CI](https://cirrus-ci.com/github/nlohmann/json).

Further documentation:

- [Writing tasks](https://cirrus-ci.org/guide/writing-tasks/)

> [!IMPORTANT]
> The filename `.cirrus.yml` and position (root of the repository) are predetermined by Cirrus CI.

### `.github/external_ci/appveyor.yml`

Configuration for the pipelines at [AppVeyor](https://ci.appveyor.com/project/nlohmann/json).

Further documentation:

- [appveyor.yml reference](https://www.appveyor.com/docs/appveyor-yml/)

> [!NOTE]
> The filename can be freely configured in the AppVeyor project.

## GitHub

### `CITATION.cff`

A file to configure the citation for the repository which is displayed in the sidebar of the project.

Further documentation:

- [About CITATION files](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-citation-files)

> [!IMPORTANT]
> The filename `CITATION.cff` and position (root of the repository) are predetermined by GitHub.

### `.github/CODE_OF_CONDUCT.md`

The code of conduct for the project. This is the Markdown version of the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). The code of conduct is linked on the [Community Standards](https://github.com/nlohmann/json/community) page and is mentioned by the Sentiment Bot.

Further documentation:

- [Adding a code of conduct to your project](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/adding-a-code-of-conduct-to-your-project)

> [!IMPORTANT]
> The filename `.github/CODE_OF_CONDUCT.md` is predetermined by GitHub.

> [!NOTE]
> The file is part of the documentation and is included in `docs/mkdocs/docs/community/code_of_conduct.md`.

### `.github/CODEOWNERS`

The code owners file for the project which is used to select reviewers for new pull requests.

Further documentation:

- [About code owners](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)

> [!IMPORTANT]
> The filename `.github/CODEOWNERS` is predetermined by GitHub.

### `.github/config.yml`

Configuration file for [probot](https://probot.github.io/apps/), in particular the [Sentiment Bot](https://probot.github.io/apps/sentiment-bot/) and the [Request Info](https://probot.github.io/apps/request-info/).

> [!IMPORTANT]
> The filename `.github/config.yml` is predetermined by probot.

### `.github/CONTRIBUTING.md`

The contribution guidelines which are linked in the [Community Standards](https://github.com/nlohmann/json/community) and at <https://github.com/nlohmann/json/contribute>.

Further documentation:

- [Setting guidelines for repository contributors](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/setting-guidelines-for-repository-contributors)

> [!IMPORTANT]
> The filename `.github/CONTRIBUTING.md` is predetermined by GitHub.

> [!NOTE]
> The file is part of the documentation and is included in `docs/mkdocs/docs/community/contribution_guidelines.md`.

### `.github/dependabot.yml`

The configuration of [dependabot](https://github.com/dependabot) which ensures the dependencies (GitHub actions and Python packages used in the CI) remain up to date.

Further documentation:

- [Configuring Dependabot security updates](https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/configuring-dependabot-security-updates)

> [!IMPORTANT]
> The filename `.github/dependabot.yml` is predetermined by GitHub.

### `.github/FUNDING.yml`

A file to configure the sponsor button of the repository which is displayed in the sidebar of the project.

Further documentation:

- [Displaying a sponsor button in your repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/displaying-a-sponsor-button-in-your-repository)

> [!IMPORTANT]
> The filename `.github/FUNDING.yml` is predetermined by GitHub.

### `.github/ISSUE_TEMPLATE/bug.yaml`

Issue form template for bugs.

Further documentation:

- [Configuring issue templates for your repository](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/configuring-issue-templates-for-your-repository)

> [!IMPORTANT]
> The folder `.github/ISSUE_TEMPLATE` is predetermined by GitHub.

### `.github/ISSUE_TEMPLATE/config.yaml`

Issue template chooser configuration. The file is used to configure the dialog when a new issue is created.

Further documentation:

- [Configuring issue templates for your repository](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/configuring-issue-templates-for-your-repository)

> [!IMPORTANT]
> The filename `.github/ISSUE_TEMPLATE/config.yaml` is predetermined by GitHub.

### `.github/labeler.yml`

Configuration file for the "Pull Request Labeler" workflow defined in `workflows/labeler.yml`. This file defines rules how labels are assigned to pull requests based on which files are changed.

Further documentation:

- [Label manager for PRs and issues based on configurable conditions](https://github.com/srvaroa/labeler)

> [!NOTE]
> The filename defaults to `.github/labeler.yml` and can be configured in the workflow.

### `.github/PULL_REQUEST_TEMPLATE.md`

The pull request template which prefills new pull requests.

Further documentation:

- [Creating a pull request template for your repository](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/creating-a-pull-request-template-for-your-repository)

> [!IMPORTANT]
> The filename `.github/PULL_REQUEST_TEMPLATE.md` is predetermined by GitHub.

### `.github/SECURITY.md`

The goal is to describe how to securely report security vulnerabilities for this repository. The security policy is linked at <https://github.com/nlohmann/json/security/policy>.

Further documentation:

- [Adding a security policy to your repository](https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository)

> [!IMPORTANT]
> The filename `.github/SECURITY.yml` is predetermined by GitHub.

> [!NOTE]
> The file is part of the documentation and is included in `docs/mkdocs/docs/community/security_policy.md`.

### `LICENSE.MIT`

The license of the project.

Further documentation:

- [Adding a license to a repository](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/adding-a-license-to-a-repository)

> [!IMPORTANT]
> The filename `LICENSE.MIT` is partly predetermined by GitHub. The root filename must be `LICENSE`.

## REUSE

### `.reuse/dep5`

The file defines the licenses of certain third-party components in the repository. The root `Makefile` contains a target `reuse` that checks for compliance.

Further documentation:

- [DEP5](https://reuse.software/spec-3.2/#dep5-deprecated)
- [reuse command-line tool](https://pypi.org/project/reuse/)
- [documentation of linting](https://reuse.readthedocs.io/en/stable/man/reuse-lint.html)
- [REUSE](http://reuse.software)

> [!IMPORTANT]
> The filename `.reuse/dep5` is predetermined by REUSE. Alternatively, a `REUSE.toml` file can be used.

### `.reuse/templates`

Copyright header templates for source files. The root `Makefile` contains a target `reuse` that updates copyright headers with the templates.

Further information:

- [reuse command-line tool](https://pypi.org/project/reuse/)
- [documentation on templates](https://reuse.readthedocs.io/en/stable/man/reuse-annotate.html#cmdoption-t)
- [REUSE](http://reuse.software)

> [!IMPORTANT]
> The folder name `.reuse/templates` is predetermined by REUSE.

### `LICENSES`

A folder that contains every license of all license files (library and third-party code).

Further documentation:

- [REUSE specification](https://reuse.software/spec-3.3/)

> [!IMPORTANT]
> The folder name `LICENSES` is predetermined by REUSE.


## Package Managers

### `BUILD.bazel`

The file can be updated by calling

```shell
make BUILD.bazel
```

### `meson.build`

### `Package.swift`

### `WORKSPACE.bazel`
