#!/usr/bin/env bash
set -o errexit

copy_contents() {
  local source="$1"
  status "Copying contents from $source"
  if [[ ! "$dryrun" == "1" ]]; then
    (cd "$source" >/dev/null && tar c .) | tar xv
  else
    _ "(cd \"$source\" >/dev/null && tar c .) | tar xv"
  fi
}

# Sets git config
set_config() {
  if [ -n "$GIT_NAME" ]; then _ git config user.name "$GIT_NAME"; fi
  if [ -n "$GIT_EMAIL" ]; then _ git config user.email "$GIT_EMAIL"; fi
}

# Runs the deployment
run() {
  if [ ! -d "$source" ]; then
    echo "Source is not a directory: $source"
    exit 1
  fi

  local tmpdir="$(mktemp -d)"

  if [[ "$force" == "1" ]]; then
    _ cd "$tmpdir"
    _ git init
    _ git checkout -b "$branch"
    copy_contents "$source"
    if [[ "$useenv" == "1" ]]; then set_config; fi
    _ git add -A .
    git_commit
    git_push --force
  else
    _ cd "$tmpdir"
    _ git clone "$repo" . -b "$branch" || ( \
      _ git init && \
      _ git checkout -b "$branch")
    if [[ "$keep" == "0" ]]; then _ rm -rf ./*; fi
    copy_contents "$source"
    if [[ "$useenv" == "1" ]]; then set_config; fi
    _ git add -A .
    git_commit || true
    git_push
  fi
  _ rm -rf "$tmpdir"
  status_ "Done"
}

git_commit() {
  if [ -z "$author" ]; then
    _ git commit -m "$message"
  else
    _ git commit -m "$message" --author "$author"
  fi
}

git_push() {
  if [ -z "$GITHUB_TOKEN" ]; then
    _ git push "${repo}" "$branch" "$@"
  else
    status "Pushing via \$GITHUB_TOKEN $@"
    _ git push "https://${GITHUB_TOKEN}@github.com/${repospec}.git" "$branch" "$@" \
      --quiet >/dev/null 2>&1 || \
      ( status_ "Failed to push"; exit 1 )
  fi
}

status() {
  echo -e "\n\033[34m==>\033[0;1m" "$@\033[0m"
}
status_() {
  echo -e "\033[33;1m==>\033[0m" "$@"
}

_() {
  echo ""
  status_ "$@"
  if [[ ! "$dryrun" == "1" ]]; then "$@"; fi
}

help() {
  local cmd="$(basename $0)"
  echo 'Usage:'
  echo "  $cmd <REPO> <SOURCE>"
  echo ''
  echo 'Parameters:'
  echo "  REPO             repository to push to in 'user/repo' form"
  echo "  SOURCE           path to upload to repository's gh-pages branch"
  echo ''
  echo 'Options:'
  echo '  -h, --help       show help screen'
  echo '  -f, --force      force push'
  echo '  -n, --dry-run    run in simulation mode'
  echo '  -e, --use-env    pick up arguments from environment variables'
  echo '  -b, --branch     use this branch name (default: gh-pages)'
  echo '  -a, --author     set the author'
  echo '  -k, --keep       keep existing files in the repo'
  echo ''
  echo 'Env var options:'
  echo '  GITHUB_TOKEN     if set, use this to push to the repo'
  echo ''
  echo 'Optional env vars:'
  echo "  Run with '-e' to enable the use of these variables."
  echo "  GIT_NAME         set this as the repos user.name"
  echo '  GIT_EMAIL        set this as the repos user.email'
  echo '  GITHUB_REPO      substitute as the REPO (1st argument)'
  echo '  GIT_SOURCE       substitute as the SOURCE (2nd argument)'
  echo '  GIT_BRANCH       use this branch name (--branch)'
  echo ''
  echo 'Example:'
  echo "  $cmd rstacruz/myproject doc"
  echo "    # pushes './doc' into the gh-pages branch of rstacruz/myproject"
  echo ''
  echo "  export GITHUB_REPO='xyz/abc'"
  echo "  export GIT_SOURCE='docs'"
  echo "  $cmd -e"
  echo "    # pushes './doc' into the gh-pages branch of xyz/abc"
}

#
# Defaults
#

force=0
dryrun=0
repospec=
source=
branch=
message="Update"
useenv=0
author=""
keep=0

#
# Parse args
#

while [[ "$1" =~ ^- && ! "$1" == '--' ]]; do case $1 in
  -h | --help )
    help
    exit
    ;;
  -b | --branch )
    shift
    branch="$1"
    ;;
  -n | --dry-run )
    dryrun=1
    ;;
  -e | --use-env )
    useenv=1
    ;;
  -k | --keep )
    keep=1
    ;;
  -a | --author)
    shift
    author="$1"
    ;;
  -f | --force )
    force=1
    ;;
esac; shift; done
if [[ "$1" == '--' ]]; then shift; fi

if [[ "$useenv" == "1" ]] && [[ -n "$GIT_BRANCH" ]] && [[ -z "$branch" ]]; then
  branch="$GIT_BRANCH"
fi

if [[ "$useenv" == "1" ]] && [[ -n "$GITHUB_REPO" ]] && [[ -n "$GIT_SOURCE" ]] && [[ -z "$2" ]]; then
  repospec="$GITHUB_REPO"
  source="$GIT_SOURCE"
else
  repospec="$1"
  source="$2"
fi

: ${branch:="gh-pages"}

if [ -z "$source" ]; then
  help
  exit 1
fi

source="`pwd -LP`/$source"
repo="https://github.com/${repospec}.git"

run
