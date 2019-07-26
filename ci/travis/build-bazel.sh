#!/usr/bin/env bash

export PATH=$PATH:$HOME/bin

bazel build --test_output=errors --verbose_failures=true --keep_going -- //...:all
