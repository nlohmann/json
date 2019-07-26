#!/usr/bin/env bash
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -eu

sudo apt-get update
sudo apt-get install -y \
     gcc \
     g++ \
     unzip \
     wget \
     zip

readonly BAZEL_VERSION=0.24.0
readonly GITHUB_DL="https://github.com/bazelbuild/bazel/releases/download"
wget -q "${GITHUB_DL}/${BAZEL_VERSION}/bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh"
chmod +x "bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh"
./bazel-${BAZEL_VERSION}-installer-linux-x86_64.sh --user
