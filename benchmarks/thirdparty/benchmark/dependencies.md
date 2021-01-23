# Build tool dependency policy

To ensure the broadest compatibility when building the benchmark library, but
still allow forward progress, we require any build tooling to be available for:

* Debian stable AND
* The last two Ubuntu LTS releases AND

Currently, this means using build tool versions that are available for Ubuntu
16.04 (Xenial), Ubuntu 18.04 (Bionic), and Debian stretch.

_Note, [travis](.travis.yml) runs under Ubuntu 14.04 (Trusty) for linux builds._

## cmake
The current supported version is cmake 3.5.1 as of 2018-06-06.

_Note, this version is also available for Ubuntu 14.04, the previous Ubuntu LTS
release, as `cmake3`._
