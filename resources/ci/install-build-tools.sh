#!/usr/bin/env bash
#
# Copyright 2020 Brian Smith.
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

set -eux -o pipefail
IFS=$'\n\t'

target=$1
features=${2-}

function install_packages {
  sudo apt-get -yq --no-install-suggests --no-install-recommends install "$@"
}

use_clang=
case $target in
--target=aarch64-unknown-linux-gnu)
  # Clang is needed for code coverage.
  use_clang=1
  install_packages \
    qemu-user \
    gcc-aarch64-linux-gnu \
    g++-aarch64-linux-gnu \
    libc6-dev-arm64-cross
  ;;
--target=aarch64-unknown-linux-musl|--target=armv7-unknown-linux-musleabihf|--target=arm-unknown-linux-musleabihf)
  use_clang=1
  install_packages \
    qemu-user
  ;;
--target=arm-unknown-linux-gnueabihf)
  install_packages \
    qemu-user \
    gcc-arm-linux-gnueabihf \
    g++-arm-linux-gnueabihf \
    libc6-dev-armhf-cross
  ;;
--target=armv7-unknown-linux-gnueabihf)
  install_packages \
    qemu-user \
    gcc-arm-linux-gnueabihf \
    g++-arm-linux-gnueabihf \
    libc6-dev-armhf-cross
  ;;  
--target=x86_64-unknown-linux-musl)
  use_clang=1
  ;;
--target=*)
  ;;
esac

