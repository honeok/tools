#!/bin/sh
# Copyright (c) 2025 honeok <i@honeok.com>
# SPDX-License-Identifier: Apache-2.0

set -e

git config --global core.autocrlf false
git rm --cached -r .
git reset --hard
