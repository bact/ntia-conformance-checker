#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0
#
# Smoke test the built wheel as a user would get it.
#
# Usage: smoke-test-wheel.sh DIST_DIR [--expect-sbom]
#
# Installs the one wheel in DIST_DIR into a clean virtual environment and
# runs the CLI from outside the source tree, so a module left out of the
# wheel (for example a subpackage missing from the package list) fails here
# and is not hidden by the checkout. With --expect-sbom, also requires
# exactly one PEP 770 SBOM (*.dist-info/sboms/*.spdx3.json) in the wheel.
#
# Needs: python, unzip (only with --expect-sbom).

set -euo pipefail
shopt -s nullglob

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 DIST_DIR [--expect-sbom]" >&2
  exit 2
fi
dist_dir=$(cd "$1" && pwd)
expect_sbom=false
if [ "${2-}" = "--expect-sbom" ]; then
  expect_sbom=true
fi
data_dir="$(cd "$(dirname "$0")/../.." && pwd)/tests/data"

fail() {
  echo "::error::$*" >&2
  exit 1
}

wheels=("${dist_dir}"/*.whl)
if [ "${#wheels[@]}" -ne 1 ]; then
  fail "expected exactly one wheel in ${dist_dir}, found ${#wheels[@]}"
fi
whl=${wheels[0]}

if [ "${expect_sbom}" = true ]; then
  sboms=0
  while IFS= read -r entry; do
    case "${entry}" in
      *.dist-info/sboms/*.spdx3.json) sboms=$((sboms + 1)) ;;
    esac
  done < <(unzip -Z1 "${whl}")
  if [ "${sboms}" -ne 1 ]; then
    fail "expected one *.dist-info/sboms/*.spdx3.json in ${whl}, found ${sboms}"
  fi
fi

work=$(mktemp -d)
trap 'rm -rf "${work}"' EXIT
python -m venv "${work}/venv"
if [ -x "${work}/venv/bin/python" ]; then
  venv_bin="${work}/venv/bin"
else
  venv_bin="${work}/venv/Scripts" # Windows
fi
"${venv_bin}/python" -m pip install --quiet "${whl}"

# Run from outside the checkout so the installed copy is the one imported.
cd "${work}"
cli=("${venv_bin}/python" -m ntia_conformance_checker.main)

# expect_exit EXPECTED_CODE ARGS...: run the CLI and compare the exit code.
expect_exit() {
  local expected=$1
  shift
  local code=0
  "${cli[@]}" "$@" > "${work}/out.txt" 2> "${work}/err.txt" || code=$?
  if [ "${code}" -ne "${expected}" ]; then
    cat "${work}/err.txt" >&2
    fail "'$*': expected exit ${expected}, got ${code}"
  fi
}

"${cli[@]}" --version > /dev/null || fail "--version failed"

spdx2="${data_dir}/no_elements_missing/SPDXJSONExample-v2.3.spdx.json"
spdx3="${data_dir}/spdx3/no_elements_missing.json"
expect_exit 0 "${spdx2}"
expect_exit 0 --sbom-spec spdx3 "${spdx3}"
expect_exit 1 --comply bsi "${spdx2}"
expect_exit 1 "${data_dir}/missing_supplier_name/SPDXJSONExample-v2.3.spdx.json"
expect_exit 1 "${work}/nonexistent.json"
grep -q "File not found" "${work}/err.txt" || fail "no 'File not found' message"
expect_exit 0 --output json "${spdx2}"
"${venv_bin}/python" -c 'import json,sys; json.load(open(sys.argv[1]))' \
  "${work}/out.txt" || fail "--output json is not valid JSON"

echo "Smoke test passed: ${whl##*/}"
