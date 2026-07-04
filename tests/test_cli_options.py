# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests for the CLI option surface (argument parsing + alias handling) and
the checker's maturity-target validation."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pytest
from pytest import MonkeyPatch

from ntia_conformance_checker import NTIAChecker, cli_utils
from ntia_conformance_checker import main as main_module
from ntia_conformance_checker.rule_based_checker import RuleBasedChecker
from ntia_conformance_checker.spec_loader import load_spec

_FIXTURE = str(
    Path(__file__).parent
    / "data"
    / "no_elements_missing"
    / "SPDXJSONExample-v2.3.spdx.json"
)

_TWO_TIER_SPEC = """\
spec:
  id: demo3
  title: Demo Two-Tier Spec
categories:
  - id: c
    code: C
    title: C
maturity_levels:
  - level: 0
    id: baseline
  - level: 1
    id: extra
rules:
  - number: 1
    slug: demo-author-missing
    spec_category: c
    probe: { name: require_document_attribute, params: { attribute: author } }
  - number: 2
    slug: demo-extra-missing
    spec_category: c
    maturity: 1
    probe: { name: require_document_attribute, params: { attribute: does-not-exist } }
"""


def _parse(monkeypatch: MonkeyPatch, argv: list[str]) -> argparse.Namespace:
    monkeypatch.setattr(sys, "argv", ["sbomcheck", *argv])
    return cli_utils.get_parsed_args()


# ---- report output type --------------------------------------------------


def test_output_quiet_aliases_to_none(monkeypatch: MonkeyPatch) -> None:
    assert _parse(monkeypatch, ["f.json", "--output", "quiet"]).output == "none"


def test_output_none_and_sarif_sbom_accepted(monkeypatch: MonkeyPatch) -> None:
    assert _parse(monkeypatch, ["f.json", "-r", "none"]).output == "none"
    assert _parse(monkeypatch, ["f.json", "-r", "sarif-sbom"]).output == "sarif-sbom"


def test_output_invalid_exits(monkeypatch: MonkeyPatch) -> None:
    with pytest.raises(SystemExit):
        _parse(monkeypatch, ["f.json", "--output", "bogus"])


# ---- maturity ------------------------------------------------------------


def test_mature_default_and_value(monkeypatch: MonkeyPatch) -> None:
    assert _parse(monkeypatch, ["f.json"]).maturity == 0
    assert _parse(monkeypatch, ["f.json", "-m", "2"]).maturity == 2
    assert _parse(monkeypatch, ["f.json", "--mature", "1"]).maturity == 1


def test_removed_flags_are_unrecognized(monkeypatch: MonkeyPatch) -> None:
    for argv in (
        ["f.json", "--maturity", "1"],
        ["f.json", "--maturity-level", "1"],
        ["f.json", "--embed-sbom"],
    ):
        with pytest.raises(SystemExit):
            _parse(monkeypatch, argv)


# ---- log verbosity -------------------------------------------------------


def test_verbosity_flags(monkeypatch: MonkeyPatch) -> None:
    assert _parse(monkeypatch, ["f.json"]).verbose == 0
    assert _parse(monkeypatch, ["f.json", "-v"]).verbose == 1
    assert _parse(monkeypatch, ["f.json", "-vv"]).verbose == 2
    assert _parse(monkeypatch, ["f.json", "--debug"]).debug is True
    assert _parse(monkeypatch, ["f.json", "-q"]).quiet is True


def test_skip_validation_shortcut(monkeypatch: MonkeyPatch) -> None:
    assert _parse(monkeypatch, ["f.json", "-k"]).skip_validation is True


# ---- maturity-target validation (checker) --------------------------------


def test_target_within_declared_levels_ok() -> None:
    # NTIA is flat (only level 0); maturity 0 is valid.
    checker = NTIAChecker(_FIXTURE)
    assert isinstance(checker.check_compliance(maturity=0), bool)


def test_target_above_declared_levels_raises() -> None:
    # NTIA is flat (only level 0); maturity 3 is invalid.
    checker = NTIAChecker(_FIXTURE)
    with pytest.raises(ValueError):
        checker.check_compliance(maturity=3)


def test_target_negative_raises() -> None:
    checker = NTIAChecker(_FIXTURE)
    with pytest.raises(ValueError):
        checker.check_compliance(maturity=-1)


def test_maturity_scopes_which_rules_are_blocking(tmp_path: Path) -> None:
    """A rule declared at maturity 1 is out of scope (and non-blocking) at
    the baseline, but blocks compliance once the target reaches its tier."""
    spec_path = tmp_path / "demo3.yaml"
    spec_path.write_text(_TWO_TIER_SPEC, encoding="utf-8")
    checker = RuleBasedChecker(_FIXTURE, compliance=load_spec(spec_path))

    assert checker.check_compliance(maturity=0) is True
    assert checker.check_compliance(maturity=1) is False


# ---- main() entrypoint ----------------------------------------------------


def test_main_invalid_maturity_exits_cleanly(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys, "argv", ["sbomcheck", _FIXTURE, "-c", "ntia", "-m", "99", "-q"]
    )
    with pytest.raises(SystemExit) as exc_info:
        main_module.main()
    assert exc_info.value.code == 2


def test_main_unknown_compliance_exits_cleanly(monkeypatch: MonkeyPatch) -> None:
    # Bypasses argparse's own -c choices restriction to exercise main()'s
    # defensive ValueError handling around SbomChecker construction.
    fake_args = argparse.Namespace(
        file=_FIXTURE,
        file_opt=None,
        sbom_spec="spdx2",
        comply="does-not-exist",
        skip_validation=False,
        output="print",
        output_file=None,
        verbose=0,
        debug=False,
        quiet=True,
        maturity=0,
        version=False,
    )
    monkeypatch.setattr(main_module, "get_parsed_args", lambda: fake_args)
    with pytest.raises(SystemExit) as exc_info:
        main_module.main()
    assert exc_info.value.code == 2
