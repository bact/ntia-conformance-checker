# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests for BSI TR-03183-2 v2.1.0 support: outcomes, provisions, conditions."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any, Callable

import pytest

from ntia_conformance_checker import SbomChecker
from ntia_conformance_checker.main import main
from ntia_conformance_checker.rule_based_checker import RuleBasedChecker

DATA = Path(__file__).parent / "data"
BSI = DATA / "bsi"
OK = BSI / "compliant_bsi_spdx3.json"
SPDX2 = DATA / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
E = "https://example.com/spdx/"
P = "BOM-BSI2025-"
Graph = list[dict[str, Any]]


def _checker(path: Path) -> RuleBasedChecker:
    return RuleBasedChecker(str(path), compliance="bsi", sbom_spec="spdx3")


def _edited(tmp_path: Path, edit: Callable[[Graph], None]) -> RuleBasedChecker:
    doc = json.loads(OK.read_text(encoding="utf-8"))
    graph = copy.deepcopy(doc["@graph"])
    edit(graph)
    doc["@graph"] = graph
    path = tmp_path / "bsi.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    checker = _checker(path)
    assert checker.doc is not None and not checker.parsing_errors
    return checker


def _el(graph: Graph, name: str) -> dict[str, Any]:
    return next(e for e in graph if e.get("spdxId") == E + name)


def _missing(checker: RuleBasedChecker) -> set[str]:
    return {
        k.removeprefix(P) for k, v in checker.rule_outcomes().items() if v == "missing"
    }


# Every checked component rule, conditional ones included: with no component
# to inspect, a component rule fails rather than passes over nothing.
_NOTHING_REACHABLE = {f"COMP-{n:03d}" for n in range(1, 18)} - {
    "COMP-008",
    "COMP-009",
    "COMP-016",
}


@pytest.mark.parametrize(
    ("name", "conformant", "missing"),
    [
        ("compliant_bsi_spdx3", True, set()),
        # COMP-015 (effective license) and COMP-017 (security.txt) are
        # permissions: reported, never blocking
        ("missing_bsi_creator", False, {"DOC-001", "COMP-001", "COMP-017"}),
        ("missing_concluded_license", False, {"COMP-006", "COMP-015", "COMP-017"}),
        # no distribution file: no filename, nor a hash or purpose on it
        (
            "missing_distribution_filename",
            False,
            {"COMP-004", "COMP-007", "COMP-010", "COMP-017"},
        ),
        # optional and conditional data absent: still conformant
        ("missing_optional_warnings", True, {"COMP-017"}),
        ("missing_sha512_hash", False, {"COMP-007", "COMP-017"}),
        ("missing_structured_property", False, {"COMP-010", "COMP-017"}),
        # no root: no component is reachable, so none is evaluated
        ("missing_sbom_uri", False, _NOTHING_REACHABLE),
    ],
)
def test_fixture_outcomes(name: str, conformant: bool, missing: set[str]) -> None:
    checker = _checker(BSI / f"{name}.json")
    assert (checker.check_compliance(), _missing(checker)) == (conformant, missing)


def test_missing_creator_names_the_component_and_the_document() -> None:
    results = _checker(BSI / "missing_bsi_creator.json").rule_results()
    assert [f.component_name for f in results[P + "COMP-001"].findings] == [
        "example-component"
    ]
    assert results[P + "DOC-001"].findings[0].is_document_level


def test_conditional_rules_on_the_compliant_sbom() -> None:
    outcomes = _checker(OK).rule_outcomes()
    # The source URI is given BSI's way (a source artifact that generates the
    # package), which the mapping does not read: no vcs reference, so the rule
    # does not apply. The others are given.
    assert {n: outcomes[P + f"COMP-0{n}"] for n in range(11, 15)} == {
        11: "not-applicable",
        12: "present",
        13: "present",
        14: "present",
    }
    assert {outcomes[P + i] for i in ("DOC-003", "COMP-008", "COMP-016")} == {
        "out-of-scope"
    }


def _add_vcs(graph: Graph) -> None:
    _el(graph, "package-01")["externalRef"].append(
        {"type": "ExternalRef", "externalRefType": "vcs", "locator": ["https://g"]}
    )


def _drop_deps(graph: Graph) -> None:
    graph.remove(_el(graph, "rel-deps"))


def _deps_without_completeness(graph: Graph) -> None:
    _el(graph, "rel-deps").pop("completeness")


def _hash_on_package_only(graph: Graph) -> None:
    hashes = _el(graph, "file-01").pop("verifiedUsing")
    _el(graph, "package-01")["verifiedUsing"] = hashes


def _purposes(*values: str) -> Callable[[Graph], None]:
    def edit(graph: Graph) -> None:
        _el(graph, "file-01")["software_additionalPurpose"] = list(values)

    return edit


def _unnamed_file(graph: Graph) -> None:
    _el(graph, "file-01").pop("name")


def _supplier_only(graph: Graph) -> None:
    pkg = _el(graph, "package-01")
    pkg["suppliedBy"] = pkg.pop("originatedBy")[0]


def _download_location_only(graph: Graph) -> None:
    _el(graph, "file-01").pop("externalRef")
    _el(graph, "package-01")["software_downloadLocation"] = "https://example.com/d"


def _no_security_txt(graph: Graph) -> None:
    _el(graph, "package-01").pop("externalRef")


@pytest.mark.parametrize(
    ("edit", "rule", "outcome", "conformant"),
    [
        (_add_vcs, "COMP-011", "present", True),
        (_drop_deps, "COMP-005", "missing", False),
        (_deps_without_completeness, "COMP-005", "missing", False),
        (_hash_on_package_only, "COMP-007", "present", True),
        (_purposes("firmware"), "COMP-010", "present", True),  # unstructured
        # archive is the archive property; it says nothing about structure
        (_purposes("archive"), "COMP-010", "missing", False),
        (_no_security_txt, "COMP-017", "missing", True),  # a permission
        (_unnamed_file, "COMP-004", "missing", False),
        (_supplier_only, "COMP-001", "missing", False),  # BSI: originator only
        (_download_location_only, "COMP-012", "present", True),
    ],
    ids=[
        "vcs",
        "no-dependencies",
        "no-completeness",
        "hash-on-package",
        "firmware",
        "archive-only",
        "no-security-txt",
        "unnamed-file",
        "supplier-only",
        "download-location",
    ],
)
def test_edits(
    tmp_path: Path,
    edit: Callable[[Graph], None],
    rule: str,
    outcome: str,
    conformant: bool,
) -> None:
    checker = _edited(tmp_path, edit)
    assert checker.rule_outcomes()[P + rule] == outcome
    assert checker.check_compliance() is conformant


@pytest.mark.parametrize(
    ("expression", "given"),
    [
        ("noassertion", False),
        ("NONE", True),
        ("NoneLicense", True),
        ("NoAssertionLicense", False),
        (" ", False),
        ("Apache-2.0 OR MIT", True),
    ],
)
def test_blank_license_expression(tmp_path: Path, expression: str, given: bool) -> None:
    """NOASSERTION is no license: the distribution license is missing and an
    original license is not given (so not required); NONE is a license."""

    def edit(graph: Graph) -> None:
        for obj in graph:
            if obj.get("type") == "simplelicensing_LicenseExpression":
                obj["simplelicensing_licenseExpression"] = expression

    outcomes = _edited(tmp_path, edit).rule_outcomes()
    assert (outcomes[P + "COMP-006"], outcomes[P + "COMP-014"]) == (
        ("present", "present") if given else ("missing", "not-applicable")
    )


def test_spdx2_sbom_is_not_covered() -> None:
    checker = RuleBasedChecker(str(SPDX2), compliance="bsi", sbom_spec="spdx2")
    outcomes = set(checker.rule_outcomes().values())
    assert outcomes == {"not-applicable", "out-of-scope"}
    assert checker.check_compliance() is False


@pytest.mark.parametrize(
    ("name", "code", "conformant"),
    [("compliant_bsi_spdx3", 0, True), ("missing_sha512_hash", 1, False)],
)
def test_cli_runs_bsi_with_rule_results(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    name: str,
    code: int,
    conformant: bool,
) -> None:
    path = str(BSI / f"{name}.json")
    monkeypatch.setattr(sys, "argv", ["sbomcheck", "-c", "bsi", "-r", "json", path])
    with pytest.raises(SystemExit) as exc:
        main()
    out = json.loads(capsys.readouterr().out)
    assert (exc.value.code, out["isConformant"]) == (code, conformant)
    assert len(out["ruleResults"]) == 20
    assert out["clusterCompliance"] == {
        "sbom-itself": True,
        "each-component": conformant,
    }
    assert isinstance(
        SbomChecker(path, compliance="bsi", sbom_spec="spdx3"), RuleBasedChecker
    )


def test_report_does_not_call_a_permission_required(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _checker(BSI / "missing_sha512_hash.json").print_components_missing_info()
    out = capsys.readouterr().out
    assert "SHA-512 hash of the deployable component (1)" in out
    assert "security.txt" not in out


def test_sarif_says_what_each_kind_of_rule_checks(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Conditional and catalogue-only rules are not described as always checked."""
    monkeypatch.setattr(sys, "argv", ["sbomcheck", "-c", "bsi", "-r", "sarif", str(OK)])
    with pytest.raises(SystemExit):
        main()
    rules = {
        r["id"].removeprefix(P): r
        for r in json.loads(capsys.readouterr().out)["runs"][0]["tool"]["driver"][
            "rules"
        ]
    }
    text = {k: v["fullDescription"]["text"] for k, v in rules.items()}
    assert "not-applicable" in text["COMP-011"]
    assert "does not check it" in text["COMP-008"]
    assert "result is emitted" in text["COMP-001"]
    assert {k for k, v in rules.items() if v["properties"]["conditional"]} == {
        f"COMP-0{n}" for n in range(11, 15)
    }
