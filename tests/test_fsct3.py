# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Behaviour of the fsct3 rules on SPDX 3: what flips a rule, and the limits."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Callable

import pytest

from ntia_conformance_checker.model import RuleResult
from ntia_conformance_checker.rule_based_checker import RuleBasedChecker

from ._ai_graph import add_model_and_dataset

SOURCE = Path(__file__).parent / "data" / "spdx3" / "cisa2026" / "conformant.json"
B = "https://spdx.org/spdxdocs/cisa2026-tests/"
P = "BOM-FSCT2024-"
Edit = Callable[[list[dict[str, Any]]], None]


def _el(graph: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(e for e in graph if e.get("spdxId") == B + name)


def _complete(graph: list[dict[str, Any]]) -> None:
    """Give every package what the fsct3 rules look for."""
    for name in ("App", "Lib"):
        pkg = _el(graph, name)
        pkg["suppliedBy"] = B + "Org1"
        pkg["software_copyrightText"] = "Copyright Example Org"
    graph.extend(
        {
            "type": "Relationship",
            "spdxId": f"{B}Rel-{n}-concluded",
            "creationInfo": "_:ci",
            "relationshipType": "hasConcludedLicense",
            "from": B + n,
            "to": [B + "MIT"],
        }
        for n in ("App", "Lib")
    )


def _results(tmp_path: Path, *edits: Edit) -> dict[str, RuleResult]:
    doc = json.loads(SOURCE.read_text(encoding="utf-8"))
    graph = copy.deepcopy(doc["@graph"])
    _complete(graph)
    for edit in edits:
        edit(graph)
    doc["@graph"] = graph
    path = tmp_path / "fsct.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    checker = RuleBasedChecker(str(path), compliance="fsct3", sbom_spec="spdx3")
    assert checker.doc is not None and not checker.parsing_errors
    return checker.rule_results()


def _outcomes(tmp_path: Path, *edits: Edit) -> dict[str, str]:
    return {k[len(P) :]: v.outcome for k, v in _results(tmp_path, *edits).items()}


def _info(prop: str) -> Edit:
    def edit(graph: list[dict[str, Any]]) -> None:
        next(e for e in graph if e["type"] == "CreationInfo").pop(prop)

    return edit


def _drop(name: str, prop: str) -> Edit:
    def edit(graph: list[dict[str, Any]]) -> None:
        _el(graph, name).pop(prop)

    return edit


def _unlink(*rels: str) -> Edit:
    def edit(graph: list[dict[str, Any]]) -> None:
        graph[:] = [e for e in graph if e.get("spdxId") not in {B + r for r in rels}]

    return edit


CHECKED = {
    "META-001",
    "META-002",
    "META-003",
    "META-005",
    "COMP-001",
    "COMP-002",
    "COMP-003",
    "COMP-004",
    "COMP-007",
    "COMP-008",
}


def test_a_complete_sbom_has_every_checked_rule_present(tmp_path: Path) -> None:
    got = _outcomes(tmp_path)
    assert {k for k, v in got.items() if v == "present"} == CHECKED
    assert {k for k, v in got.items() if v == "out-of-scope"} == {
        "META-004",
        "COMP-005",
        "COMP-006",
    }


@pytest.mark.parametrize(
    ("edit", "flipped"),
    [
        (_info("createdBy"), {"META-001"}),
        (_info("created"), {"META-002"}),
        (_unlink("Rel-dep"), {"META-005"}),
        (_drop("Lib", "name"), {"COMP-001"}),
        (_drop("Lib", "software_packageVersion"), {"COMP-002"}),
        (_drop("Lib", "suppliedBy"), {"COMP-003"}),
        (_unlink("Rel-Lib-concluded"), {"COMP-007"}),
        (_drop("Lib", "software_copyrightText"), {"COMP-008"}),
    ],
    ids=lambda p: "-".join(sorted(p)) if isinstance(p, set) else "edit",
)
def test_removing_a_carrier_flips_only_its_rules(
    tmp_path: Path, edit: Edit, flipped: set[str]
) -> None:
    base, got = _outcomes(tmp_path), _outcomes(tmp_path, edit)
    assert {k for k in got if got[k] != base[k]} == flipped
    assert {got[f] for f in flipped} == {"missing"}


def test_sbom_type_is_read_from_the_sbom_element(tmp_path: Path) -> None:
    def drop_type(graph: list[dict[str, Any]]) -> None:
        _el(graph, "SBOM1").pop("software_sbomType")

    assert _outcomes(tmp_path, drop_type)["META-003"] == "missing"


@pytest.mark.parametrize(
    "value", ["NOASSERTION", "", "  "], ids=["noassertion", "empty", "blank"]
)
def test_a_blank_supplier_or_copyright_counts_as_missing(
    tmp_path: Path, value: str
) -> None:
    def blank(graph: list[dict[str, Any]]) -> None:
        _el(graph, "Lib")["software_copyrightText"] = value

    assert _outcomes(tmp_path, blank)["COMP-008"] == "missing"


@pytest.mark.parametrize(
    ("edits", "missing"),
    [
        ((_drop("Lib", "software_packageUrl"),), ["Lib"]),
        (
            (_drop("Lib", "software_packageUrl"), _drop("App", "software_packageUrl")),
            ["App", "Lib"],
        ),
    ],
    ids=["one", "both"],
)
def test_a_package_with_only_an_spdx_id_has_no_unique_identifier(
    tmp_path: Path, edits: tuple[Edit, ...], missing: list[str]
) -> None:
    """The spdxId every element has is not a unique identifier on its own."""
    got = _results(tmp_path, *edits)[P + "COMP-004"]
    assert got.outcome == "missing"
    assert [f.component_id for f in got.findings] == [B + n for n in missing]


def test_a_contains_relationship_stands_in_for_a_dependency(tmp_path: Path) -> None:
    """Documented limit: the dependency check also accepts `contains`."""

    def to_contains(graph: list[dict[str, Any]]) -> None:
        _el(graph, "Rel-dep")["relationshipType"] = "contains"

    assert _outcomes(tmp_path, to_contains)["META-005"] == "present"


@pytest.mark.parametrize(
    ("link", "expected"),
    [("trainedOn", "missing"), ("testedOn", "missing"), (None, "present")],
    ids=["trained", "tested", "unlinked"],
)
def test_a_dataset_reached_by_trained_or_tested_on_is_judged(
    tmp_path: Path, link: str | None, expected: str
) -> None:
    got = _outcomes(tmp_path, add_model_and_dataset(link, "suppliedBy"))
    assert got["COMP-003"] == expected
