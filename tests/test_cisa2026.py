# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests for CISA 2026 Minimum Elements support: ids, outcomes, honest limits."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path
from typing import Any, Callable

import pytest

from ntia_conformance_checker import get_spec
from ntia_conformance_checker.adapters.spdx3_adapter import IDENTIFIER_PROPERTIES
from ntia_conformance_checker.model import RuleResult
from ntia_conformance_checker.rule_based_checker import RuleBasedChecker
from ntia_conformance_checker.spec import Spec

from ._ai_graph import add_model_and_dataset

DATA = Path(__file__).parent / "data"
CISA = DATA / "spdx3" / "cisa2026" / "conformant.json"
SPDX2 = str(DATA / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json")
B = "https://spdx.org/spdxdocs/cisa2026-tests/"
P = "BOM-CISA2026-"
#: The ontology's SARIF rule ids (https://bact.github.io/bom/req/cisa2026/).
#: The Practices and Processes ids are the checker's: the ontology gives those
#: elements a notation (CISA2026-PP-01) but no SARIF rule id.
ONTOLOGY_IDS = {
    "sbom-author": "META-001",
    "sbom-author-signature": "META-002",
    "sbom-data-format-name": "META-003",
    "sbom-data-format-version": "META-004",
    "sbom-generation-context": "META-005",
    "sbom-timestamp": "META-006",
    "sbom-tool-name": "META-007",
    "sbom-tool-version": "META-008",
    "sbom-version": "META-009",
    "component-producer": "COMP-001",
    "component-dependency-relationship": "COMP-002",
    "component-hash-value": "COMP-003",
    "component-hash-algorithm": "COMP-004",
    "component-identifiers": "COMP-005",
    "component-license": "COMP-006",
    "component-name": "COMP-007",
    "component-version": "COMP-008",
}
CATALOGUE_ONLY = {
    "META-002",
    "META-008",
    "META-009",
    *(f"PP-00{n}" for n in range(1, 7)),
}


def _results(
    tmp_path: Path,
    edit: Callable[[list[dict[str, Any]]], None],
    compliance: str | Spec = "cisa2026",
) -> dict[str, RuleResult]:
    """Results for a copy of the conformant SBOM after ``edit`` changes its graph."""
    doc = json.loads(CISA.read_text(encoding="utf-8"))
    graph = copy.deepcopy(doc["@graph"])
    edit(graph)
    doc["@graph"] = graph
    path = tmp_path / "cisa.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    checker = RuleBasedChecker(str(path), compliance=compliance, sbom_spec="spdx3")
    assert checker.doc is not None and not checker.parsing_errors
    return checker.rule_results()


def _edit(
    tmp_path: Path, edit: Callable[[list[dict[str, Any]]], None]
) -> dict[str, str]:
    """Outcomes for a copy of the conformant SBOM after ``edit`` changes its graph."""
    return {k: v.outcome for k, v in _results(tmp_path, edit).items()}


def _el(graph: list[dict[str, Any]], name: str) -> dict[str, Any]:
    return next(e for e in graph if e.get("spdxId") == B + name)


def _drop(name: str, *props: str) -> Callable[[list[dict[str, Any]]], None]:
    def edit(graph: list[dict[str, Any]]) -> None:
        for prop in props:
            _el(graph, name).pop(prop)

    return edit


def _drop_relationship(rel: str) -> Callable[[list[dict[str, Any]]], None]:
    def edit(graph: list[dict[str, Any]]) -> None:
        graph.remove(_el(graph, rel))

    return edit


def _creation_info(prop: str) -> Callable[[list[dict[str, Any]]], None]:
    def edit(graph: list[dict[str, Any]]) -> None:
        next(e for e in graph if e["type"] == "CreationInfo").pop(prop)

    return edit


def test_ids_follow_the_ontology() -> None:
    spec = get_spec("cisa2026")
    got = {
        r.slug[len("cisa2026-") : -len("-missing")]: spec.rule_id(r) for r in spec.rules
    }
    assert len(got) == 23
    assert {s: got[s] for s in ONTOLOGY_IDS} == {
        s: P + i for s, i in ONTOLOGY_IDS.items()
    }


def test_conformant_sbom_has_every_checkable_rule_present(tmp_path: Path) -> None:
    got = _edit(tmp_path, lambda graph: None)
    assert {k[len(P) :] for k, v in got.items() if v == "out-of-scope"} == (
        CATALOGUE_ONLY
    )
    assert {v for k, v in got.items() if k[len(P) :] not in CATALOGUE_ONLY} == {
        "present"
    }


@pytest.mark.parametrize(
    ("edit", "flipped"),
    [
        (_creation_info("createdBy"), {"META-001"}),
        (_creation_info("createdUsing"), {"META-007"}),
        (_creation_info("specVersion"), {"META-003", "META-004"}),
        (_creation_info("created"), {"META-006"}),
        (_drop("Lib", "name"), {"COMP-007"}),
        (_drop("SBOM1", "software_sbomType"), {"META-005"}),
        (_drop("Lib", "originatedBy"), {"COMP-001"}),
        (_drop("Lib", "verifiedUsing"), {"COMP-003", "COMP-004"}),
        (_drop("Lib", "software_packageUrl"), {"COMP-005"}),
        (_drop("Lib", "software_packageVersion"), {"COMP-008"}),
        (_drop_relationship("Rel-dep"), {"COMP-002"}),
        (_drop_relationship("Rel-lib-lic"), {"COMP-006"}),
    ],
    ids=lambda p: "-".join(sorted(p)) if isinstance(p, set) else "edit",
)
def test_removing_the_carrier_flips_only_its_rules(
    tmp_path: Path, edit: Callable[[list[dict[str, Any]]], None], flipped: set[str]
) -> None:
    base = _edit(tmp_path, lambda graph: None)
    got = _edit(tmp_path, edit)
    assert {k[len(P) :] for k in got if got[k] != base[k]} == flipped
    assert {got[P + f] for f in flipped} == {"missing"}


def _unlink_lib(graph: list[dict[str, Any]]) -> None:
    graph.remove(_el(graph, "Rel-dep"))
    _drop("Lib", "software_packageUrl")(graph)


def test_a_package_unreachable_from_the_root_is_not_evaluated(tmp_path: Path) -> None:
    """Documented limit: only packages reachable from the root are judged."""
    got = _edit(tmp_path, _unlink_lib)
    assert got[P + "COMP-005"] == "present"


def _identifier(kind: str) -> Callable[[list[dict[str, Any]]], None]:
    def edit(graph: list[dict[str, Any]]) -> None:
        lib = _el(graph, "Lib")
        lib.pop("software_packageUrl")
        lib["externalIdentifier"] = [
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": kind,
                "identifier": "https://example.com/lib",
            }
        ]

    return edit


@pytest.mark.parametrize(
    ("kind", "outcome"),
    [("cpe23", "present"), ("swid", "present"), ("urlScheme", "missing")],
)
def test_identifier_types_are_those_the_shared_check_accepts(
    tmp_path: Path, kind: str, outcome: str
) -> None:
    """COMP-005 and the NTIA/FSCT identifier check share one definition."""
    assert _edit(tmp_path, _identifier(kind))[P + "COMP-005"] == outcome
    slug = "cisa2026-component-identifiers-missing"
    rule = next(r for r in get_spec("cisa2026").rules if r.slug == slug)
    assert rule.probe is not None
    assert tuple(rule.probe.params["properties"]) == IDENTIFIER_PROPERTIES


NO_REACH_VIA = dataclasses.replace(get_spec("cisa2026"), reach_via=())


@pytest.mark.parametrize(
    ("link", "dropped", "spec", "flipped"),
    [
        ("trainedOn", (), "cisa2026", set()),
        ("trainedOn", ("software_packageVersion",), "cisa2026", {"COMP-008"}),
        ("testedOn", ("originatedBy",), "cisa2026", {"COMP-001"}),
        ("testedOn", ("verifiedUsing",), "cisa2026", {"COMP-003", "COMP-004"}),
        ("trainedOn", ("software_packageUrl",), "cisa2026", {"COMP-005"}),
        (None, ("software_packageVersion",), "cisa2026", set()),
        ("trainedOn", ("software_packageVersion",), NO_REACH_VIA, set()),
    ],
    ids=["complete", "trained", "tested", "hash", "id", "unlinked", "no-reach-via"],
)
def test_a_dataset_reached_by_reach_via_is_judged(
    tmp_path: Path,
    link: str | None,
    dropped: tuple[str, ...],
    spec: str | Spec,
    flipped: set[str],
) -> None:
    """``reach_via`` follows trainedOn/testedOn to the dataset; without it, or
    unlinked, the dataset is not evaluated."""
    got = _results(tmp_path, add_model_and_dataset(link, *dropped), spec)
    assert {k[len(P) :] for k, v in got.items() if v.outcome == "missing"} == flipped
    for rule in flipped:
        assert [f.component_id for f in got[P + rule].findings] == [B + "Data"]


def test_cisa2026_and_fsct3_follow_trained_and_tested_on() -> None:
    assert get_spec("cisa2026").reach_via == ("trainedOn", "testedOn")
    assert get_spec("fsct3").reach_via == ("trainedOn", "testedOn")
    assert not get_spec("ntia").reach_via and not get_spec("g7ai").reach_via


def test_spdx2_means_nothing_applies() -> None:
    checker = RuleBasedChecker(SPDX2, compliance="cisa2026", sbom_spec="spdx2")
    got = {k: v.outcome for k, v in checker.rule_results().items()}
    assert set(got.values()) <= {"not-applicable", "out-of-scope"}
    assert checker.check_compliance() is False
