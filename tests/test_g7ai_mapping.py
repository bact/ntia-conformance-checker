# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests that the g7ai rules agree with the G7 -> SPDX 3.0.1 SSSOM mapping."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ntia_conformance_checker import get_spec

if TYPE_CHECKING:
    from ntia_conformance_checker.spec import SpecRule

MAPPING = Path(__file__).parent / "data" / "g7ai2026-to-spdx30.sssom.tsv"
_SLUG = ("g7ai-", "-missing")
# Document-level attributes the checker names itself -> SPDX property.
_DOC_ATTRIBUTES = {
    "author": "createdBy",
    "createdUsing": "name",
    "dependency_relationship": "dependsOn",
    "sbom_type": "sbomType",
    "spec_version": "specVersion",
    "timestamp": "created",
}


def _subject(rule: SpecRule) -> str:
    return rule.slug[len(_SLUG[0]) : -len(_SLUG[1])]


def _load() -> dict[str, list[dict[str, str]]]:
    with MAPPING.open(encoding="utf-8") as f:
        lines = (line for line in f if not line.startswith("#"))
        rows: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in csv.DictReader(lines, delimiter="\t"):
            rows[row["subject_id"].split(":", 1)[1]].append(row)
    return rows


def _properties(rule: SpecRule) -> set[str]:
    """SPDX property names the rule's probe reads."""
    if rule.probe is None:
        return set()
    params = rule.probe.params
    props = (
        params.get("properties")
        or params.get("relationships")
        or [params.get("attribute")]
    )
    return {
        _DOC_ATTRIBUTES.get(p, p.split("_", 1)[-1]) for p in props if isinstance(p, str)
    }


def _mapped_names(rows: list[dict[str, str]]) -> set[str]:
    """Local names of the SPDX targets and carrier properties of a subject."""
    names = {r["object_id"].split(":", 1)[1].split("/")[-1] for r in rows}
    paths = {r["object_path"].split(":", 1)[-1] for r in rows if r["object_path"]}
    return names | paths


#: Relationship types a rule accepts beyond its mapping rows, and why
#: (stated in rules/g7ai.md, "Beyond the mapping").
_BEYOND_MAPPING = {
    "system-components": {"dependsOn"},  # a dependency is also a component
    "dataset-lifecycle-role": {"testedOn"},  # the other lifecycle role of a dataset
}

RULES = get_spec("g7ai").rules
ROWS = _load()


def test_rules_and_mapping_subjects_match() -> None:
    assert {_subject(r) for r in RULES} == set(ROWS)


@pytest.mark.parametrize("rule", RULES, ids=_subject)
def test_probe_properties_are_mapped(rule: SpecRule) -> None:
    mapped = _mapped_names(ROWS[_subject(rule)])
    unmapped = _properties(rule) - mapped - _BEYOND_MAPPING.get(_subject(rule), set())
    assert not unmapped, f"{_subject(rule)} reads {unmapped}, mapped: {mapped}"


@pytest.mark.parametrize(
    "rule",
    [r for r in RULES if r.status == "catalogue-only"],
    ids=_subject,
)
def test_catalogue_only_has_a_reason(rule: SpecRule) -> None:
    rows = ROWS[_subject(rule)]
    gap = any(r["comment"].startswith("GAP") for r in rows)
    # Rules not yet reviewed (infrastructure, KPIs, some security elements).
    unreviewed = rule.spec_category in {
        "infrastructure",
        "security-properties",
        "key-performance-indicators",
    }
    assert gap or unreviewed, f"{_subject(rule)} could be checked"
