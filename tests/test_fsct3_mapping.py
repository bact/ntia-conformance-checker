# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests that the fsct3 rules agree with the FSCT 2024 -> SPDX 3.0.1 mapping."""

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

MAPPING = Path(__file__).parent / "data" / "fsct2024-to-spdx30.sssom.tsv"
#: Rule id (without the prefix) -> mapping subject, in the ontology's order.
SUBJECTS = {
    "META-001": "author-name",
    "META-002": "timestamp",
    "META-003": "sbom-type",
    "META-004": "primary-component",
    "META-005": "dependency-relationship",
    "COMP-001": "name",
    "COMP-002": "version",
    "COMP-003": "supplier",
    "COMP-004": "unique-identifier",
    "COMP-005": "cryptographic-hash",
    "COMP-006": "relationship",
    "COMP-007": "concluded-license",
    "COMP-008": "copyright-notice",
}
#: The checker's element name -> the SPDX 3 property it reads.
ATTRIBUTES = {
    "author": "createdBy",
    "timestamp": "created",
    "sbom_type": "sbomType",
    "dependency_relationship": "dependsOn",
    "name": "name",
    "version": "packageVersion",
    "supplier": "suppliedBy",
    "unique_identifier": "packageUrl",
    "concluded_license": "hasConcludedLicense",
    "copyright_notice": "copyrightText",
}
#: Rules that are listed and never checked, and why.
CATALOGUE_ONLY = {
    "META-004": "primary component: not yet probed",
    "COMP-005": "hash: the mapping is only close (verifiedUsing)",
    "COMP-006": "relationship and completeness: not yet probed",
}


def _load() -> dict[str, list[dict[str, str]]]:
    with MAPPING.open(encoding="utf-8") as f:
        lines = (line for line in f if not line.startswith("#"))
        rows: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in csv.DictReader(lines, delimiter="\t"):
            rows[row["subject_id"].split(":", 1)[1]].append(row)
    return rows


SPEC = get_spec("fsct3")
ROWS = _load()
RULES = {SPEC.rule_id(r).split("-", 2)[2]: r for r in SPEC.rules}


def _mapped_names(rows: list[dict[str, str]]) -> set[str]:
    return {r["object_id"].split(":", 1)[1].split("/")[-1] for r in rows}


def test_rules_and_mapping_subjects_match() -> None:
    assert set(RULES) == set(SUBJECTS)
    assert set(SUBJECTS.values()) == set(ROWS)


@pytest.mark.parametrize("rule_id", sorted(SUBJECTS))
def test_probe_reads_a_mapped_property(rule_id: str) -> None:
    rule: SpecRule = RULES[rule_id]
    if rule.status == "catalogue-only":
        return
    assert rule.probe is not None
    attribute = rule.probe.params["attribute"]
    assert ATTRIBUTES[attribute] in _mapped_names(ROWS[SUBJECTS[rule_id]])


def test_catalogue_only_rules_are_the_listed_ones() -> None:
    assert {k for k, r in RULES.items() if r.status == "catalogue-only"} == set(
        CATALOGUE_ONLY
    )
