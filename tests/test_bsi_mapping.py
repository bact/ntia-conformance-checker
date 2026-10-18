# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests that the bsi rules agree with the BSI TR-03183-2 -> SPDX 3.0.1 mapping."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import csv
import re
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ntia_conformance_checker import get_spec
from ntia_conformance_checker.adapters.spdx3_adapter import (
    IDENTIFIER_PROPERTIES,
    IDENTIFIER_TYPES,
)

if TYPE_CHECKING:
    from ntia_conformance_checker.spec import SpecRule

DATA = Path(__file__).parent / "data"
MAPPING = DATA / "bsi2025-to-spdx30.sssom.tsv"
ONTOLOGY = DATA / "bsi2025.ttl"
_SLUG = ("bsi-", "-missing")
#: The checker's element name -> the SPDX 3 property it reads.
_ATTRIBUTES = {"timestamp": "created", "name": "name", "version": "packageVersion"}
#: What a rule reads beyond the mapping, and where BSI TR-03183-2 v2.1.0 says so.
BEYOND = {
    # Table 9: the deployable file is a software_File, linked to the package by
    # hasDistributionArtifact, carrying the hash and the BSI purposes.
    "component-hash-deployable": {"hasDistributionArtifact"},
    # Table 9: "firmware" marks a file that is not structured; the mapping has
    # no carrier for "unstructured" (GAP).
    "is-structured": {"firmware", "hasDistributionArtifact"},
    # Table 11: the URI of the deployable form, on the distribution file.
    "component-distribution-uri": {"binaryArtifact", "hasDistributionArtifact"},
    # Table 9 and the mapping's own comment: "contains for the inclusion reading".
    "component-dependencies": {"contains"},
    # Table 12: security.txt as an externalRef of type securityOther.
    "component-security-txt": {"securityOther"},
    # The identifier definition shared with NTIA, FSCT 2024 and CISA 2026.
    "component-identifiers": {"contentIdentifier"},
}
#: Rules that are listed and never checked, and why.
CATALOGUE_ONLY = {
    "doc-uri": "every SPDX 3 element has an spdxId, so a BOM-URI always exists",
    "is-executable": "non-executable is stated by leaving the purpose out",
    "is-archive": "no archive is stated by leaving the purpose out",
    "component-hash-source": "no link from a component to its source artifact",
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


def _local(name: str) -> str:
    """``software_packageUrl`` -> ``packageUrl``; ``externalRef/vcs`` -> ``vcs``."""
    return name.rsplit("/", 1)[-1].removeprefix("software_")


def _properties(rule: SpecRule) -> set[str]:
    """SPDX names (properties, relationship types, values) the probe reads."""
    assert rule.probe is not None
    params = rule.probe.params
    names = {_ATTRIBUTES.get(params.get("attribute", ""), "")} - {""}
    for key in ("properties", "relationships", "target_has", "via", "algorithms"):
        names |= {_local(p) for p in params.get(key, [])}
    if rule.probe.name == "require_hash":
        names.add("verifiedUsing")
    if params.get("completeness"):
        names.add("completeness")
    return names


def _mapped_names(rows: list[dict[str, str]]) -> set[str]:
    """Local names of the SPDX targets and carrier properties of a subject."""
    names = {r["object_id"].split(":", 1)[1].split("/")[-1] for r in rows}
    paths = {
        p.split(":", 1)[-1]
        for r in rows
        for p in (r["object_path"], r["object_property"])
        if p and "[" not in p and not p.startswith("^")
    }
    return names | paths


SPEC = get_spec("bsi")
RULES = SPEC.rules
ROWS = _load()


def test_rules_mapping_and_ontology_have_the_same_twenty_elements() -> None:
    ontology = set(
        re.findall(
            r"^bsi2025:([a-z-]+)\n    a skos:Concept ;",
            ONTOLOGY.read_text("utf-8"),
            re.M,
        )
    )
    assert {_subject(r) for r in RULES} == set(ROWS) == ontology
    assert len(RULES) == 20


def test_rule_ids_are_the_ontology_notations() -> None:
    text = ONTOLOGY.read_text(encoding="utf-8")
    notations = dict(
        re.findall(
            r'^bsi2025:(\S+)\n(?:    .*\n)*?    skos:notation "([^"]+)"', text, re.M
        )
    )
    assert {_subject(r): SPEC.rule_id(r) for r in RULES} == notations


CHECKED = [r for r in RULES if r.status == "active"]


@pytest.mark.parametrize("rule", CHECKED, ids=_subject)
def test_probe_reads_mapped_properties(rule: SpecRule) -> None:
    unmapped = _properties(rule) - _mapped_names(ROWS[_subject(rule)])
    assert unmapped == BEYOND.get(_subject(rule), set())


def test_catalogue_only_rules_are_the_listed_ones() -> None:
    assert {_subject(r) for r in RULES if r.status == "catalogue-only"} == set(
        CATALOGUE_ONLY
    )


def test_conditional_rules_apply_where_their_element_is_given() -> None:
    """Required "if it exists": the condition is the check itself, so such a
    rule is present or not-applicable, never missing."""
    conditional = {_subject(r) for r in RULES if r.applies_when is not None}
    assert conditional == {
        "component-source-uri",
        "component-distribution-uri",
        "component-identifiers",
        "component-original-license",
    }
    assert all(r.applies_when == r.probe for r in RULES if r.applies_when)


def test_identifiers_are_the_shared_definition() -> None:
    rule = next(r for r in RULES if _subject(r) == "component-identifiers")
    assert rule.probe is not None
    assert tuple(rule.probe.params["properties"]) == IDENTIFIER_PROPERTIES
    mapped = _mapped_names(ROWS["component-identifiers"])
    assert set(IDENTIFIER_TYPES) <= mapped
