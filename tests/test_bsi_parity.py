# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Parity of the rule-based BSI checker with the hand-written one it replaced.

``data/bsi_old_checker.json`` records, for every BSI and SPDX 3 fixture, the
verdict of the old ``BSIChecker`` and its result per element. The rule-based
checker must give the same verdict on each, and the same result per element
unless the difference is explained below. ``KNOWN_VERDICT_DIFFERENCES`` lists
the inputs on which the two verdicts differ, and why.
"""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Callable

import pytest

from ntia_conformance_checker.rule_based_checker import RuleBasedChecker

DATA = Path(__file__).parent / "data"
RECORD_FILE = DATA / "bsi_old_checker.json"
RECORD: dict[str, dict[str, Any]] = json.loads(RECORD_FILE.read_text("utf-8"))
FILES = sorted(
    p.relative_to(DATA).as_posix()
    for pattern in ("bsi/*.json", "spdx3/*.json", "spdx3/*/*.json")
    for p in DATA.glob(pattern)
)
P = "BOM-BSI2025-"

#: Old checker attribute -> the rule that checks the same element. The record
#: holds the attribute's result: for a ``components_without_*`` list, true when
#: components were evaluated and none misses the element.
OLD_TO_NEW: dict[str, str | None] = {
    "doc_creator": "DOC-001",
    "doc_timestamp": "DOC-002",
    "doc_uri": "DOC-003",
    "components_without_creators": "COMP-001",
    "components_without_names": "COMP-002",
    "components_without_versions": "COMP-003",
    "components_without_filenames": "COMP-004",
    "dependency_completeness": "COMP-005",
    "components_without_concluded_licenses": "COMP-006",
    "components_without_sha512_hashes": "COMP-007",
    "components_without_executable_prop": "COMP-008",
    "components_without_archive_prop": "COMP-009",
    "components_without_structured_prop": "COMP-010",
    "components_without_source_code_uris": "COMP-011",
    "components_without_deployable_uris": "COMP-012",
    "components_without_unique_identifiers": "COMP-013",
    "components_without_original_licenses": "COMP-014",
    "components_without_effective_licenses": "COMP-015",
    "components_without_source_code_hashes": "COMP-016",
    "components_without_security_txt": "COMP-017",
    # BSI Table 12 "References to another BOM": not an element of the ontology.
    "components_without_bom_references": None,
}

_NOT_CHECKED = "not checked (catalogue-only); see rules/bsi.md"
_CONDITIONAL = (
    "a conditional requirement applies only to the packages that give the "
    "element; the old checker reported every package without it (a "
    "non-blocking warning)"
)
_NO_ARTIFACT = (
    "the old checker skipped a package with no distribution artifact; the rule "
    "needs the value on the package or its distribution artifact"
)
#: (rule, old result, new outcome) -> why they differ, on any file.
EXPLAINED: dict[tuple[str, bool, str], str] = {
    **{
        (rule, old, "out-of-scope"): _NOT_CHECKED
        for rule in ("DOC-003", "COMP-008", "COMP-009", "COMP-016")
        for old in (True, False)
    },
    **{
        (rule, False, "not-applicable"): _CONDITIONAL
        for rule in ("COMP-011", "COMP-012", "COMP-013", "COMP-014")
    },
    ("COMP-014", False, "present"): _CONDITIONAL,
    ("COMP-013", False, "present"): (
        f"{_CONDITIONAL}; and the shared identifier definition also accepts "
        "software_packageUrl, a content identifier, swhid and gitoid, where the "
        "old checker read only an externalIdentifier of type cpe22, cpe23, swid "
        "or packageUrl"
    ),
    ("COMP-005", True, "missing"): (
        "the old check always passed (an absent completeness counted as "
        "noAssertion); BSI Table 9 asks every package to enumerate its "
        "dependencies with a completeness"
    ),
    ("COMP-015", False, "present"): (
        "the mapping reads hasConcludedLicense (a related match); the old "
        "checker read BSI Table 12's other relationship with the comment "
        "hasEffectiveLicense"
    ),
}
#: Differences that hold only where the old checker found no distribution
#: file (its filename element failed), as _NO_ARTIFACT says.
NO_ARTIFACT: set[tuple[str, bool, str]] = {
    ("COMP-007", True, "missing"),
    ("COMP-010", True, "missing"),
    ("COMP-012", True, "not-applicable"),
}
#: (file, rule) -> why, for a difference on one file only.
ON_ONE_FILE: dict[tuple[str, str], str] = {
    ("bsi/compliant_bsi_spdx3.json", "COMP-011"): (
        "the source code URI is given BSI's way (Table 11: a source artifact "
        "that generates the package); the rule reads the mapping's vcs "
        "reference on the package, which this SBOM does not give"
    ),
}


def _new(path: Path) -> RuleBasedChecker:
    return RuleBasedChecker(str(path), compliance="bsi", sbom_spec="spdx3")


def _old_record(path: Path) -> dict[str, Any]:
    """The old checker's verdict and per-element results, as recorded."""
    # pylint: disable-next=import-outside-toplevel
    from ntia_conformance_checker.bsi_checker import BSIChecker

    old = BSIChecker(str(path), sbom_spec="spdx3")
    elements = {
        attr: (
            old._all_provided(getattr(old, attr))  # pylint: disable=protected-access
            if attr.startswith("components_without_")
            else bool(getattr(old, attr))
        )
        for attr in OLD_TO_NEW
    }
    return {
        "conformant": bool(old.doc) and old.check_compliance(),
        "elements": elements,
    }


def test_record_covers_every_fixture_and_element() -> None:
    assert sorted(RECORD) == FILES
    assert all(sorted(r["elements"]) == sorted(OLD_TO_NEW) for r in RECORD.values())


@pytest.mark.parametrize("rel", FILES)
def test_record_is_what_the_old_checker_says(rel: str) -> None:
    assert _old_record(DATA / rel) == RECORD[rel]


@pytest.mark.parametrize("rel", FILES)
def test_verdict_is_the_old_checkers(rel: str) -> None:
    assert _new(DATA / rel).check_compliance() is RECORD[rel]["conformant"]


def _why(rel: str, rule: str, old: bool, new: str) -> str | None:
    """Why the old result and the new outcome differ, or None if unexplained."""
    key = (rule, old, new)
    if key in NO_ARTIFACT:
        no_file = not RECORD[rel]["elements"]["components_without_filenames"]
        return _NO_ARTIFACT if no_file else None
    return EXPLAINED.get(key) or ON_ONE_FILE.get((rel, rule))


@pytest.mark.parametrize("rel", FILES)
def test_elements_agree_or_the_difference_is_explained(rel: str) -> None:
    outcomes = _new(DATA / rel).rule_outcomes()
    unexplained = []
    for attr, rule in OLD_TO_NEW.items():
        if rule is None:
            continue
        old, new = RECORD[rel]["elements"][attr], outcomes[P + rule]
        if new == ("present" if old else "missing"):
            continue
        if _why(rel, rule, old, new) is None:
            unexplained.append(f"{rule}: old {old}, new {new}")
    assert not unexplained


def test_every_explanation_is_used() -> None:
    """No stale explanation: each one accounts for a difference somewhere."""
    used: set[object] = set()
    for rel in FILES:
        outcomes = _new(DATA / rel).rule_outcomes()
        for attr, rule in OLD_TO_NEW.items():
            if rule is not None:
                key = (rule, RECORD[rel]["elements"][attr], outcomes[P + rule])
                used |= {key, (rel, rule)}
    assert {*EXPLAINED, *NO_ARTIFACT, *ON_ONE_FILE} - used == set()


# ---- inputs on which the verdicts differ ----------------------------------

Graph = list[dict[str, Any]]
E = "https://example.com/spdx/"
OK = DATA / "bsi" / "compliant_bsi_spdx3.json"


def _el(graph: Graph, name: str) -> dict[str, Any]:
    return next(e for e in graph if e.get("spdxId") == E + name)


def _no_dependencies(graph: Graph) -> None:
    graph.remove(_el(graph, "rel-deps"))


def _hash_on_package_only(graph: Graph) -> None:
    _el(graph, "package-01")["verifiedUsing"] = _el(graph, "file-01").pop(
        "verifiedUsing"
    )


def _container_on_package_only(graph: Graph) -> None:
    _el(graph, "file-01")["software_additionalPurpose"] = ["executable"]
    _el(graph, "package-01")["software_primaryPurpose"] = "container"


def _creator_url_as_security_other(graph: Graph) -> None:
    _el(graph, "person-01")["externalIdentifier"] = [
        {
            "type": "ExternalIdentifier",
            "externalIdentifierType": "securityOther",
            "identifier": "https://example.com/contact",
        }
    ]


def _license_not_an_expression(graph: Graph) -> None:
    _el(graph, "rel-02")["to"] = ["https://example.com/spdx/elsewhere"]


#: id -> (edit of the compliant fixture, old verdict, new verdict, why)
KNOWN_VERDICT_DIFFERENCES: dict[
    str, tuple[Callable[[Graph], None], bool, bool, str]
] = {
    "no-dependency-list": (
        _no_dependencies,
        True,
        False,
        "COMP-005: a package with no dependsOn or contains relationship gives "
        "no dependency list (BSI Table 9); the fixture as it was before "
        "rel-deps was added",
    ),
    "hash-on-package": (
        _hash_on_package_only,
        False,
        True,
        "COMP-007: the mapping puts the hash in the package's verifiedUsing; "
        "the old checker read the distribution file only",
    ),
    "container-on-package": (
        _container_on_package_only,
        False,
        True,
        "COMP-010: the mapping reads the package's primaryPurpose; the old "
        "checker read the distribution file's additionalPurpose only",
    ),
    "creator-url-as-security-other": (
        _creator_url_as_security_other,
        True,
        False,
        "DOC-001, COMP-001: a URL is an urlScheme or other identifier (BSI "
        "Tables 8, 9); the old checker matched 'other' as a substring of "
        "securityOther",
    ),
    "license-target-elsewhere": (
        _license_not_an_expression,
        False,
        True,
        "COMP-006: a license target that is not in the document counts, as "
        "for FSCT 2024 and CISA 2026; the old checker needed a "
        "LicenseExpression in the document",
    ),
}


def _write(tmp_path: Path, edit: Callable[[Graph], None]) -> Path:
    doc = json.loads(OK.read_text(encoding="utf-8"))
    doc["@graph"] = copy.deepcopy(doc["@graph"])
    edit(doc["@graph"])
    path = tmp_path / "bsi.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("edit", "old", "new", "why"),
    KNOWN_VERDICT_DIFFERENCES.values(),
    ids=KNOWN_VERDICT_DIFFERENCES.keys(),
)
def test_known_verdict_differences(
    tmp_path: Path, edit: Callable[[Graph], None], old: bool, new: bool, why: str
) -> None:
    path = _write(tmp_path, edit)
    assert why and old is not new
    assert _old_record(path)["conformant"] is old
    assert _new(path).check_compliance() is new
