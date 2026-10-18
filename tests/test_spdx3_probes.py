# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests for SPDX 3 probe parameters, contact probes and conditional rules."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable
from unittest.mock import MagicMock

import pytest
from spdx_python_model.bindings import v3_0_1 as spdx3

from ntia_conformance_checker.adapters import NullAdapter, Spdx2Adapter
from ntia_conformance_checker.adapters.spdx3_adapter import _is_value_named
from ntia_conformance_checker.model import RuleResult
from ntia_conformance_checker.rule_based_checker import RuleBasedChecker
from ntia_conformance_checker.spec import ProbeRef, Spec, SpecCategory, SpecRule
from ntia_conformance_checker.spec_loader import SpecLoadError, load_spec

B = "https://example.com/t/"
CORE = "https://spdx.org/rdf/3.0.1/terms/Core/"
Graph = list[dict[str, Any]]
Edit = Callable[[Graph], None]


def _base() -> Graph:
    """A document whose SBOM root lists two packages, p1 and p2, and a file."""

    def element(kind: str, ident: str, **props: Any) -> dict[str, Any]:
        return {"type": kind, "spdxId": B + ident, "creationInfo": "_:ci", **props}

    return [
        {
            "type": "CreationInfo",
            "@id": "_:ci",
            "specVersion": "3.0.1",
            "createdBy": [B + "person"],
            "created": "2026-01-01T00:00:00Z",
        },
        element("SpdxDocument", "doc", rootElement=[B + "sbom"]),
        element("software_Sbom", "sbom", rootElement=[B + "p1", B + "p2"]),
        element(
            "Person",
            "person",
            name="P",
            externalIdentifier=[
                {
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "email",
                    "identifier": "p@example.com",
                }
            ],
        ),
        element("software_Package", "p1", name="p1", originatedBy=[B + "person"]),
        element("software_Package", "p2", name="p2", originatedBy=[B + "person"]),
        element("software_File", "f1", name="f1.tar"),
    ]


def _el(graph: Graph, name: str) -> dict[str, Any]:
    return next(e for e in graph if e.get("spdxId") == B + name)


def _set(element: str, **props: Any) -> Edit:
    def edit(graph: Graph) -> None:
        _el(graph, element).update(props)

    return edit


def _rel(from_: str, rel_type: str, to: list[str], **props: Any) -> Edit:
    def edit(graph: Graph) -> None:
        graph.append(
            {
                "type": "Relationship",
                "spdxId": f"{B}rel-{from_}-{rel_type}-{len(graph)}",
                "creationInfo": "_:ci",
                "from": B + from_,
                "relationshipType": rel_type,
                "to": [t if ":" in t or t == "NoneElement" else B + t for t in to],
                **props,
            }
        )

    return edit


def _both(*edits: Edit) -> Edit:
    def edit(graph: Graph) -> None:
        for each in edits:
            each(graph)

    return edit


_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"


def _spec(probe: ProbeRef, applies_when: ProbeRef | None = None) -> Spec:
    rule = SpecRule(
        number=1,
        slug="demo-a",
        spec_category="c",
        probe=probe,
        applies_when=applies_when,
    )
    return Spec(
        id="demo",
        title="Demo",
        sbom_specs=("spdx3",),
        categories=(SpecCategory(id="c", code="C", title="C"),),
        rules=(rule,),
    )


def _checker(tmp_path: Path, edit: Edit, spec: Spec) -> RuleBasedChecker:
    graph = _base()
    edit(graph)
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps({"@context": _CONTEXT, "@graph": graph}), "utf-8")
    checker = RuleBasedChecker(str(path), compliance=spec, sbom_spec="spdx3")
    assert not checker.parsing_errors and not checker.has_unknown_pointers
    return checker


def _run(
    tmp_path: Path,
    edit: Edit,
    probe: ProbeRef,
    applies_when: ProbeRef | None = None,
) -> RuleResult:
    checker = _checker(tmp_path, edit, _spec(probe, applies_when))
    return checker.rule_results()["SBOM-DEMO-C-001"]


def _failing(result: RuleResult) -> list[str]:
    return sorted(f.component_id.removeprefix(B) for f in result.findings)


def _prop(*properties: str, via: list[str] | None = None) -> ProbeRef:
    params: dict[str, Any] = {"kind": "component", "properties": list(properties)}
    if via:
        params["via"] = via
    return ProbeRef(name="require_property", params=params)


def _ref(ref_type: str, locator: list[str] | None = None) -> dict[str, Any]:
    ref: dict[str, Any] = {"type": "ExternalRef", "externalRefType": ref_type}
    if locator is not None:
        ref["locator"] = locator
    return ref


# ---- require_property: one value of a vocabulary property, via a link ----

VCS = _prop("externalRef/vcs")
PURPOSE = _prop("software_additionalPurpose/container", via=["hasDistributionArtifact"])


@pytest.mark.parametrize(
    ("probe", "edit", "failing"),
    [
        (VCS, _set("p1", externalRef=[_ref("vcs", ["https://git"])]), ["p2"]),
        # the type must match and the reference must say where
        (VCS, _set("p1", externalRef=[_ref("other", ["https://git"])]), ["p1", "p2"]),
        (VCS, _set("p1", externalRef=[_ref("vcs")]), ["p1", "p2"]),
        (VCS, _set("p1", externalRef=[_ref("vcs", [" "])]), ["p1", "p2"]),
        (
            _prop("externalIdentifier/cpe23"),
            _set(
                "p1",
                externalIdentifier=[
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cpe23",
                        "identifier": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*",
                    }
                ],
            ),
            ["p2"],
        ),
        (
            _prop("software_primaryPurpose/source"),
            _set("p1", software_primaryPurpose="source"),
            ["p2"],
        ),
        (
            _prop("software_primaryPurpose/source"),
            _set("p1", software_primaryPurpose="library"),
            ["p1", "p2"],
        ),
        # via: on the package itself, or on an element it links to
        (PURPOSE, _set("p1", software_additionalPurpose=["container"]), ["p2"]),
        (
            PURPOSE,
            _both(
                _set("f1", software_additionalPurpose=["container"]),
                _rel("p2", "hasDistributionArtifact", ["f1"]),
            ),
            ["p1"],
        ),
        # a file that is not linked, or linked through another relationship
        (PURPOSE, _set("f1", software_additionalPurpose=["container"]), ["p1", "p2"]),
        (
            PURPOSE,
            _both(
                _set("f1", software_additionalPurpose=["container"]),
                _rel("p2", "contains", ["f1"]),
            ),
            ["p1", "p2"],
        ),
    ],
    ids=[
        "vcs",
        "other-type",
        "no-locator",
        "blank-locator",
        "cpe23",
        "purpose",
        "other-purpose",
        "via-self",
        "via-file",
        "unlinked-file",
        "other-link",
    ],
)
def test_require_property_values_and_via(
    tmp_path: Path, probe: ProbeRef, edit: Edit, failing: list[str]
) -> None:
    assert _failing(_run(tmp_path, edit, probe)) == failing


# ---- require_hash via a link --------------------------------------------

_SHA512 = {"type": "Hash", "algorithm": "sha512", "hashValue": "ab" * 64}


@pytest.mark.parametrize(
    ("edit", "failing"),
    [
        (_set("p1", verifiedUsing=[_SHA512]), ["p2"]),
        (
            _both(
                _set("f1", verifiedUsing=[_SHA512]),
                _rel("p1", "hasDistributionArtifact", ["f1"]),
            ),
            ["p2"],
        ),
        (
            _both(
                _set("f1", verifiedUsing=[{**_SHA512, "algorithm": "sha256"}]),
                _rel("p1", "hasDistributionArtifact", ["f1"]),
            ),
            ["p1", "p2"],
        ),
        (_set("f1", verifiedUsing=[_SHA512]), ["p1", "p2"]),
    ],
    ids=["self", "linked-file", "linked-sha256", "unlinked-file"],
)
def test_require_hash_via(tmp_path: Path, edit: Edit, failing: list[str]) -> None:
    probe = ProbeRef(
        name="require_hash",
        params={
            "kind": "component",
            "algorithms": ["sha512"],
            "via": ["hasDistributionArtifact"],
        },
    )
    assert _failing(_run(tmp_path, edit, probe)) == failing


# ---- require_relationship: completeness, target properties ---------------

DEPS = ProbeRef(
    name="require_relationship",
    params={
        "kind": "component",
        "relationships": ["dependsOn", "contains"],
        "completeness": True,
    },
)
FILENAME = ProbeRef(
    name="require_relationship",
    params={
        "kind": "component",
        "relationships": ["hasDistributionArtifact"],
        "target_has": ["name"],
    },
)


@pytest.mark.parametrize(
    ("probe", "edit", "failing"),
    [
        (DEPS, _rel("p1", "dependsOn", ["p2"], completeness="complete"), ["p2"]),
        (DEPS, _rel("p1", "contains", ["p2"], completeness="noAssertion"), ["p2"]),
        (DEPS, _rel("p1", "dependsOn", ["p2"]), ["p1", "p2"]),  # no completeness
        # a component with no dependency says so with NoneElement
        (
            DEPS,
            _both(
                _rel(
                    "p1", "dependsOn", [CORE + "NoneElement"], completeness="complete"
                ),
                _rel("p2", "dependsOn", ["NoneElement"], completeness="complete"),
            ),
            [],
        ),
        (DEPS, _rel("p1", "describes", ["p2"], completeness="complete"), ["p1", "p2"]),
        (FILENAME, _rel("p1", "hasDistributionArtifact", ["f1"]), ["p2"]),
        (
            FILENAME,
            _both(_set("f1", name=" "), _rel("p1", "hasDistributionArtifact", ["f1"])),
            ["p1", "p2"],
        ),
        (FILENAME, _rel("p1", "hasDistributionArtifact", ["p2"]), ["p2"]),
    ],
    ids=[
        "complete",
        "noassertion",
        "no-completeness",
        "none-element",
        "other-type",
        "filename",
        "blank-filename",
        "named-package-target",
    ],
)
def test_require_relationship_completeness_and_target(
    tmp_path: Path, probe: ProbeRef, edit: Edit, failing: list[str]
) -> None:
    assert _failing(_run(tmp_path, edit, probe)) == failing


def test_relationship_without_targets_does_not_count(tmp_path: Path) -> None:
    edit = _rel("p1", "dependsOn", [], completeness="complete")
    assert _failing(_run(tmp_path, edit, DEPS)) == ["p1", "p2"]


def test_relationship_direction_is_checked_by_the_adapter(tmp_path: Path) -> None:
    checker = _checker(tmp_path, lambda graph: None, _spec(DEPS))
    with pytest.raises(ValueError, match="direction"):
        checker.components_without_relationship("component", ("dependsOn",), "up")


def test_target_has_ignores_a_target_missing_from_the_document(
    tmp_path: Path,
) -> None:
    graph_edit = _rel("p1", "hasDistributionArtifact", ["https://example.com/gone"])

    def edit(graph: Graph) -> None:
        graph_edit(graph)
        graph.append(  # keeps the pointer known, so only target_has decides
            {
                "type": "software_File",
                "spdxId": "https://example.com/gone",
                "creationInfo": "_:ci",
            }
        )

    assert _failing(_run(tmp_path, edit, FILENAME)) == ["p1", "p2"]


# ---- contact probes ------------------------------------------------------


def _contact(id_type: str, value: str, agent: str = "Person") -> Edit:
    def edit(graph: Graph) -> None:
        person = _el(graph, "person")
        person["type"] = agent
        person["externalIdentifier"] = [
            {
                "type": "ExternalIdentifier",
                "externalIdentifierType": id_type,
                "identifier": value,
            }
        ]

    return edit


@pytest.mark.parametrize(
    ("edit", "has_contact"),
    [
        (_contact("email", "p@example.com"), True),
        (_contact("email", "p@example.com", agent="Organization"), True),
        (_contact("urlScheme", "https://example.com"), True),
        (_contact("other", "http://example.com"), True),
        (_contact("email", "not-an-address"), False),
        (_contact("other", "just-a-name"), False),
        (_contact("securityOther", "https://example.com"), False),
        (_contact("email", "p@example.com", agent="SoftwareAgent"), False),
        (_set("person", externalIdentifier=[]), False),
    ],
    ids=[
        "email",
        "organization",
        "url-scheme",
        "other-url",
        "email-no-at",
        "other-no-url",
        "security-other",
        "software-agent",
        "none",
    ],
)
def test_contact_probes(tmp_path: Path, edit: Edit, has_contact: bool) -> None:
    component = ProbeRef(
        name="require_contact",
        params={"kind": "component", "properties": ["originatedBy"]},
    )
    document = ProbeRef(
        name="require_document_contact", params={"properties": ["createdBy"]}
    )
    want = "present" if has_contact else "missing"
    assert _run(tmp_path, edit, component).outcome == want
    assert _run(tmp_path, edit, document).outcome == want


def test_contact_needs_the_agent_in_the_document(tmp_path: Path) -> None:
    edit = _both(
        _set("p1", originatedBy=["https://example.com/elsewhere"]),
        _set("p2", originatedBy=[], suppliedBy=B + "person"),
    )
    probe = ProbeRef(
        name="require_contact",
        params={"kind": "component", "properties": ["originatedBy", "suppliedBy"]},
    )
    assert _failing(_run(tmp_path, edit, probe)) == ["p1"]


def test_only_the_spdx3_adapter_reads_contacts() -> None:
    adapter = NullAdapter()
    assert adapter.document_has_contact(("createdBy",)) is False
    with pytest.raises(ValueError, match="cannot check"):
        Spdx2Adapter(MagicMock()).document_has_contact(("createdBy",))
    for method, args in (
        ("get_components_of_kind", ("component", set())),
        ("get_components_without_contact", ("component", ("originatedBy",), set())),
    ):
        with pytest.raises(ValueError, match="cannot check"):
            getattr(adapter, method)(*args)


# ---- applies_when: conditional requirements ------------------------------


@pytest.mark.parametrize(
    ("edit", "outcome", "failing"),
    [
        # neither package has the thing: the rule applies to none
        (lambda graph: None, "not-applicable", []),
        # p1 has it: the rule applies to p1 only
        (_set("p1", externalRef=[_ref("vcs", ["https://git"])]), "present", []),
    ],
    ids=["none-has-it", "one-has-it"],
)
def test_conditional_rule_applies_only_where_the_thing_exists(
    tmp_path: Path, edit: Edit, outcome: str, failing: list[str]
) -> None:
    result = _run(tmp_path, edit, VCS, applies_when=VCS)
    assert (result.outcome, _failing(result)) == (outcome, failing)


def test_condition_can_differ_from_the_probe(tmp_path: Path) -> None:
    """A source URI required of a package that declares a source purpose."""
    condition = _prop("software_primaryPurpose/source")
    edit = _both(
        _set("p1", software_primaryPurpose="source"),
        _set("p2", software_primaryPurpose="source"),
        _set("p2", externalRef=[_ref("vcs", ["https://git"])]),
    )
    result = _run(tmp_path, edit, VCS, applies_when=condition)
    assert (result.outcome, _failing(result)) == ("missing", ["p1"])


@pytest.mark.parametrize(
    ("edit", "outcome"),
    [
        (lambda graph: None, "not-applicable"),
        (_set("doc", comment="a comment"), "missing"),
    ],
    ids=["document-lacks-it", "document-has-it"],
)
def test_document_condition(tmp_path: Path, edit: Edit, outcome: str) -> None:
    condition = ProbeRef(
        name="require_document_property", params={"properties": ["comment"]}
    )
    assert _run(tmp_path, edit, VCS, applies_when=condition).outcome == outcome


# ---- loader validation of the new parameters -----------------------------

_SPEC = """\
spec: {{ id: demo, title: Demo }}
categories: [{{ id: c, code: C, title: C }}]
rules:
  - number: 1
    slug: demo-a
    spec_category: c
    {rule}
"""
_PROPERTY = "probe: {{ name: require_property, params: {{ kind: component, {p} }} }}"


def _load(tmp_path: Path, rule: str) -> Spec:
    path = tmp_path / "demo.yaml"
    path.write_text(_SPEC.format(rule=rule), encoding="utf-8")
    return load_spec(path)


def _p(params: str) -> str:
    return _PROPERTY.format(p=params)


_REL = "probe: { name: require_relationship, params: { kind: component, P } }"
_COND = "\n    applies_when: { name: NAME, params: PARAMS }"

_BAD = {
    "unknown vocabulary value": _p("properties: [externalRef/vcz]"),
    "value on a plain property": _p("properties: [name/x]"),
    "unknown property with value": _p("properties: [externalRefs/vcs]"),
    "unknown via": _p("properties: [name], via: [hasDistribution]"),
    "via not a list": _p("properties: [name], via: hasDistributionArtifact"),
    "hash via unknown": "probe: { name: require_hash, params: { via: [x] } }",
    "completeness not bool": _REL.replace(
        "P", "relationships: [dependsOn], completeness: 'yes'"
    ),
    "target_has with direction to": _REL.replace(
        "P", "relationships: [trainedOn], direction: to, target_has: [name]"
    ),
    "unknown target property": _REL.replace(
        "P", "relationships: [hasDistributionArtifact], target_has: [nam]"
    ),
    "contact on a non-agent property": (
        "probe: { name: require_contact, params: "
        "{ kind: component, properties: [name] } }"
    ),
    "document contact on originatedBy": (
        "probe: { name: require_document_contact, params: "
        "{ properties: [originatedBy] } }"
    ),
    "condition without a probe": "status: catalogue-only"
    + _COND.replace("NAME", "require_property").replace(
        "PARAMS", "{ kind: component, properties: [name] }"
    ),
    "condition with an attribute probe": _p("properties: [name]")
    + _COND.replace("NAME", "require_component_attribute").replace(
        "PARAMS", "{ attribute: name }"
    ),
    "condition on another kind": _p("properties: [name]")
    + _COND.replace("NAME", "require_property").replace(
        "PARAMS", "{ kind: dataset, properties: [name] }"
    ),
    "condition with a bad param": _p("properties: [name]")
    + _COND.replace("NAME", "require_property").replace(
        "PARAMS", "{ kind: component, properties: [nam] }"
    ),
}


@pytest.mark.parametrize("rule", _BAD.values(), ids=_BAD.keys())
def test_loader_rejects_bad_new_params(tmp_path: Path, rule: str) -> None:
    with pytest.raises(SpecLoadError):
        _load(tmp_path, rule)


def test_loader_builds_a_conditional_rule(tmp_path: Path) -> None:
    rule = (
        "probe: &vcs { name: require_property, params: "
        "{ kind: component, properties: [externalRef/vcs], via: [contains] } }"
        "\n    applies_when: *vcs"
    )
    built = _load(tmp_path, rule).rules[0]
    assert built.probe is not None and built.applies_when == built.probe
    assert built.probe.params["via"] == ["contains"]


def test_a_value_object_without_a_type_names_nothing() -> None:
    hash_ = spdx3.Hash(algorithm=spdx3.HashAlgorithm.sha512, hashValue="ab")
    assert not _is_value_named(hash_, "sha512")
    assert _is_value_named(spdx3.ExternalRefType.vcs, "vcs")
