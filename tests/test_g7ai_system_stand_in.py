# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""A project that ships one AI model and no system of its own is judged by the
model for the System-level properties (G7 ``SLP``)."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

from ntia_conformance_checker.main import main
from ntia_conformance_checker.rule_based_checker import RuleBasedChecker

if TYPE_CHECKING:
    from collections.abc import Callable

DATA = Path(__file__).parent / "data"
G7 = DATA / "spdx3" / "g7ai" / "conformant.json"
SPDX2 = str(DATA / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json")
B = "https://spdx.org/spdxdocs/g7ai-tests/"
P = "BOM-G7AI2026-"
Graph = list[dict[str, Any]]


def _el(graph: Graph, name: str) -> dict[str, Any]:
    return next(e for e in graph if e.get("spdxId") == B + name)


def _project_root(graph: Graph) -> None:
    """The root is a plain software package: no system of its own."""
    system = _el(graph, "System1")
    system["type"] = "software_Package"
    for key in [k for k in system if k.startswith("ai_")]:
        del system[key]


def _model_is_a_root_too(graph: Graph) -> None:
    """The shape Pitloom writes: the project and its model are both roots."""
    _project_root(graph)
    _el(graph, "SBOM1")["rootElement"].append(B + "Model1")


def _ai_system_and_a_package(graph: Graph) -> None:
    """A real AI system (an AI application) beside a plain package: the
    application is the system, not the model."""
    _el(graph, "SBOM1")["rootElement"].append(B + "Tool2")


def _drop_model_prop(graph: Graph) -> None:
    _project_root(graph)
    del _el(graph, "Model1")["ai_useSensitivePersonalInformation"]


def _second_model(graph: Graph) -> None:
    _project_root(graph)
    other = copy.deepcopy(_el(graph, "Model1"))
    other["spdxId"] = B + "Model2"
    other["name"] = "Second Model"
    graph.append(other)
    _el(graph, "Rel-contains-model")["to"].append(B + "Model2")


def _unreachable_model(graph: Graph) -> None:
    _project_root(graph)
    _el(graph, "Rel-contains-model")["to"] = [B + "Tool2"]
    # The model is still the dataset's trainer, but nothing leads to it.
    _el(graph, "Rel-trainedOn")["from"] = B + "Model1"


def _not_a_model(graph: Graph) -> None:
    _project_root(graph)
    _el(graph, "Model1")["software_primaryPurpose"] = "application"


def _check(tmp_path: Path, edit: Callable[[Graph], None]) -> RuleBasedChecker:
    doc = json.loads(G7.read_text(encoding="utf-8"))
    graph = copy.deepcopy(doc["@graph"])
    edit(graph)
    doc["@graph"] = graph
    path = tmp_path / "g7.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return RuleBasedChecker(str(path), compliance="g7ai", sbom_spec="spdx3")


_MODEL = ("Test AI Model", B + "Model1")


@pytest.mark.parametrize(
    ("edit", "stand_in", "slp_007"),
    [
        (lambda g: None, None, "present"),  # the root is an AI package
        (_project_root, _MODEL, "present"),
        (_model_is_a_root_too, _MODEL, "present"),
        (_ai_system_and_a_package, None, "missing"),  # no stand-in: the roots stay
        (_drop_model_prop, _MODEL, "missing"),  # the model's gap, not the root's
        (_second_model, None, "missing"),  # which one is not for us to guess
        (_unreachable_model, None, "missing"),
        (_not_a_model, None, "missing"),  # an application is not a model
    ],
    ids=[
        "ai-root", "one-model", "model-also-a-root", "ai-system-and-package",
        "model-lacks-it", "two-models", "unreachable", "app",
    ],  # fmt: skip
)
def test_the_system_rules_read_the_model_only_when_it_is_the_one(
    tmp_path: Path,
    edit: Callable[[Graph], None],
    stand_in: tuple[str, str] | None,
    slp_007: str,
) -> None:
    checker = _check(tmp_path, edit)
    assert checker.system_judged_by_model() == stand_in
    assert checker.rule_outcomes()[P + "SLP-007"] == slp_007
    assert checker.output_json()["systemJudgedByModel"] == (
        stand_in[0] if stand_in else None
    )
    run = checker.output_sarif()["runs"][0]
    assert run["properties"]["systemJudgedByModel"] == (
        stand_in[0] if stand_in else None
    )


def test_a_finding_names_the_model_it_judged(tmp_path: Path) -> None:
    checker = _check(tmp_path, _drop_model_prop)
    (finding,) = checker.rule_results()[P + "SLP-007"].findings
    assert (finding.component_name, finding.component_id) == _MODEL


def test_relationship_rules_still_read_the_root(tmp_path: Path) -> None:
    """The root holds the model and its dependencies: SLP-002 is its."""
    outcomes = _check(tmp_path, _project_root).rule_outcomes()
    assert outcomes[P + "SLP-002"] == "present"


def test_an_spdx2_sbom_has_no_stand_in() -> None:
    checker = RuleBasedChecker(SPDX2, compliance="g7ai", sbom_spec="spdx2")
    assert checker.system_judged_by_model() is None


def test_the_json_report_of_the_cli_carries_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    doc = json.loads(G7.read_text(encoding="utf-8"))
    _project_root(doc["@graph"])
    path = tmp_path / "g7.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["sbomcheck", "-s", "spdx3", "-c", "g7ai", "-r", "json", str(path)]
    )
    with pytest.raises(SystemExit):  # the exit code is the verdict
        main()
    report = json.loads(capsys.readouterr().out)
    assert report["systemJudgedByModel"] == "Test AI Model"
