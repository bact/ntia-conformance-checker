# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""An SBOM whose only root is an AI model is judged by that model for the
System-level properties (G7 ``SLP``), and the JSON and SARIF reports say so."""

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


def _roots(*names: str) -> Callable[[Graph], None]:
    def edit(graph: Graph) -> None:
        _el(graph, "SBOM1")["rootElement"] = [B + n for n in names]

    return edit


def _model_only(graph: Graph) -> None:
    _roots("Model1")(graph)


def _model_only_lacking_it(graph: Graph) -> None:
    _model_only(graph)
    del _el(graph, "Model1")["ai_useSensitivePersonalInformation"]


def _model_is_a_root_too(graph: Graph) -> None:
    """The shape Pitloom writes: the project and its model are both roots."""
    _project_root(graph)
    _roots("System1", "Model1")(graph)


def _two_models(graph: Graph) -> None:
    other = copy.deepcopy(_el(graph, "Model1"))
    other["spdxId"] = B + "Model2"
    other["name"] = "Second Model"
    graph.append(other)
    _roots("Model1", "Model2")(graph)


def _app_depends_on_model(graph: Graph) -> None:
    """An ordinary application whose dependency is a model."""
    _project_root(graph)
    _el(graph, "System1")["software_primaryPurpose"] = "application"
    _el(graph, "Rel-contains-model")["relationshipType"] = "dependsOn"


def _unset_purpose(graph: Graph) -> None:
    """An AI package with no purpose is a model, as for the ai_model kind."""
    _model_only(graph)
    del _el(graph, "Model1")["software_primaryPurpose"]


def _not_a_model(graph: Graph) -> None:
    _model_only(graph)
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
        (lambda g: None, None, "present"),  # the root is an AI system
        (_model_only, _MODEL, "present"),
        (_model_only_lacking_it, _MODEL, "missing"),  # the model's gap
        (_unset_purpose, _MODEL, "present"),
        (_project_root, None, "missing"),  # a model below a plain root
        (_model_is_a_root_too, None, "missing"),  # a plain root beside it
        (_two_models, None, "present"),  # both roots are judged as the system
        (_app_depends_on_model, None, "missing"),
        (_not_a_model, None, "present"),  # an AI application is a system
    ],
    ids=[
        "ai-system-root", "model-only-root", "model-lacks-it", "unset-purpose",
        "plain-root-model-below", "plain-and-model-roots", "two-models",
        "app-depends-on-model", "ai-application-root",
    ],  # fmt: skip
)
def test_the_system_rules_read_a_model_only_when_it_is_the_only_root(
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
    checker = _check(tmp_path, _model_only_lacking_it)
    (finding,) = checker.rule_results()[P + "SLP-007"].findings
    assert (finding.component_name, finding.component_id) == _MODEL


def test_the_text_and_html_reports_do_not_say_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    checker = _check(tmp_path, _model_only)
    checker.print_table_output(verbose=True)
    text = capsys.readouterr().out + checker.output_html()
    assert "judged" not in text.lower()


def test_an_spdx2_sbom_has_no_stand_in() -> None:
    checker = RuleBasedChecker(SPDX2, compliance="g7ai", sbom_spec="spdx2")
    assert checker.system_judged_by_model() is None


def test_the_json_report_of_the_cli_carries_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    doc = json.loads(G7.read_text(encoding="utf-8"))
    _model_only(doc["@graph"])
    path = tmp_path / "g7.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    monkeypatch.setattr(
        sys, "argv", ["sbomcheck", "-s", "spdx3", "-c", "g7ai", "-r", "json", str(path)]
    )
    with pytest.raises(SystemExit):  # the exit code is the verdict
        main()
    report = json.loads(capsys.readouterr().out)
    assert report["systemJudgedByModel"] == "Test AI Model"


@pytest.mark.parametrize("standard", ["ntia", "fsct3", "cisa2026", "bsi"])
def test_a_standard_without_system_rules_names_no_stand_in(
    tmp_path: Path, standard: str
) -> None:
    doc = json.loads(G7.read_text(encoding="utf-8"))
    _model_only(doc["@graph"])
    path = tmp_path / "g7.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    checker = RuleBasedChecker(str(path), compliance=standard, sbom_spec="spdx3")
    assert checker.system_judged_by_model() is None
    assert checker.output_json()["systemJudgedByModel"] is None
