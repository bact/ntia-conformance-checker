# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""CLI robustness: bad SPDX 3 content, failed report writes, HTML escaping."""

# pylint: disable=missing-function-docstring

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from ntia_conformance_checker.main import main
from ntia_conformance_checker.rule_based_checker import RuleBasedChecker

CISA = Path(__file__).parent / "data" / "spdx3" / "cisa2026" / "conformant.json"
B = "https://spdx.org/spdxdocs/cisa2026-tests/"


def _doc() -> dict[str, Any]:
    return copy.deepcopy(json.loads(CISA.read_text(encoding="utf-8")))


def _write(tmp_path: Path, doc: Any, name: str = "s.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _run(monkeypatch: pytest.MonkeyPatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["sbomcheck", *argv])
    with pytest.raises(SystemExit) as exc:
        main()
    return int(exc.value.code or 0)


def _no_spdx_id(doc: dict[str, Any]) -> None:
    del doc["@graph"][1]["spdxId"]


def _unknown_type(doc: dict[str, Any]) -> None:
    doc["@graph"][1]["type"] = "NotAnSpdxType"


def _graph_is_a_dict(doc: dict[str, Any]) -> None:
    doc["@graph"] = {}


def _abstract_type(doc: dict[str, Any]) -> None:
    doc["@graph"][6]["type"] = "software_SoftwareArtifact"


def _tool_as_author(doc: dict[str, Any]) -> None:
    doc["@graph"][0]["createdBy"] = [B + "Tool1"]


@pytest.mark.parametrize(
    "damage",
    [_no_spdx_id, _unknown_type, _graph_is_a_dict, _tool_as_author, _abstract_type],
    ids=lambda f: f.__name__.strip("_"),
)
def test_spdx3_content_that_parses_as_json_is_a_parsing_error(
    tmp_path: Path, damage: Any
) -> None:
    """Not a traceback: the checker reports a parsing error and checks nothing."""
    doc = _doc()
    damage(doc)
    checker = RuleBasedChecker(
        str(_write(tmp_path, doc)), compliance="cisa2026", sbom_spec="spdx3"
    )
    assert checker.doc is None
    assert checker.parsing_errors
    assert checker.check_compliance() is False


def test_a_failed_report_write_is_not_a_pass(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A CI job must not read a missing report as success."""
    target = str(tmp_path / "no-such-dir" / "out")
    for kind in ("sarif", "json", "html"):
        code = _run(
            monkeypatch,
            "-s",
            "spdx3",
            "-c",
            "cisa2026",
            "-r",
            kind,
            "-o",
            target,
            str(CISA),
        )
        assert code == 2, kind


def test_html_report_escapes_names_and_errors(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    doc = _doc()
    lib = next(e for e in doc["@graph"] if e.get("spdxId") == B + "Lib")
    lib["name"] = "<script>alert(1)</script>"
    del lib["software_packageVersion"]
    path = _write(tmp_path, doc, "<img src=x onerror=alert(2)>.json")
    out = tmp_path / "r.html"
    _run(
        monkeypatch,
        "-s",
        "spdx3",
        "-c",
        "cisa2026",
        "-v",
        "-r",
        "html",
        "-o",
        str(out),
        str(path),
    )
    html = out.read_text(encoding="utf-8")
    assert "<script>alert" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html  # the name is shown, escaped
    capsys.readouterr()


def test_sbom_type_is_found_when_the_sbom_is_not_the_first_root(
    tmp_path: Path,
) -> None:
    doc = _doc()
    document = next(e for e in doc["@graph"] if e["type"] == "SpdxDocument")
    document["rootElement"] = [B + "App", B + "SBOM1"]
    checker = RuleBasedChecker(
        str(_write(tmp_path, doc)), compliance="cisa2026", sbom_spec="spdx3"
    )
    assert checker.rule_outcomes()["BOM-CISA2026-META-005"] == "present"


def test_sbom_type_is_missing_when_no_root_is_an_sbom(tmp_path: Path) -> None:
    doc = _doc()
    document = next(e for e in doc["@graph"] if e["type"] == "SpdxDocument")
    document["rootElement"] = [B + "App"]
    checker = RuleBasedChecker(
        str(_write(tmp_path, doc)), compliance="cisa2026", sbom_spec="spdx3"
    )
    assert checker.rule_outcomes()["BOM-CISA2026-META-005"] == "missing"
