# SPDX-FileCopyrightText: 2026 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests for checker results when parsing fails."""

from pathlib import Path

import pytest

from ntia_conformance_checker import NTIAChecker
from ntia_conformance_checker.adapters import NullAdapter

DEFAULTS: dict[str, object] = {
    "check_doc_version": False,
    "check_author": False,
    "check_timestamp": False,
    "check_dependency_relationships": False,
    "get_doc_spec_version": None,
    "get_sbom_name": "",
    "get_sbom_types": [],
    "get_total_number_components": 0,
    "get_components_without_names": [],
    "get_components_without_versions": [],
    "get_components_without_suppliers": [],
    "get_components_without_identifiers": [],
    "get_components_without_concluded_licenses": [],
    "get_components_without_copyright_texts": [],
}


@pytest.mark.parametrize("sbom_spec", ["spdx2", "spdx3"])
def test_failed_parse_uses_null_adapter(tmp_path: Path, sbom_spec: str) -> None:
    """Adapter-backed methods return defaults when parsing fails."""
    garbage = tmp_path / "garbage.json"
    garbage.write_text("{not json")

    checker = NTIAChecker(str(garbage), sbom_spec=sbom_spec)

    assert isinstance(checker.adapter, NullAdapter)
    assert {name: getattr(checker, name)() for name in DEFAULTS} == DEFAULTS


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("get_components_without_properties", ("component", ("name",), set())),
        ("get_components_without_hash", ("component", (), set())),
        (
            "get_components_without_relationships",
            ("component", ("dependsOn",), "from", set()),
        ),
    ],
    ids=["properties", "hash", "relationships"],
)
def test_kind_scoped_checks_need_an_spdx3_adapter(
    method: str, args: tuple[object, ...]
) -> None:
    """Only the SPDX 3 adapter reads components of a kind; others refuse."""
    adapter = NullAdapter()
    assert adapter.has_components_of_kind("component", None) is False
    assert adapter.system_stand_in(set()) is None
    with pytest.raises(ValueError, match="cannot check"):
        getattr(adapter, method)(*args)
