# SPDX-FileCopyrightText: 2024-2025 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests for SbomChecker.get_components_without_identifiers"""

# pylint: disable=missing-function-docstring,import-error,consider-using-from-import

from typing import Any
from unittest.mock import MagicMock

import pytest
from spdx_python_model.bindings import v3_0_1 as spdx3

import ntia_conformance_checker.sbom_checker as sbom_checker
from ntia_conformance_checker.adapters import Spdx2Adapter, Spdx3Adapter

_ID = "http://example.com/spdx3/pkg"
_TYPES = spdx3.ExternalIdentifierType.NAMED_INDIVIDUALS


def _external(kind: str, value: str = "x") -> dict[str, Any]:
    return {
        "externalIdentifier": [
            spdx3.ExternalIdentifier(
                externalIdentifierType=_TYPES[kind], identifier=value
            )
        ]
    }


@pytest.mark.parametrize(
    ("props", "missing"),
    [
        ({}, True),  # the spdxId every element has does not count
        ({"software_packageUrl": "pkg:pypi/a@1"}, False),
        ({"software_packageUrl": "  "}, True),
        ({"software_packageUrl": "NOASSERTION"}, True),
        (
            {
                "software_contentIdentifier": [
                    spdx3.software_ContentIdentifier(
                        software_contentIdentifierType=(
                            spdx3.software_ContentIdentifierType.gitoid
                        ),
                        software_contentIdentifierValue="gitoid:blob:sha1:" + "a" * 40,
                    )
                ]
            },
            False,
        ),
        *[
            (_external(kind), False)
            for kind in ("packageUrl", "cpe22", "cpe23", "swid", "swhid", "gitoid")
        ],
        (_external("packageUrl", " "), True),
        *[(_external(kind), True) for kind in ("urlScheme", "email", "cve", "other")],
    ],
    ids=lambda v: v if isinstance(v, bool) else "-".join(map(str, v)) or "spdxId",
)
def test_get_components_without_identifiers_spdx3(
    props: dict[str, Any], missing: bool
) -> None:
    """A package needs a package URL, a content identifier or an identifying
    external identifier; a urlScheme names a resource, not the component."""
    doc_set = spdx3.SHACLObjectSet()
    doc_set.add(spdx3.software_Package(_id=_ID, name="pkg", **props))
    doc_set.add(spdx3.Agent(_id="http://example.com/spdx3/agent1", name="agent1"))
    adapter = Spdx3Adapter(doc_set, None)

    reachable = {_ID, "http://example.com/spdx3/agent1"}
    assert adapter.get_components_without_identifiers(reachable) == (
        [("pkg", _ID)] if missing else []
    )
    # A package not reachable from the root is not evaluated.
    assert adapter.get_components_without_identifiers(set()) == []


def test_get_components_without_identifiers_spdx2() -> None:
    """Test get_components_without_identifiers with SPDX 2 documents."""
    checker = sbom_checker.SbomChecker("", validate=False, sbom_spec="spdx2")
    doc = MagicMock()
    pkg1 = MagicMock()
    pkg1.name = "pkg1"
    pkg1.spdx_id = "SPDXRef-Package1"

    pkg_no_id = MagicMock()
    pkg_no_id.name = "pkg-no-id"
    pkg_no_id.spdx_id = None

    pkg_empty_id = MagicMock()
    pkg_empty_id.name = "pkg-empty-id"
    pkg_empty_id.spdx_id = "   "

    doc.packages = [pkg1, pkg_no_id, pkg_empty_id]
    checker.doc = doc
    checker.reachable_component_ids = {"SPDXRef-Package1"}
    checker.adapter = Spdx2Adapter(doc)

    assert checker.get_components_without_identifiers() == [
        ("pkg-no-id", ""),
        ("pkg-empty-id", "   "),
    ]
