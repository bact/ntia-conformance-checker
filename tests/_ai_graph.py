# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Graph edits shared by the cisa2026 and fsct3 tests: a model and a dataset."""

from __future__ import annotations

from typing import Any, Callable

B = "https://spdx.org/spdxdocs/cisa2026-tests/"
Edit = Callable[[list[dict[str, Any]]], None]


def _package(kind: str, name: str) -> dict[str, Any]:
    """A package with every field the cisa2026 and fsct3 component rules read."""
    return {
        "type": kind,
        "spdxId": B + name,
        "creationInfo": "_:ci",
        "name": name.lower(),
        "software_packageVersion": "1.0",
        "software_packageUrl": f"pkg:generic/{name.lower()}@1.0",
        "originatedBy": [B + "Org1"],
        "suppliedBy": B + "Org1",
        "software_copyrightText": "Copyright Example Org",
        "verifiedUsing": [
            {"type": "Hash", "algorithm": "sha256", "hashValue": "ab" * 32}
        ],
    }


def _relationship(rel: str, src: str, dst: str) -> dict[str, Any]:
    return {
        "type": "Relationship",
        "spdxId": f"{B}Rel-{src}-{rel}-{dst}",
        "creationInfo": "_:ci",
        "relationshipType": rel,
        "from": B + src,
        "to": [B + dst],
    }


def add_model_and_dataset(link: str | None, *dropped: str) -> Edit:
    """Add a model the root ``App`` contains and a dataset ``Data``, linked from
    the model by ``link`` (``None``: not linked), without the ``dropped``
    dataset properties."""

    def edit(graph: list[dict[str, Any]]) -> None:
        model = _package("ai_AIPackage", "Model")
        data = _package("dataset_DatasetPackage", "Data")
        for prop in dropped:
            data.pop(prop)
        graph += [model, data, _relationship("contains", "App", "Model")]
        graph += [
            _relationship(lic, name, "MIT")
            for name in ("Model", "Data")
            for lic in ("hasDeclaredLicense", "hasConcludedLicense")
        ]
        if link:
            graph.append(_relationship(link, "Model", "Data"))

    return edit
