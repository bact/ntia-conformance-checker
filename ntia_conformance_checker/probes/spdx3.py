# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Probes that read SPDX 3 properties, relationships and hashes.

They let a rule say which SPDX 3 property a kind of component must carry
(for example ``ai_typeOfModel`` on an AI package) without new Python.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from spdx_python_model.bindings import v3_0_1 as spdx3

from ..model import COMPONENT_KINDS, Finding
from ..spdx3_utils import SPDX3_RELATIONSHIP_TYPES
from ._registry import CheckerProtocol, probe

if TYPE_CHECKING:
    from collections.abc import Iterable


_KIND_CLASSES: dict[str, tuple[type, ...]] = {
    "component": (spdx3.software_Package,),
    "ai_model": (spdx3.ai_AIPackage,),
    "dataset": (spdx3.dataset_DatasetPackage,),
    # The system is whatever the SBOM describes, so any of these.
    "system": (
        spdx3.software_Package,
        spdx3.ai_AIPackage,
        spdx3.dataset_DatasetPackage,
    ),
}


def _names(params: dict[str, Any], key: str) -> list[str]:
    """A param that must be a non-empty list of strings."""
    value = params.get(key)
    if (
        not isinstance(value, list)
        or not value
        or not all(isinstance(v, str) for v in value)
    ):
        raise ValueError(f"{key!r} must be a non-empty list of strings; got {value!r}")
    return value


def _kind(params: dict[str, Any]) -> str:
    kind = params.get("kind")
    if kind not in COMPONENT_KINDS:
        raise ValueError(
            f"kind must be one of {sorted(COMPONENT_KINDS)!r}; got {kind!r}"
        )
    return str(kind)


def _validate_property(params: dict[str, Any]) -> None:
    classes = _KIND_CLASSES[_kind(params)]
    for prop in _names(params, "properties"):
        if not any(hasattr(cls, prop) for cls in classes):
            raise ValueError(
                f"unknown SPDX 3 property {prop!r} for kind {params['kind']!r}"
            )


def _validate_relationship(params: dict[str, Any]) -> None:
    _kind(params)
    unknown = sorted(set(_names(params, "relationships")) - SPDX3_RELATIONSHIP_TYPES)
    if unknown:
        raise ValueError(f"unknown SPDX 3 relationship type(s) {unknown!r}")
    if params.get("direction", "from") not in ("from", "to"):
        raise ValueError(
            f"direction must be 'from' or 'to'; got {params['direction']!r}"
        )


_HASH_ALGORITHMS = frozenset(a.lower() for a in spdx3.HashAlgorithm.NAMED_INDIVIDUALS)


def _validate_hash(params: dict[str, Any]) -> None:
    _kind(params)
    if "algorithms" in params:
        unknown = sorted(
            a for a in _names(params, "algorithms") if a.lower() not in _HASH_ALGORITHMS
        )
        if unknown:
            raise ValueError(f"unknown SPDX 3 hash algorithm(s) {unknown!r}")


def _validate_document_property(params: dict[str, Any]) -> None:
    for prop in _names(params, "properties"):
        if not any(
            hasattr(cls, prop) for cls in (spdx3.SpdxDocument, spdx3.CreationInfo)
        ):
            raise ValueError(f"unknown SPDX 3 document property {prop!r}")


@probe("require_property", validate=_validate_property)
def require_property(
    checker: CheckerProtocol, *, kind: str, properties: list[str]
) -> Iterable[Finding]:
    """Require every component of ``kind`` to declare one of ``properties``.

    Args:
        checker: the running checker instance.
        kind: a component kind from
            :data:`ntia_conformance_checker.model.COMPONENT_KINDS`.
        properties: SPDX 3 property names (e.g. ``["ai_typeOfModel"]``); a
            component passes when it declares at least one.
    """
    for name, spdx_id in checker.components_without_property(kind, tuple(properties)):
        yield Finding(component_id=spdx_id or "", component_name=name or "")


@probe("require_relationship", validate=_validate_relationship)
def require_relationship(
    checker: CheckerProtocol,
    *,
    kind: str,
    relationships: list[str],
    direction: str = "from",
) -> Iterable[Finding]:
    """Require every component of ``kind`` to be in one of ``relationships``.

    Args:
        checker: the running checker instance.
        kind: a component kind from
            :data:`ntia_conformance_checker.model.COMPONENT_KINDS`.
        relationships: relationship type names (e.g. ``["dependsOn"]``).
        direction: ``"from"`` if the component is the source of the
            relationship, ``"to"`` if it is a target.
    """
    for name, spdx_id in checker.components_without_relationship(
        kind, tuple(relationships), direction
    ):
        yield Finding(component_id=spdx_id or "", component_name=name or "")


@probe("require_hash", validate=_validate_hash)
def require_hash(
    checker: CheckerProtocol,
    *,
    kind: str = "component",
    algorithms: list[str] | None = None,
) -> Iterable[Finding]:
    """Require every component of ``kind`` to have a hash of itself.

    A component passes when a ``verifiedUsing`` entry is a ``Hash`` with a
    non-blank algorithm and value. Another integrity method, such as a package
    verification code, does not count.

    Args:
        checker: the running checker instance.
        kind: a component kind from
            :data:`ntia_conformance_checker.model.COMPONENT_KINDS`.
        algorithms: SPDX 3 hash algorithm names (e.g. ``["sha512"]``, matched
            case-insensitively); when given, the hash must use one of them.
    """
    for name, spdx_id in checker.components_without_hash(kind, tuple(algorithms or ())):
        yield Finding(component_id=spdx_id or "", component_name=name or "")


@probe("require_document_property", validate=_validate_document_property)
def require_document_property(
    checker: CheckerProtocol, *, properties: list[str]
) -> Iterable[Finding]:
    """Require the SBOM document to declare one of ``properties``.

    Args:
        checker: the running checker instance.
        properties: SPDX 3 property names of the document or its creation info
            (e.g. ``["createdUsing"]``).
    """
    if not checker.document_declares(tuple(properties)):
        yield Finding(component_id="document")
