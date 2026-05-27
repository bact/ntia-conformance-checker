# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Generic per-element specification for compliance checkers.

Defines :class:`Spec`, a small frozen dataclass that describes one
minimum-element check.  Compliance checkers use a tuple of ``Spec`` entries
as a single source of truth for the element's identifier, instance attribute,
report label, result kind, optional cluster grouping, SPDX-spec applicability,
JSON output mapping, and getter method.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True, kw_only=True)
# pylint: disable=too-many-instance-attributes
class Spec:
    """Per-element check specification, reusable across compliance checkers.

    ``cluster`` is optional: cluster-agnostic checkers (e.g. NTIA, FSCT3) leave
    it as the empty default.  Cluster-aware checkers (e.g. G7) set it on every
    entry; rendering code that iterates clusters simply skips entries whose
    ``cluster`` does not match.
    """

    key: str
    """Element identifier.  For ``kind == "list"`` entries this matches a key
    in :attr:`BaseChecker._COMPONENTS_WITHOUT_INFO`."""

    attr: str
    """Instance attribute on the checker that holds the result."""

    label: str
    """Exact table label used in text/HTML reports."""

    kind: Literal["list", "bool"]
    """``"list"``: attribute is a list of missing items (passes if empty).
    ``"bool"``: attribute is a boolean flag (passes if truthy)."""

    cluster: str = ""
    """Optional cluster name.  Falsy means the element belongs to no cluster."""

    spdx3_only: bool = False
    """If True, the element is omitted from cluster tables when the SBOM is
    not SPDX 3.  The attribute still exists with its class-level default."""

    json_group: str | None = None
    """JSON output group name (e.g. ``"aiPackages"``).  ``None`` means the
    entry, if emitted, lives at the top level of the JSON output."""

    json_key: str | None = None
    """JSON output key within ``json_group``.  ``None`` means the entry is
    not emitted in JSON output."""

    getter: str | None = None
    """Method name to call from the checker's ``__init__`` to populate
    ``attr``.  ``None`` if the base class already sets the attribute."""
