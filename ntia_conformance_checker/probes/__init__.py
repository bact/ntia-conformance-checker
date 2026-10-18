# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026-present SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Probe registry and built-in probe implementations.

A *probe* is a small, registered Python function that answers one yes/no
question about a parsed SBOM (e.g. "do all components have a supplier?").
Rules declared in ``rules/*.yaml`` reference probes by name; the engine
calls them and collects :class:`Finding` objects.

Importing :mod:`ntia_conformance_checker.probes` registers every built-in
probe as a side effect:

* :file:`probes/presence.py` -- ``require_component_attribute`` and
  ``require_document_attribute``, which cover every active NTIA and FSCT rule.
* :file:`probes/spdx3.py` -- SPDX 3 probes scoped to a kind of component:
  ``require_property`` (one of some properties), ``require_relationship``
  (in one of some relationships), ``require_hash`` (a ``Hash`` with a
  non-blank algorithm and value, optionally of given ``algorithms``), and
  ``require_document_property``.
"""

from __future__ import annotations

# Import side-effect: register built-in probes by importing their modules.
from . import presence, spdx3  # noqa: F401  (registration only)
from ._registry import attribute_scope, lookup, probe, registered_names, validator

__all__ = ["attribute_scope", "lookup", "probe", "registered_names", "validator"]
