---
SPDX-FileContributor: Arthit Suriyawongkul
SPDX-FileCopyrightText: 2026-present SPDX contributors
SPDX-FileType: DOCUMENTATION
SPDX-License-Identifier: Apache-2.0
---

# Declarative rule files

- Each `*.yaml` in this directory defines one compliance standard loaded by
  `registry.py` at import time;
  - dropping a new `<spec_id>.yaml` here is all that is needed to add
    a standard.
- [`g7ai.md`](g7ai.md), [`cisa2026.md`](cisa2026.md) and
  [`fsct3.md`](fsct3.md) list what those rules check.
- Files prefixed with `_` (e.g. [`_example.yaml`](_example.yaml)) are skipped
  by the registry and not shipped.

## Probes

A rule's `probe` names a registered probe and its `params`; the loader rejects
an unknown probe, parameter, property, relationship type or vocabulary value.

| Probe | Passes when |
|---|---|
| `require_component_attribute`, `require_document_attribute` | every component (the document) has the element (`attribute`) |
| `require_property` | every component of `kind` declares one of `properties`; `name/value` asks for one value of a vocabulary property (`externalRef/vcs`, `externalIdentifier/cpe23`, `software_primaryPurpose/container`) |
| `require_relationship` | every component of `kind` is the `from` (or, with `direction: to`, a target) of one of `relationships`; `completeness: true` counts only a relationship that declares its completeness, `target_has` only one to a target with one of those properties |
| `require_hash` | every component of `kind` has a `Hash`, of one of `algorithms` when given |
| `require_contact`, `require_document_contact` | an agent in `properties` (`originatedBy`, `suppliedBy`; `createdBy`) is a person or organization with an email address or a URL |
| `require_document_property` | the document or its creation info declares one of `properties` |

`require_property` and `require_hash` take `via`: relationship types through
which the value may also be on an element the component links to (a
distribution artifact through `hasDistributionArtifact`, for example).

## Conditional requirements

A requirement that holds only "if it exists" sets `applies_when` to a probe,
written like `probe`: the rule applies only to the components (or the
document) that probe finds nothing on, and is `not-applicable` when that
excludes every component. The condition is on the rule's `kind` or on the
document, and cannot be an attribute probe. When the condition and the probe
are the same (a YAML anchor: `probe: &p {...}`, `applies_when: *p`), the rule
is `present` where the element is given and `not-applicable` where it is not:
the SBOM cannot show that something exists without giving it.

## Provisions

`provision` is `requirement` (blocks conformance), `recommendation` or
`permission` (reported, never blocking). A conditional requirement is a
`requirement` with `applies_when`.
