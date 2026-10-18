---
SPDX-FileContributor: Arthit Suriyawongkul
SPDX-FileCopyrightText: 2026-present SPDX contributors
SPDX-FileType: DOCUMENTATION
SPDX-License-Identifier: Apache-2.0
---

# FSCT 2024: what is checked

`-c fsct3` checks an SPDX 3 or SPDX 2 SBOM against the baseline attributes of
[Framing Software Component Transparency, third edition (2024)][fsct]
(minimum expected level). Rule ids and provisions follow the
[SBOM requirements ontology](https://bact.github.io/bom/req/fsct2024/); the SPDX
3.0.1 fields follow its
[mapping](https://bact.github.io/bom/mapping/fsct2024-to-spdx30.sssom.tsv).
Outcomes are reported as for [`g7ai`](g7ai.md).

## Checked

| Rule | Element | What the checker looks for (SPDX 3) |
|---|---|---|
| META-001 | Author Name | `createdBy` |
| META-002 | Timestamp | `created` |
| META-003 | SBOM Type | `software_sbomType` |
| META-005 | Dependency Relationship | at least one `contains`, `dependsOn`, `hasStaticLink` or `hasDynamicLink` relationship in the SBOM, between any two elements (a document-level check, standing in for COMP-006) |
| COMP-001 | Component Name | `name` on every package |
| COMP-002 | Version | `software_packageVersion` on every package |
| COMP-003 | Supplier Name | `suppliedBy` on every package |
| COMP-004 | Unique Identifier | on SPDX 3, the `spdxId` that every element has, so it cannot fail (see Limits) |
| COMP-007 | License | a `hasConcludedLicense` relationship from every package |
| COMP-008 | Copyright Notice | `software_copyrightText` on every package |

A component rule covers the packages reachable from the SBOM root by
composition; a package that is not reachable is not evaluated. COMP-004 on
SPDX 3 is the exception: it looks at every package.

## Not checked (catalogue-only)

Listed in the output, never counted as missing.

| Rule | Element | Why |
|---|---|---|
| META-004 | Primary Component | not yet probed, though the mapping has an exact match (`rootElement`) |
| COMP-005 | Cryptographic Hash | the mapping is only close (`verifiedUsing` holds any integrity method) |
| COMP-006 | Relationship | needs a relationship and a completeness assertion per component; not yet probed |

## Limits

- COMP-004 on SPDX 3 accepts the `spdxId`, which the mapping lists as a close
  match, so a package with no package URL, no external identifier and no content
  identifier still passes. It reports nothing about identifier quality. A
  stricter reading (a package URL or another identifier type) is not applied:
  it would also change the NTIA check, which shares this logic.
- COMP-007 reads `hasConcludedLicense` only. A package with only a
  `hasDeclaredLicense` is reported missing, as the mapping makes the declared
  license a close match, not an exact one.
- A supplier or copyright notice that is blank or `NOASSERTION` counts as
  missing. Other values are not checked for quality.

[fsct]: https://www.cisa.gov/resources-tools/resources/framing-software-component-transparency-2024
