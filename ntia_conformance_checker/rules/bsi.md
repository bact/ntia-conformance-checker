---
SPDX-FileContributor: Arthit Suriyawongkul
SPDX-FileCopyrightText: 2026-present SPDX contributors
SPDX-FileType: DOCUMENTATION
SPDX-License-Identifier: Apache-2.0
---

# BSI TR-03183-2: what is checked

`-c bsi` checks an SPDX 3 SBOM against the SBOM content requirements (section
5.2) of [BSI TR-03183-2 v2.1.0][bsi]. The rules in [`bsi.yaml`](bsi.yaml) take
their ids and provisions from the
[SBOM requirements ontology](https://bact.github.io/bom/req/bsi2025/); the SPDX
fields follow its
[SPDX 3.0.1 mapping](https://bact.github.io/bom/mapping/bsi2025-to-spdx30.sssom.tsv)
and, where the mapping has no carrier, the SPDX 3.0.1 tables of the TR's own
Appendix 8.2 (see "Beyond the mapping"). Outcomes are reported as for
[`g7ai`](g7ai.md). SPDX 2 SBOMs are not covered: every checked rule is
then `not-applicable`.

## Provisions

| Ontology provision | Rules | Effect |
|---|---|---|
| Requirement | DOC-001, DOC-002, COMP-001 to COMP-010 | `missing` makes the SBOM non-conformant |
| Conditional requirement ("if it exists") | COMP-011 to COMP-014 (and DOC-003, not checked) | applies only to the components that give the element (`applies_when`): `present` or `not-applicable` |
| Permission (optional) | COMP-015 to COMP-017 | `present` or `missing`, never blocking |

An SBOM cannot show that something exists without giving it, so a conditional
requirement does not fail: a component without a source code URI is read as
one whose source code URI does not exist. Like every component rule, it is
`missing` only when no component is reachable from the SBOM root.

## Checked

| Rule | Element | What the checker looks for |
|---|---|---|
| DOC-001 | Creator of the SBOM | an agent in `createdBy` that is a `Person` or `Organization` with an `email` external identifier containing `@`, or a `urlScheme` or `other` one starting with `http://` or `https://` |
| DOC-002 | Timestamp | `created` |
| COMP-001 | Component creator | an agent in `originatedBy` of every package, as for DOC-001 |
| COMP-002 | Component name | `name` on every package |
| COMP-003 | Component version | `software_packageVersion` on every package |
| COMP-004 | Filename of the component | a `hasDistributionArtifact` relationship from every package to an element with a `name` |
| COMP-005 | Dependencies on other components | a `dependsOn` or `contains` relationship from every package that declares its `completeness`; a package without dependencies says so with one to `NoneElement` and `completeness` `complete` |
| COMP-006 | Distribution licenses | a `hasConcludedLicense` relationship from every package |
| COMP-007 | Hash value of the deployable component | a SHA-512 `Hash` in `verifiedUsing` of every package, or of an element it links to by `hasDistributionArtifact` |
| COMP-010 | Structured property | `container` (structured) or `firmware` (unstructured) as `software_primaryPurpose` or `software_additionalPurpose` of every package, or of its distribution artifact |
| COMP-011 | Source code URI (if it exists) | an `externalRef` of type `vcs` with a locator |
| COMP-012 | URI of the deployable form (if it exists) | `software_downloadLocation`, or an `externalRef` of type `altDownloadLocation` or `binaryArtifact`, on the package or its distribution artifact |
| COMP-013 | Other unique identifiers (if they exist) | `software_packageUrl`, `software_contentIdentifier`, or an `externalIdentifier` of type packageUrl, cpe22, cpe23, swid, swhid or gitoid (the identifier definition of NTIA, FSCT 2024 and CISA 2026) |
| COMP-014 | Original licenses (if they exist) | a `hasDeclaredLicense` relationship |
| COMP-015 | Effective license (optional) | a `hasConcludedLicense` relationship (a related match) |
| COMP-017 | URL of the security.txt (optional) | an `externalRef` of type `securityPolicy` or `securityOther` |

A component rule covers the packages (AI and dataset packages included)
**reachable from the SBOM root**, the root included, following the composition
and dependency relationships listed in [`cisa2026.md`](cisa2026.md), but not
`trainedOn` or `testedOn` (CISA 2026, FSCT 2024 and G7 follow those). A
distribution artifact is read for the package that links to it; it is not a
component itself.

## Not checked (catalogue-only)

Listed in the JSON and SARIF reports (as `out-of-scope`), never counted as
missing.

| Rule | Element | Why |
|---|---|---|
| DOC-003 | BOM-URI | every SPDX 3 element has a mandatory `spdxId`, so the BOM-URI always exists (the mapping is close for this reason); there is nothing to check |
| COMP-008 | Executable property | BSI Table 9 states "non-executable" by leaving `executable` out of the purposes, so every component gives a value |
| COMP-009 | Archive property | likewise, "no archive" is stated by leaving `archive` out |
| COMP-016 | Hash value of the source code | SPDX 3.0.1 has no link from a component to its source artifact that the mapping names; BSI Table 12 uses a source artifact that `generates` the component |

BSI Table 12 also lists "References to another BOM"; the ontology has no
element for it, so the checker does not report it.

## Beyond the mapping

The mapping places these values on the component itself or has no carrier
for them; BSI Appendix 8.2 gives an SPDX 3.0.1 shape, which the rules also
accept. `tests/test_bsi_mapping.py` pins each addition.

| Rule | Also accepted | BSI table |
|---|---|---|
| COMP-005 | `contains` (the mapping's comment: "contains for the inclusion reading") | 9 |
| COMP-007 | the hash on the distribution artifact (`hasDistributionArtifact`) | 9 |
| COMP-010 | `firmware`, for an unstructured component (the mapping marks "unstructured" as a gap), and the purpose on the distribution artifact | 9 |
| COMP-012 | `binaryArtifact` on the distribution artifact | 11 |
| COMP-013 | `software_contentIdentifier` (the shared identifier definition) | |
| COMP-017 | `securityOther` | 12 |

## Limits

- COMP-010 does not accept `archive`, which the mapping lists as a close
  match: BSI uses `archive` for the archive property, and a firmware image can
  be an unstructured archive. A component with neither `container` nor
  `firmware` is reported missing.
- COMP-005 is checked per package. A relationship that declares a
  completeness counts whatever its targets: one to `NoAssertionElement` with
  `noAssertion` says the list is unknown, which BSI allows.
- COMP-006 and COMP-015 read the same relationship, so they pass or fail
  together. COMP-015 does not check who concluded the license, nor read BSI
  Table 12's `other` relationship with the comment `hasEffectiveLicense`.
- COMP-006 accepts any license target that says something, including one that
  is not in the document; a `NoAssertionLicense` or a `NOASSERTION` expression
  is reported missing.
- COMP-011 reads the component's own `vcs` reference only, not BSI Table 11's
  source artifact that `generates` the component.
- COMP-004 accepts any named element linked by `hasDistributionArtifact`, not
  only a `software_File`. COMP-007 does not check that the hash is of that
  file.
- DOC-001 and COMP-001 check the shape of the contact only. A `Tool`,
  `SoftwareAgent` or plain `Agent` does not count.
- A conditional requirement treats a blank or `NOASSERTION` value as not
  given, so as not applicable.

[bsi]: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.html
