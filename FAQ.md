# Frequently asked questions

**Q: I am having trouble installing the Python modules. What gives?**

A: It could be due to using an OS package manager (like `apt`) to install
modules rather than using `pip`. Please try using `pip`.

**Q: Why does my SPDX 3 SBOM fail the BSI compliance check for "deployable form
URIs" when I copied the example from the BSI document?**

A: The BSI TR-03183-2 document contains an example where `binaryArtifact` is
used as a direct property on a file. However, the official SPDX 3.0.1
specification strictly defines `binaryArtifact` as an `ExternalRefType`.
To pass compliance, you must define it inside an `externalRef` array.

**Q: I am getting a "NotImplementedError: software_SoftwareArtifact is abstract
and cannot be implemented" when parsing my SPDX 3 SBOM. How do I fix this?**

A: You are likely using `software_SoftwareArtifact` as the `"type"` for
an element in your JSON-LD file (which is sometimes shown in BSI examples for
Source Code URIs). Because it is an abstract class in the SPDX model,
it cannot be instantiated directly. You must change the type to a concrete
subclass, such as `software_File`, `software_Package`, or `software_Snippet`.

**Q: The CLI output warns me that it "Found X disconnected 'floating'
elements." What does this mean?**

A: The conformance checker traverses the SBOM's relationship graph starting
from the root document. This warning means your file contains elements that
are not connected to the primary software tree via relationships.
The checker safely ignores these floating elements during compliance
validation, but it is a sign that the tool which generated your SBOM may be
leaving unlinked "garbage" data in the file.

**Q: Which relationships connect an element to the tree?**

A: References are to the [SPDX 2.3 specification][spdx-2.3], the
[SPDX 3.0.1 `RelationshipType` vocabulary][spdx-3.0.1-reltype] and the SPDX 3.0
[Annex A.1 "Relationship" translation table][spdx-3.0-a1].

The checker follows relationships from parent to child, never from child to
parent. The relationship graph is directed, so the checker keeps a traversal
direction for each relationship type, as well as its name. A forward type is
followed from its source (SPDX 2 `spdxElementId`, SPDX 3 `from`) to its target
(SPDX 2 `relatedSpdxElement`, SPDX 3 `to`). A reverse type is followed the
other way. The checker does not check the types of the elements at the two
ends: SPDX 2.3 Table 68 writes every relationship between `SPDXRef-A` and
`SPDXRef-B` and does not restrict them to packages, files or snippets.

For SPDX 3, the roots are the `rootElement` of the `SpdxDocument` and the
targets of relationships from the `SpdxDocument`. Each collection, such as an
`Sbom`, also links to its own `rootElement`. The checker follows these
relationship types:

- Forward, composition: `contains`, `hasOptionalComponent` and
  `packagedBy`
- Forward, dependency: `dependsOn`, `hasDynamicLink`,
  `hasStaticLink`, `hasPrerequisite`, `hasOptionalDependency` and
  `hasProvidedDependency`
- Forward, from product to tool: `usesTool`
- Reverse, from product to source: `generates`

`generates` is the one reverse type. "The `from` Element generates each `to`
Element", so the `to` element is the product and the `from` element is its
source. The checker goes from the product to the source, as it goes from a
product to its tool and from a dependent to its dependency. This choice is
ours: SPDX does not define a parent and a child for these relationships.
We include tools and sources because they are part of how a component was
made, which an SBOM describes.

For SPDX 2, the roots are the elements that the document describes:
`SPDXRef-DOCUMENT DESCRIBES A` or `A DESCRIBED_BY SPDXRef-DOCUMENT`
(SPDX 2.3 clause 11.1, Table 68). `SPDXRef-DOCUMENT` is the document's own ID
(clause 6.3).

SPDX 2.3 does not say that one relationship type is the inverse of another, or
which end is the parent. The checker derives each SPDX 2 type from its SPDX 3
translation in Annex A.1. An SPDX 2 type is followed if its SPDX 3 type is
followed. Its direction is the SPDX 3 direction, reversed when Annex A.1 says
"Swap to and from? Y". The same SBOM in SPDX 2 and in SPDX 3 gives the same
result. This gives:

- Forward: `CONTAINS`, `DEPENDS_ON`, `DYNAMIC_LINK`, `STATIC_LINK`,
  `HAS_PREREQUISITE` and `GENERATED_FROM`, and `DESCRIBES` (see below)
- Reverse: `CONTAINED_BY`, `OPTIONAL_COMPONENT_OF`, `PACKAGE_OF`,
  `DEPENDENCY_OF`, `BUILD_DEPENDENCY_OF`, `DEV_DEPENDENCY_OF`,
  `OPTIONAL_DEPENDENCY_OF`, `PROVIDED_DEPENDENCY_OF`, `RUNTIME_DEPENDENCY_OF`,
  `TEST_DEPENDENCY_OF`, `PREREQUISITE_FOR`, `BUILD_TOOL_OF`, `DEV_TOOL_OF`,
  `TEST_TOOL_OF` and `GENERATES`

For example, Table 68 says "SPDXRef-A is a build dependency of SPDXRef-B" for
`A BUILD_DEPENDENCY_OF B`. Annex A.1 translates it to `B dependsOn A`, with the
build lifecycle scope, so the checker goes from B to A. All three tool types
translate to `usesTool`, so they are all followed. Annex A.1 translates
`A GENERATED_FROM B` to `B generates A`, so the checker goes from A, the
product, to B, the source.

The checker departs from Annex A.1 in two places:

- `DESCRIBES` is followed forward. SPDX 3 marks roots with `rootElement`, so
  the checker does not follow `describes` for SPDX 3. SPDX 2 has no
  `rootElement` and uses `DESCRIBES` for both roots and other elements.
- `DYNAMIC_LINK` is followed forward. Annex A.1 says "Swap to and from? Y" for
  it, but Table 68 says "SPDXRef-A dynamically links to SPDXRef-B" and
  SPDX 3.0.1 says "The `from` Element dynamically links in each `to` Element".
  Both read the same way, as `STATIC_LINK` and `hasStaticLink` do, which
  Annex A.1 does not swap. We read the Annex A.1 row as a mistake.

We found one more row that reads as a mistake. Annex A.1 does not swap
`FILE_MODIFIED` to `modifiedBy`, but "SPDXRef-A is a file that was modified
from SPDXRef-B" reads as `B modifiedBy A`. The checker does not follow it, so
it makes no difference.

**Q: The CLI output reports that a relationship points to a missing element.
What does this mean?**

A: A relationship that the checker follows refers to an element that the SBOM
does not define.

For SPDX 3, the checker checks each `to` element. For `generates`, which it
follows from `to` to `from`, it also checks the `from` element.

For SPDX 2, SPDX 2.3 clause 11.1 (Table 69) gives the format of a
relationship as:

```text
["DocumentRef-"[idstring]":"]SPDXID <relationship>
    ["DocumentRef-"[idstring]":"]SPDXID | NONE | NOASSERTION
```

The checker reads this as follows:

- Either end can be an SPDX ID, so either end can be missing. When the
  `spdxElementId` is missing, the error is reported from the related element.
- `NONE` means there are no other relationships and `NOASSERTION` means it is
  not known whether there are any (Table 69). Neither is an element, so neither
  is missing.
- `DocumentRef-<id>:SPDXRef-<id>` refers to an element in another SPDX
  document. Table 69 calls the prefix "an optional reference to an external
  SPDX Document as described in 6.6". Clause 6.6 (External document
  references field) declares `DocumentRef-<id>` in an `ExternalDocumentRef`.
  If `DocumentRef-<id>` is declared, the element is not missing. If it is not
  declared, the element is missing.
- The external document itself is `DocumentRef-<id>:SPDXRef-DOCUMENT`, as in
  the Annex A.1 "External Document Reference" translation. A bare
  `DocumentRef-<id>` does not match the format, so it is reported as missing.

The checker does not download or read external documents. Clause 6.6 gives a
URI and a checksum for each one, but the document may not be reachable, and
fetching it would make the result depend on the network. The checker trusts
the declaration instead. An external element is not a component of this SBOM,
so the checker neither checks it for conformance nor reports it as floating.

[spdx-2.3]: https://spdx.github.io/spdx-spec/v2.3.1/
[spdx-3.0-a1]: https://github.com/spdx/using/blob/main/docs/diffs-from-previous-editions.md
[spdx-3.0.1-reltype]: https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Vocabularies/RelationshipType/
