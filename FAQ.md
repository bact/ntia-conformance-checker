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
from the root elements. This warning means your file contains packages that
are not connected to the primary software tree via relationships.
The checker safely ignores these floating packages during compliance
validation, but it is a sign that the tool which generated your SBOM may be
leaving unlinked "garbage" data in the file. Only packages (components) can
be floating. Files, snippets and other elements are traversed, but are not
reported as floating.

**Q: Which relationships connect an element to the tree?**

A: References are to the [SPDX 2.3 specification][spdx-2.3], the
[SPDX 3.0.1 `RelationshipType` vocabulary][spdx-3.0.1-reltype] and the SPDX 3.0
[Annex A.1 "Relationship" translation table][spdx-3.0-a1].

The checker starts from the root elements and follows relationships from
parent to child, never from child to parent. The relationship graph is
directed, so the checker keeps a traversal direction for each relationship
type, as well as its name. In SPDX 2, `A <type> B` is written from
`spdxElementId` A to `relatedSpdxElement` B. In SPDX 3, `A <type> B` is
written from `from` A to `to` B.

- A forward type is followed from A to B.
- A reverse type is followed from B to A.

The checker does not check the types of the elements at the two ends.
SPDX 2.3 clause 11.1.1 says "you can represent a relationship between two
different Files, between a Package and a File, between two Packages, or
between one SPDXDocument and another SPDXDocument".

This table summarizes what the checker follows. Each row is one SPDX 3 type
and the SPDX 2 types that Annex A.1 translates to it.

<!-- markdownlint-disable MD013 -->

| Kind | SPDX 3 type | SPDX 3 direction | SPDX 2 forward types | SPDX 2 reverse types | Parent to child |
| --- | --- | --- | --- | --- | --- |
| Root | Any relationship from the `SpdxDocument`, such as `describes` | Root | `DESCRIBES` from `SPDXRef-DOCUMENT`; between other elements, followed (see the overrides below) | `DESCRIBED_BY` to `SPDXRef-DOCUMENT`; between other elements, followed | Describing element to described element |
| Root | `rootElement` of a collection | Root | none | none | Collection to root element |
| Composition | `contains` | Forward | `CONTAINS` | `CONTAINED_BY` | Whole to part |
| Composition | `hasOptionalComponent` | Forward | none | `OPTIONAL_COMPONENT_OF` | Whole to optional part |
| Composition | `packagedBy` | Forward | none | `PACKAGE_OF` | Element to its package |
| Dependency | `dependsOn` | Forward | `DEPENDS_ON` | `DEPENDENCY_OF`, `BUILD_DEPENDENCY_OF`, `DEV_DEPENDENCY_OF`, `RUNTIME_DEPENDENCY_OF`, `TEST_DEPENDENCY_OF` | Dependent to dependency |
| Dependency | `hasOptionalDependency` | Forward | none | `OPTIONAL_DEPENDENCY_OF` | Dependent to dependency |
| Dependency | `hasProvidedDependency` | Forward | none | `PROVIDED_DEPENDENCY_OF` | Dependent to dependency |
| Dependency | `hasPrerequisite` | Forward | `HAS_PREREQUISITE` | `PREREQUISITE_FOR` | Dependent to prerequisite |
| Dependency | `hasDynamicLink` | Forward | `DYNAMIC_LINK` (see the overrides below) | none | Linking element to linked element |
| Dependency | `hasStaticLink` | Forward | `STATIC_LINK` | none | Linking element to linked element |
| Tool | `usesTool` | Forward | none | `BUILD_TOOL_OF`, `DEV_TOOL_OF`, `TEST_TOOL_OF` | Product to tool |
| Provenance | `generates` | Reverse | `GENERATED_FROM` | `GENERATES` | Product to source |

<!-- markdownlint-enable MD013 -->

The checker follows no other relationship type, for example `DESCENDANT_OF`,
`FILE_MODIFIED`, `OTHER`, `hasDataFile` or `other`.

`generates` is the one reverse SPDX 3 type. "The `from` Element generates each
`to` Element", so the `to` element is the product and the `from` element is
its source. The checker goes from the product to the source, as it goes from a
product to its tool and from a dependent to its dependency. This choice is
ours: SPDX does not define a parent and a child for these relationships.
We include tools and sources because they are part of how a component was
made, which an SBOM describes.

The roots are:

- SPDX 2: the elements in `SPDXRef-DOCUMENT DESCRIBES A` or
  `A DESCRIBED_BY SPDXRef-DOCUMENT` (SPDX 2.3 clause 11.1, Table 68).
  `SPDXRef-DOCUMENT` is the document's own ID (clause 6.3). If the document
  has another ID, the checker also accepts `SPDXRef-DOCUMENT` for it.
- SPDX 3: the `rootElement` of the `SpdxDocument` and the `to` elements of
  any relationship from the `SpdxDocument`. Each collection, such as an
  `Sbom`, also links to its own `rootElement`.

SPDX 2.3 does not say that one relationship type is the inverse of another,
or which end is the parent. The checker derives each SPDX 2 type from its
SPDX 3 translation in Annex A.1. An SPDX 2 type is followed if its SPDX 3 type
is followed. Its direction is the SPDX 3 direction, reversed when Annex A.1
says "Swap to and from? Y". The same SBOM in SPDX 2 and in SPDX 3 gives the
same result. For example:

- Table 68 says "SPDXRef-A is a build dependency of SPDXRef-B" for
  `A BUILD_DEPENDENCY_OF B`. Annex A.1 translates it to `B dependsOn A`, with
  the build lifecycle scope, so the checker goes from B to A.
- Annex A.1 translates `A GENERATED_FROM B` to `B generates A`. `generates` is
  reverse, and the swap reverses it again, so the checker goes from A, the
  product, to B, the source.
- All three tool types translate to `usesTool`, so they are all followed.

The checker departs from Annex A.1 in two places:

- `DESCRIBES` is followed forward and `DESCRIBED_BY` in reverse, between any
  elements, so `B DESCRIBES C` and `C DESCRIBED_BY B` both go from B to C.
  Table 68 defines them only with `SPDXRef-DOCUMENT`, but SBOMs also use them
  between other elements. For SPDX 3, the checker makes the `to` elements of
  any relationship from the `SpdxDocument` roots, but does not follow
  `describes` from other elements: SPDX 3 marks roots with `rootElement`.
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

A: A root, or a relationship that the checker follows, refers to an element
that the SBOM does not define. SPDX 2.3 clause 11.1 (Table 69) gives the
format of an SPDX 2 relationship as:

```text
["DocumentRef-"[idstring]":"]SPDXID <relationship>
    ["DocumentRef-"[idstring]":"]SPDXID | NONE | NOASSERTION
```

An element ID can be at either end, so either end can be missing. The checker
reads relationships as written, from A to B, whatever the traversal direction,
and checks the same things for SPDX 2 and SPDX 3:

<!-- markdownlint-disable MD013 -->

| Case | Reported as missing | Report line or reason |
| --- | --- | --- |
| Followed relationship `A <type> B`, B missing | Yes | "Component 'A' links to missing element 'B'" |
| Followed relationship `A <type> B`, only A missing | Yes | "Component 'B' links to missing element 'A'" |
| Followed relationship `A <type> B`, both missing | Yes | "Missing element 'A' links to missing element 'B'" |
| Root missing | Yes | "Component '\<document or collection\>' links to missing element '\<root\>'" |
| Relationship that the checker does not follow | No | Not checked |
| `NONE`, `NOASSERTION` (SPDX 2) | No | Not elements (Table 69) |
| SPDX 3 individuals such as `NoneElement` | No | Defined by SPDX 3 |
| SPDX 3 element in an `ExternalMap` of an `import` | No | Defined in another document |
| `DocumentRef-<id>:SPDXID` with `DocumentRef-<id>` declared (SPDX 2) | No | Defined in the external document |
| `DocumentRef-<id>:SPDXID` with `DocumentRef-<id>` not declared (SPDX 2) | Yes | No such external document |
| Bare `DocumentRef-<id>` (SPDX 2) | Yes | Does not match the Table 69 format |

<!-- markdownlint-enable MD013 -->

Each missing element is reported once for each element that links to it.
The JSON output also lists every missing element ID in
`graphValidation.unknownPointers.missingElementIds`.

`NONE` means there are no other relationships and `NOASSERTION` means it is
not known whether there are any (Table 69). Neither is an element.

`DocumentRef-<id>:SPDXRef-<id>` refers to an element in another SPDX
document. Table 69 calls the prefix "an optional reference to an external
SPDX Document as described in 6.6". Clause 6.6 (External document references
field) declares `DocumentRef-<id>` in an `ExternalDocumentRef`. The external
document itself is `DocumentRef-<id>:SPDXRef-DOCUMENT`: clause 6.3.1 says
"To reference another SPDX Document in total, this identifier should be used
with the external document identifier preceding it", and clause 11.1.3
Example 1 has `SPDXRef-DOCUMENT AMENDS DocumentRef-SPDXA:SPDXRef-DOCUMENT`.

The checker does not download or read external documents. Clause 6.6 gives a
URI and a checksum for each one, but the document may not be reachable, and
fetching it would make the result depend on the network. The checker trusts
the declaration instead. An external element is not a component of this SBOM,
so the checker neither checks it for conformance nor reports it as floating.

[spdx-2.3]: https://spdx.github.io/spdx-spec/v2.3.1/
[spdx-3.0-a1]: https://github.com/spdx/using/blob/10e4b14c9cc5642aa4b4ce629e2b0560b771cf34/docs/diffs-from-previous-editions.md
[spdx-3.0.1-reltype]: https://spdx.github.io/spdx-spec/v3.0.1/model/Core/Vocabularies/RelationshipType/
