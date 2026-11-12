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

**Q: Which SPDX 2 relationships connect an element to the tree?**

A: References are to the [SPDX 2.3 specification][spdx-2.3] and, where it
gives no answer, to the SPDX 3.0
[Annex A.1 "Relationship" translation table][spdx-3.0-a1].

The roots are the elements that the document describes:
`SPDXRef-DOCUMENT DESCRIBES A` or `A DESCRIBED_BY SPDXRef-DOCUMENT`
(SPDX 2.3 clause 11.1, Table 68). `SPDXRef-DOCUMENT` is the document's own ID
(clause 6.3).

From the roots, the checker follows relationships from parent to child.
It follows these forward relationships from the element to the related
element:

- `DESCRIBES`, `CONTAINS`, `DEPENDS_ON`, `DYNAMIC_LINK`, `STATIC_LINK` and
  `HAS_PREREQUISITE`

Table 68 describes each of them from the parent's side, such as
"SPDXRef-A contains SPDXRef-B".

It follows these reverse relationships from the related element to the
element:

- `CONTAINED_BY`, `OPTIONAL_COMPONENT_OF`, `PACKAGE_OF`, `DEPENDENCY_OF`,
  `BUILD_DEPENDENCY_OF`, `DEV_DEPENDENCY_OF`, `OPTIONAL_DEPENDENCY_OF`,
  `PROVIDED_DEPENDENCY_OF`, `RUNTIME_DEPENDENCY_OF`, `TEST_DEPENDENCY_OF` and
  `PREREQUISITE_FOR`

SPDX 2.3 does not say that one relationship type is the inverse of another.
This is our reading:

- Table 68 describes each reverse type as the same fact from the child's side.
  For example, "SPDXRef-A is contained by SPDXRef-B" states what
  "SPDXRef-B contains SPDXRef-A" states.
- Annex A.1 translates each reverse type to an SPDX 3 type that the checker
  follows for SPDX 3, with "Swap to and from? Y". For example,
  `BUILD_DEPENDENCY_OF` becomes `dependsOn` with the build lifecycle scope,
  from the related element to the element. Following them gives the same
  result for an SBOM in SPDX 2 and in SPDX 3.
- SBOM generators write either form. If the checker ignored the reverse form,
  it would skip the components that a generator links that way.

The checker does not follow other relationships, such as `BUILD_TOOL_OF`,
`DEV_TOOL_OF`, `TEST_TOOL_OF`, `GENERATED_FROM` or `DESCENDANT_OF`. They describe
how an element was built or where it came from, not what it is made of or
what it needs. Annex A.1 translates the tool relationships to `usesTool`,
which the checker also does not follow for SPDX 3.

Annex A.1 also marks `DYNAMIC_LINK` as "Swap to and from? Y", but not
`STATIC_LINK`. Table 68 describes both the same way: "SPDXRef-A dynamically
links to SPDXRef-B" and "SPDXRef-A statically links to SPDXRef-B". The checker
follows the SPDX 2.3 text and treats both as forward relationships.

**Q: The CLI output reports that a relationship points to a missing element.
What does this mean?**

A: A relationship that the checker follows refers to an element that the SBOM
does not define. SPDX 2.3 clause 11.1 (Table 69) gives the format of a
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
