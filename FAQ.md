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

For SPDX 2, the checker follows these relationships from parent to child:

- `DESCRIBES`, `CONTAINS`, `DEPENDS_ON`, `DYNAMIC_LINK`, `STATIC_LINK` and
  `HAS_PREREQUISITE`, from the element to the related element
- `CONTAINED_BY`, `OPTIONAL_COMPONENT_OF`, `PACKAGE_OF`, `DEPENDENCY_OF`,
  `BUILD_DEPENDENCY_OF`, `DEV_DEPENDENCY_OF`, `OPTIONAL_DEPENDENCY_OF`,
  `PROVIDED_DEPENDENCY_OF`, `RUNTIME_DEPENDENCY_OF`, `TEST_DEPENDENCY_OF` and
  `PREREQUISITE_FOR`, from the related element to the element

Other relationships, such as `BUILD_TOOL_OF` or `GENERATED_FROM`, do not
connect an element to the tree.

**Q: The CLI output reports that a relationship points to a missing element.
What does this mean?**

A: A composition or dependency relationship refers to an element that is not
defined in the SBOM. In SPDX 2, an element in another document, written as
`DocumentRef-<id>:SPDXRef-<id>`, is not missing when the document declares
`DocumentRef-<id>` in an `ExternalDocumentRef`.
