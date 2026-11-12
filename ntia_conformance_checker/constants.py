# SPDX-FileCopyrightText: 2025 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Constants."""

SUPPORTED_SBOM_SPECS_DESC = {
    "spdx2": "Software Package Data Exchange (SPDX) 2.x",
    "spdx3": "System Package Data Exchange (SPDX) 3.x",
}
DEFAULT_SBOM_SPEC = "spdx2"
SUPPORTED_SBOM_SPECS = set(SUPPORTED_SBOM_SPECS_DESC.keys())

# Each SPDX 2 relationship type that connects an element to the graph is
# listed with its traversal direction: forward types are followed from
# spdxElementId to relatedSpdxElement, reverse types the other way.
# The traversal direction is the one from the parent (the element closer to
# the root) to the child. It is not always the direction of the relationship
# in SPDX 3, so it is kept here per type, next to the type name.
#
# SPDX 2 relationships of the form "A <type> B" where A is the parent and B is
# the child. Their SPDX 2.3 clause 11.1 (Table 68) descriptions read
# "SPDXRef-A contains SPDXRef-B", "SPDXRef-A depends on SPDXRef-B", and so on.
VALID_SPDX2_COMPOSITION_RELATIONSHIPS = {
    # Composition
    "DESCRIBES",
    "CONTAINS",
    # Dependencies
    "DEPENDS_ON",
    # DYNAMIC_LINK is forward: Table 68 says "SPDXRef-A dynamically links to
    # SPDXRef-B", although the SPDX 3.0 Annex A.1 table marks it as swapped.
    "DYNAMIC_LINK",
    "STATIC_LINK",
    "HAS_PREREQUISITE",
    # Provenance: "SPDXRef-A is generated from SPDXRef-B" (Table 68).
    # A is the product and B is its source, so traversal goes from A to B.
    # This is against the SPDX 3 direction: Annex A.1 translates it to
    # "B generates A".
    "GENERATED_FROM",
}
# SPDX 2 relationships of the form "A <type> B" where B is the parent and A is
# the child. Traversal follows them from B to A, as it follows
# "B CONTAINS A" or "B DEPENDS_ON A".
# SPDX 2.3 clause 11.1 (Table 68) describes each from the child's side,
# such as "SPDXRef-A is contained by SPDXRef-B", but does not say that it is
# the inverse of another type. The SPDX 3.0 Annex A.1 "Relationship"
# translation table marks each with "Swap to and from? Y". For composition
# and dependency types, it maps each to a type in
# VALID_SPDX3_COMPOSITION_RELATIONSHIPS, so SPDX 2 and SPDX 3 results agree.
VALID_SPDX2_REVERSE_COMPOSITION_RELATIONSHIPS = {
    # Composition
    "CONTAINED_BY",
    "OPTIONAL_COMPONENT_OF",
    "PACKAGE_OF",
    # Dependencies
    "DEPENDENCY_OF",
    "BUILD_DEPENDENCY_OF",
    "DEV_DEPENDENCY_OF",
    "OPTIONAL_DEPENDENCY_OF",
    "PROVIDED_DEPENDENCY_OF",
    "RUNTIME_DEPENDENCY_OF",
    "TEST_DEPENDENCY_OF",
    "PREREQUISITE_FOR",
    # Build tools: "SPDXRef-A is used to build SPDXRef-B" (Table 68).
    # B is the product and A is the tool, so traversal goes from B to A.
    # Annex A.1 translates it to "B usesTool A".
    "BUILD_TOOL_OF",
    # Provenance: "SPDXRef-A generates SPDXRef-B" (Table 68) is the
    # GENERATED_FROM fact from the source's side. B is the product and A is
    # its source, so traversal goes from B to A, as for "B GENERATED_FROM A".
    "GENERATES",
}
VALID_SPDX3_COMPOSITION_RELATIONSHIPS = {
    # Composition
    "contains",
    "hasOptionalComponent",
    "packagedBy",
    # Dependencies
    "dependsOn",
    "hasDynamicLink",
    "hasStaticLink",
    "hasPrerequisite",
    "hasOptionalDependency",
    "hasProvidedDependency",
}

SUPPORTED_COMPLIANCE_STANDARDS_DESC = {
    # "cisasbom2025": "2025 CISA SBOM Minimum Elements",
    # https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom
    "bsi": "BSI TR-03183-2 v2.1.0 Cyber Resilience Requirements for Manufacturers and Products",
    "fsct3-min": "2024 CISA Framing Software Component Transparency (minimum expectation)",
    "ntia": "2021 NTIA SBOM Minimum Elements",
}
DEFAULT_COMPLIANCE_STANDARD = "ntia"
SUPPORTED_COMPLIANCE_STANDARDS = set(SUPPORTED_COMPLIANCE_STANDARDS_DESC.keys())

SUPPORTED_SPDX_VERSIONS = {(2, 2), (2, 3), (3, 0)}  # (Major, Minor)
SUPPORTED_SPDX2_VERSION_STRINGS = {
    f"SPDX-{maj}.{min}" for (maj, min) in SUPPORTED_SPDX_VERSIONS if maj == 2
}  # e.g. "SPDX-2.2", "SPDX-2.3"
SUPPORTED_SPDX3_VERSION_STRINGS = {
    f"{maj}.{min}" for (maj, min) in SUPPORTED_SPDX_VERSIONS if maj == 3
}  # e.g. "3.0"
