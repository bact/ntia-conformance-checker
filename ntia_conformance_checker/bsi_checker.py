# SPDX-FileCopyrightText: 2026 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""BSI TR-03183-2 v2.1.0 checking functionality.

Requirements are from BSI TR-03183-2 v2.1.0 §4 "SBOM formats" and §5.2
"Data fields", with licences in §6.1 "Licence identifiers and expressions".
§2 "Requirements language" applies RFC 2119/8174 keywords in capitals only.
§8.2 "Mapping of the individual data fields" (Tables 8 to 12) gives the SPDX
3.0.1 field for each data field; §8 is explanatory, not normative.

Strength of each group of checks:

- §4, §5.2.1 and §5.2.2 (MUST): required; a failure blocks compliance.
- §5.2.3 "SBOM-URI" (MUST, "if it exists"): required; an SPDX 3 root
  element always has an ``spdxId``.
- §5.2.4 (MUST, "if it exists"): reported as "(Warning)" and does not block
  compliance, because the SBOM cannot show whether the information exists.
- §5.2.5 (MAY): reported as "(Optional)" and never blocks compliance.
"""

from __future__ import annotations

from typing import Any

from spdx_python_model.bindings import v3_0_1 as spdx3
from spdx_tools.spdx.validation.validation_message import (
    ValidationContext,
    ValidationMessage,
)

from .adapters.spdx3_adapter import is_blank_license_expression
from .base_checker import BaseChecker
from .spdx3_utils import (
    get_dependency_relationships_stated_completeness,
    get_distribution_artifacts_map,
    has_sha512_hash,
    iter_objects_with_property,
    iter_relationships_by_type,
)


def _is_license_expression(obj: object) -> bool:
    """
    Check whether an object is a license expression with license information.

    Args:
        obj: The relationship target object.

    Returns:
        bool: True if ``obj`` is a ``simplelicensing_LicenseExpression`` that
        is not blank per :func:`is_blank_license_expression`.
    """
    return isinstance(
        obj, spdx3.simplelicensing_LicenseExpression
    ) and not is_blank_license_expression(obj)


def _ids_with_license_expression(
    object_set: spdx3.SHACLObjectSet, rel_type: str
) -> set[str]:
    """
    Get IDs of elements with at least one license expression via ``rel_type``.

    Args:
        object_set: The SPDX 3 object set.
        rel_type: The relationship type, e.g. ``hasConcludedLicense``.

    Returns:
        set[str]: SPDX IDs of the relationships' ``from`` elements.
    """
    return {
        from_id
        for from_id, to_ids in iter_relationships_by_type(object_set, rel_type)
        if any(_is_license_expression(object_set.find_by_id(t)) for t in to_ids)
    }


# BSI TR-03183-2 v2.1.0 §4 "SBOM formats": an SBOM MUST be valid "System
# Package Data Exchange (SPDX), version 3.0.1 or higher" (or CycloneDX 1.6+,
# which this tool does not read). The SPDX 3 parser reads 3.0.1 only.
SBOM_FORMAT_LABEL = "SBOM Format (SPDX 3.0.1 or higher)"
SBOM_FORMAT_MESSAGE = (
    'BSI TR-03183-2 v2.1.0 §4 "SBOM formats" requires SPDX version 3.0.1 '
    "or higher; SPDX 2 is not accepted. Other requirements were not checked."
)


# pylint: disable=too-many-instance-attributes
class BSIChecker(BaseChecker):
    """
    BSI TR-03183-2 v2.1.0 Part 2: SBOM check.

    See the module docstring for the clauses and the strength of each check.

    See:
        https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.html
    """

    MIN_ELEMENTS = [
        "creator",
        "name",
        "version",
        "filename",
        "distribution_licenses",
        "sha512_hash",
        "executable_property",
        "archive_property",
        "structured_property",
        "dependency_completeness",
    ]

    _COMPONENTS_WITHOUT_INFO = {
        **BaseChecker._COMPONENTS_WITHOUT_INFO,
        "creator": (
            "components_without_creators",
            "Components missing a creator (Email/URL)",
        ),
        "filename": (
            "components_without_filenames",
            "Components missing a distribution filename",
        ),
        "distribution_licenses": (
            "components_without_concluded_licenses",
            "Components missing distribution licenses",
        ),
        "sha512_hash": (
            "components_without_sha512_hashes",
            "Components missing SHA-512 hash",
        ),
        "executable_property": (
            "components_without_executable_prop",
            "Components missing executable property",
        ),
        "archive_property": (
            "components_without_archive_prop",
            "Components missing archive property",
        ),
        "structured_property": (
            "components_without_structured_prop",
            "Components missing structured property",
        ),
        "dependency_completeness": (
            "components_without_dependency_completeness",
            "Components missing dependencies with stated completeness",
        ),
    }

    def __init__(
        self,
        file: str,
        validate: bool = True,
        compliance: str = "bsi",
        sbom_spec: str = "spdx3",
    ) -> None:
        """
        Initialize the BSI Minimum Element Checker.

        Args:
            file (str): The name of the file to be checked.
            validate (bool): Whether to validate the file.
            compliance (str): The compliance standard to be used.
            sbom_spec (str): The SBOM specification to be used.
        """

        if compliance not in {"bsi"}:
            raise ValueError("Only BSI compliance is supported.")

        self.components_without_creators: list[tuple[str, str]] = []
        self.components_without_filenames: list[tuple[str, str]] = []
        self.components_without_sha512_hashes: list[tuple[str, str]] = []
        self.components_without_executable_prop: list[tuple[str, str]] = []
        self.components_without_archive_prop: list[tuple[str, str]] = []
        self.components_without_structured_prop: list[tuple[str, str]] = []
        self.components_without_dependency_completeness: list[tuple[str, str]] = []

        # Initialize Additional/Optional lists (Warnings)
        self.components_without_source_code_uris: list[tuple[str, str]] = []
        self.components_without_deployable_uris: list[tuple[str, str]] = []
        self.components_without_unique_identifiers: list[tuple[str, str]] = []
        self.components_without_original_licenses: list[tuple[str, str]] = []
        self.components_without_effective_licenses: list[tuple[str, str]] = []
        self.components_without_source_code_hashes: list[tuple[str, str]] = []
        self.components_without_security_txt: list[tuple[str, str]] = []
        self.components_without_bom_references: list[tuple[str, str]] = []

        self.doc_creator: bool = False
        self.doc_uri: bool = False
        self.dependency_completeness: bool = False

        super().__init__(
            file=file, validate=validate, compliance=compliance, sbom_spec=sbom_spec
        )

        self.sbom_format: bool = self.sbom_spec == "spdx3"
        if not self.sbom_format:
            self._report_unsupported_format()
            return

        if self.doc:
            self.compliant = self.check_compliance()

        self.table_elements = [
            (SBOM_FORMAT_LABEL, self.sbom_format),
            ("Creator of the SBOM", self.doc_creator),
            ("Timestamp", self.doc_timestamp),
            ("Dependency Completeness", self.dependency_completeness),
            ("Component Names", self._all_provided(self.components_without_names)),
            (
                "Component Versions",
                self._all_provided(self.components_without_versions),
            ),
            (
                "Component Creators",
                self._all_provided(self.components_without_creators),
            ),
            (
                "Distribution Filenames",
                self._all_provided(self.components_without_filenames),
            ),
            (
                "Executable Properties",
                self._all_provided(self.components_without_executable_prop),
            ),
            (
                "Archive Properties",
                self._all_provided(self.components_without_archive_prop),
            ),
            (
                "Structured Properties",
                self._all_provided(self.components_without_structured_prop),
            ),
            (
                "Distribution Licenses",
                self._all_provided(self.components_without_concluded_licenses),
            ),
            (
                "Deployable Component Hashes",
                self._all_provided(self.components_without_sha512_hashes),
            ),
            (
                "Source Code URIs (Warning)",
                self._all_provided(self.components_without_source_code_uris),
            ),
            (
                "Deployable Form URIs (Warning)",
                self._all_provided(self.components_without_deployable_uris),
            ),
            (
                "Other Unique Identifiers (Warning)",
                self._all_provided(self.components_without_unique_identifiers),
            ),
            (
                "Original Licenses (Warning)",
                self._all_provided(self.components_without_original_licenses),
            ),
            (
                "Effective Licenses (Optional)",
                self._all_provided(self.components_without_effective_licenses),
            ),
            (
                "Source Code Hashes (Optional)",
                self._all_provided(self.components_without_source_code_hashes),
            ),
            (
                "Security.txt URLs (Optional)",
                self._all_provided(self.components_without_security_txt),
            ),
            (
                "BOM References (Optional)",
                self._all_provided(self.components_without_bom_references),
            ),
        ]

    def check_compliance(self) -> bool:
        """Check overall compliance with BSI TR-03183-2 v2.1.0."""
        # §5.2.1 Table 2 "Creator of the SBOM" and "Timestamp" (MUST);
        # §5.2.3 Table 4 "SBOM-URI" (MUST, if it exists)
        self.doc_creator = self.check_doc_creator()
        self.doc_uri = self.check_sbom_uri()
        self.doc_timestamp = self.check_timestamp()

        # §5.2.2 Table 3 "Required data fields for each component" (MUST)
        self.components_without_dependency_completeness = (
            self.get_components_without_dependency_completeness()
        )
        self.dependency_completeness = self._all_provided(
            self.components_without_dependency_completeness
        )
        self.components_without_names = self.get_components_without_names()
        self.components_without_versions = self.get_components_without_versions()
        self.components_without_concluded_licenses = (
            self.get_components_without_concluded_licenses()
        )
        self.components_without_creators = self.get_components_without_creators()
        self.components_without_filenames = self.get_components_without_filenames()
        self.components_without_executable_prop = (
            self.get_components_without_executable_prop()
        )
        self.components_without_archive_prop = (
            self.get_components_without_archive_prop()
        )
        self.components_without_structured_prop = (
            self.get_components_without_structured_prop()
        )
        self.components_without_sha512_hashes = (
            self.get_components_without_sha512_hashes()
        )

        # §5.2.4 Table 5 (MUST, if it exists) and §5.2.5 Table 6 (MAY):
        # reported, not part of the result
        self.components_without_source_code_uris = (
            self.get_components_without_source_code_uris()
        )
        self.components_without_deployable_uris = (
            self.get_components_without_deployable_uris()
        )
        self.components_without_unique_identifiers = (
            self.get_components_without_unique_identifiers()
        )
        self.components_without_original_licenses = (
            self.get_components_without_original_licenses()
        )
        self.components_without_effective_licenses = (
            self.get_components_without_effective_licenses()
        )
        self.components_without_source_code_hashes = (
            self.get_components_without_source_code_hashes()
        )
        self.components_without_security_txt = (
            self.get_components_without_security_txt()
        )
        self.components_without_bom_references = (
            self.get_components_without_bom_references()
        )

        # Refresh the aggregated tracking list used by the base class reporter
        self.all_components_without_info = self._get_all_components_without_info()

        return all(
            [
                self.sbom_format,
                self.doc_creator,
                self.doc_timestamp,
                self.doc_uri,
                self.dependency_completeness,
                self._all_provided(self.all_components_without_info),
                self._all_referenced_elements_defined(),
            ]
        )

    def _report_unsupported_format(self) -> None:
        """
        Report an SBOM format that BSI TR-03183-2 v2.1.0 §4 does not accept.

        The SBOM is non-compliant whatever its content, so the field checks
        are skipped and the format is the only reported requirement.
        """
        self.compliant = False
        self.all_components_without_info = []
        self._conformance_messages.append(
            ValidationMessage(SBOM_FORMAT_MESSAGE, ValidationContext())
        )
        self.table_elements = [(SBOM_FORMAT_LABEL, False)]

    @staticmethod
    def _is_valid_creator(
        creator: Any, doc: spdx3.SHACLObjectSet, url_id_types: tuple[str, ...]
    ) -> bool:
        """Validate if a creator object has a valid email or URL identifier."""
        creator_obj = (
            creator if not isinstance(creator, str) else doc.find_by_id(creator)
        )
        if not isinstance(creator_obj, (spdx3.Person, spdx3.Organization)):
            return False

        for ext_id in getattr(creator_obj, "externalIdentifier", []):
            id_type = str(getattr(ext_id, "externalIdentifierType", "")).lower()
            id_val = getattr(ext_id, "identifier", "")
            if not id_val:
                continue

            if "email" in id_type and "@" in id_val:
                return True
            if any(t in id_type for t in url_id_types) and id_val.startswith(
                ("http://", "https://")
            ):
                return True

        return False

    def check_doc_creator(self) -> bool:
        """
        Check if the SBOM creator has an email address or URL.

        §5.2.1 Table 2 "Creator of the SBOM" (MUST); mapping: §8.2 Table 8,
        ``CreationInfo.createdBy``.
        """
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return False

        spdx3_doc = getattr(self, "_BaseChecker__spdx3_doc", None)
        if not spdx3_doc:
            return False

        creation_info = getattr(spdx3_doc, "creationInfo", None)
        if not creation_info:
            return False

        creators = getattr(creation_info, "createdBy", [])
        if not creators:
            return False

        return any(
            self._is_valid_creator(c, self.doc, ("urlscheme", "other"))
            for c in creators
        )

    def check_sbom_uri(self) -> bool:
        """
        Check if the SBOM-URI exists.

        §5.2.3 Table 4 "SBOM-URI" (MUST, if it exists); mapping: §8.2
        Table 10, the ``spdxId`` of a ``software_Sbom`` or ``software_Package``
        root element.
        """
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return False

        spdx3_doc = getattr(self, "_BaseChecker__spdx3_doc", None)
        if not spdx3_doc:
            return False

        root_elements = getattr(spdx3_doc, "rootElement", [])

        for root in root_elements:
            root_obj = root if not isinstance(root, str) else self.doc.find_by_id(root)

            # The rootElement (software_Sbom or software_Package) MUST have a valid spdxId.
            if isinstance(root_obj, (spdx3.software_Sbom, spdx3.software_Package)):
                spdx_id = getattr(root_obj, "spdxId", None)
                if spdx_id and isinstance(spdx_id, str) and spdx_id.strip():
                    return True

        return False

    def get_components_without_creators(self) -> list[tuple[str, str]]:
        """
        Check if each component creator has an email address or URL.

        §5.2.2 Table 3 "Component creator" (MUST); mapping: §8.2 Table 9,
        ``originatedBy``.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        # Iterate through all packages in the reachable graph
        for name, spdx_id, originated_by_list in iter_objects_with_property(
            self.doc,
            spdx3.software_Package,
            "originatedBy",
            self.reachable_component_ids,
        ):
            creators = originated_by_list or []
            has_valid = any(
                self._is_valid_creator(c, self.doc, ("other", "urlscheme"))
                for c in creators
            )
            if not has_valid:
                missing.append((name, spdx_id))

        return missing

    def get_components_without_filenames(self) -> list[tuple[str, str]]:
        """
        Check if each component has a distribution file with a name.

        §5.2.2 Table 3 "Filename of the component" (MUST); mapping: §8.2
        Table 9, the ``name`` of a ``software_File`` linked by
        ``hasDistributionArtifact``. A component without a linked file is
        skipped: §3.2.2 does not require a filename for a logical component.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        artifacts_map = get_distribution_artifacts_map(self.doc)

        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            linked_files = artifacts_map.get(spdx_id, [])
            if not linked_files:
                continue

            has_filename = False
            for file_obj in linked_files:
                file_name = getattr(file_obj, "name", "")
                if file_name and isinstance(file_name, str) and file_name.strip():
                    has_filename = True
                    break

            if not has_filename:
                missing.append((name, spdx_id))

        return missing

    def check_dependency_completeness(self) -> bool:
        """
        Check if all components enumerate dependencies with stated completeness.

        See :meth:`get_components_without_dependency_completeness` for the
        rule.

        Returns:
            bool: True if components were evaluated and none of them fails.
        """
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return False

        return self._all_provided(self.get_components_without_dependency_completeness())

    def get_components_without_dependency_completeness(self) -> list[tuple[str, str]]:
        """
        Get components without dependencies with stated completeness.

        BSI TR-03183-2 v2.1.0 §5.2.2 Table 3 "Dependencies on other
        components" (MUST); mapping: §8.2 Table 9, a ``contains`` or
        ``dependsOn`` relationship with ``completeness``. A component fails if
        it has no such relationship, or one without ``completeness``. No
        dependencies: ``to`` ``NoneElement``, ``completeness`` ``complete``.

        Returns:
            list[tuple[str, str]]: (name, SPDX ID) of failing components.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        completeness_map = get_dependency_relationships_stated_completeness(self.doc)

        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            values = completeness_map.get(spdx_id, [])
            if not values or None in values:
                missing.append((name, spdx_id))

        return missing

    def get_components_without_concluded_licenses(self) -> list[tuple[str, str]]:
        """
        Check if each component has a distribution licence.

        §5.2.2 Table 3 "Distribution licences" (MUST), licences per §6.1;
        mapping: §8.2 Table 9, ``hasConcludedLicense`` to a
        ``simplelicensing_LicenseExpression``. A blank or NOASSERTION
        expression does not count. The §6.1 identifier rules are not checked.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        valid_license_ids = _ids_with_license_expression(
            self.doc, "hasConcludedLicense"
        )

        # Check packages against the valid license list
        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            if spdx_id not in valid_license_ids:
                missing.append((name, spdx_id))

        return missing

    def get_components_without_sha512_hashes(self) -> list[tuple[str, str]]:
        """
        Check if the deployable form of each component has a SHA-512 hash.

        §5.2.2 Table 3 "Hash value of the deployable component" (MUST);
        mapping: §8.2 Table 9, a ``sha512`` hash on a ``software_File`` linked
        by ``hasDistributionArtifact``. A component without a linked file is
        skipped: §3.2.1 omits information that is not available, and §3.2.2
        does not require it for a logical component.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        artifacts_map = get_distribution_artifacts_map(self.doc)

        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            linked_files = artifacts_map.get(spdx_id, [])

            # If no file is linked, skip file level checks.
            if not linked_files:
                continue

            has_hash = False
            for file_obj in linked_files:
                if has_sha512_hash(file_obj):
                    has_hash = True
                    break

            if not has_hash:
                missing.append((name, spdx_id))

        return missing

    def get_components_without_executable_prop(self) -> list[tuple[str, str]]:
        """
        Check the executable property; always passes.

        §5.2.2 Table 3 "Executable property" (MUST); mapping: §8.2 Table 9,
        ``executable`` in ``software_additionalPurpose`` if the component is
        executable, otherwise omitted. Both states are valid, so no component
        can fail.
        """
        return []

    def get_components_without_archive_prop(self) -> list[tuple[str, str]]:
        """
        Check the archive property; always passes.

        §5.2.2 Table 3 "Archive property" (MUST); mapping: §8.2 Table 9,
        ``archive`` in ``software_additionalPurpose`` if the component is an
        archive, otherwise omitted. Both states are valid, so no component can
        fail.
        """
        return []

    def get_components_without_structured_prop(self) -> list[tuple[str, str]]:
        """
        Check if each component declares the structured property.

        §5.2.2 Table 3 "Structured property" (MUST); mapping: §8.2 Table 9,
        ``container`` (structured) or ``firmware`` (unstructured) in
        ``software_additionalPurpose`` of a distribution file. A component
        without a linked file is skipped, as for the hash.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        artifacts_map = get_distribution_artifacts_map(self.doc)

        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            linked_files = artifacts_map.get(spdx_id, [])

            # If no file is linked, skip file level checks.
            if not linked_files:
                continue

            has_structured_prop = False
            for file_obj in linked_files:
                purposes = getattr(file_obj, "software_additionalPurpose", [])
                # Convert IRIs/Enums to strings and check for BSI keywords
                purposes_str = [str(p).lower() for p in purposes]

                if any("container" in p or "firmware" in p for p in purposes_str):
                    has_structured_prop = True
                    break

            if not has_structured_prop:
                missing.append((name, spdx_id))

        return missing

    def get_components_without_source_code_uris(self) -> list[tuple[str, str]]:
        """
        Check if each component has a source code URI.

        §5.2.4 Table 5 "Source code URI" (MUST, if it exists); mapping: §8.2
        Table 11, an ``externalRef`` on a source artifact that ``generates``
        the component.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        valid_package_ids = set()

        for from_id, to_ids in iter_relationships_by_type(self.doc, "generates"):
            is_valid_source = False

            obj = self.doc.find_by_id(from_id)
            if obj and isinstance(
                obj,
                (
                    spdx3.software_SoftwareArtifact,
                    spdx3.software_File,
                    spdx3.software_Snippet,
                    spdx3.software_Package,
                    spdx3.ai_AIPackage,
                    spdx3.dataset_DatasetPackage,
                ),
            ):
                raw_purpose = getattr(obj, "software_primaryPurpose", None) or getattr(
                    obj, "primaryPurpose", None
                )
                purposes = (
                    raw_purpose if isinstance(raw_purpose, list) else [raw_purpose]
                )
                purposes_str = [str(p).lower() for p in purposes]

                if any("source" in p for p in purposes_str):
                    if getattr(obj, "externalRef", []):
                        is_valid_source = True

            if is_valid_source:
                for target_id in to_ids:
                    valid_package_ids.add(target_id)

        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            if spdx_id not in valid_package_ids:
                missing.append((name, spdx_id))

        return missing

    def get_components_without_deployable_uris(self) -> list[tuple[str, str]]:
        """
        Check if each component has a URI of its deployable form.

        §5.2.4 Table 5 "URI of the deployable form of the component" (MUST,
        if it exists); mapping: §8.2 Table 11, read as a ``binaryArtifact``
        ``externalRef`` on a distribution file.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        artifacts_map = get_distribution_artifacts_map(self.doc)

        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            linked_files = artifacts_map.get(spdx_id, [])
            if not linked_files:
                continue

            has_deployable_uri = False
            for file_obj in linked_files:
                # §8.2 Table 11 shows "binaryArtifact" as a property; SPDX
                # 3.0.1 defines it as an ExternalRefType only.
                for ext_ref in getattr(file_obj, "externalRef", []):
                    ref_type = str(getattr(ext_ref, "externalRefType", "")).lower()
                    if "binaryartifact" in ref_type:
                        has_deployable_uri = True
                        break
                if has_deployable_uri:
                    break

            if not has_deployable_uri:
                missing.append((name, spdx_id))

        return missing

    def get_components_without_unique_identifiers(self) -> list[tuple[str, str]]:
        """
        Check if each component has another unique identifier (CPE, SWID, purl).

        §5.2.4 Table 5 "Other unique identifiers" (MUST, if it exists);
        mapping: §8.2 Table 11, ``externalIdentifier``.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        # Valid BSI external identifier types
        valid_types = {"cpe22", "cpe23", "swid", "packageurl"}

        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            has_valid_id = False

            obj = self.doc.find_by_id(spdx_id)
            if obj:
                ext_ids = getattr(obj, "externalIdentifier", [])
                for ext_id in ext_ids:
                    id_type = str(getattr(ext_id, "externalIdentifierType", "")).lower()
                    # Extract the base type name from the IRI/Enum
                    id_type_clean = id_type.rsplit("/", maxsplit=1)[-1]

                    if id_type_clean in valid_types:
                        has_valid_id = True
                        break

            if not has_valid_id:
                missing.append((name, spdx_id))

        return missing

    def get_components_without_original_licenses(self) -> list[tuple[str, str]]:
        """
        Check if each component has an original licence.

        §5.2.4 Table 5 "Original licences" (MUST, if it exists), licences per
        §6.1; mapping: §8.2 Table 11, ``hasDeclaredLicense``.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        valid_license_ids = _ids_with_license_expression(self.doc, "hasDeclaredLicense")

        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            if spdx_id not in valid_license_ids:
                missing.append((name, spdx_id))

        return missing

    def get_components_without_effective_licenses(self) -> list[tuple[str, str]]:
        """
        Check if each component has an effective licence.

        §5.2.5 Table 6 "Effective licence" (MAY); mapping: §8.2 Table 12, an
        ``other`` relationship with the comment ``hasEffectiveLicense``.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        valid_license_ids = set()

        for rel in self.doc.foreach_type(spdx3.Relationship):
            rel_type = getattr(rel, "relationshipType", "")

            if rel_type and rel_type.rsplit("/", maxsplit=1)[-1].lower() == "other":
                comment = getattr(rel, "comment", "")

                if comment and "hasEffectiveLicense" in comment:
                    from_obj = getattr(rel, "from_", None)
                    from_id = (
                        from_obj
                        if isinstance(from_obj, str)
                        else getattr(from_obj, "spdxId", "")
                    )

                    if from_id:
                        valid_license_ids.add(from_id)

        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            if spdx_id not in valid_license_ids:
                missing.append((name, spdx_id))

        return missing

    def get_components_without_source_code_hashes(self) -> list[tuple[str, str]]:
        """
        Check if the source code of each component has a SHA-512 hash.

        §5.2.5 Table 6 "Hash value of the source code of the component" (MAY).
        §5.2.5 leaves the algorithm undetermined; SHA-512 follows the example
        in §8.2 Table 12.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        valid_package_ids = set()

        for from_id, to_ids in iter_relationships_by_type(self.doc, "generates"):
            has_hash = False
            obj = self.doc.find_by_id(from_id)
            if obj and isinstance(
                obj,
                (
                    spdx3.software_SoftwareArtifact,
                    spdx3.software_File,
                    spdx3.software_Snippet,
                    spdx3.software_Package,
                    spdx3.ai_AIPackage,
                    spdx3.dataset_DatasetPackage,
                ),
            ):
                raw_purpose = getattr(obj, "software_primaryPurpose", None) or getattr(
                    obj, "primaryPurpose", None
                )
                purposes = (
                    raw_purpose if isinstance(raw_purpose, list) else [raw_purpose]
                )
                purposes_str = [str(p).lower() for p in purposes]

                if any("source" in p for p in purposes_str):
                    if has_sha512_hash(obj):
                        has_hash = True

            if has_hash:
                valid_package_ids.update(to_ids)

        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            if spdx_id not in valid_package_ids:
                missing.append((name, spdx_id))

        return missing

    def get_components_without_security_txt(self) -> list[tuple[str, str]]:
        """
        Check if each component has the URL of its creator's security.txt.

        §5.2.5 Table 6 "URL of the security.txt" (MAY); mapping: §8.2
        Table 12, a ``securityOther`` ``externalRef``.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            has_security = False
            obj = self.doc.find_by_id(spdx_id)
            if obj:
                for ext_ref in getattr(obj, "externalRef", []):
                    ref_type = str(getattr(ext_ref, "externalRefType", "")).lower()
                    if "securityother" in ref_type:
                        has_security = True
                        break

            if not has_security:
                missing.append((name, spdx_id))

        return missing

    def get_components_without_bom_references(self) -> list[tuple[str, str]]:
        """
        Check if each component is described by a referenced BOM.

        §8.2 Table 12 "References to another BOM", a ``software_Sbom`` with a
        ``buildMeta`` ``externalRef`` that ``describes`` the component.
        Optional (MAY) as part of Table 12; §5.2.5 Table 6 does not list it,
        but notes its list "is not meant to be exhaustive". See also §3.2.5.
        """
        missing: list[tuple[str, str]] = []
        if not isinstance(self.doc, spdx3.SHACLObjectSet):
            return missing

        valid_package_ids = set()

        for from_id, to_ids in iter_relationships_by_type(self.doc, "describes"):
            has_bom_ref = False
            obj = self.doc.find_by_id(from_id)
            if obj and isinstance(obj, spdx3.software_Sbom):
                for ext_ref in getattr(obj, "externalRef", []):
                    ref_type = str(getattr(ext_ref, "externalRefType", "")).lower()
                    if "buildmeta" in ref_type:
                        has_bom_ref = True
                        break

            if has_bom_ref:
                valid_package_ids.update(to_ids)

        for name, spdx_id, _ in iter_objects_with_property(
            self.doc, spdx3.software_Package, "spdxId", self.reachable_component_ids
        ):
            if spdx_id not in valid_package_ids:
                missing.append((name, spdx_id))

        return missing
