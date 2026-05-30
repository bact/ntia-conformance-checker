# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Base checking functionality for AI and dataset elements.

This intermediate base class extends :class:`BaseChecker` with checks for
fields from the SPDX 3 AI and Dataset profiles.
Compliance checkers that need to verify AI model packages or dataset packages
(e.g. the G7 SBOM for AI checker, and a future Model Openness Framework
checker) should inherit from this class.
"""

from __future__ import annotations

from typing import cast

from spdx_python_model import v3_0_1 as spdx3  # type: ignore # import-untyped

from .base_checker import BaseChecker
from .spdx3_utils import iter_objects_with_property


class BaseAIDataChecker(BaseChecker):
    """Base checker with SPDX 3 AI- and dataset-profile checks.

    Adds per-package checks for fields defined by the ``spdx-ai`` profile
    (e.g. ``ai_typeOfModel``, ``ai_domain``) and the ``spdx-dataset`` profile
    (e.g. ``dataset_datasetType``, ``dataset_dataCollectionProcess``).

    Notes:
        - All check methods return an empty list for SPDX 2 documents — the
          AI and dataset profiles are SPDX 3-only.
        - ``check_sbom_generation_context`` remains on :class:`BaseChecker`
          because it operates on the ``software_Sbom`` element (Software
          profile), not on AI/dataset packages.
    """

    # Extend the parent mapping with AI and dataset keys.
    _COMPONENTS_WITHOUT_INFO = {
        **BaseChecker._COMPONENTS_WITHOUT_INFO,
        # AI package fields (SPDX 3 / spdx-ai profile)
        "ai_type_of_model": (
            "ai_packages_without_type_of_model",
            "AI packages missing a type of model",
        ),
        "ai_domain": (
            "ai_packages_without_domain",
            "AI packages missing an intended application domain",
        ),
        "ai_sensitive_data_info": (
            "ai_packages_without_sensitive_data_info",
            "AI packages missing sensitive personal data usage declaration",
        ),
        "ai_hash": (
            "ai_packages_without_hash",
            "AI packages missing an integrity hash",
        ),
        "ai_description": (
            "ai_packages_without_description",
            "AI packages missing a description",
        ),
        "ai_timestamp": (
            "ai_packages_without_timestamp",
            "AI packages missing a release or build timestamp",
        ),
        # Dataset package fields (SPDX 3 / spdx-dataset profile)
        "dataset_type": (
            "dataset_packages_without_dataset_type",
            "Dataset packages missing a dataset type",
        ),
        "dataset_sensitive_info": (
            "dataset_packages_without_sensitive_info",
            "Dataset packages missing sensitive personal information declaration",
        ),
        "dataset_provenance": (
            "dataset_packages_without_provenance",
            "Dataset packages missing data collection provenance",
        ),
        "dataset_hash": (
            "dataset_packages_without_hash",
            "Dataset packages missing an integrity hash",
        ),
        "dataset_description": (
            "dataset_packages_without_description",
            "Dataset packages missing a description",
        ),
    }

    # AI package checks (SPDX 3 / spdx-ai profile; empty for SPDX 2 or non-AI SBOMs)
    ai_packages_without_type_of_model: list[tuple[str, str]] = []
    ai_packages_without_domain: list[tuple[str, str]] = []
    ai_packages_without_sensitive_data_info: list[tuple[str, str]] = []
    ai_packages_without_hash: list[tuple[str, str]] = []
    ai_packages_without_description: list[tuple[str, str]] = []
    ai_packages_without_timestamp: list[tuple[str, str]] = []

    # Dataset package checks (SPDX 3 / spdx-dataset profile)
    dataset_packages_without_dataset_type: list[tuple[str, str]] = []
    dataset_packages_without_sensitive_info: list[tuple[str, str]] = []
    dataset_packages_without_provenance: list[tuple[str, str]] = []
    dataset_packages_without_hash: list[tuple[str, str]] = []
    dataset_packages_without_description: list[tuple[str, str]] = []

    def __init__(
        self,
        file: str,
        validate: bool = True,
        compliance: str = "",
        sbom_spec: str = "spdx3",
    ) -> None:
        super().__init__(
            file=file, validate=validate, compliance=compliance, sbom_spec=sbom_spec
        )
        if self.doc:
            self.ai_packages_without_type_of_model = (
                self.get_ai_packages_without_type_of_model()
            )
            self.ai_packages_without_domain = self.get_ai_packages_without_domain()
            self.ai_packages_without_sensitive_data_info = (
                self.get_ai_packages_without_sensitive_data_info()
            )
            self.ai_packages_without_hash = self.get_ai_packages_without_hash()
            self.ai_packages_without_description = (
                self.get_ai_packages_without_description()
            )
            self.ai_packages_without_timestamp = (
                self.get_ai_packages_without_timestamp()
            )
            self.dataset_packages_without_dataset_type = (
                self.get_dataset_packages_without_dataset_type()
            )
            self.dataset_packages_without_sensitive_info = (
                self.get_dataset_packages_without_sensitive_info()
            )
            self.dataset_packages_without_provenance = (
                self.get_dataset_packages_without_provenance()
            )
            self.dataset_packages_without_hash = self.get_dataset_packages_without_hash()
            self.dataset_packages_without_description = (
                self.get_dataset_packages_without_description()
            )

    # ------------------------------------------------------------------
    # AI package checks (spdx-ai profile, SPDX 3 only)
    # ------------------------------------------------------------------

    def get_ai_packages_without_type_of_model(self) -> list[tuple[str, str]]:
        """Retrieve AI packages (SPDX 3) missing ``ai_typeOfModel``.

        Maps to G7 "Model properties" (typeOfModel).

        Returns:
            list[tuple[str, str]]: ``(name, spdx_id)`` tuples.
            Empty for SPDX 2 or when no ``ai_AIPackage`` elements exist.
        """
        if not self.doc or self.sbom_spec != "spdx3":
            return []
        self.doc = cast("spdx3.SHACLObjectSet", self.doc)
        return [
            (name or "", spdx_id or "")
            for name, spdx_id, type_of_model in iter_objects_with_property(
                self.doc, spdx3.ai_AIPackage, "ai_typeOfModel"
            )
            if not type_of_model
        ]

    def get_ai_packages_without_domain(self) -> list[tuple[str, str]]:
        """Retrieve AI packages (SPDX 3) missing ``ai_domain``.

        Maps to G7 "Intended application area".

        Returns:
            list[tuple[str, str]]: ``(name, spdx_id)`` tuples.
        """
        if not self.doc or self.sbom_spec != "spdx3":
            return []
        self.doc = cast("spdx3.SHACLObjectSet", self.doc)
        return [
            (name or "", spdx_id or "")
            for name, spdx_id, domain in iter_objects_with_property(
                self.doc, spdx3.ai_AIPackage, "ai_domain"
            )
            if not domain
        ]

    def get_ai_packages_without_sensitive_data_info(self) -> list[tuple[str, str]]:
        """Retrieve AI packages (SPDX 3) where ``ai_useSensitivePersonalInformation``
        is not set.

        Maps to G7 "System data usage". Any PresenceType value (yes/no/noAssertion)
        satisfies the requirement; only a completely absent field is flagged.

        Returns:
            list[tuple[str, str]]: ``(name, spdx_id)`` tuples.
        """
        if not self.doc or self.sbom_spec != "spdx3":
            return []
        self.doc = cast("spdx3.SHACLObjectSet", self.doc)
        return [
            (name or "", spdx_id or "")
            for name, spdx_id, sensitive_info in iter_objects_with_property(
                self.doc,
                spdx3.ai_AIPackage,
                "ai_useSensitivePersonalInformation",
            )
            if sensitive_info is None
        ]

    def get_ai_packages_without_hash(self) -> list[tuple[str, str]]:
        """Retrieve AI packages (SPDX 3) with no ``verifiedUsing`` entry.

        Maps to G7 "Model hash value" and "Model hash algorithm".

        Returns:
            list[tuple[str, str]]: ``(name, spdx_id)`` tuples.
        """
        if not self.doc or self.sbom_spec != "spdx3":
            return []
        self.doc = cast("spdx3.SHACLObjectSet", self.doc)
        return [
            (name or "", spdx_id or "")
            for name, spdx_id, verified_using in iter_objects_with_property(
                self.doc, spdx3.ai_AIPackage, "verifiedUsing"
            )
            if not verified_using
        ]

    def get_ai_packages_without_description(self) -> list[tuple[str, str]]:
        """Retrieve AI packages (SPDX 3) missing both ``description`` and ``summary``.

        Maps to G7 "Model description".

        Returns:
            list[tuple[str, str]]: ``(name, spdx_id)`` tuples.
        """
        if not self.doc or self.sbom_spec != "spdx3":
            return []
        doc = cast("spdx3.SHACLObjectSet", self.doc)
        result: list[tuple[str, str]] = []
        for obj in doc.foreach_type(spdx3.ai_AIPackage):
            if not getattr(obj, "description", None) and not getattr(
                obj, "summary", None
            ):
                name = (getattr(obj, "name", "") or "").strip()
                spdx_id = (getattr(obj, "spdxId", "") or "").strip()
                result.append((name, spdx_id))
        return result

    def get_ai_packages_without_timestamp(self) -> list[tuple[str, str]]:
        """Retrieve AI packages (SPDX 3) missing both ``builtTime`` and ``releaseTime``.

        Maps to G7 "Model timestamp" and "System timestamp".

        Returns:
            list[tuple[str, str]]: ``(name, spdx_id)`` tuples.
        """
        if not self.doc or self.sbom_spec != "spdx3":
            return []
        doc = cast("spdx3.SHACLObjectSet", self.doc)
        result = []
        for obj in doc.foreach_type(spdx3.ai_AIPackage):
            if not getattr(obj, "builtTime", None) and not getattr(
                obj, "releaseTime", None
            ):
                name = (getattr(obj, "name", "") or "").strip()
                spdx_id = (getattr(obj, "spdxId", "") or "").strip()
                result.append((name, spdx_id))
        return result

    # ------------------------------------------------------------------
    # Dataset package checks (spdx-dataset profile, SPDX 3 only)
    # ------------------------------------------------------------------

    def get_dataset_packages_without_dataset_type(self) -> list[tuple[str, str]]:
        """Retrieve dataset packages (SPDX 3) missing ``dataset_datasetType``.

        Maps to G7 "Dataset content".

        Returns:
            list[tuple[str, str]]: ``(name, spdx_id)`` tuples.
            Empty for SPDX 2 or when no ``dataset_DatasetPackage`` elements exist.
        """
        if not self.doc or self.sbom_spec != "spdx3":
            return []
        self.doc = cast("spdx3.SHACLObjectSet", self.doc)
        return [
            (name or "", spdx_id or "")
            for name, spdx_id, dataset_type in iter_objects_with_property(
                self.doc, spdx3.dataset_DatasetPackage, "dataset_datasetType"
            )
            if not dataset_type
        ]

    def get_dataset_packages_without_sensitive_info(self) -> list[tuple[str, str]]:
        """Retrieve dataset packages (SPDX 3) where
        ``dataset_hasSensitivePersonalInformation`` is not set.

        Maps to G7 "Dataset sensitivity". Any PresenceType value satisfies
        the requirement; only a completely absent field is flagged.

        Returns:
            list[tuple[str, str]]: ``(name, spdx_id)`` tuples.
        """
        if not self.doc or self.sbom_spec != "spdx3":
            return []
        self.doc = cast("spdx3.SHACLObjectSet", self.doc)
        return [
            (name or "", spdx_id or "")
            for name, spdx_id, sensitive_info in iter_objects_with_property(
                self.doc,
                spdx3.dataset_DatasetPackage,
                "dataset_hasSensitivePersonalInformation",
            )
            if sensitive_info is None
        ]

    def get_dataset_packages_without_provenance(self) -> list[tuple[str, str]]:
        """Retrieve dataset packages (SPDX 3) missing ``dataset_dataCollectionProcess``.

        Maps to G7 "Dataset provenance" (dataCollectionProcess component).

        Returns:
            list[tuple[str, str]]: ``(name, spdx_id)`` tuples.
        """
        if not self.doc or self.sbom_spec != "spdx3":
            return []
        self.doc = cast("spdx3.SHACLObjectSet", self.doc)
        return [
            (name or "", spdx_id or "")
            for name, spdx_id, provenance in iter_objects_with_property(
                self.doc,
                spdx3.dataset_DatasetPackage,
                "dataset_dataCollectionProcess",
            )
            if not provenance
            or (isinstance(provenance, str) and provenance.strip() == "")
        ]

    def get_dataset_packages_without_hash(self) -> list[tuple[str, str]]:
        """Retrieve dataset packages (SPDX 3) with no ``verifiedUsing`` entry.

        Maps to G7 "Dataset hash".

        Returns:
            list[tuple[str, str]]: ``(name, spdx_id)`` tuples.
        """
        if not self.doc or self.sbom_spec != "spdx3":
            return []
        self.doc = cast("spdx3.SHACLObjectSet", self.doc)
        return [
            (name or "", spdx_id or "")
            for name, spdx_id, verified_using in iter_objects_with_property(
                self.doc, spdx3.dataset_DatasetPackage, "verifiedUsing"
            )
            if not verified_using
        ]

    def get_dataset_packages_without_description(self) -> list[tuple[str, str]]:
        """Retrieve dataset packages (SPDX 3) missing both ``description``
        and ``summary``.

        Maps to G7 "Dataset description".

        Returns:
            list[tuple[str, str]]: ``(name, spdx_id)`` tuples.
        """
        if not self.doc or self.sbom_spec != "spdx3":
            return []
        doc = cast("spdx3.SHACLObjectSet", self.doc)
        result = []
        for obj in doc.foreach_type(spdx3.dataset_DatasetPackage):
            if not getattr(obj, "description", None) and not getattr(
                obj, "summary", None
            ):
                name = (getattr(obj, "name", "") or "").strip()
                spdx_id = (getattr(obj, "spdxId", "") or "").strip()
                result.append((name, spdx_id))
        return result
