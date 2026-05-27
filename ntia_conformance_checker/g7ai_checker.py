# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""G7 SBOM for AI - Minimum Elements checking functionality."""

from __future__ import annotations

from typing import Any

from .base_ai_data_checker import BaseAIDataChecker


# pylint: disable=too-many-instance-attributes
class G7AIChecker(BaseAIDataChecker):
    """G7 SBOM for AI - Minimum Elements checker.

    Checks conformance with the minimum elements defined in the
    G7 SBOM for AI document published by BSI and the G7 AI working group.

    For SPDX 2, only standard component fields are checked (name, version,
    identifier, supplier, concluded license) since SPDX 2 has no native AI
    profile.  For SPDX 3, AI-specific and dataset-specific fields from the
    spdx-ai and spdx-dataset profiles are also verified.

    Results are available both flat (``table_elements``, derived from the
    cluster structure) and per G7 cluster (``cluster_table_elements`` and
    ``cluster_compliance``).  The seven G7 clusters are listed in ``CLUSTERS``.

    See:
        https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.html
    """

    MIN_ELEMENTS = [
        # Standard component fields (all SBOM specs)
        "name",
        "version",
        "identifier",
        "supplier",
        "concluded_license",
        # AI package fields (SPDX 3 / spdx-ai profile)
        "ai_type_of_model",  # G7: Model properties → typeOfModel
        "ai_domain",  # G7: Intended application area → domain
        "ai_sensitive_data_info",  # G7: System/model data usage → useSensitivePersonalInformation
        "ai_hash",  # G7: Model hash value/algorithm → verifiedUsing
        "ai_description",  # G7: Model description → description / summary
        "ai_timestamp",  # G7: Model/system timestamp → builtTime / releaseTime
        # Dataset package fields (SPDX 3 / spdx-dataset profile)
        "dataset_type",  # G7: Dataset content → datasetType
        "dataset_sensitive_info",  # G7: Dataset sensitivity → hasSensitivePersonalInformation
        "dataset_provenance",  # G7: Dataset provenance → dataCollectionProcess
        "dataset_hash",  # G7: Dataset hash → verifiedUsing
        "dataset_description",  # G7: Dataset description → description / summary
    ]

    # G7 cluster names in document order.
    CLUSTERS = [
        "Metadata",
        "System Level Properties",
        "Models",
        "Dataset Properties",
        "Infrastructure",
        "Security Properties",
        "Key Performance Indicators",
    ]

    # Default class-level values so attributes always exist.
    cluster_table_elements: dict[str, list[tuple[str, bool]]] = {}
    cluster_compliance: dict[str, bool | None] = {}

    def __init__(
        self,
        file: str,
        validate: bool = True,
        compliance: str = "g7ai",
        sbom_spec: str = "spdx2",
    ) -> None:
        """
        Initialize the G7 AI SBOM Minimum Elements checker.

        Args:
            file (str): The name of the file to be checked.
            validate (bool): Whether to validate the file.
            compliance (str): The compliance standard to be used.
            sbom_spec (str): The SBOM specification to be used.
        """
        super().__init__(
            file=file, validate=validate, compliance=compliance, sbom_spec=sbom_spec
        )

        if compliance not in {"g7ai"}:
            raise ValueError("Only G7 SBOM for AI compliance is supported.")

        if self.doc:
            # Document-level check
            self.sbom_generation_context = self.check_sbom_generation_context()

            # AI package checks (SPDX 3 only; empty lists for SPDX 2)
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

            # Dataset package checks (SPDX 3 only; empty lists for SPDX 2)
            self.dataset_packages_without_dataset_type = (
                self.get_dataset_packages_without_dataset_type()
            )
            self.dataset_packages_without_sensitive_info = (
                self.get_dataset_packages_without_sensitive_info()
            )
            self.dataset_packages_without_provenance = (
                self.get_dataset_packages_without_provenance()
            )
            self.dataset_packages_without_hash = (
                self.get_dataset_packages_without_hash()
            )
            self.dataset_packages_without_description = (
                self.get_dataset_packages_without_description()
            )

            # Recompute with the updated AI/dataset-specific lists.
            self.all_components_without_info = self._get_all_components_without_info()
            self.compliant = self.check_compliance()

        # Cluster-based reporting — always populated (uses class-attribute defaults
        # when doc is None so attributes remain consistent).
        self.cluster_table_elements = self._build_cluster_table_elements()
        self.cluster_compliance = {
            cluster: (None if not elements else all(result for _, result in elements))
            for cluster, elements in self.cluster_table_elements.items()
        }
        # Flat table derived from clusters to avoid a separate 20-line specification.
        self.table_elements = [
            element
            for cluster in self.CLUSTERS
            for element in self.cluster_table_elements[cluster]
        ]

    def _build_cluster_table_elements(
        self,
    ) -> dict[str, list[tuple[str, bool]]]:
        """Organise check results by G7 cluster.

        Clusters without checkable SPDX 3 mappings (Infrastructure, KPI) have
        empty element lists; ``cluster_compliance`` maps these to ``None``.
        Models and Dataset Properties elements are omitted when ``sbom_spec``
        is not ``"spdx3"`` (also mapped to ``None``).
        """
        is_spdx3 = self.sbom_spec == "spdx3"
        return {
            "Metadata": [
                ("SBOM author name provided?", self.doc_author),
                ("SBOM creation timestamp provided?", self.doc_timestamp),
                (
                    "SBOM generation context provided? (SPDX 3)",
                    self.sbom_generation_context,
                ),
            ],
            "System Level Properties": [
                ("All component names provided?", not self.components_without_names),
                (
                    "All component versions provided?",
                    not self.components_without_versions,
                ),
                (
                    "All component identifiers provided?",
                    not self.components_without_identifiers,
                ),
                (
                    "All component suppliers provided?",
                    not self.components_without_suppliers,
                ),
            ],
            "Models": (
                [
                    (
                        "All AI packages have type of model? (SPDX 3)",
                        not self.ai_packages_without_type_of_model,
                    ),
                    (
                        "All AI packages have application domain? (SPDX 3)",
                        not self.ai_packages_without_domain,
                    ),
                    (
                        "All AI packages declare sensitive data usage? (SPDX 3)",
                        not self.ai_packages_without_sensitive_data_info,
                    ),
                    (
                        "All AI packages have integrity hash? (SPDX 3)",
                        not self.ai_packages_without_hash,
                    ),
                    (
                        "All AI packages have a description? (SPDX 3)",
                        not self.ai_packages_without_description,
                    ),
                    (
                        "All AI packages have a release/build timestamp? (SPDX 3)",
                        not self.ai_packages_without_timestamp,
                    ),
                ]
                if is_spdx3
                else []
            ),
            "Dataset Properties": (
                [
                    (
                        "All dataset packages have dataset type? (SPDX 3)",
                        not self.dataset_packages_without_dataset_type,
                    ),
                    (
                        "All dataset packages declare sensitive info? (SPDX 3)",
                        not self.dataset_packages_without_sensitive_info,
                    ),
                    (
                        "All dataset packages have provenance info? (SPDX 3)",
                        not self.dataset_packages_without_provenance,
                    ),
                    (
                        "All dataset packages have integrity hash? (SPDX 3)",
                        not self.dataset_packages_without_hash,
                    ),
                    (
                        "All dataset packages have a description? (SPDX 3)",
                        not self.dataset_packages_without_description,
                    ),
                ]
                if is_spdx3
                else []
            ),
            # Infrastructure and KPI have no current SPDX 3 mapping.
            "Infrastructure": [],
            "Security Properties": [
                (
                    "All component concluded license provided?",
                    not self.components_without_concluded_licenses,
                ),
                ("Dependency relationships provided?", self.dependency_relationships),
            ],
            "Key Performance Indicators": [],
        }

    def check_compliance(self) -> bool:
        """Check overall compliance with G7 SBOM for AI minimum elements."""
        return all(
            [
                self.doc_author,
                self.doc_timestamp,
                self.sbom_generation_context,
                self.dependency_relationships,
                not self.components_without_names,
                not self.components_without_versions,
                not self.components_without_identifiers,
                not self.components_without_suppliers,
                not self.components_without_concluded_licenses,
                not self.ai_packages_without_type_of_model,
                not self.ai_packages_without_domain,
                not self.ai_packages_without_sensitive_data_info,
                not self.ai_packages_without_hash,
                not self.ai_packages_without_description,
                not self.ai_packages_without_timestamp,
                not self.dataset_packages_without_dataset_type,
                not self.dataset_packages_without_sensitive_info,
                not self.dataset_packages_without_provenance,
                not self.dataset_packages_without_hash,
                not self.dataset_packages_without_description,
                not self.validation_messages,
            ]
        )

    def output_json(self) -> dict[str, Any]:
        """Create a JSON-serializable result dict for G7 SBOM for AI.

        Extends the base output with AI package checks, dataset package checks,
        SBOM generation context, and per-cluster compliance results.
        """
        result = super().output_json()

        # SBOM generation context
        result["sbomGenerationContext"] = self.sbom_generation_context

        # AI package checks
        ai_checks = {
            "typeOfModel": self.ai_packages_without_type_of_model,
            "domain": self.ai_packages_without_domain,
            "sensitiveDataInfo": self.ai_packages_without_sensitive_data_info,
            "hash": self.ai_packages_without_hash,
            "description": self.ai_packages_without_description,
            "timestamp": self.ai_packages_without_timestamp,
        }
        result["aiPackages"] = {
            key: {
                "nonconformantPackages": [
                    name if name not in (None, "") else spdx_id
                    for name, spdx_id in packages
                ],
                "allProvided": not bool(packages),
            }
            for key, packages in ai_checks.items()
        }

        # Dataset package checks
        dataset_checks = {
            "datasetType": self.dataset_packages_without_dataset_type,
            "sensitiveInfo": self.dataset_packages_without_sensitive_info,
            "provenance": self.dataset_packages_without_provenance,
            "hash": self.dataset_packages_without_hash,
            "description": self.dataset_packages_without_description,
        }
        result["datasetPackages"] = {
            key: {
                "nonconformantPackages": [
                    name if name not in (None, "") else spdx_id
                    for name, spdx_id in packages
                ],
                "allProvided": not bool(packages),
            }
            for key, packages in dataset_checks.items()
        }

        # Per-cluster compliance
        result["clusterCompliance"] = self.cluster_compliance

        return result
