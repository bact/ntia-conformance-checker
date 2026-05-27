# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""G7 SBOM for AI - Minimum Elements checking functionality."""

from __future__ import annotations

from typing import Any

from .base_ai_data_checker import BaseAIDataChecker
from .spec import Spec


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

    # Single source of truth for every G7 minimum-element check.
    # ``MIN_ELEMENTS`` (used by the base class for the missing-info report)
    # is derived from this table, as is the cluster table, the overall
    # compliance check, and the JSON output.
    _SPEC: tuple[Spec, ...] = (
        # -- Metadata --
        Spec(
            key="doc_author",
            cluster="Metadata",
            attr="doc_author",
            label="SBOM author name provided?",
            kind="bool",
        ),
        Spec(
            key="doc_timestamp",
            cluster="Metadata",
            attr="doc_timestamp",
            label="SBOM creation timestamp provided?",
            kind="bool",
        ),
        # SBOM generation context is shown in every cluster table regardless
        # of spec (it's simply False on SPDX 2), so spdx3_only stays False.
        Spec(
            key="sbom_generation_context",
            cluster="Metadata",
            attr="sbom_generation_context",
            label="SBOM generation context provided? (SPDX 3)",
            kind="bool",
            json_key="sbomGenerationContext",
            getter="check_sbom_generation_context",
        ),
        # -- System Level Properties --
        Spec(
            key="name",
            cluster="System Level Properties",
            attr="components_without_names",
            label="All component names provided?",
            kind="list",
        ),
        Spec(
            key="version",
            cluster="System Level Properties",
            attr="components_without_versions",
            label="All component versions provided?",
            kind="list",
        ),
        Spec(
            key="identifier",
            cluster="System Level Properties",
            attr="components_without_identifiers",
            label="All component identifiers provided?",
            kind="list",
        ),
        Spec(
            key="supplier",
            cluster="System Level Properties",
            attr="components_without_suppliers",
            label="All component suppliers provided?",
            kind="list",
        ),
        # -- Models (SPDX 3 / spdx-ai profile) --
        Spec(
            key="ai_type_of_model",
            cluster="Models",
            attr="ai_packages_without_type_of_model",
            label="All AI packages have type of model? (SPDX 3)",
            kind="list",
            spdx3_only=True,
            json_group="aiPackages",
            json_key="typeOfModel",
            getter="get_ai_packages_without_type_of_model",
        ),
        Spec(
            key="ai_domain",
            cluster="Models",
            attr="ai_packages_without_domain",
            label="All AI packages have application domain? (SPDX 3)",
            kind="list",
            spdx3_only=True,
            json_group="aiPackages",
            json_key="domain",
            getter="get_ai_packages_without_domain",
        ),
        Spec(
            key="ai_sensitive_data_info",
            cluster="Models",
            attr="ai_packages_without_sensitive_data_info",
            label="All AI packages declare sensitive data usage? (SPDX 3)",
            kind="list",
            spdx3_only=True,
            json_group="aiPackages",
            json_key="sensitiveDataInfo",
            getter="get_ai_packages_without_sensitive_data_info",
        ),
        Spec(
            key="ai_hash",
            cluster="Models",
            attr="ai_packages_without_hash",
            label="All AI packages have integrity hash? (SPDX 3)",
            kind="list",
            spdx3_only=True,
            json_group="aiPackages",
            json_key="hash",
            getter="get_ai_packages_without_hash",
        ),
        Spec(
            key="ai_description",
            cluster="Models",
            attr="ai_packages_without_description",
            label="All AI packages have a description? (SPDX 3)",
            kind="list",
            spdx3_only=True,
            json_group="aiPackages",
            json_key="description",
            getter="get_ai_packages_without_description",
        ),
        Spec(
            key="ai_timestamp",
            cluster="Models",
            attr="ai_packages_without_timestamp",
            label="All AI packages have a release/build timestamp? (SPDX 3)",
            kind="list",
            spdx3_only=True,
            json_group="aiPackages",
            json_key="timestamp",
            getter="get_ai_packages_without_timestamp",
        ),
        # -- Dataset Properties (SPDX 3 / spdx-dataset profile) --
        Spec(
            key="dataset_type",
            cluster="Dataset Properties",
            attr="dataset_packages_without_dataset_type",
            label="All dataset packages have dataset type? (SPDX 3)",
            kind="list",
            spdx3_only=True,
            json_group="datasetPackages",
            json_key="datasetType",
            getter="get_dataset_packages_without_dataset_type",
        ),
        Spec(
            key="dataset_sensitive_info",
            cluster="Dataset Properties",
            attr="dataset_packages_without_sensitive_info",
            label="All dataset packages declare sensitive info? (SPDX 3)",
            kind="list",
            spdx3_only=True,
            json_group="datasetPackages",
            json_key="sensitiveInfo",
            getter="get_dataset_packages_without_sensitive_info",
        ),
        Spec(
            key="dataset_provenance",
            cluster="Dataset Properties",
            attr="dataset_packages_without_provenance",
            label="All dataset packages have provenance info? (SPDX 3)",
            kind="list",
            spdx3_only=True,
            json_group="datasetPackages",
            json_key="provenance",
            getter="get_dataset_packages_without_provenance",
        ),
        Spec(
            key="dataset_hash",
            cluster="Dataset Properties",
            attr="dataset_packages_without_hash",
            label="All dataset packages have integrity hash? (SPDX 3)",
            kind="list",
            spdx3_only=True,
            json_group="datasetPackages",
            json_key="hash",
            getter="get_dataset_packages_without_hash",
        ),
        Spec(
            key="dataset_description",
            cluster="Dataset Properties",
            attr="dataset_packages_without_description",
            label="All dataset packages have a description? (SPDX 3)",
            kind="list",
            spdx3_only=True,
            json_group="datasetPackages",
            json_key="description",
            getter="get_dataset_packages_without_description",
        ),
        # -- Infrastructure: no SPDX 3 mapping yet --
        # -- Security Properties --
        Spec(
            key="concluded_license",
            cluster="Security Properties",
            attr="components_without_concluded_licenses",
            label="All component concluded license provided?",
            kind="list",
        ),
        Spec(
            key="dependency_relationships",
            cluster="Security Properties",
            attr="dependency_relationships",
            label="Dependency relationships provided?",
            kind="bool",
        ),
        # -- Key Performance Indicators: no SPDX 3 mapping yet --
    )

    # Minimum-element keys for the base class's missing-info report.
    MIN_ELEMENTS = [
        s.key
        for s in _SPEC
        if s.kind == "list" and s.key in BaseAIDataChecker._COMPONENTS_WITHOUT_INFO
    ]

    # Default class-level values so attributes always exist.
    cluster_table_elements: dict[str, list[tuple[str, bool]]] = {}
    cluster_compliance: dict[str, bool | None] = {}

    def __init__(
        self,
        file: str,
        validate: bool = True,
        compliance: str = "g7ai",
        sbom_spec: str = "spdx3",
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
            # Populate every spec attribute that has its own getter; getters
            # return empty lists / False when the SBOM spec doesn't apply,
            # so no spec check is needed here.
            for spec in self._SPEC:
                if spec.getter is not None:
                    setattr(self, spec.attr, getattr(self, spec.getter)())

            # Recompute with the updated AI/dataset-specific lists.
            self.all_components_without_info = self._get_all_components_without_info()
            self.compliant = self.check_compliance()

        # Cluster-based reporting — always populated (uses class-attribute
        # defaults when doc is None so attributes remain consistent).
        self.cluster_table_elements = self._build_cluster_table_elements()
        self.cluster_compliance = {
            cluster: (None if not elements else all(result for _, result in elements))
            for cluster, elements in self.cluster_table_elements.items()
        }
        # Flat table derived from clusters to avoid a separate specification.
        self.table_elements = [
            element
            for cluster in self.CLUSTERS
            for element in self.cluster_table_elements[cluster]
        ]

    def _spec_passes(self, spec: Spec) -> bool:
        """Return True if the spec's attribute reports a passing result."""
        value = getattr(self, spec.attr)
        return bool(value) if spec.kind == "bool" else not value

    def _build_cluster_table_elements(
        self,
    ) -> dict[str, list[tuple[str, bool]]]:
        """Organise check results by G7 cluster.

        Clusters without checkable SPDX 3 mappings (Infrastructure, KPI) have
        empty element lists; ``cluster_compliance`` maps these to ``None``.
        Entries marked ``spdx3_only`` are omitted when ``sbom_spec`` is not
        ``"spdx3"`` (also mapped to ``None``).
        """
        is_spdx3 = self.sbom_spec == "spdx3"
        result: dict[str, list[tuple[str, bool]]] = {c: [] for c in self.CLUSTERS}
        for spec in self._SPEC:
            if spec.spdx3_only and not is_spdx3:
                continue
            result[spec.cluster].append((spec.label, self._spec_passes(spec)))
        return result

    def check_compliance(self) -> bool:
        """Check overall compliance with G7 SBOM for AI minimum elements."""
        return (
            all(self._spec_passes(spec) for spec in self._SPEC)
            and not self.validation_messages
        )

    def output_json(self) -> dict[str, Any]:
        """Create a JSON-serializable result dict for G7 SBOM for AI.

        Extends the base output with AI package checks, dataset package checks,
        SBOM generation context, and per-cluster compliance results.
        """
        result = super().output_json()

        # Top-level boolean JSON keys (e.g. sbomGenerationContext).
        for spec in self._SPEC:
            if (
                spec.kind == "bool"
                and spec.json_key is not None
                and spec.json_group is None
            ):
                result[spec.json_key] = getattr(self, spec.attr)

        # Grouped list outputs (aiPackages, datasetPackages).
        groups: dict[str, dict[str, dict[str, Any]]] = {}
        for spec in self._SPEC:
            if (
                spec.kind != "list"
                or spec.json_group is None
                or spec.json_key is None
            ):
                continue
            packages = getattr(self, spec.attr)
            groups.setdefault(spec.json_group, {})[spec.json_key] = {
                "nonconformantPackages": [
                    name if name not in (None, "") else spdx_id
                    for name, spdx_id in packages
                ],
                "allProvided": not bool(packages),
            }
        result.update(groups)

        result["clusterCompliance"] = self.cluster_compliance

        return result
