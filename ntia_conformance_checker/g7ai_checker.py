# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""G7 SBOM for AI - Minimum Elements checking functionality."""

from __future__ import annotations

from typing import Any

from .base_ai_data_checker import BaseAIDataChecker
from .spec import Spec, SpecRule, SpecTaxon

G7AI_HELP_URI = (
    "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/KI/SBOM-for-AI_minimum-elements.html"
)


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

    # Single source of truth for every G7 minimum-element check.
    # ``MIN_ELEMENTS`` (used by the base class for the missing-info report)
    # is derived from this table, as is the cluster table, the overall
    # compliance check, and the JSON output.
    _SPEC: Spec = Spec(
        standard_short_id="g7ai",
        standard_id="2024-g7-sbom-for-ai-minimum-elements",
        standard_name="G7 SBOM for AI Minimum Elements",
        help_uri=G7AI_HELP_URI,
        taxa=(
            SpecTaxon(taxon_id="Metadata", taxon_name="Metadata"),
            SpecTaxon(
                taxon_id="System Level Properties",
                taxon_name="System Level Properties",
            ),
            SpecTaxon(taxon_id="Models", taxon_name="Models"),
            SpecTaxon(
                taxon_id="Dataset Properties", taxon_name="Dataset Properties"
            ),
            SpecTaxon(taxon_id="Infrastructure", taxon_name="Infrastructure"),
            SpecTaxon(
                taxon_id="Security Properties", taxon_name="Security Properties"
            ),
            SpecTaxon(
                taxon_id="Key Performance Indicators",
                taxon_name="Key Performance Indicators",
            ),
        ),
        rules=(
            # -- Metadata --
            SpecRule(
                element_id="doc_author",
                element_name="SBOM author",
                report_label="SBOM author name provided?",
                kind="bool",
                cluster="Metadata",
                attr="doc_author",
                getter="check_author",
            ),
            SpecRule(
                element_id="doc_timestamp",
                element_name="SBOM creation timestamp",
                report_label="SBOM creation timestamp provided?",
                kind="bool",
                cluster="Metadata",
                attr="doc_timestamp",
                getter="check_timestamp",
            ),
            # sbom_generation_context is True when sbom_gen_context (list from
            # BaseChecker) is non-empty; set in G7AIChecker.__init__.
            SpecRule(
                element_id="sbom_generation_context",
                element_name="SBOM generation context",
                report_label="SBOM generation context provided? (SPDX 3)",
                kind="bool",
                cluster="Metadata",
                attr="sbom_generation_context",
                getter="get_sbom_types",
                json_key="sbomGenerationContext",
            ),
            # -- System Level Properties --
            SpecRule(
                element_id="name",
                element_name="component name",
                report_label="All component names provided?",
                kind="list",
                cluster="System Level Properties",
                attr="components_without_names",
                getter="get_components_without_names",
            ),
            SpecRule(
                element_id="version",
                element_name="component version",
                report_label="All component versions provided?",
                kind="list",
                cluster="System Level Properties",
                attr="components_without_versions",
                getter="get_components_without_versions",
            ),
            SpecRule(
                element_id="identifier",
                element_name="component identifier",
                report_label="All component identifiers provided?",
                kind="list",
                cluster="System Level Properties",
                attr="components_without_identifiers",
                getter="get_components_without_identifiers",
            ),
            SpecRule(
                element_id="supplier",
                element_name="component supplier",
                report_label="All component suppliers provided?",
                kind="list",
                cluster="System Level Properties",
                attr="components_without_suppliers",
                getter="get_components_without_suppliers",
            ),
            # -- Models (SPDX 3 / spdx-ai profile) --
            SpecRule(
                element_id="ai_type_of_model",
                element_name="AI package type of model",
                report_label="All AI packages have type of model? (SPDX 3)",
                kind="list",
                cluster="Models",
                spdx3_only=True,
                attr="ai_packages_without_type_of_model",
                getter="get_ai_packages_without_type_of_model",
                json_group="aiPackages",
                json_key="typeOfModel",
            ),
            SpecRule(
                element_id="ai_domain",
                element_name="AI package application domain",
                report_label="All AI packages have application domain? (SPDX 3)",
                kind="list",
                cluster="Models",
                spdx3_only=True,
                attr="ai_packages_without_domain",
                getter="get_ai_packages_without_domain",
                json_group="aiPackages",
                json_key="domain",
            ),
            SpecRule(
                element_id="ai_sensitive_data_info",
                element_name="AI package sensitive data usage",
                report_label="All AI packages declare sensitive data usage? (SPDX 3)",
                kind="list",
                cluster="Models",
                spdx3_only=True,
                attr="ai_packages_without_sensitive_data_info",
                getter="get_ai_packages_without_sensitive_data_info",
                json_group="aiPackages",
                json_key="sensitiveDataInfo",
            ),
            SpecRule(
                element_id="ai_hash",
                element_name="AI package integrity hash",
                report_label="All AI packages have integrity hash? (SPDX 3)",
                kind="list",
                cluster="Models",
                spdx3_only=True,
                attr="ai_packages_without_hash",
                getter="get_ai_packages_without_hash",
                json_group="aiPackages",
                json_key="hash",
            ),
            SpecRule(
                element_id="ai_description",
                element_name="AI package description",
                report_label="All AI packages have a description? (SPDX 3)",
                kind="list",
                cluster="Models",
                spdx3_only=True,
                attr="ai_packages_without_description",
                getter="get_ai_packages_without_description",
                json_group="aiPackages",
                json_key="description",
            ),
            SpecRule(
                element_id="ai_timestamp",
                element_name="AI package release/build timestamp",
                report_label="All AI packages have a release/build timestamp? (SPDX 3)",
                kind="list",
                cluster="Models",
                spdx3_only=True,
                attr="ai_packages_without_timestamp",
                getter="get_ai_packages_without_timestamp",
                json_group="aiPackages",
                json_key="timestamp",
            ),
            # -- Dataset Properties (SPDX 3 / spdx-dataset profile) --
            SpecRule(
                element_id="dataset_type",
                element_name="dataset type",
                report_label="All dataset packages have dataset type? (SPDX 3)",
                kind="list",
                cluster="Dataset Properties",
                spdx3_only=True,
                attr="dataset_packages_without_dataset_type",
                getter="get_dataset_packages_without_dataset_type",
                json_group="datasetPackages",
                json_key="datasetType",
            ),
            SpecRule(
                element_id="dataset_sensitive_info",
                element_name="dataset sensitive info",
                report_label="All dataset packages declare sensitive info? (SPDX 3)",
                kind="list",
                cluster="Dataset Properties",
                spdx3_only=True,
                attr="dataset_packages_without_sensitive_info",
                getter="get_dataset_packages_without_sensitive_info",
                json_group="datasetPackages",
                json_key="sensitiveInfo",
            ),
            SpecRule(
                element_id="dataset_provenance",
                element_name="dataset provenance",
                report_label="All dataset packages have provenance info? (SPDX 3)",
                kind="list",
                cluster="Dataset Properties",
                spdx3_only=True,
                attr="dataset_packages_without_provenance",
                getter="get_dataset_packages_without_provenance",
                json_group="datasetPackages",
                json_key="provenance",
            ),
            SpecRule(
                element_id="dataset_hash",
                element_name="dataset integrity hash",
                report_label="All dataset packages have integrity hash? (SPDX 3)",
                kind="list",
                cluster="Dataset Properties",
                spdx3_only=True,
                attr="dataset_packages_without_hash",
                getter="get_dataset_packages_without_hash",
                json_group="datasetPackages",
                json_key="hash",
            ),
            SpecRule(
                element_id="dataset_description",
                element_name="dataset description",
                report_label="All dataset packages have a description? (SPDX 3)",
                kind="list",
                cluster="Dataset Properties",
                spdx3_only=True,
                attr="dataset_packages_without_description",
                getter="get_dataset_packages_without_description",
                json_group="datasetPackages",
                json_key="description",
            ),
            # -- Infrastructure: no SPDX 3 mapping yet --
            # -- Security Properties --
            SpecRule(
                element_id="concluded_license",
                element_name="component concluded license",
                report_label="All component concluded license provided?",
                kind="list",
                cluster="Security Properties",
                attr="components_without_concluded_licenses",
                getter="get_components_without_concluded_licenses",
            ),
            SpecRule(
                element_id="dependency_relationships",
                element_name="dependency relationships",
                report_label="Dependency relationships provided?",
                kind="bool",
                cluster="Security Properties",
                attr="dependency_relationships",
                getter="check_dependency_relationships",
            ),
            # -- Key Performance Indicators: no SPDX 3 mapping yet --
        ),
    )

    # G7 cluster taxon_ids in document order (for ordered iteration).
    CLUSTERS = [taxon.taxon_id for taxon in _SPEC.taxa]

    # Minimum-element keys for the base class's missing-info report.
    MIN_ELEMENTS = [
        r.element_id
        for r in _SPEC.rules
        if r.kind == "list"
        and r.element_id in BaseAIDataChecker._COMPONENTS_WITHOUT_INFO
    ]

    # Default class-level values so attributes always exist.
    sbom_generation_context: bool = False
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
            # sbom_gen_context (list) is set by BaseChecker.__init__ via
            # get_sbom_types(); derive the bool used in G7 conformance checks.
            self.sbom_generation_context = bool(self.sbom_gen_context)

            # Recompute all_components_without_info to include the AI/dataset
            # lists populated by BaseAIDataChecker.__init__.
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

    def _rule_passes(self, rule: SpecRule) -> bool:
        """Return True if the rule's attribute reports a passing result."""
        value = getattr(self, rule.attr)
        return bool(value) if rule.kind == "bool" else not value

    def _build_cluster_table_elements(
        self,
    ) -> dict[str, list[tuple[str, bool]]]:
        """Organise check results by G7 cluster.

        Clusters without checkable SPDX 3 mappings (Infrastructure, KPI) have
        empty element lists; ``cluster_compliance`` maps these to ``None``.
        Rules marked ``spdx3_only`` are omitted when ``sbom_spec`` is not
        ``"spdx3"`` (also mapped to ``None``).
        """
        is_spdx3 = self.sbom_spec == "spdx3"
        result: dict[str, list[tuple[str, bool]]] = {c: [] for c in self.CLUSTERS}
        for rule in self._SPEC.rules:
            if rule.spdx3_only and not is_spdx3:
                continue
            result[rule.cluster].append((rule.report_label, self._rule_passes(rule)))
        return result

    def check_compliance(self) -> bool:
        """Check overall compliance with G7 SBOM for AI minimum elements."""
        return (
            all(self._rule_passes(rule) for rule in self._SPEC.rules)
            and not self.validation_messages
        )

    def output_json(self) -> dict[str, Any]:
        """Create a JSON-serializable result dict for G7 SBOM for AI.

        Extends the base output with AI package checks, dataset package checks,
        SBOM generation context, and per-cluster compliance results.
        """
        result = super().output_json()

        # Top-level boolean JSON keys (e.g. sbomGenerationContext).
        for rule in self._SPEC.rules:
            if (
                rule.kind == "bool"
                and rule.json_key is not None
                and rule.json_group is None
            ):
                result[rule.json_key] = getattr(self, rule.attr)

        # Grouped list outputs (aiPackages, datasetPackages).
        groups: dict[str, dict[str, dict[str, Any]]] = {}
        for rule in self._SPEC.rules:
            if (
                rule.kind != "list"
                or rule.json_group is None
                or rule.json_key is None
            ):
                continue
            packages = getattr(self, rule.attr)
            groups.setdefault(rule.json_group, {})[rule.json_key] = {
                "nonconformantPackages": [
                    name if name not in (None, "") else spdx_id
                    for name, spdx_id in packages
                ],
                "allProvided": not bool(packages),
            }
        result.update(groups)

        result["clusterCompliance"] = self.cluster_compliance

        return result
