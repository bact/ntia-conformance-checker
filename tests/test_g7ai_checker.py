# SPDX-FileCopyrightText: 2025 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests for G7AIChecker."""

# pylint: disable=missing-function-docstring,import-error

from pathlib import Path

import pytest
from spdx_python_model import v3_0_1 as spdx3  # type: ignore # import-untyped

from ntia_conformance_checker import G7AIChecker, sbom_checker

_DATA = Path(__file__).parent / "data" / "spdx3" / "g7ai"
_SPDX2_COMPLETE = (
    Path(__file__).parent / "data" / "no_elements_missing" / "SPDXTagExample-v2.3.spdx"
)


# ---------------------------------------------------------------------------
# Complete SBOM — no elements missing
# ---------------------------------------------------------------------------


def test_g7ai_checker_no_elements_missing() -> None:
    sbom = G7AIChecker(str(_DATA / "no_elements_missing.json"), sbom_spec="spdx3")
    assert sbom.doc is not None
    assert isinstance(sbom.doc, spdx3.SHACLObjectSet)
    assert len(sbom.parsing_errors) == 0
    assert len(sbom.validation_messages) == 0
    assert sbom.sbom_name
    assert sbom.doc_version
    assert sbom.doc_author
    assert sbom.doc_timestamp
    assert sbom.dependency_relationships
    assert sbom.sbom_generation_context
    # Standard per-component
    assert not sbom.components_without_names
    assert not sbom.components_without_versions
    assert not sbom.components_without_identifiers
    assert not sbom.components_without_suppliers
    assert not sbom.components_without_concluded_licenses
    # AI package checks
    assert not sbom.ai_packages_without_type_of_model
    assert not sbom.ai_packages_without_domain
    assert not sbom.ai_packages_without_sensitive_data_info
    assert not sbom.ai_packages_without_hash
    assert not sbom.ai_packages_without_description
    assert not sbom.ai_packages_without_timestamp
    # Dataset package checks
    assert not sbom.dataset_packages_without_dataset_type
    assert not sbom.dataset_packages_without_sensitive_info
    assert not sbom.dataset_packages_without_provenance
    assert not sbom.dataset_packages_without_hash
    assert not sbom.dataset_packages_without_description
    assert sbom.compliant


def test_sbomchecker_g7ai_no_elements_missing() -> None:
    sbom = sbom_checker.SbomChecker(
        str(_DATA / "no_elements_missing.json"), sbom_spec="spdx3", compliance="g7ai"
    )
    assert sbom.compliant


# ---------------------------------------------------------------------------
# Missing ai_typeOfModel
# ---------------------------------------------------------------------------


def test_g7ai_checker_missing_ai_type_of_model() -> None:
    sbom = G7AIChecker(str(_DATA / "missing_ai_type_of_model.json"), sbom_spec="spdx3")
    assert len(sbom.ai_packages_without_type_of_model) == 1
    assert sbom.ai_packages_without_type_of_model[0][0] == "Test AI Model"
    assert not sbom.compliant


def test_g7ai_checker_missing_ai_type_of_model_reported_in_all_components() -> None:
    sbom = G7AIChecker(str(_DATA / "missing_ai_type_of_model.json"), sbom_spec="spdx3")
    info_names = [name for name, _ in sbom.all_components_without_info]
    assert "AI packages missing a type of model" in info_names


# ---------------------------------------------------------------------------
# Missing dataset_datasetType
# ---------------------------------------------------------------------------


def test_g7ai_checker_missing_dataset_type() -> None:
    sbom = G7AIChecker(str(_DATA / "missing_dataset_type.json"), sbom_spec="spdx3")
    assert len(sbom.dataset_packages_without_dataset_type) == 1
    assert sbom.dataset_packages_without_dataset_type[0][0] == "Test Training Dataset"
    assert not sbom.compliant


def test_g7ai_checker_missing_dataset_type_reported_in_all_components() -> None:
    sbom = G7AIChecker(str(_DATA / "missing_dataset_type.json"), sbom_spec="spdx3")
    info_names = [name for name, _ in sbom.all_components_without_info]
    assert "Dataset packages missing a dataset type" in info_names


# ---------------------------------------------------------------------------
# Missing SBOM generation context (software_sbomType)
# ---------------------------------------------------------------------------


def test_g7ai_checker_missing_sbom_context() -> None:
    sbom = G7AIChecker(str(_DATA / "missing_sbom_context.json"), sbom_spec="spdx3")
    assert not sbom.sbom_generation_context
    assert not sbom.compliant


# ---------------------------------------------------------------------------
# Missing AI-specific fields (domain, sensitive data info, hash, desc, timestamp)
# ---------------------------------------------------------------------------


def test_g7ai_checker_missing_ai_specific_fields() -> None:
    sbom = G7AIChecker(
        str(_DATA / "missing_ai_specific_fields.json"), sbom_spec="spdx3"
    )
    assert len(sbom.ai_packages_without_type_of_model) == 1
    assert len(sbom.ai_packages_without_domain) == 1
    assert len(sbom.ai_packages_without_sensitive_data_info) == 1
    assert len(sbom.ai_packages_without_hash) == 1
    assert len(sbom.ai_packages_without_description) == 1
    assert len(sbom.ai_packages_without_timestamp) == 1
    assert not sbom.compliant


def test_g7ai_checker_missing_ai_fields_all_reported() -> None:
    sbom = G7AIChecker(
        str(_DATA / "missing_ai_specific_fields.json"), sbom_spec="spdx3"
    )
    info_names = [name for name, _ in sbom.all_components_without_info]
    assert "AI packages missing a type of model" in info_names
    assert "AI packages missing an intended application domain" in info_names
    assert "AI packages missing sensitive personal data usage declaration" in info_names
    assert "AI packages missing an integrity hash" in info_names
    assert "AI packages missing a description" in info_names
    assert "AI packages missing a release or build timestamp" in info_names


# ---------------------------------------------------------------------------
# Missing dataset-specific fields (sensitive info, provenance, hash, description)
# ---------------------------------------------------------------------------


def test_g7ai_checker_missing_dataset_specific_fields() -> None:
    sbom = G7AIChecker(
        str(_DATA / "missing_dataset_specific_fields.json"), sbom_spec="spdx3"
    )
    assert len(sbom.dataset_packages_without_sensitive_info) == 1
    assert len(sbom.dataset_packages_without_provenance) == 1
    assert len(sbom.dataset_packages_without_hash) == 1
    assert len(sbom.dataset_packages_without_description) == 1
    assert not sbom.compliant


def test_g7ai_checker_missing_dataset_fields_all_reported() -> None:
    sbom = G7AIChecker(
        str(_DATA / "missing_dataset_specific_fields.json"), sbom_spec="spdx3"
    )
    info_names = [name for name, _ in sbom.all_components_without_info]
    assert (
        "Dataset packages missing sensitive personal information declaration"
        in info_names
    )
    assert "Dataset packages missing data collection provenance" in info_names
    assert "Dataset packages missing an integrity hash" in info_names
    assert "Dataset packages missing a description" in info_names


# ---------------------------------------------------------------------------
# SPDX 2 fallback — AI/dataset-specific lists are empty (no AI profile)
# ---------------------------------------------------------------------------


def test_g7ai_checker_spdx2_ai_lists_empty() -> None:
    sbom = G7AIChecker(str(_SPDX2_COMPLETE), sbom_spec="spdx2")
    assert not sbom.sbom_generation_context
    assert not sbom.ai_packages_without_type_of_model
    assert not sbom.ai_packages_without_domain
    assert not sbom.ai_packages_without_sensitive_data_info
    assert not sbom.ai_packages_without_hash
    assert not sbom.ai_packages_without_description
    assert not sbom.ai_packages_without_timestamp
    assert not sbom.dataset_packages_without_dataset_type
    assert not sbom.dataset_packages_without_sensitive_info
    assert not sbom.dataset_packages_without_provenance
    assert not sbom.dataset_packages_without_hash
    assert not sbom.dataset_packages_without_description


# ---------------------------------------------------------------------------
# Invalid compliance argument
# ---------------------------------------------------------------------------


def test_g7ai_checker_wrong_compliance_raises() -> None:
    with pytest.raises(ValueError, match="Only G7 SBOM for AI compliance"):
        G7AIChecker(
            str(_DATA / "no_elements_missing.json"),
            compliance="ntia",
            sbom_spec="spdx3",
        )


# ---------------------------------------------------------------------------
# SbomChecker factory
# ---------------------------------------------------------------------------


def test_sbomchecker_unknown_compliance_raises() -> None:
    with pytest.raises(ValueError, match="Unknown compliance standard"):
        sbom_checker.SbomChecker(
            str(_DATA / "no_elements_missing.json"),
            sbom_spec="spdx3",
            compliance="unknown-standard",
        )


# ---------------------------------------------------------------------------
# Existing SPDX 3 fixture — already has datasetType and no AI packages
# ---------------------------------------------------------------------------


def test_g7ai_checker_existing_spdx3_no_elements_missing() -> None:
    """The existing no_elements_missing.json has a DatasetPackage with
    datasetType, sensitive info, provenance, and a hash.  There are no
    ai_AIPackage elements so AI package checks trivially pass.
    The DatasetPackage has no description field, which is flagged correctly."""
    existing = Path(__file__).parent / "data" / "spdx3" / "no_elements_missing.json"
    sbom = G7AIChecker(str(existing), sbom_spec="spdx3")
    assert not sbom.ai_packages_without_type_of_model
    assert not sbom.dataset_packages_without_dataset_type
    assert not sbom.dataset_packages_without_sensitive_info
    assert not sbom.dataset_packages_without_provenance
    assert not sbom.dataset_packages_without_hash
    # The existing fixture deliberately has no description on the DatasetPackage;
    # G7 checker correctly flags it.
    assert len(sbom.dataset_packages_without_description) == 1


# ---------------------------------------------------------------------------
# table_elements coverage
# ---------------------------------------------------------------------------


def test_g7ai_checker_table_elements_labels() -> None:
    sbom = G7AIChecker(str(_DATA / "no_elements_missing.json"), sbom_spec="spdx3")
    labels = [label for label, _ in sbom.table_elements]
    assert "All AI packages have type of model? (SPDX 3)" in labels
    assert "All AI packages have application domain? (SPDX 3)" in labels
    assert "All AI packages declare sensitive data usage? (SPDX 3)" in labels
    assert "All AI packages have integrity hash? (SPDX 3)" in labels
    assert "All AI packages have a description? (SPDX 3)" in labels
    assert "All AI packages have a release/build timestamp? (SPDX 3)" in labels
    assert "All dataset packages have dataset type? (SPDX 3)" in labels
    assert "All dataset packages declare sensitive info? (SPDX 3)" in labels
    assert "All dataset packages have provenance info? (SPDX 3)" in labels
    assert "All dataset packages have integrity hash? (SPDX 3)" in labels
    assert "All dataset packages have a description? (SPDX 3)" in labels
    assert "SBOM generation context provided? (SPDX 3)" in labels
    assert "All component concluded license provided?" in labels


def test_g7ai_checker_table_elements_all_true_when_complete() -> None:
    sbom = G7AIChecker(str(_DATA / "no_elements_missing.json"), sbom_spec="spdx3")
    for label, result in sbom.table_elements:
        assert result is True, f"Expected True for: {label!r}"


# ---------------------------------------------------------------------------
# Cluster-based reporting
# ---------------------------------------------------------------------------

_SPDX3_BASE = Path(__file__).parent / "data" / "spdx3"


def test_g7ai_checker_cluster_keys_present() -> None:
    sbom = G7AIChecker(str(_DATA / "no_elements_missing.json"), sbom_spec="spdx3")
    assert set(sbom.cluster_compliance.keys()) == set(G7AIChecker.CLUSTERS)


def test_g7ai_checker_cluster_table_elements_keys_present() -> None:
    sbom = G7AIChecker(str(_DATA / "no_elements_missing.json"), sbom_spec="spdx3")
    assert set(sbom.cluster_table_elements.keys()) == set(G7AIChecker.CLUSTERS)


def test_g7ai_checker_infrastructure_kpi_not_applicable() -> None:
    """Infrastructure and KPI have no SPDX 3 mapping — cluster_compliance is None."""
    sbom = G7AIChecker(str(_DATA / "no_elements_missing.json"), sbom_spec="spdx3")
    assert sbom.cluster_compliance["Infrastructure"] is None
    assert sbom.cluster_compliance["Key Performance Indicators"] is None
    assert not sbom.cluster_table_elements["Infrastructure"]
    assert not sbom.cluster_table_elements["Key Performance Indicators"]


def test_g7ai_checker_all_clusters_compliant_when_complete() -> None:
    sbom = G7AIChecker(str(_DATA / "no_elements_missing.json"), sbom_spec="spdx3")
    for cluster, result in sbom.cluster_compliance.items():
        if cluster in ("Infrastructure", "Key Performance Indicators"):
            assert result is None, f"Expected None for: {cluster!r}"
        else:
            assert result is True, f"Expected True for: {cluster!r}"


# -- Metadata cluster --


def test_g7ai_cluster_metadata_fails_when_sbom_context_missing() -> None:
    sbom = G7AIChecker(str(_DATA / "missing_sbom_context.json"), sbom_spec="spdx3")
    assert sbom.cluster_compliance["Metadata"] is False
    results = dict(sbom.cluster_table_elements["Metadata"])
    assert results["SBOM generation context provided? (SPDX 3)"] is False
    # Author and timestamp are still present in the fixture.
    assert results["SBOM author name provided?"] is True
    assert results["SBOM creation timestamp provided?"] is True


# -- System Level Properties cluster --


def test_g7ai_cluster_slp_fails_when_version_missing() -> None:
    sbom = G7AIChecker(str(_SPDX3_BASE / "missing_version.json"), sbom_spec="spdx3")
    assert sbom.cluster_compliance["System Level Properties"] is False
    results = dict(sbom.cluster_table_elements["System Level Properties"])
    assert results["All component versions provided?"] is False


def test_g7ai_cluster_slp_fails_when_supplier_missing() -> None:
    sbom = G7AIChecker(
        str(_SPDX3_BASE / "missing_supplier_name.json"), sbom_spec="spdx3"
    )
    assert sbom.cluster_compliance["System Level Properties"] is False
    results = dict(sbom.cluster_table_elements["System Level Properties"])
    assert results["All component suppliers provided?"] is False


def test_g7ai_cluster_slp_identifier_always_present_in_valid_spdx3() -> None:
    # SPDX 3 parser enforces IRI presence; valid docs always pass identifier check.
    sbom = G7AIChecker(str(_DATA / "no_elements_missing.json"), sbom_spec="spdx3")
    results = dict(sbom.cluster_table_elements["System Level Properties"])
    assert results["All component identifiers provided?"] is True


# -- Models cluster --


def test_g7ai_cluster_models_fails_when_ai_fields_missing() -> None:
    sbom = G7AIChecker(
        str(_DATA / "missing_ai_specific_fields.json"), sbom_spec="spdx3"
    )
    assert sbom.cluster_compliance["Models"] is False
    # Dataset Properties and Security Properties are unaffected by this fixture.
    assert sbom.cluster_compliance["Dataset Properties"] is True
    assert sbom.cluster_compliance["Security Properties"] is True


def test_g7ai_cluster_models_none_for_spdx2() -> None:
    sbom = G7AIChecker(str(_SPDX2_COMPLETE), sbom_spec="spdx2")
    assert sbom.cluster_compliance["Models"] is None
    assert not sbom.cluster_table_elements["Models"]


# -- Dataset Properties cluster --


def test_g7ai_cluster_dataset_fails_when_dataset_fields_missing() -> None:
    sbom = G7AIChecker(
        str(_DATA / "missing_dataset_specific_fields.json"), sbom_spec="spdx3"
    )
    assert sbom.cluster_compliance["Dataset Properties"] is False
    # Models cluster unaffected (AI package is complete in this fixture).
    assert sbom.cluster_compliance["Models"] is True


def test_g7ai_cluster_dataset_none_for_spdx2() -> None:
    sbom = G7AIChecker(str(_SPDX2_COMPLETE), sbom_spec="spdx2")
    assert sbom.cluster_compliance["Dataset Properties"] is None
    assert not sbom.cluster_table_elements["Dataset Properties"]


# -- Security Properties cluster --


def test_g7ai_cluster_security_fails_when_concluded_license_missing() -> None:
    sbom = G7AIChecker(
        str(_DATA / "missing_security_properties.json"), sbom_spec="spdx3"
    )
    assert sbom.cluster_compliance["Security Properties"] is False
    results = dict(sbom.cluster_table_elements["Security Properties"])
    assert results["All component concluded license provided?"] is False
    # Other clusters should pass (all AI/dataset fields are present).
    assert sbom.cluster_compliance["Metadata"] is True
    assert sbom.cluster_compliance["System Level Properties"] is True
    assert sbom.cluster_compliance["Models"] is True
    assert sbom.cluster_compliance["Dataset Properties"] is True
