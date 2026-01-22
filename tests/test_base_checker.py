# SPDX-FileCopyrightText: 2025 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Additional tests for base_checker to increase coverage"""

# pylint: disable=missing-function-docstring,import-error

import os
import tempfile
from pathlib import Path

import pytest

from ntia_conformance_checker import NTIAChecker
from ntia_conformance_checker.base_checker import BaseChecker


def test_basechecker_cannot_instantiate_abstract():
    """Test that BaseChecker cannot be instantiated directly (abstract class)"""
    with pytest.raises(TypeError):
        BaseChecker("dummy_file.spdx")  # type: ignore


def test_basechecker_unsupported_sbom_spec():
    """Test that unsupported SBOM spec raises ValueError"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    
    with pytest.raises(ValueError, match="Unsupported SBOM specification"):
        NTIAChecker(str(test_file), sbom_spec="unsupported_spec")


def test_basechecker_no_file_path():
    """Test parse_file with empty file path"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually test parse_file with empty path
    checker.file = ""
    result = checker.parse_file()
    assert result is None
    # The error is logged but parse_file returns None


def test_basechecker_file_not_found():
    """Test parse_file with non-existent file"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually test parse_file with non-existent file
    checker.file = "/nonexistent/path/to/file.spdx"
    result = checker.parse_file()
    assert result is None


def test_basechecker_no_file_path_spdx3():
    """Test parse_spdx3_file with empty file path"""
    test_file = Path(__file__).parent / "data" / "spdx3" / "no_elements_missing.json"
    checker = NTIAChecker(str(test_file), sbom_spec="spdx3")
    
    # Manually test parse_spdx3_file with empty path
    checker.file = ""
    result = checker.parse_spdx3_file()
    assert result is None


def test_basechecker_file_not_found_spdx3():
    """Test parse_spdx3_file with non-existent file"""
    test_file = Path(__file__).parent / "data" / "spdx3" / "no_elements_missing.json"
    checker = NTIAChecker(str(test_file), sbom_spec="spdx3")
    
    # Manually test parse_spdx3_file with non-existent file
    checker.file = "/nonexistent/path/to/file.json"
    result = checker.parse_spdx3_file()
    assert result is None


def test_basechecker_spdx3_invalid_json():
    """Test parse_spdx3_file with invalid JSON"""
    # Create a temporary invalid JSON file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("{invalid json content")
        temp_file = f.name
    
    try:
        test_file = Path(__file__).parent / "data" / "spdx3" / "no_elements_missing.json"
        checker = NTIAChecker(str(test_file), sbom_spec="spdx3")
        
        # Manually test parse_spdx3_file with invalid JSON
        checker.file = temp_file
        result = checker.parse_spdx3_file()
        assert result is None
        assert len(checker.parsing_error) > 0
    finally:
        os.unlink(temp_file)


def test_basechecker_check_author_no_doc():
    """Test check_author when doc is None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker.check_author()
    assert result is False


def test_basechecker_check_doc_version_returns_false():
    """Test check_doc_version when get_doc_spec_version returns None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None to simulate no version
    checker.doc = None
    result = checker.check_doc_version()
    assert result is False


def test_basechecker_print_components_missing_info_with_parsing_error():
    """Test print_components_missing_info when there are parsing errors"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Add a parsing error
    checker.parsing_error = ["Some parsing error"]
    
    # This should return early without printing
    checker.print_components_missing_info()  # Should not raise


def test_basechecker_print_components_missing_info_no_issues(capsys):
    """Test print_components_missing_info when all components have required info"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # This SBOM has no missing info
    checker.print_components_missing_info()
    
    # Should not print anything since all_components_without_info is empty
    captured = capsys.readouterr()
    assert captured.out == ""


def test_basechecker_print_components_missing_info_with_issues(capsys):
    """Test print_components_missing_info when there are missing components"""
    test_file = Path(__file__).parent / "data" / "missing_supplier_name" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # This SBOM has missing supplier info
    checker.print_components_missing_info()
    
    # Should print missing info
    captured = capsys.readouterr()
    assert "Missing required information" in captured.out
    assert "supplier" in captured.out


def test_basechecker_print_table_output(capsys):
    """Test print_table_output method"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    checker.print_table_output(verbose=False)
    captured = capsys.readouterr()
    assert len(captured.out) > 0


def test_basechecker_print_table_output_verbose(capsys):
    """Test print_table_output with verbose flag"""
    test_file = Path(__file__).parent / "data" / "missing_supplier_name" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    checker.print_table_output(verbose=True)
    captured = capsys.readouterr()
    assert len(captured.out) > 0
    # In verbose mode, it should print missing component info
    assert "supplier" in captured.out.lower()


def test_basechecker_check_timestamp_no_doc():
    """Test check_timestamp when doc is None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker.check_timestamp()
    assert result is False


def test_basechecker_check_dependency_relationships_no_doc():
    """Test check_dependency_relationships when doc is None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker.check_dependency_relationships()
    assert result is False


def test_basechecker_get_total_number_components_no_doc():
    """Test get_total_number_components when doc is None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker.get_total_number_components()
    assert result == 0


def test_basechecker_get_total_number_components_no_packages():
    """Test get_total_number_components when packages is empty"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set packages to empty list
    if checker.doc:
        checker.doc.packages = []
        result = checker.get_total_number_components()
        assert result == 0


def test_basechecker_check_compliance_not_implemented():
    """Test that check_compliance raises NotImplementedError in base class"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Try to call the abstract method directly on BaseChecker
    # This is covered by the abstract class test, but we verify the implementation
    with pytest.raises(NotImplementedError):
        BaseChecker.check_compliance(checker)


def test_basechecker_spdx3_failed_parse():
    """Test SPDX3 file that fails to parse"""
    # Create a file that will fail SPDX3 parsing with a different error
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        # Write invalid content that will trigger a JSONDecodeError
        f.write('not valid json at all')
        temp_file = f.name
    
    try:
        from ntia_conformance_checker import sbom_checker
        # This should trigger the parse error handling
        checker = sbom_checker.SbomChecker(temp_file, sbom_spec="spdx3")
        # The doc should be None because parsing failed
        assert checker.doc is None
        # Should have parsing errors
        assert len(checker.parsing_error) > 0
    finally:
        os.unlink(temp_file)


def test_basechecker_get_sbom_name_no_doc():
    """Test get_sbom_name when doc is None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker.get_sbom_name()
    assert result == ""


def test_basechecker_get_components_without_concluded_licenses_no_doc():
    """Test get_components_without_concluded_licenses when doc is None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker.get_components_without_concluded_licenses()
    assert result == []


def test_basechecker_get_components_without_copyright_texts_no_doc():
    """Test get_components_without_copyright_texts when doc is None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker.get_components_without_copyright_texts()
    assert result == []


def test_basechecker_get_components_without_identifiers_no_doc():
    """Test get_components_without_identifiers when doc is None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker.get_components_without_identifiers()
    assert result == []


def test_basechecker_get_components_without_names_no_doc():
    """Test get_components_without_names when doc is None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker.get_components_without_names()
    assert result == []


def test_basechecker_get_components_without_suppliers_no_doc():
    """Test get_components_without_suppliers when doc is None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker.get_components_without_suppliers()
    assert result == []


def test_basechecker_get_components_without_versions_no_doc():
    """Test get_components_without_versions when doc is None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker.get_components_without_versions()
    assert result == []


def test_basechecker_get_all_components_without_info_no_doc():
    """Test _get_all_components_without_info when doc is None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker._get_all_components_without_info()
    assert result == []


def test_basechecker_get_doc_spec_version_returns_none():
    """Test get_doc_spec_version when it returns None"""
    test_file = Path(__file__).parent / "data" / "no_elements_missing" / "SPDXJSONExample-v2.3.spdx.json"
    checker = NTIAChecker(str(test_file))
    
    # Manually set doc to None
    checker.doc = None
    result = checker.get_doc_spec_version()
    assert result is None
