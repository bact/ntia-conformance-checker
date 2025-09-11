# SPDX-FileCopyrightText: 2025 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests for checker modules (FSCT, NTIA, and SbomChecker)"""

# pylint: disable=missing-function-docstring

import tempfile
import warnings
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from ntia_conformance_checker import FSCT3Checker, NTIAChecker
from ntia_conformance_checker.sbom_checker import SbomChecker


class TestSbomChecker:
    def test_sbomchecker_factory_ntia(self):
        # Test that SbomChecker returns NTIAChecker for "ntia" compliance
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.ntia_checker.NTIAChecker") as mock_ntia:
                mock_instance = Mock()
                mock_ntia.return_value = mock_instance
                
                result = SbomChecker(temp_file, compliance="ntia")
                
                assert result == mock_instance
                mock_ntia.assert_called_once_with(temp_file, True, sbom_spec="spdx2")
        finally:
            Path(temp_file).unlink()

    def test_sbomchecker_factory_fsct3(self):
        # Test that SbomChecker returns FSCT3Checker for "fsct3-min" compliance
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.fsct_checker.FSCT3Checker") as mock_fsct:
                mock_instance = Mock()
                mock_fsct.return_value = mock_instance
                
                result = SbomChecker(temp_file, compliance="fsct3-min")
                
                assert result == mock_instance
                mock_fsct.assert_called_once_with(temp_file, True, sbom_spec="spdx2")
        finally:
            Path(temp_file).unlink()

    def test_sbomchecker_unsupported_sbom_spec(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with pytest.raises(ValueError, match="Unsupported SBOM specification"):
                SbomChecker(temp_file, sbom_spec="unsupported")
        finally:
            Path(temp_file).unlink()

    def test_sbomchecker_unknown_compliance(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with pytest.raises(ValueError, match="Unknown compliance standard"):
                SbomChecker(temp_file, compliance="unknown")
        finally:
            Path(temp_file).unlink()

    def test_sbomchecker_cannot_be_subclassed(self):
        with pytest.raises(TypeError, match="SbomChecker is a factory"):
            class CustomChecker(SbomChecker):
                pass

    def test_sbomchecker_check_compliance_not_implemented(self):
        # This should never be called in practice, but test for completeness
        instance = object.__new__(SbomChecker)
        with pytest.raises(NotImplementedError):
            instance.check_compliance()


class TestNTIAChecker:
    def test_ntia_checker_invalid_compliance(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with pytest.raises(ValueError, match="Only NTIA Minimum Element compliance"):
                NTIAChecker(temp_file, compliance="invalid")
        finally:
            Path(temp_file).unlink()

    def test_ntia_checker_deprecated_method_warning(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.base_checker.BaseChecker.__init__"):
                checker = NTIAChecker.__new__(NTIAChecker)
                checker.doc = None  # Simulate no document to avoid compliance check
                
                # Mock the check_compliance method to return a value
                with patch.object(checker, 'check_compliance', return_value=True):
                    with warnings.catch_warnings(record=True) as w:
                        warnings.simplefilter("always")
                        
                        result = checker.check_ntia_minimum_elements_compliance()
                        
                        assert len(w) == 1
                        assert issubclass(w[0].category, DeprecationWarning)
                        assert "deprecated" in str(w[0].message)
                        assert result is True
        finally:
            Path(temp_file).unlink()

    def test_ntia_checker_print_components_missing_info(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.base_checker.BaseChecker.__init__"):
                with patch("ntia_conformance_checker.base_checker.BaseChecker.print_components_missing_info") as mock_print:
                    checker = NTIAChecker.__new__(NTIAChecker)
                    checker.doc = None  # Avoid compliance check
                    
                    checker.print_components_missing_info()
                    
                    mock_print.assert_called_once_with(["name", "version", "identifier", "supplier"])
        finally:
            Path(temp_file).unlink()


class TestFSCT3Checker:
    def test_fsct3_checker_invalid_compliance(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with pytest.raises(ValueError, match="Only FSCTv3 Minimum Expected compliance"):
                FSCT3Checker(temp_file, compliance="invalid")
        finally:
            Path(temp_file).unlink()

    def test_fsct3_checker_print_components_missing_info(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.base_checker.BaseChecker.__init__"):
                with patch("ntia_conformance_checker.base_checker.BaseChecker.print_components_missing_info") as mock_print:
                    checker = FSCT3Checker.__new__(FSCT3Checker)
                    checker.doc = None  # Avoid compliance check
                    
                    checker.print_components_missing_info()
                    
                    mock_print.assert_called_once_with(
                        attributes=["name", "version", "identifier", "supplier", "concluded_license", "copyright_text"]
                    )
        finally:
            Path(temp_file).unlink()

    def test_fsct3_checker_check_compliance_all_compliant(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.base_checker.BaseChecker.__init__"):
                checker = FSCT3Checker.__new__(FSCT3Checker)
                checker.doc = Mock()  # Non-None doc
                
                # Mock all required attributes as compliant
                checker.doc_author = True
                checker.doc_timestamp = True
                checker.dependency_relationships = True
                checker.components_without_names = []
                checker.components_without_versions = []
                checker.components_without_identifiers = []
                checker.components_without_suppliers = []
                checker.components_without_concluded_licenses = []
                checker.components_without_copyright_texts = []
                checker.validation_messages = []
                
                result = checker.check_compliance()
                assert result is True
        finally:
            Path(temp_file).unlink()

    def test_fsct3_checker_check_compliance_non_compliant(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.base_checker.BaseChecker.__init__"):
                checker = FSCT3Checker.__new__(FSCT3Checker)
                checker.doc = Mock()  # Non-None doc
                
                # Mock some required attributes as non-compliant
                checker.doc_author = False  # Missing author
                checker.doc_timestamp = True
                checker.dependency_relationships = True
                checker.components_without_names = []
                checker.components_without_versions = []
                checker.components_without_identifiers = []
                checker.components_without_suppliers = []
                checker.components_without_concluded_licenses = []
                checker.components_without_copyright_texts = []
                checker.validation_messages = []
                
                result = checker.check_compliance()
                assert result is False
        finally:
            Path(temp_file).unlink()

    def test_fsct3_checker_print_table_output(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.base_checker.BaseChecker.__init__"):
                with patch("ntia_conformance_checker.base_checker.BaseChecker.print_table_output") as mock_print:
                    checker = FSCT3Checker.__new__(FSCT3Checker)
                    checker.doc = None  # Avoid compliance check
                    
                    # Mock required attributes
                    checker.components_without_names = []
                    checker.components_without_versions = []
                    checker.components_without_identifiers = []
                    checker.components_without_suppliers = []
                    checker.components_without_concluded_licenses = []
                    checker.components_without_copyright_texts = []
                    checker.doc_author = True
                    checker.doc_timestamp = True
                    checker.dependency_relationships = True
                    
                    checker.print_table_output(verbose=True)
                    
                    mock_print.assert_called_once()
                    call_args = mock_print.call_args
                    assert call_args[1]['verbose'] is True
                    assert len(call_args[1]['table_elements']) == 9  # FSCT has 9 elements
        finally:
            Path(temp_file).unlink()

    def test_fsct3_checker_output_html(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.base_checker.BaseChecker.__init__"):
                with patch("ntia_conformance_checker.base_checker.BaseChecker.output_html") as mock_html:
                    mock_html.return_value = "<html>test</html>"
                    checker = FSCT3Checker.__new__(FSCT3Checker)
                    checker.doc = None  # Avoid compliance check
                    
                    # Mock required attributes
                    checker.components_without_names = []
                    checker.components_without_versions = []
                    checker.components_without_identifiers = []
                    checker.components_without_suppliers = []
                    checker.components_without_concluded_licenses = []
                    checker.components_without_copyright_texts = []
                    checker.doc_author = True
                    checker.doc_timestamp = True
                    checker.dependency_relationships = True
                    
                    result = checker.output_html()
                    
                    assert result == "<html>test</html>"
                    mock_html.assert_called_once()
                    call_args = mock_html.call_args
                    assert len(call_args[1]['table_elements']) == 9  # FSCT has 9 elements
        finally:
            Path(temp_file).unlink()


class TestNTIACheckerSpecific:
    def test_ntia_checker_check_compliance_all_compliant(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.base_checker.BaseChecker.__init__"):
                checker = NTIAChecker.__new__(NTIAChecker)
                checker.doc = Mock()  # Non-None doc
                
                # Mock all required attributes as compliant
                checker.doc_author = True
                checker.doc_timestamp = True
                checker.dependency_relationships = True
                checker.components_without_names = []
                checker.components_without_versions = []
                checker.components_without_identifiers = []
                checker.components_without_suppliers = []
                checker.validation_messages = []
                
                result = checker.check_compliance()
                assert result is True
        finally:
            Path(temp_file).unlink()

    def test_ntia_checker_check_compliance_non_compliant(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.base_checker.BaseChecker.__init__"):
                checker = NTIAChecker.__new__(NTIAChecker)
                checker.doc = Mock()  # Non-None doc
                
                # Mock some required attributes as non-compliant
                checker.doc_author = False  # Missing author
                checker.doc_timestamp = True
                checker.dependency_relationships = True
                checker.components_without_names = []
                checker.components_without_versions = []
                checker.components_without_identifiers = []
                checker.components_without_suppliers = []
                checker.validation_messages = []
                
                result = checker.check_compliance()
                assert result is False
        finally:
            Path(temp_file).unlink()

    def test_ntia_checker_print_table_output(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.base_checker.BaseChecker.__init__"):
                with patch("ntia_conformance_checker.base_checker.BaseChecker.print_table_output") as mock_print:
                    checker = NTIAChecker.__new__(NTIAChecker)
                    checker.doc = None  # Avoid compliance check
                    
                    # Mock required attributes
                    checker.components_without_names = []
                    checker.components_without_versions = []
                    checker.components_without_identifiers = []
                    checker.components_without_suppliers = []
                    checker.doc_author = True
                    checker.doc_timestamp = True
                    checker.dependency_relationships = True
                    
                    checker.print_table_output(verbose=True)
                    
                    mock_print.assert_called_once()
                    call_args = mock_print.call_args
                    assert call_args[1]['verbose'] is True
                    assert len(call_args[1]['table_elements']) == 7  # NTIA has 7 elements
        finally:
            Path(temp_file).unlink()

    def test_ntia_checker_output_html(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            temp_file = f.name
        
        try:
            with patch("ntia_conformance_checker.base_checker.BaseChecker.__init__"):
                with patch("ntia_conformance_checker.base_checker.BaseChecker.output_html") as mock_html:
                    mock_html.return_value = "<html>test</html>"
                    checker = NTIAChecker.__new__(NTIAChecker)
                    checker.doc = None  # Avoid compliance check
                    
                    # Mock required attributes
                    checker.components_without_names = []
                    checker.components_without_versions = []
                    checker.components_without_identifiers = []
                    checker.components_without_suppliers = []
                    checker.doc_author = True
                    checker.doc_timestamp = True
                    checker.dependency_relationships = True
                    
                    result = checker.output_html()
                    
                    assert result == "<html>test</html>"
                    mock_html.assert_called_once()
                    call_args = mock_html.call_args
                    assert len(call_args[1]['table_elements']) == 7  # NTIA has 7 elements
        finally:
            Path(temp_file).unlink()