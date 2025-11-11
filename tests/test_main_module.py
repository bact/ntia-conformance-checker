# SPDX-FileCopyrightText: 2025 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests for main module functionality"""

# pylint: disable=missing-function-docstring

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from ntia_conformance_checker.main import main


class TestMain:
    def create_test_sbom_file(self, content: str) -> str:
        """Helper to create temporary SBOM file with given content"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write(content)
            return f.name

    def test_main_successful_run(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    mock_sbom = Mock()
                    mock_sbom.compliant = True
                    mock_sbom.parsing_error = False
                    mock_sbom.validation_messages = []
                    mock_sbom.sbom_name = "test-sbom"
                    mock_checker.return_value = mock_sbom
                    
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    
                    assert exc_info.value.code == 0  # Success
                    mock_checker.assert_called_once()
                    mock_sbom.print_table_output.assert_called_once()
        finally:
            Path(test_file).unlink()

    def test_main_non_compliant_run(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    mock_sbom = Mock()
                    mock_sbom.compliant = False
                    mock_sbom.parsing_error = False
                    mock_sbom.validation_messages = []
                    mock_sbom.sbom_name = "test-sbom"
                    mock_checker.return_value = mock_sbom
                    
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    
                    assert exc_info.value.code == 1  # Failure
        finally:
            Path(test_file).unlink()

    def test_main_verbose_output(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file, "--verbose"]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    mock_sbom = Mock()
                    mock_sbom.compliant = True
                    mock_sbom.parsing_error = False
                    mock_sbom.validation_messages = []
                    mock_sbom.sbom_name = "test-sbom"
                    mock_checker.return_value = mock_sbom
                    
                    with pytest.raises(SystemExit):
                        main()
                    
                    mock_sbom.print_table_output.assert_called_once_with(verbose=True)
                    mock_sbom.print_components_missing_info.assert_called_once()
        finally:
            Path(test_file).unlink()

    def test_main_json_output(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file, "--output", "json"]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    with patch("builtins.print") as mock_print:
                        mock_sbom = Mock()
                        mock_sbom.compliant = True
                        mock_sbom.parsing_error = False
                        mock_sbom.validation_messages = []
                        mock_sbom.sbom_name = "test-sbom"
                        mock_sbom.output_json.return_value = {"test": "data"}
                        mock_checker.return_value = mock_sbom
                        
                        with pytest.raises(SystemExit):
                            main()
                        
                        # Should print JSON to stdout
                        mock_print.assert_called_once()
                        printed_json = mock_print.call_args[0][0]
                        assert '"test": "data"' in printed_json
        finally:
            Path(test_file).unlink()

    def test_main_json_output_to_file(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        output_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json').name
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file, "--output", "json", "--output-file", output_file]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    mock_sbom = Mock()
                    mock_sbom.compliant = True
                    mock_sbom.parsing_error = False
                    mock_sbom.validation_messages = []
                    mock_sbom.sbom_name = "test-sbom"
                    mock_sbom.output_json.return_value = {"test": "data"}
                    mock_checker.return_value = mock_sbom
                    
                    with pytest.raises(SystemExit):
                        main()
                    
                    # Check file was written
                    with open(output_file, 'r') as f:
                        data = json.load(f)
                        assert data["test"] == "data"
        finally:
            Path(test_file).unlink()
            Path(output_file).unlink()

    def test_main_html_output(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file, "--output", "html"]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    with patch("builtins.print") as mock_print:
                        mock_sbom = Mock()
                        mock_sbom.compliant = True
                        mock_sbom.parsing_error = False
                        mock_sbom.validation_messages = []
                        mock_sbom.sbom_name = "test-sbom"
                        mock_sbom.output_html.return_value = "<html>test</html>"
                        mock_checker.return_value = mock_sbom
                        
                        with pytest.raises(SystemExit):
                            main()
                        
                        mock_print.assert_called_once_with("<html>test</html>")
        finally:
            Path(test_file).unlink()

    def test_main_unsupported_sbom_spec(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file, "--sbom-spec", "unsupported"]):
                with pytest.raises(SystemExit) as exc_info:
                    main()
                
                # argparse exits with code 2 for invalid arguments
                assert exc_info.value.code == 2
        finally:
            Path(test_file).unlink()

    def test_main_unsupported_spdx_version(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-1.0\n")  # Unsupported version
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file]):
                with patch("ntia_conformance_checker.main.get_spdx_version") as mock_get_version:
                    mock_get_version.return_value = (1, 0)  # Unsupported version
                    
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    
                    assert exc_info.value.code == 1
        finally:
            Path(test_file).unlink()

    def test_main_cannot_detect_spdx_version(self):
        test_file = self.create_test_sbom_file("Not an SPDX file\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file]):
                with patch("ntia_conformance_checker.main.get_spdx_version") as mock_get_version:
                    mock_get_version.return_value = None
                    
                    with pytest.raises(SystemExit) as exc_info:
                        main()
                    
                    assert exc_info.value.code == 1
        finally:
            Path(test_file).unlink()

    def test_main_spdx3_detection(self):
        test_file = self.create_test_sbom_file('"@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld"')
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    with patch("ntia_conformance_checker.main.get_spdx_version") as mock_get_version:
                        mock_get_version.return_value = (3, 0)
                        mock_sbom = Mock()
                        mock_sbom.compliant = True
                        mock_sbom.parsing_error = False
                        mock_sbom.validation_messages = []
                        mock_sbom.sbom_name = "test-sbom"
                        mock_checker.return_value = mock_sbom
                        
                        with pytest.raises(SystemExit):
                            main()
                        
                        # Should be called with spdx3 spec
                        mock_checker.assert_called_once_with(
                            test_file,
                            validate=True,
                            compliance="ntia",
                            sbom_spec="spdx3"
                        )
        finally:
            Path(test_file).unlink()

    def test_main_spdx2_detection(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    with patch("ntia_conformance_checker.main.get_spdx_version") as mock_get_version:
                        mock_get_version.return_value = (2, 3)
                        mock_sbom = Mock()
                        mock_sbom.compliant = True
                        mock_sbom.parsing_error = False
                        mock_sbom.validation_messages = []
                        mock_sbom.sbom_name = "test-sbom"
                        mock_checker.return_value = mock_sbom
                        
                        with pytest.raises(SystemExit):
                            main()
                        
                        # Should be called with spdx2 spec
                        mock_checker.assert_called_once_with(
                            test_file,
                            validate=True,
                            compliance="ntia",
                            sbom_spec="spdx2"
                        )
        finally:
            Path(test_file).unlink()

    def test_main_skip_validation(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file, "--skip-validation"]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    mock_sbom = Mock()
                    mock_sbom.compliant = True
                    mock_sbom.parsing_error = False
                    mock_sbom.validation_messages = []
                    mock_sbom.sbom_name = "test-sbom"
                    mock_checker.return_value = mock_sbom
                    
                    with pytest.raises(SystemExit):
                        main()
                    
                    # Should be called with validate=False
                    mock_checker.assert_called_once_with(
                        test_file,
                        validate=False,
                        compliance="ntia",
                        sbom_spec="spdx2"
                    )
        finally:
            Path(test_file).unlink()

    def test_main_custom_compliance(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file, "--comply", "fsct3-min"]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    mock_sbom = Mock()
                    mock_sbom.compliant = True
                    mock_sbom.parsing_error = False
                    mock_sbom.validation_messages = []
                    mock_sbom.sbom_name = "test-sbom"
                    mock_checker.return_value = mock_sbom
                    
                    with pytest.raises(SystemExit):
                        main()
                    
                    # Should be called with custom compliance
                    mock_checker.assert_called_once_with(
                        test_file,
                        validate=True,
                        compliance="fsct3-min",
                        sbom_spec="spdx2"
                    )
        finally:
            Path(test_file).unlink()

    def test_main_parsing_error(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    mock_sbom = Mock()
                    mock_sbom.compliant = False
                    mock_sbom.parsing_error = True  # Parsing failed
                    mock_sbom.validation_messages = []
                    mock_sbom.sbom_name = "test-sbom"
                    mock_checker.return_value = mock_sbom
                    
                    with pytest.raises(SystemExit):
                        main()
                    
                    # Should still try to output results
                    mock_sbom.print_table_output.assert_called_once()
        finally:
            Path(test_file).unlink()

    def test_main_validation_messages(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    mock_sbom = Mock()
                    mock_sbom.compliant = False
                    mock_sbom.parsing_error = False
                    mock_sbom.validation_messages = ["Some validation error"]  # Has validation issues
                    mock_sbom.sbom_name = "test-sbom"
                    mock_checker.return_value = mock_sbom
                    
                    with pytest.raises(SystemExit):
                        main()
                    
                    mock_sbom.print_table_output.assert_called_once()
        finally:
            Path(test_file).unlink()

    def test_main_logging_debug_level(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file, "--verbose"]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    with patch("logging.basicConfig") as mock_logging:
                        mock_sbom = Mock()
                        mock_sbom.compliant = True
                        mock_sbom.parsing_error = False
                        mock_sbom.validation_messages = []
                        mock_sbom.sbom_name = "test-sbom"
                        mock_checker.return_value = mock_sbom
                        
                        with pytest.raises(SystemExit):
                            main()
                        
                        # Should set debug logging level
                        mock_logging.assert_called_once()
                        args, kwargs = mock_logging.call_args
                        assert kwargs.get('level') == 10  # logging.DEBUG
        finally:
            Path(test_file).unlink()

    def test_main_logging_info_level(self):
        test_file = self.create_test_sbom_file("SPDXVersion: SPDX-2.3\n")
        
        try:
            with patch("sys.argv", ["sbomcheck", test_file]):
                with patch("ntia_conformance_checker.main.SbomChecker") as mock_checker:
                    with patch("logging.basicConfig") as mock_logging:
                        mock_sbom = Mock()
                        mock_sbom.compliant = True
                        mock_sbom.parsing_error = False
                        mock_sbom.validation_messages = []
                        mock_sbom.sbom_name = "test-sbom"
                        mock_checker.return_value = mock_sbom
                        
                        with pytest.raises(SystemExit):
                            main()
                        
                        # Should set info logging level (default)
                        mock_logging.assert_called_once()
                        args, kwargs = mock_logging.call_args
                        assert kwargs.get('level') == 20  # logging.INFO
        finally:
            Path(test_file).unlink()