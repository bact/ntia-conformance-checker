# SPDX-FileCopyrightText: 2025 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests for CLI utilities"""

# pylint: disable=missing-function-docstring

import argparse
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from ntia_conformance_checker.cli_utils import get_parsed_args, get_spdx_version


class TestGetParsedArgs:
    def test_get_parsed_args_with_file(self):
        with patch("sys.argv", ["sbomcheck", "test.spdx"]):
            args = get_parsed_args()
            assert args.file == "test.spdx"
            assert args.sbom_spec == "spdx2"  # default
            assert args.comply == "ntia"  # default
            assert not args.skip_validation
            assert args.output == "print"  # default
            assert not args.verbose

    def test_get_parsed_args_with_all_options(self):
        with patch("sys.argv", [
            "sbomcheck", "test.spdx", 
            "--sbom-spec", "spdx3",
            "--comply", "fsct3-min",
            "--skip-validation",
            "--output", "json",
            "--output-file", "report.json",
            "--verbose"
        ]):
            args = get_parsed_args()
            assert args.file == "test.spdx"
            assert args.sbom_spec == "spdx3"
            assert args.comply == "fsct3-min"
            assert args.skip_validation
            assert args.output == "json"
            assert args.output_file == "report.json"
            assert args.verbose

    def test_get_parsed_args_short_options(self):
        with patch("sys.argv", [
            "sbomcheck", "test.spdx",
            "-s", "spdx3",
            "-c", "fsct3-min", 
            "-r", "html",
            "-o", "report.html",
            "-v"
        ]):
            args = get_parsed_args()
            assert args.file == "test.spdx"
            assert args.sbom_spec == "spdx3"
            assert args.comply == "fsct3-min"
            assert args.output == "html"
            assert args.output_file == "report.html"
            assert args.verbose

    def test_get_parsed_args_legacy_file_option(self):
        with patch("sys.argv", ["sbomcheck", "--file", "test.spdx"]):
            args = get_parsed_args()
            assert args.file == "test.spdx"

    def test_get_parsed_args_legacy_conform_option(self):
        with patch("sys.argv", ["sbomcheck", "test.spdx", "--conform", "fsct3-min"]):
            args = get_parsed_args()
            assert args.comply == "fsct3-min"

    def test_get_parsed_args_legacy_output_path_option(self):
        with patch("sys.argv", ["sbomcheck", "test.spdx", "--output_path", "report.json"]):
            args = get_parsed_args()
            assert args.output_file == "report.json"

    def test_get_parsed_args_no_file_shows_help(self):
        with patch("sys.argv", ["sbomcheck"]):
            with patch("argparse.ArgumentParser.print_help") as mock_help:
                with pytest.raises(SystemExit) as exc_info:
                    get_parsed_args()
                assert exc_info.value.code == 0
                mock_help.assert_called_once()

    def test_get_parsed_args_version_option(self):
        with patch("sys.argv", ["sbomcheck", "--version"]):
            with patch("builtins.print") as mock_print:
                with pytest.raises(SystemExit) as exc_info:
                    get_parsed_args()
                assert exc_info.value.code == 0
                mock_print.assert_called_once()
                # The print should contain version info
                printed_args = mock_print.call_args[0]
                assert len(printed_args) == 1  # version string

    def test_get_parsed_args_version_short_option(self):
        with patch("sys.argv", ["sbomcheck", "-V"]):
            with patch("builtins.print") as mock_print:
                with pytest.raises(SystemExit) as exc_info:
                    get_parsed_args()
                assert exc_info.value.code == 0
                mock_print.assert_called_once()

    def test_get_parsed_args_version_with_no_file(self):
        with patch("sys.argv", ["sbomcheck", "--version"]):
            with patch("builtins.print") as mock_print:
                with pytest.raises(SystemExit) as exc_info:
                    get_parsed_args()
                assert exc_info.value.code == 0
                mock_print.assert_called_once()


class TestGetSpdxVersion:
    def test_get_spdx_version_excel_not_supported(self):
        result = get_spdx_version("test.xls")
        assert result is None
        
        result = get_spdx_version("test.xlsx")
        assert result is None
        
        result = get_spdx_version("test.XLS")  # case insensitive
        assert result is None

    def test_get_spdx_version_nonexistent_file(self):
        result = get_spdx_version("nonexistent_file.spdx")
        assert result is None

    def test_get_spdx_version_with_valid_spdx2_content(self):
        # Create a temporary file with SPDX content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.3\n")
            f.write("CreationInfo:\n")
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file)
            assert result == (2, 3)
        finally:
            Path(temp_file).unlink()

    def test_get_spdx_version_json_format(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"spdxVersion": "SPDX-2.2"}')
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file)
            assert result == (2, 2)
        finally:
            Path(temp_file).unlink()

    def test_get_spdx_version_yaml_format(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write('spdxVersion: SPDX-2.3\n')
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file)
            assert result == (2, 3)
        finally:
            Path(temp_file).unlink()

    def test_get_spdx_version_yaml_quoted_format(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write("spdxVersion: 'SPDX-2.2'\n")
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file)
            assert result == (2, 2)
        finally:
            Path(temp_file).unlink()

    def test_get_spdx_version_xml_format(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write('<spdxVersion>SPDX-2.3</spdxVersion>')
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file)
            assert result == (2, 3)
        finally:
            Path(temp_file).unlink()

    @patch("ntia_conformance_checker.cli_utils.parse_spdx2_file")
    def test_get_spdx_version_rdf_format(self, mock_parse):
        # Mock parsing failure to test regex fallback for RDF
        from spdx_tools.spdx.parser.error import SPDXParsingError
        mock_parse.side_effect = SPDXParsingError("RDF parsing failed")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('<spdx:specVersion>SPDX-2.2</spdx:specVersion>')
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file)
            assert result == (2, 2)
        finally:
            Path(temp_file).unlink()

    def test_get_spdx_version_spdx3_jsonld_format(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('"@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld"')
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file)
            assert result == (3, 0)
        finally:
            Path(temp_file).unlink()

    def test_get_spdx_version_spdx3_spec(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('"@context": "https://spdx.org/rdf/3.0/spdx-context.jsonld"')
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file, sbom_spec="spdx3")
            assert result == (3, 0)
        finally:
            Path(temp_file).unlink()

    def test_get_spdx_version_with_patch_version(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write('{"spdxVersion": "SPDX-2.2.1"}')
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file)
            # Should return only major.minor, ignoring patch
            assert result == (2, 2)
        finally:
            Path(temp_file).unlink()

    def test_get_spdx_version_no_version_found(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write('This file has no SPDX version information')
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file)
            assert result is None
        finally:
            Path(temp_file).unlink()

    def test_get_spdx_version_invalid_encoding(self):
        # Create a file with invalid UTF-8 encoding
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.spdx', delete=False) as f:
            f.write(b'\xff\xfe\x00\x00SPDXVersion: SPDX-2.3')  # Invalid UTF-8
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file)
            assert result is None
        finally:
            Path(temp_file).unlink()

    @patch("ntia_conformance_checker.cli_utils.parse_spdx2_file")
    def test_get_spdx_version_spdx_tools_success(self, mock_parse):
        # Mock successful parsing with spdx-tools
        mock_doc = Mock()
        mock_creation_info = Mock()
        mock_creation_info.spdx_version = "SPDX-2.3"
        mock_doc.creation_info = mock_creation_info
        mock_parse.return_value = mock_doc
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("some content")
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file, sbom_spec="spdx2")
            assert result == (2, 3)
            mock_parse.assert_called_once_with(temp_file)
        finally:
            Path(temp_file).unlink()

    @patch("ntia_conformance_checker.cli_utils.parse_spdx2_file")
    def test_get_spdx_version_spdx_tools_fallback_to_regex(self, mock_parse):
        # Mock spdx-tools parsing failure, should fallback to regex
        from spdx_tools.spdx.parser.error import SPDXParsingError
        mock_parse.side_effect = SPDXParsingError("Parsing failed")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.2\n")
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file, sbom_spec="spdx2")
            assert result == (2, 2)
            mock_parse.assert_called_once_with(temp_file)
        finally:
            Path(temp_file).unlink()

    @patch("ntia_conformance_checker.cli_utils.parse_spdx2_file")
    def test_get_spdx_version_spdx_tools_other_exception(self, mock_parse):
        # Mock other exceptions during parsing
        mock_parse.side_effect = ValueError("Some other error")
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.spdx', delete=False) as f:
            f.write("SPDXVersion: SPDX-2.2\n")
            temp_file = f.name
        
        try:
            result = get_spdx_version(temp_file, sbom_spec="spdx2")
            assert result == (2, 2)  # Should fallback to regex
            mock_parse.assert_called_once_with(temp_file)
        finally:
            Path(temp_file).unlink()