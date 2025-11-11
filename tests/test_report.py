# SPDX-FileCopyrightText: 2025 SPDX contributors
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: Apache-2.0

"""Tests for report generation functionality"""

# pylint: disable=missing-function-docstring

import io
import sys
from unittest.mock import Mock, patch

import pytest
from spdx_tools.spdx.validation.validation_message import ValidationMessage

from ntia_conformance_checker.report import (
    _safe_attr,
    get_validation_messages_html,
    print_validation_messages,
)


class TestSafeAttr:
    def test_safe_attr_with_valid_attribute(self):
        obj = Mock()
        obj.name = "test_value"
        result = _safe_attr(obj, "name")
        assert result == "test_value"

    def test_safe_attr_with_none_value(self):
        obj = Mock()
        obj.name = None
        result = _safe_attr(obj, "name")
        assert result == "N/A"

    def test_safe_attr_with_empty_string(self):
        obj = Mock()
        obj.name = ""
        result = _safe_attr(obj, "name")
        assert result == "N/A"

    def test_safe_attr_with_missing_attribute(self):
        obj = Mock()
        # Mock objects return Mock for missing attributes, not None
        # So this test should use an object without the attribute
        class SimpleObj:
            pass
        obj = SimpleObj()
        result = _safe_attr(obj, "nonexistent")
        assert result == "N/A"

    def test_safe_attr_with_numeric_value(self):
        obj = Mock()
        obj.count = 42
        result = _safe_attr(obj, "count")
        assert result == "42"

    def test_safe_attr_with_boolean_value(self):
        obj = Mock()
        obj.enabled = True
        result = _safe_attr(obj, "enabled")
        assert result == "True"


class TestPrintValidationMessages:
    def test_print_validation_messages_empty_list(self):
        captured_output = io.StringIO()
        with patch("sys.stdout", captured_output):
            print_validation_messages([])
        
        assert captured_output.getvalue() == ""

    def test_print_validation_messages_no_message(self):
        msg = Mock(spec=ValidationMessage)
        msg.validation_message = None
        
        captured_output = io.StringIO()
        with patch("sys.stdout", captured_output):
            print_validation_messages([msg])
        
        assert captured_output.getvalue() == ""

    def test_print_validation_messages_empty_message(self):
        msg = Mock(spec=ValidationMessage)
        msg.validation_message = ""
        
        captured_output = io.StringIO()
        with patch("sys.stdout", captured_output):
            print_validation_messages([msg])
        
        assert captured_output.getvalue() == ""

    def test_print_validation_messages_simple(self):
        msg = Mock(spec=ValidationMessage)
        msg.validation_message = "Test validation error"
        
        captured_output = io.StringIO()
        with patch("sys.stdout", captured_output):
            print_validation_messages([msg])
        
        output = captured_output.getvalue()
        assert "Test validation error" in output

    def test_print_validation_messages_with_context_verbose(self):
        context = Mock()
        context.spdx_id = "SPDXRef-Package"
        context.parent_id = "SPDXRef-Document"
        context.element_type = "Package"
        
        msg = Mock(spec=ValidationMessage)
        msg.validation_message = "Test validation error"
        msg.context = context
        
        captured_output = io.StringIO()
        with patch("sys.stdout", captured_output):
            print_validation_messages([msg], verbose=True)
        
        output = captured_output.getvalue()
        assert "Test validation error" in output
        assert "SPDXRef-Package" in output
        assert "SPDXRef-Document" in output
        assert "Package" in output

    def test_print_validation_messages_with_context_non_verbose(self):
        context = Mock()
        context.spdx_id = "SPDXRef-Package"
        context.parent_id = "SPDXRef-Document"
        context.element_type = "Package"
        
        msg = Mock(spec=ValidationMessage)
        msg.validation_message = "Test validation error"
        msg.context = context
        
        captured_output = io.StringIO()
        with patch("sys.stdout", captured_output):
            print_validation_messages([msg], verbose=False)
        
        output = captured_output.getvalue()
        assert "Test validation error" in output
        assert "SPDXRef-Package" not in output
        assert "SPDXRef-Document" not in output

    def test_print_validation_messages_multiple_messages(self):
        msg1 = Mock(spec=ValidationMessage)
        msg1.validation_message = "First error"
        
        msg2 = Mock(spec=ValidationMessage)
        msg2.validation_message = "Second error"
        
        captured_output = io.StringIO()
        with patch("sys.stdout", captured_output):
            print_validation_messages([msg1, msg2])
        
        output = captured_output.getvalue()
        assert "First error" in output
        assert "Second error" in output

    def test_print_validation_messages_no_context_attribute(self):
        msg = Mock(spec=ValidationMessage)
        msg.validation_message = "Test validation error"
        # No context attribute
        
        captured_output = io.StringIO()
        with patch("sys.stdout", captured_output):
            print_validation_messages([msg], verbose=True)
        
        output = captured_output.getvalue()
        assert "Test validation error" in output
        assert "SPDX ID:" not in output


class TestGetValidationMessagesHtml:
    def test_get_validation_messages_html_empty_list(self):
        result = get_validation_messages_html([])
        assert result == ""

    def test_get_validation_messages_html_no_message(self):
        msg = Mock(spec=ValidationMessage)
        msg.validation_message = None
        
        result = get_validation_messages_html([msg])
        # When no validation message, it still creates the ul wrapper but no li
        assert result == "<ul>\n</ul>"

    def test_get_validation_messages_html_simple(self):
        msg = Mock(spec=ValidationMessage)
        msg.validation_message = "Test validation error"
        
        result = get_validation_messages_html([msg])
        
        assert "<ul>" in result
        assert "</ul>" in result
        assert "<li>" in result
        assert "</li>" in result
        assert "Test validation error" in result
        assert "<strong>Validation message:</strong>" in result

    def test_get_validation_messages_html_with_context(self):
        context = Mock()
        context.spdx_id = "SPDXRef-Package"
        context.parent_id = "SPDXRef-Document"
        context.element_type = "Package"
        
        msg = Mock(spec=ValidationMessage)
        msg.validation_message = "Test validation error"
        msg.context = context
        
        result = get_validation_messages_html([msg])
        
        assert "Test validation error" in result
        assert "SPDXRef-Package" in result
        assert "SPDXRef-Document" in result
        assert "Package" in result
        assert "<strong>Validation context:</strong>" in result
        assert "SPDX ID:" in result
        assert "Parent ID:" in result
        assert "Element type:" in result

    def test_get_validation_messages_html_no_context(self):
        msg = Mock(spec=ValidationMessage)
        msg.validation_message = "Test validation error"
        # No context attribute
        
        result = get_validation_messages_html([msg])
        
        assert "Test validation error" in result
        assert "Validation context" not in result

    def test_get_validation_messages_html_context_with_none_values(self):
        # Create a context without the attributes to test the N/A default
        class Context:
            pass
        context = Context()
        
        msg = Mock(spec=ValidationMessage)
        msg.validation_message = "Test validation error"
        msg.context = context
        
        result = get_validation_messages_html([msg])
        
        assert "Test validation error" in result
        assert "N/A" in result

    def test_get_validation_messages_html_multiple_messages(self):
        msg1 = Mock(spec=ValidationMessage)
        msg1.validation_message = "First error"
        
        msg2 = Mock(spec=ValidationMessage)
        msg2.validation_message = "Second error"
        
        result = get_validation_messages_html([msg1, msg2])
        
        assert "First error" in result
        assert "Second error" in result
        assert result.count("<li>") == 2
        assert result.count("</li>") == 2

    def test_get_validation_messages_html_mixed_messages(self):
        # One message without validation_message, one with
        msg1 = Mock(spec=ValidationMessage)
        msg1.validation_message = None
        
        msg2 = Mock(spec=ValidationMessage)
        msg2.validation_message = "Valid error"
        
        result = get_validation_messages_html([msg1, msg2])
        
        assert "Valid error" in result
        assert result.count("<li>") == 1  # Only one should be included
        
    def test_get_validation_messages_html_all_messages_skipped(self):
        # All messages without validation_message should result in just ul wrapper
        msg1 = Mock(spec=ValidationMessage)
        msg1.validation_message = None
        
        msg2 = Mock(spec=ValidationMessage)
        msg2.validation_message = ""
        
        result = get_validation_messages_html([msg1, msg2])
        
        assert result == "<ul>\n</ul>"