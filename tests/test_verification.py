"""Tests for AWS MCP Server v2 (3-tool architecture)."""

import sys
import logging
import unittest
from unittest.mock import patch
from io import StringIO

import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from aws_cli_mcp.logging_utils import configure_logging
from aws_cli_mcp.policy.models import PolicyConfig, RequiredTag, PolicyRules, PolicyDefaults, ApprovalSettings, ServicePolicy
from aws_cli_mcp.policy.engine import PolicyEngine
from aws_cli_mcp.domain.operations import OperationRef

from aws_cli_mcp.utils.jsonschema import (
    validate_payload,
    validate_payload_structured,
    format_structured_errors,
    ValidationError,
)


class TestLogging(unittest.TestCase):

    def test_logging_to_stderr(self):
        """Verify logging goes to stderr."""
        logging.root.handlers = []

        with patch('sys.stderr', new=StringIO()) as fake_stderr:
            configure_logging()
            logging.info("Test log message")

            output = fake_stderr.getvalue()
            self.assertIn("Test log message", output)
            self.assertIn("INFO", output)


class TestPolicyEngine(unittest.TestCase):

    def test_policy_relaxed_tags_for_reads(self):
        """Verify required_tags are relaxed for operations without tags (reads)."""
        config = PolicyConfig(
            version=1,
            defaults=PolicyDefaults(),
            rules=PolicyRules(allow=["^.*$"], deny=[]),
            services=ServicePolicy(allowlist=["ec2"], denylist=[]),
            destructive_patterns=[],
            risk_patterns={},
            required_tags=[RequiredTag(key="Owner", pattern=".+")],
            approval=ApprovalSettings()
        )
        engine = PolicyEngine(config)

        op = OperationRef(service="ec2", operation="DescribeInstances")
        params = {}  # No tags

        decision = engine.evaluate(op, params)
        self.assertTrue(decision.allowed, "Read operation should be allowed even without tags")
        self.assertFalse(decision.reasons, f"Should have no deny reasons, got: {decision.reasons}")

    def test_policy_enforcement_for_writes(self):
        """Verify required_tags are STILL enforced if tags are present (simulating write with tags)."""
        config = PolicyConfig(
            version=1,
            defaults=PolicyDefaults(),
            rules=PolicyRules(allow=["^.*$"], deny=[]),
            services=ServicePolicy(allowlist=["ec2"], denylist=[]),
            destructive_patterns=[],
            risk_patterns={},
            required_tags=[RequiredTag(key="Owner", pattern=".+")],
            approval=ApprovalSettings()
        )
        engine = PolicyEngine(config)

        op = OperationRef(service="ec2", operation="RunInstances")
        params = {
            "Tags": [{"Key": "WrongKey", "Value": "Val"}]
        }

        decision = engine.evaluate(op, params)
        self.assertFalse(decision.allowed, "Operation with wrong tags should be denied")
        self.assertIn("Required tags missing or invalid", decision.reasons)

    def test_service_not_allowed(self):
        """Verify operations from non-allowlisted services are denied."""
        config = PolicyConfig(
            version=1,
            defaults=PolicyDefaults(),
            rules=PolicyRules(allow=["^.*$"], deny=[]),
            services=ServicePolicy(allowlist=["ec2"], denylist=[]),
            destructive_patterns=[],
            risk_patterns={},
            required_tags=[],
            approval=ApprovalSettings()
        )
        engine = PolicyEngine(config)

        op = OperationRef(service="lambda", operation="Invoke")
        decision = engine.evaluate(op, {})

        self.assertFalse(decision.allowed)
        self.assertIn("Service is not allowlisted", decision.reasons)


class TestStructuredValidation(unittest.TestCase):

    def test_missing_required_field(self):
        """Verify structured validation detects missing required fields."""
        schema = {
            "type": "object",
            "properties": {
                "FunctionName": {"type": "string"},
            },
            "required": ["FunctionName"],
        }
        payload = {}

        errors = validate_payload_structured(schema, payload)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].type, "missing_required")
        self.assertIn("FunctionName", errors[0].message)

    def test_invalid_type(self):
        """Verify structured validation detects type errors."""
        schema = {
            "type": "object",
            "properties": {
                "Count": {"type": "integer"},
            },
        }
        payload = {"Count": "not-an-integer"}

        errors = validate_payload_structured(schema, payload)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].type, "invalid_type")
        self.assertEqual(errors[0].expected, "integer")
        self.assertEqual(errors[0].got, "str")

    def test_enum_violation(self):
        """Verify structured validation detects enum violations."""
        schema = {
            "type": "object",
            "properties": {
                "InvocationType": {
                    "type": "string",
                    "enum": ["RequestResponse", "Event", "DryRun"],
                },
            },
        }
        payload = {"InvocationType": "Invalid"}

        errors = validate_payload_structured(schema, payload)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].type, "enum_violation")
        self.assertEqual(errors[0].allowed_values, ["RequestResponse", "Event", "DryRun"])

    def test_format_structured_errors(self):
        """Verify format_structured_errors produces correct output."""
        errors = [
            ValidationError(
                type="missing_required",
                message="'FunctionName' is a required property",
                path=None,
                hint="Add the required field 'FunctionName' to your request.",
            ),
            ValidationError(
                type="enum_violation",
                message="'Invalid' is not one of ['RequestResponse', 'Event', 'DryRun']",
                path="InvocationType",
                got="Invalid",
                allowed_values=["RequestResponse", "Event", "DryRun"],
                hint="Use one of: RequestResponse, Event, DryRun",
            ),
        ]

        result = format_structured_errors(errors)

        self.assertIn("FunctionName", result["missing"])
        self.assertEqual(len(result["invalid"]), 1)
        self.assertEqual(result["invalid"][0]["path"], "InvocationType")
        self.assertIn("InvocationType", result["allowedValues"])
        self.assertTrue(result["retryable"])


class TestToolSchemas(unittest.TestCase):

    def test_search_schema_validation(self):
        """Verify aws_search_operations input validation."""
        from aws_cli_mcp.tools.aws_unified import SEARCH_SCHEMA

        valid_payload = {"query": "lambda invoke"}
        errors = validate_payload(SEARCH_SCHEMA, valid_payload)
        self.assertEqual(errors, [])

        invalid_payload = {"serviceHint": "lambda"}  # Missing query
        errors = validate_payload(SEARCH_SCHEMA, invalid_payload)
        self.assertNotEqual(errors, [])

    def test_get_schema_validation(self):
        """Verify aws_get_operation_schema input validation."""
        from aws_cli_mcp.tools.aws_unified import GET_SCHEMA_SCHEMA

        valid_payload = {"service": "lambda", "operation": "Invoke"}
        errors = validate_payload(GET_SCHEMA_SCHEMA, valid_payload)
        self.assertEqual(errors, [])

        invalid_payload = {"service": "lambda"}  # Missing operation
        errors = validate_payload(GET_SCHEMA_SCHEMA, invalid_payload)
        self.assertNotEqual(errors, [])

    def test_execute_schema_validation(self):
        """Verify aws_execute input validation."""
        from aws_cli_mcp.tools.aws_unified import EXECUTE_SCHEMA

        valid_payload = {
            "action": "validate",
            "service": "lambda",
            "operation": "Invoke",
            "payload": {"FunctionName": "my-func"},
        }
        errors = validate_payload(EXECUTE_SCHEMA, valid_payload)
        self.assertEqual(errors, [])

        invalid_payload = {
            "action": "invalid-action",  # Not in enum
            "service": "lambda",
            "operation": "Invoke",
            "payload": {},
        }
        errors = validate_payload(EXECUTE_SCHEMA, invalid_payload)
        self.assertNotEqual(errors, [])


if __name__ == '__main__':
    unittest.main()
