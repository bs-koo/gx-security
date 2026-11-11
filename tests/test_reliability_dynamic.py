"""Authorization evidence must resolve a valid pointer to a JSON-typed value."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from gxsec.dynamic import _matches


@pytest.mark.parametrize("body,pointer,expected", [
    ({}, "/error", None),
    ({"error": None}, "/error/missing", None),
    ({"error": None}, None, None),
    ({"error": None}, 1, None),
    ({"error": None}, "error", None),
    ({"~2": None}, "/~2", None),
    ({"~": None}, "/~", None),
    ({"items": [None]}, "/items/-1", None),
    ({"items": [None]}, "/items/+0", None),
    ({"items": [None]}, "/items/00", None),
    ({"items": [None]}, "/items/ 0", None),
    ({"items": [None]}, "/items/1", None),
    ({"value": True}, "/value", 1),
    ({"value": 0}, "/value", False),
    ({"value": [True]}, "/value", [1]),
    ({"value": {"a": False}}, "/value", {"a": 0}),
])
def test_unresolved_or_differently_typed_json_evidence_never_matches(body, pointer, expected):
    assert not _matches({"body": json.dumps(body)}, {"json_pointer": pointer, "expected": expected})


@pytest.mark.parametrize("body,pointer,expected", [
    ({"error": None}, "/error", None),
    ({"items": [None]}, "/items/0", None),
    ({"items": ["nonce"]}, "$.items.0", "nonce"),
    ({"a/b": {"~": "nonce"}}, "/a~1b/~0", "nonce"),
    ({"~1": None}, "/~01", None),
    ({"": None}, "/", None),
    ({"value": True}, "/value", True),
    ({"value": {"a": [None, 1, "nonce"]}}, "/value", {"a": [None, 1, "nonce"]}),
    ({"value": 1.0}, "/value", 1),
])
def test_resolved_json_null_and_existing_oracle_syntax_still_match(body, pointer, expected):
    assert _matches({"body": json.dumps(body)}, {"json_pointer": pointer, "expected": expected})
