from __future__ import annotations

import pytest

from mcp_firewall import yaml_lite


def test_nested_mappings_sequences_and_comments():
    doc = yaml_lite.loads(
        """
# leading comment
version: 1
default: deny   # trailing comment
servers:
  filesystem:
    tools:
      allow:
        - read_file
        - "write_*"
      deny: [delete_*, "rm_rf"]
    rate_limit:
      calls: 30
      per_seconds: 1.5
"""
    )
    assert doc["version"] == 1
    assert doc["default"] == "deny"
    fs = doc["servers"]["filesystem"]
    assert fs["tools"]["allow"] == ["read_file", "write_*"]
    assert fs["tools"]["deny"] == ["delete_*", "rm_rf"]
    assert fs["rate_limit"] == {"calls": 30, "per_seconds": 1.5}


def test_sequence_of_mappings():
    doc = yaml_lite.loads(
        """
items:
  - name: one
    value: 1
  - name: two
    value: 2
"""
    )
    assert doc["items"] == [{"name": "one", "value": 1}, {"name": "two", "value": 2}]


def test_scalars_and_empty_values():
    doc = yaml_lite.loads(
        """
a: true
b: no
c: null
d: ~
e: 3.25
f: -7
g: hello world
h: "quoted: value"
i:
j: '{"json": true}'
"""
    )
    assert doc["a"] is True
    assert doc["b"] is False
    assert doc["c"] is None
    assert doc["d"] is None
    assert doc["e"] == 3.25
    assert doc["f"] == -7
    assert doc["g"] == "hello world"
    assert doc["h"] == "quoted: value"
    assert doc["i"] is None
    assert doc["j"] == '{"json": true}'


def test_hash_inside_quotes_is_not_a_comment():
    doc = yaml_lite.loads('key: "value # not a comment"\nother: plain # comment\n')
    assert doc["key"] == "value # not a comment"
    assert doc["other"] == "plain"


def test_flow_sequence_with_commas_in_strings():
    doc = yaml_lite.loads('tags: ["a,b", c, "d"]\n')
    assert doc["tags"] == ["a,b", "c", "d"]


def test_json_document_is_accepted():
    doc = yaml_lite.loads('{"version": 1, "servers": {"fake": {"tools": {"allow": ["echo"]}}}}')
    assert doc["servers"]["fake"]["tools"]["allow"] == ["echo"]


def test_block_scalar():
    doc = yaml_lite.loads("note: |\n  line one\n  line two\nnext: 1\n")
    assert doc["note"] == "line one\nline two"
    assert doc["next"] == 1


@pytest.mark.parametrize(
    "text, fragment",
    [
        ("a:\n\tb: 1", "tabs"),
        ("a: 1\na: 2", "duplicate key"),
        ("a: 1\n  b: 2", "unexpected indentation"),
        ("a: [1, 2", "unterminated flow sequence"),
        ('a: "unterminated', "unterminated double quoted string"),
        ("just a scalar\nb: 1", "unexpected content"),
    ],
)
def test_bad_documents_raise_with_line_numbers(text, fragment):
    with pytest.raises(yaml_lite.YamlError) as excinfo:
        yaml_lite.loads(text)
    assert fragment in str(excinfo.value)
