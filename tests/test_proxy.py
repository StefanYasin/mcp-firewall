from __future__ import annotations

from mcp_firewall.proxy import _id_key, split_command


def test_split_command_keeps_windows_paths_intact():
    assert split_command(r"python C:\tools\server.py") == ["python", r"C:\tools\server.py"]


def test_split_command_handles_quoted_paths():
    assert split_command('"C:/Program Files/Python/python.exe" server.py') == [
        "C:/Program Files/Python/python.exe",
        "server.py",
    ]


def test_split_command_accepts_lists_and_rejects_empty():
    assert split_command(["python", "server.py"]) == ["python", "server.py"]
    assert split_command("   ") == []


def test_id_key_separates_ids_of_different_types():
    assert _id_key(1) != _id_key("1")
    assert _id_key(None) == "NoneType:null"
