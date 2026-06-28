from commitsentinel.scanners.conflict_markers import ConflictMarkerScanner


def _scan(tmp_path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8")
    return ConflictMarkerScanner().scan(tmp_path)


def test_detects_full_conflict_block(tmp_path):
    content = (
        "<<<<<<< HEAD\n"
        "our version\n"
        "=======\n"
        "their version\n"
        ">>>>>>> feature-branch\n"
    )
    findings = _scan(tmp_path, "main.py", content)
    assert len(findings) == 3
    assert [f.line for f in findings] == [1, 3, 5]
    assert all(f.severity.value == "high" for f in findings)
    assert all(f.asset == "main.py" for f in findings)


def test_markdown_heading_underline_is_not_flagged(tmp_path):
    content = "My Heading\n=======\n\nSome regular paragraph text.\n"
    findings = _scan(tmp_path, "README.md", content)
    assert findings == []


def test_lone_start_marker_without_close_is_still_flagged(tmp_path):
    # Truncated/corrupted conflict — only the start marker present.
    content = "<<<<<<< HEAD\nsome content\n"
    findings = _scan(tmp_path, "broken.py", content)
    assert len(findings) == 1
    assert findings[0].rule == "MERGE_CONFLICT_MARKER"


def test_clean_file_has_no_findings(tmp_path):
    findings = _scan(tmp_path, "clean.py", "def hello():\n    return 'world'\n")
    assert findings == []
