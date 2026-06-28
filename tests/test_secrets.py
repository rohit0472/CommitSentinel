from commitsentinel.scanners.secrets import SecretScanner


def _scan(tmp_path, name: str, content: str):
    (tmp_path / name).write_text(content, encoding="utf-8")
    return SecretScanner().scan(tmp_path)


def test_detects_aws_access_key(tmp_path):
    secret = "AKIAABCDEFGHIJ123456"
    findings = _scan(tmp_path, "config.py", f'AWS_KEY = "{secret}"\n')
    assert any(f.rule == "AWS_ACCESS_KEY_ID" for f in findings)
    f = next(f for f in findings if f.rule == "AWS_ACCESS_KEY_ID")
    assert f.severity.value == "critical"
    assert f.line == 1
    assert f.asset == "config.py"
    assert secret not in f.metadata["preview"]
    assert "*" in f.metadata["preview"]


def test_detects_github_token(tmp_path):
    findings = _scan(tmp_path, "ci.yml", f"TOKEN: ghp_{'A' * 36}\n")
    assert any(f.rule == "GITHUB_TOKEN" for f in findings)


def test_detects_private_key_block(tmp_path):
    findings = _scan(
        tmp_path,
        "id_rsa_backup.txt",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfakekeydata\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    assert any(f.rule == "PRIVATE_KEY_BLOCK" and f.severity.value == "critical" for f in findings)


def test_generic_assignment_flags_real_looking_value(tmp_path):
    findings = _scan(tmp_path, "settings.py", 'password = "sup3rSecretValue!"\n')
    assert any(f.rule == "GENERIC_SECRET_ASSIGNMENT" for f in findings)


def test_generic_assignment_skips_placeholder(tmp_path):
    findings = _scan(tmp_path, "settings.py", 'password = "changeme"\n')
    assert not any(f.rule == "GENERIC_SECRET_ASSIGNMENT" for f in findings)


def test_entropy_detection_flags_random_token(tmp_path):
    findings = _scan(tmp_path, "config.txt", "CONFIG_VALUE = qX7vM2pL9zK4wR8bT3nJ6sH1\n")
    assert any(f.rule == "HIGH_ENTROPY" for f in findings)


def test_entropy_detection_skips_repeated_characters(tmp_path):
    findings = _scan(tmp_path, "config.txt", "PADDING = " + "a" * 30 + "\n")
    assert not any(f.rule == "HIGH_ENTROPY" for f in findings)


def test_entropy_detection_skips_uuid(tmp_path):
    findings = _scan(tmp_path, "config.txt", "REQUEST_ID = 123e4567-e89b-12d3-a456-426614174000\n")
    assert not any(f.rule == "HIGH_ENTROPY" for f in findings)


def test_entropy_detection_skips_sha256_hash(tmp_path):
    findings = _scan(
        tmp_path,
        "config.txt",
        "COMMIT = " + "a1b2c3d4" * 8 + "\n",  # 64 hex chars
    )
    assert not any(f.rule == "HIGH_ENTROPY" for f in findings)


def test_lockfile_is_skipped_for_entropy(tmp_path):
    findings = _scan(tmp_path, "package-lock.json", '"integrity": "qX7vM2pL9zK4wR8bT3nJ6sH1abcdefgh"\n')
    assert not any(f.rule == "HIGH_ENTROPY" for f in findings)


def test_clean_file_has_no_findings(tmp_path):
    findings = _scan(tmp_path, "app.py", "def hello():\n    return 'world'\n")
    assert findings == []
