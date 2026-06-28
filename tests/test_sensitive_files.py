import subprocess

from commitsentinel.scanners.sensitive_files import SensitiveFileScanner


def _git(args, repo_path):
    subprocess.run(
        ["git", *args], cwd=repo_path, check=True, capture_output=True, stdin=subprocess.DEVNULL
    )


def _init_repo(repo_path):
    _git(["init", "-q"], repo_path)
    _git(["config", "user.email", "test@example.com"], repo_path)
    _git(["config", "user.name", "Test"], repo_path)


def test_tracked_sensitive_file_is_critical(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / ".env").write_text("SECRET=1\n")
    _git(["add", ".env"], tmp_path)
    _git(["commit", "-q", "-m", "oops"], tmp_path)

    findings = SensitiveFileScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    assert findings[0].rule == "ROTATE_AND_PURGE_HISTORY"
    assert findings[0].asset == ".env"


def test_staged_sensitive_file_is_high(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "service-account.pem").write_text("fake-key-data\n")
    _git(["add", "service-account.pem"], tmp_path)

    findings = SensitiveFileScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert findings[0].rule == "UNSTAGE_AND_GITIGNORE"


def test_untracked_ungitignored_file_is_medium(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "credentials.json").write_text("{}\n")

    findings = SensitiveFileScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert findings[0].rule == "ADD_TO_GITIGNORE"


def test_untracked_gitignored_file_has_no_finding(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env").write_text("SECRET=1\n")

    findings = SensitiveFileScanner().scan(tmp_path)
    assert findings == []


def test_non_git_directory_falls_back_to_generic_warning(tmp_path):
    (tmp_path / "id_rsa").write_text("fake-key-data\n")

    findings = SensitiveFileScanner().scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].severity.value == "medium"
    assert findings[0].rule == "REVIEW_AND_GITIGNORE"


def test_env_example_is_not_flagged(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / ".env.example").write_text("SECRET=changeme\n")

    findings = SensitiveFileScanner().scan(tmp_path)
    assert findings == []


def test_public_key_is_not_flagged(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "id_rsa.pub").write_text("ssh-rsa AAAA...\n")

    findings = SensitiveFileScanner().scan(tmp_path)
    assert findings == []


def test_clean_repo_has_no_findings(tmp_path):
    _init_repo(tmp_path)
    (tmp_path / "app.py").write_text("print('hello')\n")

    findings = SensitiveFileScanner().scan(tmp_path)
    assert findings == []
