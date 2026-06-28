from typer.testing import CliRunner

from commitsentinel.cli import app

runner = CliRunner()


def test_scan_empty_repo_reports_zero_findings_and_full_score(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "0 findings, score 100" in result.stdout


def test_scan_missing_path_exits_nonzero(tmp_path):
    missing = tmp_path / "does-not-exist"
    result = runner.invoke(app, ["scan", str(missing)])
    assert result.exit_code == 1


def test_scan_defaults_to_current_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 0
    assert "0 findings, score 100" in result.stdout
