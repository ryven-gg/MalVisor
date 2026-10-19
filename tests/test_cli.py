import subprocess
import sys

from malvisor import __version__


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "malvisor", *args], capture_output=True, text=True, check=False)


def test_help_and_version():
    help_result = run_cli("--help")
    assert help_result.returncode == 0
    assert "Offline static PE analysis" in help_result.stdout
    version = run_cli("version")
    assert version.returncode == 0
    assert version.stdout.strip() == __version__


def test_missing_input_fails_without_report(tmp_path):
    missing = tmp_path / "does-not-exist.exe"
    output = tmp_path / "report.json"
    result = run_cli("analyze", str(missing), "--output", str(output))
    assert result.returncode == 5
    assert "ERROR input_io" in result.stderr
    assert not missing.exists()
    assert not output.exists()
