import subprocess
import sys


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "malvisor", *args], capture_output=True, text=True, check=False)


def test_help_and_version():
    help_result = run_cli("--help")
    assert help_result.returncode == 0
    assert "Phase 0" in help_result.stdout
    version = run_cli("version")
    assert version.returncode == 0
    assert version.stdout.strip() == "0.1.0"


def test_analyze_is_unsupported_and_never_opens_sample(tmp_path):
    missing = tmp_path / "does-not-exist.exe"
    result = run_cli("analyze", str(missing))
    assert result.returncode == 2
    assert "Not implemented in Phase 0" in result.stdout
    assert not missing.exists()
