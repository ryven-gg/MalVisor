import json
import hashlib
from pathlib import Path
import subprocess
import sys

from jsonschema import Draft202012Validator

from fixtures.build_pe import synthetic_pe
from malvisor.core.evidence import validate_payload_references


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "malvisor", "analyze", *args],
                          capture_output=True, text=True, check=False)


def test_cli_valid_pe_and_no_overwrite(tmp_path):
    sample = tmp_path / "inert.pe"
    report_path = tmp_path / "report.json"
    sample.write_bytes(synthetic_pe(import_kind="name"))
    before = sample.read_bytes()
    result = run(str(sample), "--output", str(report_path))
    assert result.returncode == 0, result.stderr
    payload = json.loads(report_path.read_text(encoding="utf-8"))
    schema = json.loads((Path(__file__).resolve().parents[1] / "schemas/report-v1.schema.json").read_text())
    Draft202012Validator(schema).validate(payload)
    validate_payload_references(payload)
    assert payload["schema_version"] == "1.1.0"
    assert payload["parser_versions"].keys() == {"pefile"}
    assert payload["input_sha256"] == hashlib.sha256(before).hexdigest()
    assert sample.read_bytes() == before
    second = run(str(sample), "--output", str(report_path))
    assert second.returncode == 5
    assert "output_exists" in second.stderr


def test_cli_invalid_and_limit_do_not_write(tmp_path):
    bad = tmp_path / "invalid.pe"
    bad.write_bytes(b"no pe here")
    output = tmp_path / "out.json"
    result = run(str(bad), "--output", str(output))
    assert result.returncode == 2
    assert "invalid_dos_header" in result.stderr
    assert not output.exists()
    good = tmp_path / "good.pe"
    good.write_bytes(synthetic_pe())
    result = run(str(good), "--output", str(output), "--max-input-size", "128")
    assert result.returncode == 3
    assert not output.exists()


def test_cli_output_path_error_is_controlled(tmp_path):
    sample = tmp_path / "inert.pe"
    sample.write_bytes(synthetic_pe())
    output = tmp_path / "missing-parent" / "report.json"
    result = run(str(sample), "--output", str(output))
    assert result.returncode == 5
    assert "output_io" in result.stderr
    assert not output.exists()


def test_cli_rejects_symlink(tmp_path):
    target = tmp_path / "target.pe"
    link = tmp_path / "link.pe"
    target.write_bytes(synthetic_pe())
    try:
        link.symlink_to(target)
    except OSError:
        return
    result = run(str(link))
    assert result.returncode == 5
    assert "invalid_input_type" in result.stderr


def test_cli_opt_in_real_lief(tmp_path):
    import pytest
    pytest.importorskip("lief")
    sample = tmp_path / "inert.pe"
    sample.write_bytes(synthetic_pe(import_kind="ordinal"))
    result = run(str(sample), "--compare-parsers")
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert set(payload["parser_versions"]) == {"pefile", "lief"}
    assert payload["comparison"]["disagreement_count"] == 0


def test_cli_missing_lief_is_explicit(tmp_path):
    sample = tmp_path / "inert.pe"
    report_path = tmp_path / "should-not-exist.json"
    sample.write_bytes(synthetic_pe())
    code = ("import sys; sys.modules['lief']=None; "
            "from malvisor.cli.main import main; "
            "raise SystemExit(main(['analyze', sys.argv[1], '--compare-parsers', '--output', sys.argv[2]]))")
    result = subprocess.run([sys.executable, "-c", code, str(sample), str(report_path)],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 4
    assert "reference_unavailable" in result.stderr
    assert not report_path.exists()
