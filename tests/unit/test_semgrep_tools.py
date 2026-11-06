from __future__ import annotations

import json
import pathlib
import shutil
import pytest
from unittest.mock import patch, MagicMock

FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures" / "sample_repo"
RULES_DIR = pathlib.Path("cryptodep/rules")

_RG_AVAILABLE = shutil.which("rg") is not None


# ── _ripgrep_prefilter ────────────────────────────────────────────────────


@pytest.mark.skipif(not _RG_AVAILABLE, reason="ripgrep not installed")
def test_prefilter_returns_only_matching_files(tmp_path):
    from cryptodep.tools.semgrep_tools import _ripgrep_prefilter

    crypto_file = tmp_path / "Crypto.java"
    plain_file = tmp_path / "Plain.java"
    crypto_file.write_text('KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");')
    plain_file.write_text("public class Plain { void foo() {} }")

    result = _ripgrep_prefilter([str(crypto_file), str(plain_file)])

    assert str(crypto_file) in result
    assert str(plain_file) not in result


@pytest.mark.skipif(not _RG_AVAILABLE, reason="ripgrep not installed")
def test_prefilter_keeps_spring_digest_utils(tmp_path):
    from cryptodep.tools.semgrep_tools import _ripgrep_prefilter

    source = tmp_path / "UserService.java"
    source.write_text(
        "import org.springframework.util.DigestUtils;\n"
        "class UserService { String hash(String password) {\n"
        "return DigestUtils.md5DigestAsHex(password.getBytes()); } }\n"
    )
    assert _ripgrep_prefilter([str(source)]) == [str(source)]


def test_prefilter_returns_all_files_when_rg_not_found():
    from cryptodep.tools.semgrep_tools import _ripgrep_prefilter

    files = ["/some/file.java", "/other/file.py"]
    with patch("shutil.which", return_value=None):
        result = _ripgrep_prefilter(files)
    assert result == files


def test_prefilter_falls_back_when_rg_exits_nonzero():
    from cryptodep.tools.semgrep_tools import _ripgrep_prefilter
    import subprocess

    files = ["/some/file.java"]
    mock_proc = MagicMock()
    mock_proc.returncode = 2  # rg exit 2 = error
    mock_proc.stdout = ""

    with patch("shutil.which", return_value="/usr/bin/rg"):
        with patch("subprocess.run", return_value=mock_proc):
            result = _ripgrep_prefilter(files)
    assert result == files


@pytest.mark.skipif(not _RG_AVAILABLE, reason="ripgrep not installed")
def test_prefilter_returns_empty_when_no_files_match(tmp_path):
    from cryptodep.tools.semgrep_tools import _ripgrep_prefilter

    plain = tmp_path / "Plain.java"
    plain.write_text("public class Plain { void foo() {} }")

    result = _ripgrep_prefilter([str(plain)])
    assert result == []


def test_copy_to_tmpdir_files_are_readable(tmp_path):
    from cryptodep.tools.semgrep_tools import _copy_to_tmpdir
    from pathlib import Path
    import tempfile

    f = tmp_path / "Crypto.java"
    f.write_text('KeyPairGenerator.getInstance("RSA");')

    with tempfile.TemporaryDirectory() as td:
        mapping = _copy_to_tmpdir([str(f)], td)
        assert len(mapping) == 1
        tmp_path_val, orig_path = list(mapping.items())[0]
        assert orig_path == str(f)
        assert Path(tmp_path_val).read_text() == f.read_text()


def test_copy_to_tmpdir_mapping_keys_are_tmp_paths(tmp_path):
    from cryptodep.tools.semgrep_tools import _copy_to_tmpdir
    import tempfile

    f = tmp_path / "Auth.java"
    f.write_text("class Auth {}")

    with tempfile.TemporaryDirectory() as td:
        mapping = _copy_to_tmpdir([str(f)], td)
        for tmp_p in mapping:
            assert tmp_p.startswith(td)


def test_run_semgrep_uses_prefilter(tmp_path):
    """run_semgrep must call _ripgrep_prefilter before invoking Semgrep."""
    from cryptodep.tools import semgrep_tools

    files = ["/fake/file.java"]
    with patch.object(semgrep_tools, "_ripgrep_prefilter", return_value=[]) as mock_filter:
        with patch("subprocess.run") as mock_sub:
            semgrep_tools.run_semgrep(["fake_rule.yaml"], files)
    mock_filter.assert_called_once_with(files)
    # Semgrep not called when pre-filter returns empty list
    mock_sub.assert_not_called()


# ── run_semgrep ───────────────────────────────────────────────────────────


def test_run_semgrep_returns_list(java_semgrep_raw):
    assert isinstance(java_semgrep_raw, list)


def test_run_semgrep_finds_cipher_getinstance(java_semgrep_raw):
    messages = [r["extra"]["message"] for r in java_semgrep_raw]
    assert any("Cipher" in m or "KeyPairGenerator" in m or "SSLContext" in m for m in messages)


def test_run_semgrep_python_findings(python_semgrep_raw):
    assert len(python_semgrep_raw) > 0


def test_run_semgrep_no_findings_for_plain_file():
    from cryptodep.tools.semgrep_tools import run_semgrep

    results = run_semgrep(
        [str(RULES_DIR / "crypto-java.yaml"), str(RULES_DIR / "crypto-python.yaml")],
        [str(FIXTURES / "plain_utils.py")],
    )
    assert len(results) == 0


def test_run_semgrep_raises_on_bad_rule(tmp_path):
    from cryptodep.tools.semgrep_tools import run_semgrep

    with patch("cryptodep.tools.semgrep_tools._is_windows", return_value=False), \
         patch("cryptodep.tools.semgrep_tools._find_semgrep_bin", return_value=["semgrep"]), \
         patch("cryptodep.tools.semgrep_tools.subprocess.run", return_value=MagicMock(returncode=2, stderr="bad rule")), \
         patch("cryptodep.tools.semgrep_tools._ripgrep_prefilter", return_value=[str(FIXTURES / "AuthService.java")]):
        with pytest.raises(RuntimeError, match="Semgrep exited"):
            run_semgrep([str(tmp_path / "nonexistent_rule.yaml")], [str(FIXTURES / "AuthService.java")])


def test_run_semgrep_keeps_results_on_partial_parse_warning_but_fails_on_error(tmp_path):
    from cryptodep.tools.semgrep_tools import run_semgrep

    result = {"path": "x", "start": {"line": 1}, "end": {"line": 1}, "extra": {"lines": "md5"}}
    warn = {"level": "warn", "type": ["PartialParsing", []], "path": "broken.java"}
    with patch("cryptodep.tools.semgrep_tools._is_windows", return_value=False), \
         patch("cryptodep.tools.semgrep_tools._find_semgrep_bin", return_value=["semgrep"]), \
         patch("cryptodep.tools.semgrep_tools._ripgrep_prefilter", return_value=[str(FIXTURES / "AuthService.java")]), \
         patch("cryptodep.tools.semgrep_tools.subprocess.run") as run:
        run.return_value = MagicMock(returncode=0, stdout=json.dumps({"results": [result], "errors": [warn]}))
        assert len(run_semgrep(["rule.yaml"], [str(FIXTURES / "AuthService.java")])) == 1
        run.return_value = MagicMock(returncode=0, stdout=json.dumps({"results": [], "errors": [{**warn, "level": "error"}]}))
        with pytest.raises(RuntimeError, match="analysis errors"):
            run_semgrep(["rule.yaml"], [str(FIXTURES / "AuthService.java")])


# ── parse_semgrep_findings ────────────────────────────────────────────────


def test_parse_findings_returns_crypto_finding_shape(java_semgrep_raw):
    from cryptodep.tools.semgrep_tools import parse_semgrep_findings

    findings = parse_semgrep_findings(java_semgrep_raw)
    assert len(findings) > 0
    for f in findings:
        assert "algorithm_family" in f
        assert "source_ref" in f
        assert "confidence" in f
        assert "detected_by" in f
        assert f["detected_by"] == "static_rule"


def test_parse_api_category_gets_high_confidence(java_semgrep_raw):
    from cryptodep.tools.semgrep_tools import parse_semgrep_findings

    findings = parse_semgrep_findings(java_semgrep_raw)
    api_findings = [f for f in findings if f["confidence"] == 0.90]
    # Cipher.getInstance and KeyPairGenerator.getInstance are crypto-java-api → 0.90
    assert len(api_findings) > 0


def test_parse_findings_source_ref_format(java_semgrep_raw):
    from cryptodep.tools.semgrep_tools import parse_semgrep_findings

    findings = parse_semgrep_findings(java_semgrep_raw)
    for f in findings:
        assert ":L" in f["source_ref"]


def test_parse_findings_empty_input():
    from cryptodep.tools.semgrep_tools import parse_semgrep_findings
    assert parse_semgrep_findings([]) == []


def test_extract_parameter_set_jce_string():
    from cryptodep.tools.semgrep_tools import _extract_parameter_set
    assert _extract_parameter_set("AES", "message", 'Cipher.getInstance("AES/CBC/PKCS5Padding")') == "AES-CBC"

def test_extract_parameter_set_keysize_in_line():
    from cryptodep.tools.semgrep_tools import _extract_parameter_set
    assert _extract_parameter_set("RSA", "message", 'KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", 2048);') == "RSA-2048"

def test_extract_parameter_set_algo_only_literal():
    from cryptodep.tools.semgrep_tools import _extract_parameter_set
    assert _extract_parameter_set("RSA", "message", 'KeyPairGenerator.getInstance("RSA")') is None

def test_extract_parameter_set_combined_literal_sha256():
    from cryptodep.tools.semgrep_tools import _extract_parameter_set
    assert _extract_parameter_set("SHA", "message", 'MessageDigest.getInstance("SHA-256")') == "SHA-256"

def test_extract_parameter_set_jwt_rs256():
    from cryptodep.tools.semgrep_tools import _extract_parameter_set
    assert _extract_parameter_set("RSA", "message", 'Algorithm.RS256(publicKey, privateKey)') is None  # Does not match subpattern C but is handled via _ALGO_RE elsewhere

def test_parse_semgrep_findings_spring_bcrypt():
    from cryptodep.tools.semgrep_tools import parse_semgrep_findings
    raw = [{
        "path": "src/AppConfig.java",
        "start": {"line": 10},
        "extra": {
            "message": "Spring Security: BCryptPasswordEncoder",
            "metadata": {
                "category": "crypto-spring-api",
                "algorithm_family": "BCRYPT"
            },
            "lines": "return new BCryptPasswordEncoder();"
        }
    }]
    findings = parse_semgrep_findings(raw)
    assert len(findings) == 1
    assert findings[0]["algorithm_family"] == "BCRYPT"
    assert findings[0]["parameter_set"] is None

