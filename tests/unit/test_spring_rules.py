import pytest
from pathlib import Path
from cryptodep.tools.semgrep_tools import parse_semgrep_findings, run_semgrep

RULES_DIR = Path("cryptodep/rules")
FIXTURES_DIR = Path("tests/fixtures/spring")

RULE_PATHS = [
    str(RULES_DIR / "crypto-java-spring.yaml"),
    str(RULES_DIR / "crypto-java-spring-vault.yaml"),
]

def test_dvja_style_md5_survives_prefilter(tmp_path):
    source = tmp_path / "UserService.java"
    source.write_text(
        "import org.springframework.util.DigestUtils;\n"
        "class UserService {\n"
        "String passwordHash(String password) { return DigestUtils.md5DigestAsHex(password.getBytes()); }\n"
        "String resetKey(String login) { return DigestUtils.md5DigestAsHex(login.getBytes()); }\n"
        "}\n"
    )
    findings = parse_semgrep_findings(run_semgrep(RULE_PATHS, [str(source)]))
    md5 = [finding for finding in findings if finding["algorithm_family"] == "MD5"]
    assert len(md5) == 2
    assert all(finding["confidence"] == .9 for finding in md5)
    assert all(finding["source_ref"].startswith(str(source) + ":L") for finding in md5)
    assert all("md5DigestAsHex" in finding["evidence"] for finding in md5)

def test_bcrypt_config_rule():
    results = run_semgrep(RULE_PATHS, [str(FIXTURES_DIR / "BCryptConfig.java")])
    assert len(results) >= 1
    messages = [r["extra"]["message"] for r in results]
    assert any("BCryptPasswordEncoder" in msg for msg in messages)

def test_jwt_config_rule():
    results = run_semgrep(RULE_PATHS, [str(FIXTURES_DIR / "JwtConfig.java")])
    assert len(results) >= 1
    messages = [r["extra"]["message"] for r in results]
    assert any("NimbusJwtDecoder" in msg for msg in messages)

def test_vault_config_rule():
    results = run_semgrep(RULE_PATHS, [str(FIXTURES_DIR / "VaultConfig.java")])
    assert len(results) >= 1
    messages = [r["extra"]["message"] for r in results]
    assert any("VaultTemplate.write" in msg for msg in messages)
