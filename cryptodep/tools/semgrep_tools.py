"""Semgrep runner and result parser for crypto detection (PRD Section 5.2).

Rule categories (bundled in cryptodep/rules/):
  crypto-java-import, crypto-java-api, crypto-python-import,
  crypto-python-api, crypto-constants, crypto-tls-config, crypto-jwt
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

from cryptodep.state import CryptoFinding

log = structlog.get_logger().bind(module="semgrep_tools")

# Base confidence per Semgrep rule category
_CATEGORY_CONFIDENCE: Dict[str, float] = {
    "crypto-java-api": 0.90,
    "crypto-python-api": 0.90,
    "crypto-javascript-api": 0.90,
    "crypto-tls-config": 0.85,
    "crypto-jwt": 0.85,
    "crypto-java-import": 0.80,
    "crypto-python-import": 0.80,
    "crypto-constants": 0.65,
    "crypto-spring-api": 0.90,
    "crypto-spring-jwt": 0.85,
    "crypto-spring-import": 0.75,
    "crypto-spring-vault": 0.85,
    "crypto-spring-vault-import": 0.75,
}

# Algorithm family extraction â€” ordered longest-match first
_ALGO_RE = re.compile(
    r'\b(ECDSA|ECDH|SHA-?512|SHA-?384|SHA-?256|SHA-?1|SHA1|3DES|RSA|DH|ECC|EC|AES|'
    r'DES|MD5|Fernet|HMAC|TLS|SSL|RS512|RS384|RS256|ES512|ES384|ES256|HS512|HS384|HS256)\b',
    re.IGNORECASE,
)
_ALGO_NORMALIZE: Dict[str, str] = {
    "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
    "RS256": "RSA", "RS384": "RSA", "RS512": "RSA",
    "ES256": "ECDSA", "ES384": "ECDSA", "ES512": "ECDSA",
    "HS256": "HMAC", "HS384": "HMAC", "HS512": "HMAC",
    "SSL": "TLS", "ECC": "EC",
    "DHE": "DH", "ECDHE": "ECDH", "DIFFIE-HELLMAN": "DH",
    "BCRYPT": "BCRYPT", "SCRYPT": "SCRYPT", "ARGON2": "ARGON2",
}


# Crypto keywords used by ripgrep pre-filter â€” superset of all YAML rule patterns
_RG_CRYPTO_PATTERN = (
    r"getInstance|MessageDigest|KeyPairGenerator|SecretKeySpec|Cipher|"
    r"SSLContext|TrustManager|javax\.crypto|java\.security|BouncyCastle|"
    r"hashlib|cryptography\.hazmat|RSA|AES|DES|3DES|MD5|SHA-1|SHA1|"
    r"RS256|RS384|RS512|ES256|ES384|ES512|HS256|HS384|HS512|"
    r"KeyAgreement|DHParameterSpec|DiffieHellman|DHE|ECDHE"
    r"|BCryptPasswordEncoder|SCryptPasswordEncoder|Argon2PasswordEncoder|"
    r"PasswordEncoderFactories|NimbusJwtDecoder|JwtDecoder|DigestUtils|md5DigestAsHex|"
    r"VaultTemplate|VaultTransitOperations|"
    r"org\.springframework\.security|org\.springframework\.vault"
    r"|node:crypto|createHash|createHmac|createCipheriv|createDecipheriv|generateKeyPair"
    r"|createSign|createVerify|subtle|randomBytes|diffieHellman|createECDH"
)


def _ripgrep_prefilter(file_paths: List[str]) -> List[str]:
    """Return the subset of file_paths that contain any crypto keyword.

    Uses ripgrep for near-instant filtering of large file sets.
    Falls back to returning all file_paths if rg is not available or errors.
    """
    if not file_paths:
        return file_paths

    rg_bin = shutil.which("rg")
    if rg_bin is None:
        log.debug("rg_not_found_skipping_prefilter")
        return file_paths

    try:
        proc = subprocess.run(
            [rg_bin, "--files-with-matches", "--no-messages",
             "-e", _RG_CRYPTO_PATTERN] + file_paths,
            capture_output=True,
            text=True,
        )
        # rg exit 0 = matches found, exit 1 = no matches, exit 2 = error
        if proc.returncode == 2:
            log.warning("rg_prefilter_error", stderr=proc.stderr[:200])
            return file_paths
        matched = [p for p in proc.stdout.splitlines() if p]
        log.debug("rg_prefilter", total=len(file_paths), matched=len(matched))
        return matched
    except Exception as exc:
        log.warning("rg_prefilter_exception", error=str(exc))
        return file_paths


def _copy_to_tmpdir(file_paths: List[str], tmp_dir: str) -> Dict[str, str]:
    """Copy files to a native Linux temp dir and return {tmp_path: original_path}.

    This moves files off WSL2's slow /mnt/c/ VirtioFS mount onto tmpfs,
    eliminating the cross-filesystem I/O bottleneck for Semgrep.
    Files keep their original filename with a flat counter prefix to avoid collisions.
    """
    mapping: Dict[str, str] = {}
    for i, orig in enumerate(file_paths):
        try:
            src = Path(orig)
            dst = Path(tmp_dir) / f"{i:04d}_{src.name}"
            shutil.copy2(str(src), str(dst))
            mapping[str(dst)] = orig
        except OSError:
            pass  # skip unreadable files
    return mapping


def _is_windows() -> bool:
    import sys
    return sys.platform == "win32"


def _win_to_wsl(path: str) -> str:
    """Convert a Windows path to a WSL /mnt/x/... path."""
    p = path.replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        drive = p[0].lower()
        p = f"/mnt/{drive}/{p[3:]}"
    return p


def _wsl_to_win(path: str) -> str:
    """Convert a WSL /mnt/x/... path back to a Windows C:\\... path."""
    import re as _re
    m = _re.match(r"^/mnt/([a-z])/(.*)$", path)
    if m:
        return f"{m.group(1).upper()}:\\{m.group(2).replace('/', chr(92))}"
    return path


def _find_semgrep_bin() -> List[str]:
    """Return the semgrep command as a list (may be ['wsl', '/path/semgrep'] on Windows)."""
    import sys

    if _is_windows():
        # On Windows, semgrep.exe is not supported â€” use WSL semgrep instead.
        wsl_candidates = [
            "/tmp/semgrep_env/bin/semgrep",
            "/home/girnot/.local/bin/semgrep",
            "/usr/local/bin/semgrep",
            "/usr/bin/semgrep",
        ]
        for c in wsl_candidates:
            check = subprocess.run(
                ["wsl", c, "--version"],
                capture_output=True, text=True, timeout=10,
            )
            if check.returncode == 0:
                log.debug("semgrep_via_wsl", path=c)
                return ["wsl", c]
        log.warning("semgrep_wsl_not_found")
        return ["wsl", "semgrep"]  # last-resort fallback

    # Linux / macOS: native semgrep
    project_root = Path(__file__).resolve().parents[2]
    candidates = [
        project_root / ".venv" / "bin" / "semgrep",
        Path(sys.prefix) / "bin" / "semgrep",
    ]
    native = next((str(c) for c in candidates if c.exists()), shutil.which("semgrep") or "semgrep")
    return [native]


def _has_fatal_errors(data: Dict[str, Any], rule_path: str) -> bool:
    """Semgrep "warn" errors (e.g. PartialParsing of one broken file) still return valid results."""
    errors = data.get("errors") or []
    warnings = [e for e in errors if e.get("level") == "warn"]
    if warnings:
        log.warning("semgrep_partial_errors", rule=Path(rule_path).name, count=len(warnings),
                    paths=[e.get("path") for e in warnings][:5])
    return len(warnings) < len(errors)


def run_semgrep(rule_paths: List[str], target_paths: List[str]) -> List[Dict[str, Any]]:
    """Run Semgrep CLI rules against target files. Returns list of raw Semgrep result dicts."""
    if not target_paths:
        return []

    # Pre-filter: only pass files containing crypto keywords to Semgrep
    filtered_paths = _ripgrep_prefilter(target_paths)
    if not filtered_paths:
        log.info("semgrep_skipped_no_candidates", total_files=len(target_paths))
        return []

    all_findings: List[Dict[str, Any]] = []
    failures: List[str] = []
    semgrep_cmd = _find_semgrep_bin()
    use_wsl = _is_windows() and semgrep_cmd[0] == "wsl"

    if use_wsl:
        # On Windows+WSL: convert paths to /mnt/... and batch to stay under cmd-line limit
        wsl_path_map = {_win_to_wsl(p): p for p in filtered_paths}
        all_wsl_paths = list(wsl_path_map.keys())
        _BATCH = 30  # keep WSL command line well under 32 KB

        def _batches(lst: List[str], n: int):
            for i in range(0, len(lst), n):
                yield lst[i:i + n]

        for rule_path in rule_paths:
            wsl_rule = _win_to_wsl(rule_path)
            for batch in _batches(all_wsl_paths, _BATCH):
                cmd = semgrep_cmd + [
                    "--json", "--quiet",
                    "--timeout", "30",
                    "--jobs", "1",
                    "--config", wsl_rule,
                ] + batch
                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=300,
                    )
                    if proc.returncode not in (0, 1):
                        log.warning("semgrep_nonzero_exit", rule=rule_path,
                                    returncode=proc.returncode, stderr=proc.stderr[:200])
                        failures.append(f"Semgrep exited with status {proc.returncode} for {Path(rule_path).name}")
                        continue
                    data = json.loads(proc.stdout)
                    if _has_fatal_errors(data, rule_path):
                        failures.append(f"Semgrep reported analysis errors for {Path(rule_path).name}")
                    results = data.get("results", [])
                    for r in results:
                        wsl_p = r.get("path", "")
                        if wsl_p in wsl_path_map:
                            r["path"] = wsl_path_map[wsl_p]
                    all_findings.extend(results)
                except subprocess.TimeoutExpired:
                    failures.append(f"Semgrep timed out for {Path(rule_path).name}")
                    log.warning("semgrep_timeout", rule=rule_path)
                except (json.JSONDecodeError, Exception) as exc:
                    failures.append(f"Semgrep could not scan with {Path(rule_path).name}")
                    log.warning("semgrep_error", rule=rule_path, error=str(exc))

    else:
        # Copy filtered files to a temp dir (native tmpfs on Linux)
        with tempfile.TemporaryDirectory() as tmp_dir:
            path_map = _copy_to_tmpdir(filtered_paths, tmp_dir)
            scan_paths = list(path_map.keys()) if path_map else filtered_paths

            for rule_path in rule_paths:
                cmd = semgrep_cmd + [
                    "--json", "--quiet",
                    "--timeout", "30",
                    "--jobs", "4",
                    "--config", rule_path,
                ] + scan_paths
                try:
                    proc = subprocess.run(
                        cmd, capture_output=True, text=True, timeout=120,
                    )
                    if proc.returncode not in (0, 1):
                        log.warning("semgrep_nonzero_exit", rule=rule_path,
                                    returncode=proc.returncode, stderr=proc.stderr[:200])
                        failures.append(f"Semgrep exited with status {proc.returncode} for {Path(rule_path).name}")
                        continue
                    data = json.loads(proc.stdout)
                    if _has_fatal_errors(data, rule_path):
                        failures.append(f"Semgrep reported analysis errors for {Path(rule_path).name}")
                    results = data.get("results", [])
                    for r in results:
                        tmp_p = r.get("path", "")
                        if tmp_p in path_map:
                            r["path"] = path_map[tmp_p]
                    all_findings.extend(results)
                except subprocess.TimeoutExpired:
                    failures.append(f"Semgrep timed out for {Path(rule_path).name}")
                    log.warning("semgrep_timeout", rule=rule_path)
                except (json.JSONDecodeError, Exception) as exc:
                    failures.append(f"Semgrep could not scan with {Path(rule_path).name}")
                    log.warning("semgrep_error", rule=rule_path, error=str(exc))

    if failures:
        raise RuntimeError("; ".join(failures))

    # Recent Semgrep versions omit snippets from unauthenticated JSON output.
    source_lines: Dict[str, List[str]] = {}
    for finding in all_findings:
        extra = finding.setdefault("extra", {})
        path = finding.get("path", "")
        if extra.get("lines") not in (None, "", "requires login") or path not in target_paths:
            continue
        try:
            if path not in source_lines:
                source_lines[path] = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
            start = max(0, finding.get("start", {}).get("line", 1) - 1)
            end = finding.get("end", {}).get("line", start + 1)
            extra["lines"] = "\n".join(source_lines[path][start:end])
        except OSError as exc:
            log.warning("semgrep_evidence_unavailable", path=path, error=str(exc))
    return all_findings


def _extract_parameter_set(algo_family: str, message: str, evidence: str) -> Optional[str]:
    # Sub-pattern A â€” JCE transformation strings
    jce_match = re.search(r'"([A-Z0-9]+)/([A-Z0-9]+)/[^"]*"', evidence, re.IGNORECASE)
    if jce_match:
        algo = jce_match.group(1).upper()
        mode = jce_match.group(2).upper()
        return f"{algo}-{mode}"

    # Sub-pattern C â€” Algorithm-size combined literals
    combined_match = re.search(r'"([A-Z]{2,})-(\d{3,4})"', evidence, re.IGNORECASE)
    if combined_match:
        return combined_match.group(0).strip('"').upper()

    # Sub-pattern B â€” Key-size integer on the same evidence line
    keysize_match = re.findall(r'\b(512|1024|2048|3072|4096|128|192|256)\b', evidence)
    if keysize_match:
        largest = max(int(size) for size in keysize_match)
        return f"{algo_family}-{largest}"

    return None


def parse_semgrep_findings(raw_findings: List[Dict[str, Any]]) -> List[CryptoFinding]:
    """Map raw Semgrep output to CryptoFinding TypedDicts."""
    findings: List[CryptoFinding] = []

    for raw in raw_findings:
        path = raw.get("path", "")
        start_line = raw.get("start", {}).get("line", 0)
        message = raw.get("extra", {}).get("message", "")
        metadata = raw.get("extra", {}).get("metadata", {})
        category = metadata.get("category", "")
        evidence = raw.get("extra", {}).get("lines", "").strip()

        confidence = _CATEGORY_CONFIDENCE.get(category, 0.70)

        algo_family = metadata.get("algorithm_family")
        if not algo_family:
            algo_match = _ALGO_RE.search(message)
            if algo_match:
                algo = algo_match.group(0).upper()
                algo_family = _ALGO_NORMALIZE.get(algo, algo)
            else:
                algo_family = _category_to_family(category)

        parameter_set = _extract_parameter_set(algo_family, message, evidence)
        if category == "crypto-javascript-api":
            captured = raw.get("extra", {}).get("metavars", {}).get("$ALG", {}).get("abstract_content", "")
            method = raw.get("extra", {}).get("metavars", {}).get("$METHOD", {}).get("abstract_content", "")
            if not captured:
                match = re.fullmatch(r"(?:Node crypto|Web Crypto) API: (\w+) using (.+)", message)
                if match:
                    method, captured = match.groups()
            algorithm = captured.strip("\"'").upper()
            if algorithm:
                algo_family = _ALGO_NORMALIZE.get(algorithm, algorithm)
                if algorithm.startswith("AES-"):
                    algo_family = "AES"
                    parameter_set = algorithm
                elif algorithm.startswith("RSA"):
                    algo_family = "RSA"
                elif algorithm in ("ED25519", "ED448"):
                    algo_family = "ECC"
                elif algorithm in ("EC", "X25519", "X448", "SECP256K1", "PRIME256V1"):
                    algo_family = "ECDH" if method == "createECDH" or algorithm.startswith("X") else "ECC"
                elif algorithm in ("SHA-1", "SHA-256", "SHA-384", "SHA-512", "HMAC", "ECDSA", "ECDH", "DH"):
                    algo_family = algorithm
                if method == "createHmac":
                    algo_family = "HMAC"
                if not algorithm.startswith("AES-"):
                    parameter_set = _extract_parameter_set(algo_family, message, evidence)
                if algorithm in ("ED25519", "ED448", "X25519", "X448", "SECP256K1", "PRIME256V1"):
                    parameter_set = algorithm
                if method in ("createSign", "createVerify", "sign", "verify") or algorithm in ("RSA-PSS", "RSASSA-PKCS1-V1_5", "ECDSA", "ED25519", "ED448"):
                    metadata = {**metadata, "use_context": "digital_signature"}
                elif method == "createECDH" or algorithm in ("RSA-OAEP", "ECDH", "DH", "X25519", "X448"):
                    metadata = {**metadata, "use_context": "key_exchange"}
                elif method in ("createCipheriv", "createDecipheriv", "encrypt", "decrypt"):
                    metadata = {**metadata, "use_context": "encryption"}
                elif method in ("createHash", "digest"):
                    metadata = {**metadata, "use_context": "hashing"}

        finding: CryptoFinding = {
            "algorithm_family": algo_family,
            "parameter_set": parameter_set,
            "use_context": metadata.get("use_context", "other"),
            "source_ref": f"{path}:L{start_line}",
            "confidence": confidence,
            "evidence": evidence,
            "detected_by": "static_rule",
        }
        findings.append(finding)

    return findings


def _category_to_family(category: str) -> str:
    """Best-effort algorithm family from rule category when message regex finds nothing."""
    if "import" in category:
        return "CRYPTO_IMPORT"
    if "tls" in category:
        return "TLS"
    if "jwt" in category:
        return "JWT"
    if "constants" in category:
        return "UNKNOWN"
    return "UNKNOWN"
