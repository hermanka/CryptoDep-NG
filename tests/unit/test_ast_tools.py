from __future__ import annotations

import pathlib
import pytest

FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures" / "sample_repo"


# ── filter_source_files ────────────────────────────────────────────────────


def test_filter_returns_only_java_and_python():
    from cryptodep.tools.ast_tools import filter_source_files

    files = filter_source_files(str(FIXTURES), ["java", "python"], [])
    suffixes = {f.suffix for f in files}
    assert suffixes == {".java", ".py"}


def test_filter_excludes_build_dir(tmp_path):
    from cryptodep.tools.ast_tools import filter_source_files

    build = tmp_path / "build"
    build.mkdir()
    (build / "Generated.java").write_text("public class Generated {}")
    (tmp_path / "Real.java").write_text("public class Real {}")

    files = filter_source_files(str(tmp_path), ["java"], ["**/build/**"])
    names = [f.name for f in files]
    assert "Real.java" in names
    assert "Generated.java" not in names


def test_filter_returns_sorted_list():
    from cryptodep.tools.ast_tools import filter_source_files

    files = filter_source_files(str(FIXTURES), ["java", "python"], [])
    paths = [str(f) for f in files]
    assert paths == sorted(paths)


# ── parse_file_ast ─────────────────────────────────────────────────────────


def test_parse_java_file_returns_tree_and_source():
    from cryptodep.tools.ast_tools import parse_file_ast

    result = parse_file_ast(FIXTURES / "AuthService.java", "java")
    assert result is not None
    assert "tree" in result
    assert "source" in result
    assert "KeyPairGenerator" in result["source"]


def test_parse_python_file_returns_tree_and_source():
    from cryptodep.tools.ast_tools import parse_file_ast

    result = parse_file_ast(FIXTURES / "crypto_utils.py", "python")
    assert result is not None
    assert "RSA" in result["source"]


def test_parse_nonexistent_file_returns_none():
    from cryptodep.tools.ast_tools import parse_file_ast

    result = parse_file_ast(pathlib.Path("/nonexistent/missing.java"), "java")
    assert result is None


# ── extract_imports ────────────────────────────────────────────────────────


def test_extract_java_imports():
    from cryptodep.tools.ast_tools import parse_file_ast, extract_imports

    result = parse_file_ast(FIXTURES / "AuthService.java", "java")
    assert result is not None
    imports = extract_imports(result["tree"], result["source"], "java")
    assert any("javax.crypto" in imp for imp in imports)
    assert any("java.security" in imp for imp in imports)


def test_extract_java_bouncycastle_import():
    from cryptodep.tools.ast_tools import parse_file_ast, extract_imports

    result = parse_file_ast(FIXTURES / "LegacyEncryptor.java", "java")
    assert result is not None
    imports = extract_imports(result["tree"], result["source"], "java")
    assert any("bouncycastle" in imp for imp in imports)


def test_extract_python_imports():
    from cryptodep.tools.ast_tools import parse_file_ast, extract_imports

    result = parse_file_ast(FIXTURES / "crypto_utils.py", "python")
    assert result is not None
    imports = extract_imports(result["tree"], result["source"], "python")
    assert "hashlib" in imports


def test_extract_python_from_import():
    from cryptodep.tools.ast_tools import parse_file_ast, extract_imports

    result = parse_file_ast(FIXTURES / "crypto_utils.py", "python")
    assert result is not None
    imports = extract_imports(result["tree"], result["source"], "python")
    # "from Crypto.PublicKey import RSA" → captures "Crypto.PublicKey"
    assert any("Crypto" in imp for imp in imports)


def test_extract_no_imports_for_plain_file():
    from cryptodep.tools.ast_tools import parse_file_ast, extract_imports

    result = parse_file_ast(FIXTURES / "plain_service.java", "java")
    assert result is not None
    imports = extract_imports(result["tree"], result["source"], "java")
    assert imports == []


def test_extract_imports_deduplicates():
    from cryptodep.tools.ast_tools import parse_file_ast, extract_imports

    result = parse_file_ast(FIXTURES / "AuthService.java", "java")
    assert result is not None
    imports = extract_imports(result["tree"], result["source"], "java")
    assert len(imports) == len(set(imports))


# ── build_file_graph ───────────────────────────────────────────────────────


def test_build_file_graph_keys_match_file_index():
    from cryptodep.tools.ast_tools import filter_source_files, parse_file_ast, build_file_graph

    files = filter_source_files(str(FIXTURES), ["java", "python"], [])
    file_index = {}
    ast_cache = {}
    for path in files:
        lang = "java" if path.suffix == ".java" else "python"
        result = parse_file_ast(path, lang)
        if result:
            file_index[str(path)] = {"path": str(path), "language": lang, "size_bytes": 0, "loc": 0}
            ast_cache[str(path)] = result

    graph = build_file_graph(file_index, ast_cache)
    assert set(graph.keys()) == set(file_index.keys())


def test_build_file_graph_auth_service_has_imports():
    from cryptodep.tools.ast_tools import filter_source_files, parse_file_ast, build_file_graph

    files = filter_source_files(str(FIXTURES), ["java"], [])
    file_index = {}
    ast_cache = {}
    for path in files:
        result = parse_file_ast(path, "java")
        if result:
            file_index[str(path)] = {"path": str(path), "language": "java", "size_bytes": 0, "loc": 0}
            ast_cache[str(path)] = result

    graph = build_file_graph(file_index, ast_cache)
    auth_key = next(k for k in graph if "AuthService" in k)
    assert len(graph[auth_key]) > 0
