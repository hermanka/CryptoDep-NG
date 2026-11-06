from __future__ import annotations
from pathlib import Path
import pytest
from cryptodep.tools.ast_tools import parse_file_ast

_FIXTURES = Path(__file__).parent.parent / "fixtures" / "sample_repo"


def _build_ast_cache(*filenames: str) -> dict:
    cache = {}
    for name in filenames:
        path = _FIXTURES / name
        language = "java" if name.endswith(".java") else "python"
        result = parse_file_ast(path, language)
        if result:
            cache[str(path)] = result
    return cache


def _build_file_index(ast_cache: dict) -> dict:
    idx = {}
    for path_str in ast_cache:
        lang = "java" if path_str.endswith(".java") else "python"
        idx[path_str] = {"path": path_str, "language": lang, "size_bytes": 100, "loc": 10}
    return idx


# ── Task 3: Entry point detection ────────────────────────────────────────────

def test_detect_java_rest_controller():
    from cryptodep.tools.callgraph_tools import detect_entry_points
    ast_cache = _build_ast_cache("LoginController.java")
    file_index = _build_file_index(ast_cache)
    eps = detect_entry_points(file_index, ast_cache)
    assert len(eps) >= 2
    assert all(ep["type"] == "rest_endpoint" for ep in eps)
    methods = {ep["method"] for ep in eps}
    assert "login" in methods
    assert "encrypt" in methods


def test_detect_java_main_method():
    from cryptodep.tools.callgraph_tools import detect_entry_points
    ast_cache = _build_ast_cache("plain_service.java")
    file_index = _build_file_index(ast_cache)
    eps = detect_entry_points(file_index, ast_cache)
    assert eps == []


def test_detect_python_flask_route():
    from cryptodep.tools.callgraph_tools import detect_entry_points
    ast_cache = _build_ast_cache("app.py")
    file_index = _build_file_index(ast_cache)
    eps = detect_entry_points(file_index, ast_cache)
    route_eps = [ep for ep in eps if ep["type"] == "rest_endpoint"]
    assert len(route_eps) >= 1
    assert route_eps[0]["method"] == "handle_encrypt"


def test_detect_python_main_block():
    from cryptodep.tools.callgraph_tools import detect_entry_points
    ast_cache = _build_ast_cache("app.py")
    file_index = _build_file_index(ast_cache)
    eps = detect_entry_points(file_index, ast_cache)
    main_eps = [ep for ep in eps if ep["type"] == "main"]
    assert len(main_eps) == 1


def test_plain_python_no_entry_points():
    from cryptodep.tools.callgraph_tools import detect_entry_points
    ast_cache = _build_ast_cache("plain_utils.py")
    file_index = _build_file_index(ast_cache)
    eps = detect_entry_points(file_index, ast_cache)
    assert eps == []


# ── Task 4: Call graph builder ────────────────────────────────────────────────

def test_build_call_graph_java_has_method_nodes():
    from cryptodep.tools.callgraph_tools import build_call_graph
    ast_cache = _build_ast_cache("LoginController.java", "AuthService.java")
    file_index = _build_file_index(ast_cache)
    cg = build_call_graph(file_index, ast_cache)
    keys = set(cg.keys())
    assert any("login" in k for k in keys)


def test_build_call_graph_java_resolves_calls():
    from cryptodep.tools.callgraph_tools import build_call_graph
    ast_cache = _build_ast_cache("LoginController.java", "AuthService.java")
    file_index = _build_file_index(ast_cache)
    cg = build_call_graph(file_index, ast_cache)
    login_key = [k for k in cg if "login" in k.lower()][0]
    callees = cg[login_key]
    assert any("generateRSAKey" in c for c in callees)


def test_build_call_graph_python_has_method_nodes():
    from cryptodep.tools.callgraph_tools import build_call_graph
    ast_cache = _build_ast_cache("app.py", "crypto_utils.py")
    file_index = _build_file_index(ast_cache)
    cg = build_call_graph(file_index, ast_cache)
    keys = set(cg.keys())
    assert any("handle_encrypt" in k for k in keys)


def test_build_call_graph_python_resolves_calls():
    from cryptodep.tools.callgraph_tools import build_call_graph
    ast_cache = _build_ast_cache("app.py", "crypto_utils.py")
    file_index = _build_file_index(ast_cache)
    cg = build_call_graph(file_index, ast_cache)
    handler_key = [k for k in cg if "handle_encrypt" in k][0]
    callees = cg[handler_key]
    assert any("encrypt_data" in c for c in callees)


def test_build_call_graph_empty_cache():
    from cryptodep.tools.callgraph_tools import build_call_graph
    cg = build_call_graph({}, {})
    assert cg == {}
