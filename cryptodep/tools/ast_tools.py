"""Tree-sitter AST parsing and import extraction tools (PRD Section 5.1).

Tool contracts:
  parse_file_ast(path, language)     → Tree-sitter Tree
  extract_imports(tree, language)    → List[str] of imported modules/paths
  build_file_graph(file_index, ast_cache) → Dict[str, List[str]]
  filter_source_files(repo_path, languages, exclude_patterns) → List[Path]
"""
from __future__ import annotations

import re as _re
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

import structlog
from tree_sitter import Language, Parser
import tree_sitter_java
import tree_sitter_python
import tree_sitter_javascript

log = structlog.get_logger().bind(module="ast_tools")

# ── Language / Parser singletons (created once at import time) ────────────
_JAVA_LANG = Language(tree_sitter_java.language())
_PY_LANG = Language(tree_sitter_python.language())
_JS_LANG = Language(tree_sitter_javascript.language())
_PARSERS: Dict[str, Parser] = {
    "java": Parser(_JAVA_LANG),
    "python": Parser(_PY_LANG),
    "javascript": Parser(_JS_LANG),
}
_LANGS: Dict[str, Language] = {
    "java": _JAVA_LANG,
    "python": _PY_LANG,
    "javascript": _JS_LANG,
}

_JAVA_IMPORT_RE = _re.compile(r'^import\s+(?:static\s+)?')

LANG_EXTENSIONS: Dict[str, str] = {"java": ".java", "python": ".py", "javascript": ".js"}
EXT_LANG: Dict[str, str] = {v: k for k, v in LANG_EXTENSIONS.items()}
EXT_LANG.update({".mjs": "javascript", ".cjs": "javascript"})


def source_ref_path(source_ref: str) -> str:
    """Remove a trailing line reference while preserving Windows drive letters."""
    return _re.sub(r":L?\d+(?:-L?\d+)?$", "", source_ref)


def filter_source_files(
    repo_path: str,
    languages: List[str],
    exclude_patterns: List[str],
) -> List[Path]:
    """Return sorted source files for the selected languages, excluding matched paths."""
    allowed_suffixes = {ext for ext, lang in EXT_LANG.items() if lang in languages}
    results: List[Path] = []

    for path in Path(repo_path).rglob("*"):
        if "node_modules" in path.relative_to(repo_path).parts:
            continue
        if path.is_symlink() or not path.is_file():
            continue
        if path.suffix not in allowed_suffixes:
            continue
        if any(path.match(pattern) for pattern in exclude_patterns):
            continue
        results.append(path)

    return sorted(results, key=str)


def parse_file_ast(path: Path, language: str) -> Optional[Dict[str, Any]]:
    """Parse a source file with Tree-sitter. Returns {tree, source} or None on error."""
    try:
        parser = _PARSERS[language]
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = parser.parse(source.encode("utf-8"))
        return {"tree": tree, "source": source}
    except Exception as exc:
        log.warning("parse_failed", path=str(path), error=str(exc))
        return None


def _walk_nodes(node: Any) -> Generator[Any, None, None]:
    """Yield all nodes in a tree via depth-first traversal."""
    yield node
    for child in node.children:
        yield from _walk_nodes(child)


def extract_imports(tree: Any, source: str, language: str) -> List[str]:
    """Extract raw import strings from a parsed AST. Returns deduplicated list."""
    results: List[str] = []

    if language == "java":
        for node in _walk_nodes(tree.root_node):
            if node.type == "import_declaration":
                text = node.text.decode("utf-8").strip()
                # Strip leading "import " / "import static " and trailing ";"
                text = _JAVA_IMPORT_RE.sub("", text).removesuffix(";").strip()
                if text:
                    results.append(text)

    elif language == "python":
        for node in _walk_nodes(tree.root_node):
            if node.type == "import_statement":
                # "import foo, bar" — named children are dotted_name nodes
                for child in node.named_children:
                    if child.type == "dotted_name":
                        text = child.text.decode("utf-8").strip()
                        if text:
                            results.append(text)
            elif node.type == "import_from_statement":
                # "from foo.bar import baz" — first named child is module dotted_name
                named = node.named_children
                if named and named[0].type == "dotted_name":
                    text = named[0].text.decode("utf-8").strip()
                    if text:
                        results.append(text)

    elif language == "javascript":
        for node in _walk_nodes(tree.root_node):
            module = None
            if node.type in ("import_statement", "export_statement"):
                module = node.child_by_field_name("source")
            elif node.type == "call_expression":
                function = node.child_by_field_name("function")
                args = node.child_by_field_name("arguments")
                if (function and function.text in (b"require", b"import")
                        and args and len(args.named_children) == 1):
                    module = args.named_children[0]
            if module is not None and module.type == "string":
                results.append(module.text.decode("utf-8")[1:-1])
            # shortcut: recognize standard Web Crypto globals by syntax, add binding resolution if shadowing causes false positives.
            if node.type == "member_expression":
                prop = node.child_by_field_name("property")
                obj = node.child_by_field_name("object")
                if prop and obj and prop.text == b"subtle" and _re.sub(rb"\s+", b"", obj.text) in (
                    b"crypto", b"globalThis.crypto", b"window.crypto",
                ):
                    results.append("webcrypto")

    # Deduplicate preserving order
    seen: set = set()
    deduped: List[str] = []
    for imp in results:
        if imp not in seen:
            seen.add(imp)
            deduped.append(imp)
    return deduped


def build_file_graph(
    file_index: Dict[str, Any],
    ast_cache: Dict[str, Any],
) -> Dict[str, List[str]]:
    """Build import_graph: {file_path: [import_strings]}."""
    graph: Dict[str, List[str]] = {}
    local_files = {str(Path(path).resolve()): path for path in file_index}
    for path_str, file_info in file_index.items():
        language = file_info.get("language", "")
        cached = ast_cache.get(path_str)
        if cached is None:
            graph[path_str] = []
            continue
        try:
            imports = extract_imports(cached["tree"], cached["source"], language)
            if language == "javascript":
                # shortcut: resolve literal relative modules only, add package/alias resolution when needed.
                for imp in list(imports):
                    if not imp.startswith("."):
                        continue
                    base = Path(path_str).parent / imp
                    candidates = [base] + [Path(str(base) + ext) for ext in (".js", ".mjs", ".cjs")]
                    candidates += [base / ("index" + ext) for ext in (".js", ".mjs", ".cjs")]
                    for candidate in candidates:
                        match = local_files.get(str(candidate.resolve()))
                        if match is not None:
                            imports.append(match)
                            break
        except Exception as exc:
            log.warning("import_extraction_failed", path=path_str, error=str(exc))
            imports = []
        graph[path_str] = imports
    return graph
