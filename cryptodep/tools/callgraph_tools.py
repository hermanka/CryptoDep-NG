"""Call graph analysis tools: entry point detection and method-level call graph builder.

Tool contracts:
  detect_entry_points(file_index, ast_cache) → List[EntryPoint]
  build_call_graph(file_index, ast_cache)    → Dict[str, List[str]]
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

from cryptodep.state import EntryPoint
from cryptodep.tools.ast_tools import _walk_nodes

log = structlog.get_logger().bind(module="callgraph_tools")

# ── Java annotation sets ────────────────────────────────────────────────────
_JAVA_REST_CLASS_ANNOTATIONS = {
    "RestController",
    "Controller",
    "RequestMapping",
}

_JAVA_REST_METHOD_ANNOTATIONS = {
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "DeleteMapping",
    "PatchMapping",
    "RequestMapping",
}

# ── Python framework decorators ─────────────────────────────────────────────
_PYTHON_ROUTE_DECORATOR_ATTRS = {
    "route",
    "get",
    "post",
    "put",
    "delete",
    "patch",
}

_PYTHON_TASK_DECORATOR_NAMES = {
    "shared_task",
    "task",
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _node_text(node: Any) -> str:
    """Return the UTF-8 text of a Tree-sitter node."""
    return node.text.decode("utf-8") if node.text else ""


def _get_java_annotations(node: Any) -> List[str]:
    """Return annotation names on a Java class or method declaration node.

    Handles both marker_annotation (@RestController) and annotation (@PostMapping("...")).
    """
    names: List[str] = []
    for child in node.children:
        if child.type == "modifiers":
            for mod_child in child.children:
                if mod_child.type in ("annotation", "marker_annotation"):
                    # Annotation child: "@" + identifier
                    for ann_child in mod_child.children:
                        if ann_child.type == "identifier":
                            names.append(_node_text(ann_child))
                            break
    return names


def _get_java_class_name(node: Any) -> Optional[str]:
    """Return the identifier of a Java class_declaration node."""
    for child in node.children:
        if child.type == "identifier":
            return _node_text(child)
    return None


def _get_java_method_name(node: Any) -> Optional[str]:
    """Return the identifier of a Java method_declaration node."""
    for child in node.children:
        if child.type == "identifier":
            return _node_text(child)
    return None


def _get_python_function_name(node: Any) -> Optional[str]:
    """Return the name identifier of a Python function_definition node."""
    for child in node.children:
        if child.type == "identifier":
            return _node_text(child)
    return None


def _get_python_decorator_info(decorator_node: Any) -> tuple[Optional[str], Optional[str]]:
    """
    Parse a Python decorator node and return (object_name, attribute_name).
    E.g. @app.route → ("app", "route")
         @shared_task → (None, "shared_task")
    """
    # decorator has a child that is either an identifier or attribute/call
    for child in decorator_node.children:
        if child.type == "identifier":
            return (None, _node_text(child))
        if child.type == "attribute":
            # attribute: object "." attribute
            parts = [c for c in child.children if c.type == "identifier"]
            if len(parts) >= 2:
                return (_node_text(parts[0]), _node_text(parts[1]))
            elif len(parts) == 1:
                return (None, _node_text(parts[0]))
        if child.type == "call":
            # @app.route(...) — the function part of the call
            func_child = child.children[0] if child.children else None
            if func_child is not None:
                if func_child.type == "attribute":
                    parts = [c for c in func_child.children if c.type == "identifier"]
                    if len(parts) >= 2:
                        return (_node_text(parts[0]), _node_text(parts[1]))
                elif func_child.type == "identifier":
                    return (None, _node_text(func_child))
    return (None, None)


# ── Entry point detection ────────────────────────────────────────────────────

def _detect_java_entry_points(path_str: str, ast_data: Dict[str, Any]) -> List[EntryPoint]:
    """Extract Java entry points from a parsed AST."""
    entry_points: List[EntryPoint] = []
    tree = ast_data["tree"]
    root = tree.root_node

    # Walk top-level class declarations
    for node in _walk_nodes(root):
        if node.type != "class_declaration":
            continue

        class_annotations = _get_java_annotations(node)
        class_name = _get_java_class_name(node) or "Unknown"
        is_rest_controller = bool(
            set(class_annotations) & _JAVA_REST_CLASS_ANNOTATIONS
        )

        # Walk methods within this class
        for child in _walk_nodes(node):
            if child.type == "method_declaration":
                method_annotations = _get_java_annotations(child)
                method_name = _get_java_method_name(child) or ""
                method_line = child.start_point[0] + 1

                rest_annotations = set(method_annotations) & _JAVA_REST_METHOD_ANNOTATIONS
                if is_rest_controller and rest_annotations:
                    entry_points.append(EntryPoint(
                        file=path_str,
                        method=method_name,
                        type="rest_endpoint",
                        line=method_line,
                    ))
                    continue

                # public static void main(String[] args)
                if method_name == "main":
                    modifiers_text = ""
                    for c in child.children:
                        if c.type == "modifiers":
                            modifiers_text = _node_text(c)
                    if "static" in modifiers_text and "public" in modifiers_text:
                        entry_points.append(EntryPoint(
                            file=path_str,
                            method=method_name,
                            type="main",
                            line=method_line,
                        ))
                        continue

                # Servlet doGet / doPost
                if method_name in ("doGet", "doPost", "service"):
                    entry_points.append(EntryPoint(
                        file=path_str,
                        method=method_name,
                        type="servlet",
                        line=method_line,
                    ))

    return entry_points


def _detect_python_entry_points(path_str: str, ast_data: Dict[str, Any]) -> List[EntryPoint]:
    """Extract Python entry points from a parsed AST."""
    entry_points: List[EntryPoint] = []
    tree = ast_data["tree"]
    root = tree.root_node

    # Collect decorated_definition nodes at module level (and nested)
    for node in _walk_nodes(root):
        if node.type == "decorated_definition":
            # Collect all decorator children
            decorators = [c for c in node.children if c.type == "decorator"]
            # The actual function definition
            func_node = next(
                (c for c in node.children if c.type == "function_definition"), None
            )
            if func_node is None:
                continue

            func_name = _get_python_function_name(func_node) or ""
            func_line = func_node.start_point[0] + 1

            for decorator in decorators:
                obj_name, attr_name = _get_python_decorator_info(decorator)

                # @app.route, @router.get, etc.
                if attr_name in _PYTHON_ROUTE_DECORATOR_ATTRS:
                    entry_points.append(EntryPoint(
                        file=path_str,
                        method=func_name,
                        type="rest_endpoint",
                        line=func_line,
                    ))
                    break

                # @shared_task, @celery.task
                if attr_name in _PYTHON_TASK_DECORATOR_NAMES:
                    entry_points.append(EntryPoint(
                        file=path_str,
                        method=func_name,
                        type="async_task",
                        line=func_line,
                    ))
                    break

        # Detect if __name__ == "__main__": blocks
        if node.type == "if_statement":
            # Check condition is `__name__ == "__main__"`
            condition = node.children[1] if len(node.children) > 1 else None
            if condition is not None and condition.type == "comparison_operator":
                cond_text = _node_text(condition).replace(" ", "")
                if '__name__=="__main__"' in cond_text or "__name__=='__main__'" in cond_text:
                    entry_points.append(EntryPoint(
                        file=path_str,
                        method="__main__",
                        type="main",
                        line=node.start_point[0] + 1,
                    ))

    return entry_points


def detect_entry_points(
    file_index: Dict[str, Any],
    ast_cache: Dict[str, Any],
) -> List[EntryPoint]:
    """Detect all entry points across a repository.

    Detects:
    - Java: @RestController/@Controller + @*Mapping, public static void main, servlet doGet/doPost
    - Python: @app.route/@router.get/post decorated functions, if __name__ == "__main__" blocks,
              @shared_task/@celery.task

    Args:
        file_index: Map of file path → FileInfo dict.
        ast_cache: Map of file path → {tree, source} from parse_file_ast.

    Returns:
        List of EntryPoint TypedDicts.
    """
    all_entry_points: List[EntryPoint] = []

    for path_str, file_info in file_index.items():
        ast_data = ast_cache.get(path_str)
        if ast_data is None:
            continue

        language = file_info.get("language", "")

        try:
            if language == "java":
                eps = _detect_java_entry_points(path_str, ast_data)
            elif language == "python":
                eps = _detect_python_entry_points(path_str, ast_data)
            else:
                eps = []

            all_entry_points.extend(eps)

        except Exception as exc:
            log.warning(
                "entry_point_detection_failed",
                path=path_str,
                error=str(exc),
            )

    log.info("entry_points_detected", count=len(all_entry_points))
    return all_entry_points


# ── Call graph builder ────────────────────────────────────────────────────────

def _extract_java_call_graph(
    path_str: str,
    ast_data: Dict[str, Any],
) -> Dict[str, List[str]]:
    """Phase 1: Extract Java method defs and their raw call expressions."""
    tree = ast_data["tree"]
    root = tree.root_node
    cg: Dict[str, List[str]] = {}

    for node in _walk_nodes(root):
        if node.type != "class_declaration":
            continue
        class_name = _get_java_class_name(node) or Path(path_str).stem

        for child in _walk_nodes(node):
            if child.type != "method_declaration":
                continue
            method_name = _get_java_method_name(child) or ""
            if not method_name:
                continue
            key = f"{class_name}.{method_name}"

            # Find all method_invocation nodes within this method body
            calls: List[str] = []
            for sub in _walk_nodes(child):
                if sub.type == "method_invocation":
                    # method_invocation: [object "."] method_name "(" args ")"
                    # The method name is usually the last identifier before "("
                    # In tree-sitter-java: field_access or identifier + argument_list
                    invoked_name: Optional[str] = None
                    for sc in sub.children:
                        if sc.type == "identifier":
                            invoked_name = _node_text(sc)
                        # Don't break — we want the last identifier (the method name)
                        # before argument_list
                        if sc.type == "argument_list":
                            break
                    if invoked_name:
                        calls.append(invoked_name)

            cg[key] = calls

    return cg


def _extract_python_call_graph(
    path_str: str,
    ast_data: Dict[str, Any],
) -> Dict[str, List[str]]:
    """Phase 1: Extract Python function defs and their raw call expressions."""
    tree = ast_data["tree"]
    root = tree.root_node
    module_name = Path(path_str).stem
    cg: Dict[str, List[str]] = {}

    def _process_function(func_node: Any, class_name: Optional[str]) -> None:
        func_name = _get_python_function_name(func_node) or ""
        if not func_name:
            return
        prefix = class_name if class_name else module_name
        key = f"{prefix}.{func_name}"

        calls: List[str] = []
        for sub in _walk_nodes(func_node):
            if sub.type == "call":
                # call: function "(" arguments ")"
                func_child = sub.children[0] if sub.children else None
                if func_child is None:
                    continue
                if func_child.type == "identifier":
                    calls.append(_node_text(func_child))
                elif func_child.type == "attribute":
                    # e.g. obj.method — extract method name (last identifier)
                    ids = [c for c in func_child.children if c.type == "identifier"]
                    if ids:
                        calls.append(_node_text(ids[-1]))

        cg[key] = calls

    # Walk for class definitions and standalone functions
    for node in root.children:
        if node.type == "class_definition":
            class_name_node = next(
                (c for c in node.children if c.type == "identifier"), None
            )
            cname = _node_text(class_name_node) if class_name_node else module_name
            # Walk class body for method definitions
            for child in _walk_nodes(node):
                if child.type == "function_definition":
                    _process_function(child, cname)

        elif node.type == "function_definition":
            _process_function(node, None)

        elif node.type == "decorated_definition":
            # Find the underlying function
            func_node = next(
                (c for c in node.children if c.type == "function_definition"), None
            )
            if func_node:
                _process_function(func_node, None)

    return cg


def build_call_graph(
    file_index: Dict[str, Any],
    ast_cache: Dict[str, Any],
) -> Dict[str, List[str]]:
    """Build a method-level call graph across all files in the index.

    Algorithm:
    - Phase 1: For each file, extract method definitions (ClassName.methodName)
      and the raw call expression names within each method.
    - Phase 2: Resolve call targets by basename matching against known method defs,
      producing qualified "ClassName.methodName" callee strings where possible.

    Args:
        file_index: Map of file path → FileInfo dict.
        ast_cache: Map of file path → {tree, source} from parse_file_ast.

    Returns:
        Dict mapping "ClassName.methodName" → list of callee keys (qualified where resolvable).
    """
    if not file_index:
        return {}

    # Phase 1: Collect raw call graph per file
    raw_cg: Dict[str, List[str]] = {}

    for path_str, file_info in file_index.items():
        ast_data = ast_cache.get(path_str)
        if ast_data is None:
            continue

        language = file_info.get("language", "")
        try:
            if language == "java":
                file_cg = _extract_java_call_graph(path_str, ast_data)
            elif language == "python":
                file_cg = _extract_python_call_graph(path_str, ast_data)
            else:
                file_cg = {}
            raw_cg.update(file_cg)
        except Exception as exc:
            log.warning("call_graph_extraction_failed", path=path_str, error=str(exc))

    # Phase 2: Resolve raw method names to qualified keys
    # Build a lookup: method_basename → [qualified_key, ...]
    basename_to_keys: Dict[str, List[str]] = {}
    for key in raw_cg:
        parts = key.split(".")
        basename = parts[-1]
        basename_to_keys.setdefault(basename, []).append(key)

    resolved_cg: Dict[str, List[str]] = {}
    for caller_key, raw_callees in raw_cg.items():
        resolved_callees: List[str] = []
        seen_callees: set = set()
        for raw_callee in raw_callees:
            candidates = basename_to_keys.get(raw_callee, [])
            if candidates:
                for cand in candidates:
                    if cand not in seen_callees:
                        resolved_callees.append(cand)
                        seen_callees.add(cand)
            else:
                # Keep as unresolved bare name
                if raw_callee not in seen_callees:
                    resolved_callees.append(raw_callee)
                    seen_callees.add(raw_callee)
        resolved_cg[caller_key] = resolved_callees

    log.info("call_graph_built", methods=len(resolved_cg))
    return resolved_cg
