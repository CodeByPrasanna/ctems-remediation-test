# /services/reconciliation/inspector.py

import os
import re
import csv

from pathlib import Path

SCOPE_KEYWORDS = {
    "drive": ["drive", "file", "folder", "storage", "document"],
    "spreadsheets": ["sheet", "spreadsheet", "row", "column", "cell", "data", "csv"],
    "gmail.send": ["email", "mail", "send", "gmail", "message", "notify"],
    "calendar": ["calendar", "event", "schedule", "meeting", "appointment"],
}

KNOWN_API_CALLS = {
    "DriveApp.getFileById":           "drive.readonly",
    "DriveApp.createFile":            "drive.file",
    "SpreadsheetApp.openById":        "spreadsheets",
    "SpreadsheetApp.getActiveSpreadsheet": "spreadsheets",
    "GmailApp.sendEmail":             "gmail.send",
    "MailApp.sendEmail":              "gmail.send",
    "CalendarApp.createEvent":        "calendar",
    "AdminDirectory.Users.list":      "admin.directory.user.readonly",
}

# Expanded known calls
KNOWN_API_CALLS.update({
    "DriveApp.getFilesByName":        "drive.readonly",
    "DriveApp.getRootFolder":         "drive.readonly",
    "DriveApp.removeFile":            "drive",
    "SpreadsheetApp.getActiveSheet":  "spreadsheets",
    "SpreadsheetApp.getUi":           "spreadsheets",
    "GmailApp.sendDraft":             "gmail.send",
    "CalendarApp.getCalendarsByName": "calendar",
    "AdminDirectory.Users.get":       "admin.directory.user.readonly",
    "AdminDirectory.Users.update":    "admin.directory.user",
    "UrlFetchApp.fetch":              "script.external_request",
    "PropertiesService.getScriptProperties": "script.properties",
})


def _get_scope_descriptions() -> dict:
    csv_path = Path(__file__).resolve().parents[2] / "data" / "google_oauth_scopes.csv"
    descriptions = {}
    try:
        with open(csv_path, newline='', encoding='utf-8') as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                scope_url = row.get("scope", "").strip()
                suffix = scope_url.split("/")[-1]
                if suffix and suffix not in descriptions:
                    descriptions[suffix] = row.get("description", "")
    except Exception:
        pass
    return descriptions


def _extract_comments(code: str) -> str:
    comments = []
    comments += re.findall(r"//(.*)", code)
    comments += re.findall(r"/\*(.*?)\*/", code, re.DOTALL)
    return " ".join(comment.strip() for comment in comments).lower()


def _compute_keyword_similarity(comments: str, description: str) -> float:
    if not comments or not description:
        return 0.0
    comment_tokens = set(re.findall(r"\w+", comments))
    description_tokens = set(re.findall(r"\w+", description.lower()))
    if not description_tokens:
        return 0.0
    common = comment_tokens.intersection(description_tokens)
    return len(common) / len(description_tokens)


def _compute_semantic_similarity(comments: str, descriptions: list[str]) -> float:
    try:
        from sentence_transformers import SentenceTransformer
        from scipy.spatial.distance import cosine
    except ImportError:
        return 0.0

    if not comments or not descriptions:
        return 0.0

    model = SentenceTransformer("all-MiniLM-L6-v2")
    embeddings = model.encode([comments] + descriptions, normalize_embeddings=True)
    comment_vec = embeddings[0]
    max_similarity = 0.0
    for target_vec in embeddings[1:]:
        sim = 1.0 - cosine(comment_vec, target_vec)
        if not isinstance(sim, float):
            continue
        max_similarity = max(max_similarity, sim)
    return float(max_similarity)


def _detect_api_calls(code: str) -> list[dict]:
    # Primary: try tree-sitter-based detection
    calls = []
    ast_calls = _parse_calls_with_treesitter(code)
    if ast_calls is not None:
        return ast_calls

    # Fallback: simple line-based substring detection
    lines = code.splitlines()
    for index, line in enumerate(lines, start=1):
        for api_call, scope in KNOWN_API_CALLS.items():
            if api_call in line:
                calls.append({
                    "call_path": api_call,
                    "line_number": index,
                    "required_scope": scope,
                })
    return calls


def _parse_calls_with_treesitter(code: str) -> list[dict] | None:
    """
    Attempt to parse JavaScript/Apps Script code with tree-sitter and extract call expressions.
    Returns a list of call dicts or None if tree-sitter is unavailable or parsing fails.

    This function will try to load/compile the tree-sitter JavaScript grammar dynamically.
    Building the grammar requires a C compiler and `git` available; if build fails we return None
    so the caller can fall back to simpler detection.
    """
    try:
        from tree_sitter import Language, Parser
    except Exception:
        return None

    # location for the compiled language library
    build_dir = os.path.join(os.path.dirname(__file__), "..", "..", ".treesitter")
    os.makedirs(build_dir, exist_ok=True)
    so_path = os.path.join(build_dir, "javascript.so")

    # If shared lib does not exist, try to build it
    if not os.path.exists(so_path):
        try:
            import subprocess, tempfile, shutil

            tmp = tempfile.mkdtemp(prefix="ts_build_")
            repo_dir = os.path.join(tmp, "tree-sitter-javascript")
            git_cmd = ["git", "clone", "https://github.com/tree-sitter/tree-sitter-javascript", repo_dir]
            subprocess.run(git_cmd, check=True, timeout=60)

            Language.build_library(
                so_path,
                [repo_dir]
            )
            shutil.rmtree(tmp)
        except Exception:
            # Build failed — give up and fall back
            try:
                if os.path.exists(tmp):
                    shutil.rmtree(tmp)
            except Exception:
                pass
            return None

    # Try to load the compiled language
    try:
        JS_LANGUAGE = Language(so_path, "javascript")
        parser = Parser()
        parser.set_language(JS_LANGUAGE)
        tree = parser.parse(bytes(code, "utf8"))
        root = tree.root_node

        results = []

        # Walk the tree and find call_expression nodes
        def node_text(n):
            return code[n.start_byte:n.end_byte]

        cursor = root.walk()
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == "call_expression":
                # function being called can be member_expression or identifier
                fn = None
                for child in node.children:
                    if child.type in ("member_expression", "identifier", "scoped_identifier"):
                        fn = child
                        break

                if fn is not None:
                    # Build dotted call path
                    if fn.type == "identifier":
                        call_path = node_text(fn)
                    else:
                        # member_expression — walk to get object.property chain
                        parts = []
                        def collect_member(m):
                            if m.type == "identifier":
                                parts.append(node_text(m))
                            else:
                                for ch in m.children:
                                    if ch.type in ("identifier", "property_identifier"):
                                        parts.append(node_text(ch))
                                    elif ch.type == "member_expression":
                                        collect_member(ch)
                        collect_member(fn)
                        call_path = ".".join(parts)

                    # Map to scope if known
                    required_scope = KNOWN_API_CALLS.get(call_path)
                    # compute severity heuristic
                    severity = "MEDIUM"
                    if required_scope and ("manage" in required_scope or "insert" in required_scope or "create" in call_path):
                        severity = "HIGH"

                    results.append({
                        "call_path": call_path,
                        "line_number": node.start_point[0] + 1,
                        "required_scope": required_scope,
                        "severity": severity,
                    })

            # push children
            for c in reversed(node.children):
                stack.append(c)

        return results
    except Exception:
        return None


def inspect_file(gs_file_path: str, used_scopes: list[str]) -> dict:
    try:
        with open(gs_file_path, "r", encoding="utf-8") as f:
            code = f.read()
    except Exception:
        code = ""

    comments = _extract_comments(code)
    scope_descriptions = _get_scope_descriptions()
    descriptions = [scope_descriptions.get(scope, scope.replace('.', ' ')) for scope in used_scopes]

    similarity = _compute_semantic_similarity(comments, descriptions)
    if similarity == 0.0:
        keyword_scores = [_compute_keyword_similarity(comments, desc) for desc in descriptions]
        similarity = max(keyword_scores) if keyword_scores else 0.0

    if similarity >= 0.65:
        intent_flag = "MATCH"
    elif similarity >= 0.35:
        intent_flag = "SUSPICIOUS"
    else:
        intent_flag = "MISMATCH"

    ast_calls = []
    for call in _detect_api_calls(code):
        call_scope = call["required_scope"]
        ast_calls.append({
            "call_path": call["call_path"],
            "line_number": call["line_number"],
            "required_oauth_scope": call_scope,
            "severity": "HIGH" if "manage" in call_scope or "create" in call["call_path"] else "MEDIUM",
        })

    developer_intent = comments.strip() if comments.strip() else "No developer comments found"

    return {
        "file": gs_file_path,
        "ast_calls": ast_calls,
        "intent_similarity": float(round(similarity, 3)),
        "intent_flag": intent_flag,
        "developer_intent": developer_intent,
    }
