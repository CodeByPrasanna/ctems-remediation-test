# /services/reconciliation/scanner.py
#
# TRD: Repository Scanner
# - Accepts .zip file stream or GitHub URL
# - Extracts into secure quarantined temp directory
# - Prevents ZIP Slip / path traversal attacks
# - Only keeps .gs and appsscript.json files
# - Returns scan_id, valid files, and quarantined files

import os
import zipfile
import tempfile
import requests

ALLOWED_EXTENSIONS = {".gs"}
ALLOWED_FILENAMES = {"appsscript.json"}
BLOCKED_EXTENSIONS = {".py", ".exe", ".sh", ".env", ".bat", ".cmd", ".php", ".rb"}


# ─────────────────────────────────────────────
# Clerk JWT Validation Placeholder
# Replace with real Clerk SDK verification when available
# ─────────────────────────────────────────────
def validate_clerk_jwt(token: str) -> dict:
    """
    Placeholder for Clerk JWT validation.
    In production: verify token using Clerk's JWKS endpoint.
    Returns decoded payload or raises ValueError.
    """
    if not token:
        raise ValueError("No JWT token provided")
    return {"user_id": "placeholder", "verified": False}


# ─────────────────────────────────────────────
# ZIP Slip / Hidden File Prevention
# ─────────────────────────────────────────────
def _is_safe_path(base_dir: str, target_path: str) -> bool:
    base_dir = os.path.realpath(base_dir)
    target_path = os.path.realpath(target_path)
    return target_path.startswith(base_dir + os.sep) or target_path == base_dir


def _is_unsafe_member(member_name: str) -> bool:
    normalized = member_name.replace('\\', '/').lstrip('/')
    if normalized.startswith('__macosx') or normalized.startswith('._'):
        return True
    path_parts = normalized.split('/')
    if any(part.startswith('.') for part in path_parts):
        return True
    if '..' in path_parts:
        return True
    return False


def _normalize_github_url(github_url: str) -> tuple[str, str]:
    if github_url.startswith('git@github.com:'):
        github_url = github_url.replace('git@github.com:', 'https://github.com/')
    github_url = github_url.rstrip('/')
    if not github_url.startswith('https://github.com/'):
        raise ValueError('Unsupported GitHub URL. Use https://github.com/owner/repo')
    parts = github_url.replace('https://github.com/', '').split('/')
    if len(parts) < 2:
        raise ValueError('Invalid GitHub URL format. Expected https://github.com/owner/repo')
    return parts[0], parts[1]


# ─────────────────────────────────────────────
# Core ZIP Scanner
# ─────────────────────────────────────────────
def scan_zip(file_stream) -> dict:
    temp_dir = tempfile.mkdtemp(prefix="ctems_scan_")
    valid_files = []
    quarantined_files = []

    with zipfile.ZipFile(file_stream, 'r') as zf:
        for member in zf.infolist():
            member_name = member.filename

            if member_name.endswith('/'):
                continue

            if _is_unsafe_member(member_name):
                quarantined_files.append({"file": member_name, "reason": "hidden_or_unsafe_path"})
                continue

            extract_path = os.path.join(temp_dir, member_name)
            if not _is_safe_path(temp_dir, extract_path):
                quarantined_files.append({"file": member_name, "reason": "path_traversal"})
                continue

            basename = os.path.basename(member_name)
            _, ext = os.path.splitext(basename)
            ext_lower = ext.lower()

            if ext_lower in BLOCKED_EXTENSIONS:
                quarantined_files.append({"file": member_name, "reason": "blocked_extension"})
                continue

            is_manifest = basename == 'appsscript.json'
            is_script = ext_lower in ALLOWED_EXTENSIONS

            if is_manifest or is_script:
                os.makedirs(os.path.dirname(extract_path), exist_ok=True)
                with zf.open(member) as src, open(extract_path, 'wb') as dst:
                    dst.write(src.read())
                valid_files.append(extract_path)
            else:
                quarantined_files.append({"file": member_name, "reason": "unsupported_type"})

    return {
        "temp_dir": temp_dir,
        "files": valid_files,
        "quarantined": quarantined_files,
        "total_valid": len(valid_files),
        "total_quarantined": len(quarantined_files),
    }


# ─────────────────────────────────────────────
# GitHub ZIP Scanner
# ─────────────────────────────────────────────
def scan_github_url(github_url: str) -> dict:
    owner, repo = _normalize_github_url(github_url)
    api_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
    response = requests.get(api_url, timeout=30, stream=True)

    if response.status_code != 200:
        raise RuntimeError(f"GitHub API returned {response.status_code} for {api_url}")

    with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_file:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                tmp_file.write(chunk)
        temp_zip_path = tmp_file.name

    try:
        with open(temp_zip_path, 'rb') as f:
            return scan_zip(f)
    finally:
        try:
            os.unlink(temp_zip_path)
        except Exception:
            pass
