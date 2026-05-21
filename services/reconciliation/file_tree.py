# /services/reconciliation/file_tree.py
#
# TRD: Workspace File Tree
# - Reads requested scopes from appsscript.json  → S_requested
# - Detects used scopes from .gs code            → S_used
# - Computes:
#     unused_scopes  = S_requested - S_used   → OVERPRIVILEGED
#     missing_scopes = S_used - S_requested   → UNDERPRIVILEGED
# - Classification: PERFECT / OVERPRIVILEGED / UNDERPRIVILEGED / MISCONFIGURED
# - Loads severity from google_oauth_scopes.csv (O(1) dict lookup)

import os
import json
import re
import csv

API_SCOPE_MAP = {
    "DriveApp":             ["drive"],
    "Drive":                ["drive"],
    "SpreadsheetApp":       ["spreadsheets"],
    "Sheets":               ["spreadsheets"],
    "GmailApp":             ["gmail.send", "gmail.modify", "gmail.readonly"],
    "MailApp":              ["gmail.send"],
    "CalendarApp":          ["calendar"],
    "Calendar":             ["calendar"],
    "DocumentApp":          ["documents"],
    "FormApp":              ["forms.body"],
    "SlidesApp":            ["presentations"],
    "AdminDirectory":       ["admin.directory.user", "admin.directory.group"],
    "AdminReports":         ["admin.reports.audit.readonly"],
    "Analytics":            ["analytics.readonly"],
    "BigQuery":             ["bigquery"],
    "ContactsApp":          ["contacts"],
    "People":               ["contacts.readonly"],
    "Tasks":                ["tasks"],
    "UrlFetchApp":          ["script.external_request"],
    "PropertiesService":    [],
    "Utilities":            [],
    "Logger":               [],
    "console":              [],
}

METHOD_SCOPE_MAP = {
    "DriveApp.getFileById":           ["drive.readonly"],
    "DriveApp.createFile":            ["drive.file"],
    "DriveApp.getFolderById":         ["drive.readonly"],
    "SpreadsheetApp.openById":        ["spreadsheets"],
    "SpreadsheetApp.create":          ["spreadsheets"],
    "GmailApp.sendEmail":             ["gmail.send"],
    "GmailApp.getInboxThreads":       ["gmail.readonly"],
    "CalendarApp.createEvent":        ["calendar"],
    "CalendarApp.getEvents":          ["calendar.readonly"],
    "AdminDirectory.Users.list":      ["admin.directory.user.readonly"],
    "AdminDirectory.Users.insert":    ["admin.directory.user"],
}

# Expanded method-level mappings for broader coverage
METHOD_SCOPE_MAP.update({
    "DriveApp.getFilesByName":        ["drive.readonly"],
    "DriveApp.getRootFolder":         ["drive.readonly"],
    "DriveApp.removeFile":            ["drive"],
    "SpreadsheetApp.getActiveSpreadsheet": ["spreadsheets"],
    "SpreadsheetApp.getUi":           ["spreadsheets"],
    "SpreadsheetApp.getActiveSheet":  ["spreadsheets"],
    "GmailApp.sendDraft":             ["gmail.send"],
    "MailApp.sendEmail":              ["gmail.send"],
    "CalendarApp.getCalendarsByName": ["calendar"],
    "AdminDirectory.Users.get":       ["admin.directory.user.readonly"],
    "AdminDirectory.Users.update":    ["admin.directory.user"],
    "UrlFetchApp.fetch":              ["script.external_request"],
    "PropertiesService.getScriptProperties": ["script.properties"],
})
SCOPE_SEVERITY_MAP = {}


def load_scope_severity(csv_path: str) -> None:
    global SCOPE_SEVERITY_MAP
    if not os.path.exists(csv_path):
        return
    try:
        with open(csv_path, newline='', encoding='utf-8') as handle:
            reader = csv.DictReader(handle)
            seen = set()
            for row in reader:
                scope_url = row.get("scope", "").strip()
                if not scope_url or scope_url in seen:
                    continue
                suffix = scope_url.split("/")[-1]
                SCOPE_SEVERITY_MAP[suffix] = {
                    "full_url":    scope_url,
                    "description": row.get("description", ""),
                    "api_name":    row.get("api_name", ""),
                    "version":     row.get("version", ""),
                    "severity":    _derive_severity(row.get("description", ""))
                }
                seen.add(scope_url)
    except Exception:
        pass


def _derive_severity(description: str) -> str:
    desc = description.lower()
    if any(w in desc for w in ["delete", "manage", "edit", "configure", "admin", "insert"]):
        return "HIGH"
    if any(w in desc for w in ["see", "view", "read", "download"]):
        return "MEDIUM"
    return "LOW"


def get_scope_severity(scope_suffix: str) -> str:
    entry = SCOPE_SEVERITY_MAP.get(scope_suffix)
    if entry:
        return entry["severity"]
    if any(w in scope_suffix for w in ["readonly", "read"]):
        return "MEDIUM"
    return "HIGH"


def extract_requested_scopes(json_path: str) -> set:
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        scopes = manifest.get("oauthScopes", [])
        return set(scope.split("/")[-1] for scope in scopes if scope)
    except Exception:
        return set()


def extract_used_scopes_from_code(code: str) -> set:
    used = set()
    for method, scopes in METHOD_SCOPE_MAP.items():
        if method in code:
            used.update(scopes)
    for api_class, scopes in API_SCOPE_MAP.items():
        if re.search(r'\b' + re.escape(api_class) + r'\.', code):
            used.update(scopes)
    return used


def analyze_file(gs_file_path: str, requested_scopes: set) -> dict:
    try:
        with open(gs_file_path, "r", encoding="utf-8") as f:
            code = f.read()
    except Exception:
        code = ""

    used_scopes = extract_used_scopes_from_code(code)
    unused_scopes = requested_scopes - used_scopes
    missing_scopes = used_scopes - requested_scopes

    if unused_scopes and missing_scopes:
        status = "MISCONFIGURED"
    elif unused_scopes:
        status = "OVERPRIVILEGED"
    elif missing_scopes:
        status = "UNDERPRIVILEGED"
    else:
        status = "PERFECT"

    color_map = {
        "OVERPRIVILEGED":  "RED",
        "UNDERPRIVILEGED": "YELLOW",
        "PERFECT":         "GREEN",
        "MISCONFIGURED":   "RED",
        "UNKNOWN":         "GRAY",
    }

    def enrich(scopes):
        return [{"scope": scope, "severity": get_scope_severity(scope)} for scope in sorted(scopes)]

    def build_manifest_diff():
        diff = []
        for scope in sorted(unused_scopes):
            diff.append({"scope": scope, "type": "removed"})
        for scope in sorted(missing_scopes):
            diff.append({"scope": scope, "type": "added"})
        return diff

    return {
        "file":             gs_file_path,
        "requested_scopes": list(sorted(requested_scopes)),
        "used_scopes":      list(sorted(used_scopes)),
        "unused_scopes":    list(sorted(unused_scopes)),
        "missing_scopes":   list(sorted(missing_scopes)),
        "status":           status,
        "color":            color_map.get(status, "GRAY"),
        "scope_detail": {
            "requested": enrich(requested_scopes),
            "used":      enrich(used_scopes),
            "unused":    enrich(unused_scopes),
            "missing":   enrich(missing_scopes),
        },
        "manifest_diff":    build_manifest_diff(),
    }