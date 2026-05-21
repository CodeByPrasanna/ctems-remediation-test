import json
import os

from services.reconciliation.file_tree import (
    analyze_file,
    extract_requested_scopes
)

# Sample project folder
PROJECT_DIR = "sample_project"

# Path of manifest file
MANIFEST_PATH = os.path.join(
    PROJECT_DIR,
    "appsscript.json"
)


def generate_minimum_scopes():

    # Read scopes currently requested
    requested_scopes = extract_requested_scopes(
        MANIFEST_PATH
    )

    gs_file = None

    # Find first .gs file
    for file in os.listdir(PROJECT_DIR):

        if file.endswith(".gs"):

            gs_file = os.path.join(
                PROJECT_DIR,
                file
            )

            break

    if gs_file is None:

        raise Exception(
            "No .gs file found"
        )

    # Call Paresh's analyzer
    result = analyze_file(
        gs_file,
        requested_scopes
    )

    used = result[
        "used_scopes"
    ]

    missing = result[
        "missing_scopes"
    ]

    # Least privilege scopes
    s_min = list(
        set(
            used + missing
        )
    )

    return result, s_min


def update_manifest():

    analysis, s_min = generate_minimum_scopes()

    with open(
        MANIFEST_PATH,
        "r"
    ) as f:

        manifest = json.load(f)

    old_scopes = manifest[
        "oauthScopes"
    ]

    # Replace old scopes
    manifest[
        "oauthScopes"
    ] = s_min

    with open(
        MANIFEST_PATH,
        "w"
    ) as f:

        json.dump(
            manifest,
            f,
            indent=4
        )

    # Generate diff
    removed = list(
        set(old_scopes)
        -
        set(s_min)
    )

    added = list(
        set(s_min)
        -
        set(old_scopes)
    )

    return (
        old_scopes,
        s_min,
        analysis,
        removed,
        added
    )


old, new, report, removed, added = update_manifest()


print("\n========== OLD SCOPES ==========")
print(old)

print("\n========== NEW SCOPES ==========")
print(new)

print("\n========== STATUS ==========")
print(
    report["status"]
)

print("\n========== UNUSED SCOPES ==========")
print(
    report["unused_scopes"]
)

print("\n========== REMOVED ==========")
print(
    removed
)

print("\n========== ADDED ==========")
print(
    added
)
