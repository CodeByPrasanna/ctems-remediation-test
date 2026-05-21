import base64

from github import Github

from core.config import (
    GITHUB_TOKEN
)

USERNAME = "CodeByPrasanna"

REPO_NAME = "ctems-remediation-test"

BRANCH_NAME = "remediation-fix"

FILE_PATH = "sample_project/appsscript.json"


def create_pull_request():

    g = Github(
        GITHUB_TOKEN
    )

    repo = g.get_repo(
        f"{USERNAME}/{REPO_NAME}"
    )

    # get remediation branch
    branch = repo.get_branch(
        BRANCH_NAME
    )

    # Read local updated manifest
    with open(
        FILE_PATH,
        "r"
    ) as f:

        content = f.read()

    # Push updated file
    repo.update_file(

        path=FILE_PATH,

        message=
        "Automatic least privilege remediation",

        content=content,

        sha=repo.get_contents(
            FILE_PATH,
            ref=BRANCH_NAME
        ).sha,

        branch=BRANCH_NAME
    )

    # Create PR
    pr = repo.create_pull(

        title=
        "Security Remediation: Least Privilege Fix",

        body=
        """
Removed unnecessary permissions

Applied least privilege remediation

Generated automatically by C-TEMS
        """,

        head=BRANCH_NAME,

        base="main"
    )

    print()

    print(
        "PR Created:"
    )

    print(
        pr.html_url
    )


if __name__=="__main__":

    create_pull_request()