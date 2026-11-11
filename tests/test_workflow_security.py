from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = ROOT / ".github" / "workflows"

PINNED_ACTIONS = {
    "actions/checkout": (
        "11d5960a326750d5838078e36cf38b85af677262",
        "v4.4.0",
    ),
    "actions/setup-python": (
        "a26af69be951a213d495a4c3e4e4022e16d87065",
        "v5.6.0",
    ),
    "actions/upload-artifact": (
        "ea165f8d65b6e75b540449e92b4886f43607fa02",
        "v4.6.2",
    ),
}

ACTION_LINE = re.compile(
    r"^\s*(?:-\s+)?uses:\s+(?P<action>[^@\s]+)@(?P<ref>[^\s#]+)"
    r"(?:\s+#\s*(?P<comment>\S+))?\s*$",
    re.MULTILINE,
)


def _load_workflow(name: str) -> dict:
    with (WORKFLOW_DIR / name).open(encoding="utf-8") as workflow_file:
        return yaml.safe_load(workflow_file)


def test_all_remote_actions_use_verified_commit_pins() -> None:
    observed_actions = set()
    for workflow_path in WORKFLOW_DIR.glob("*.yml"):
        text = workflow_path.read_text(encoding="utf-8")
        matches = list(ACTION_LINE.finditer(text))
        for match in matches:
            action = match.group("action")
            if action.startswith("./") or action.startswith("docker://"):
                continue

            observed_actions.add(action)
            assert action in PINNED_ACTIONS, (
                f"{workflow_path.name}: verify and allow-list remote action {action}"
            )
            expected_ref, expected_version = PINNED_ACTIONS[action]
            assert match.group("ref") == expected_ref, (
                f"{workflow_path.name}: {action} must use the verified commit pin"
            )
            assert match.group("comment") == expected_version, (
                f"{workflow_path.name}: keep the human-readable release beside the SHA"
            )
    assert observed_actions == PINNED_ACTIONS.keys()


def test_checkout_never_persists_workflow_credentials() -> None:
    for workflow_name in ("ci.yml", "deploy-pages.yml"):
        workflow = _load_workflow(workflow_name)
        for job_name, job in workflow["jobs"].items():
            for step in job.get("steps", []):
                if not step.get("uses", "").startswith("actions/checkout@"):
                    continue
                assert step.get("with", {}).get("persist-credentials") is False, (
                    f"{workflow_name}:{job_name} checkout must not retain GITHUB_TOKEN"
                )


def test_ci_has_read_only_repository_permissions() -> None:
    workflow = _load_workflow("ci.yml")
    assert workflow.get("permissions") == {"contents": "read"}
    for job_name, job in workflow["jobs"].items():
        assert job.get("permissions", {}).get("contents") != "write", (
            f"ci.yml:{job_name} must not receive repository write permission"
        )


def test_pages_write_permission_is_scoped_to_publish_job() -> None:
    workflow = _load_workflow("deploy-pages.yml")
    assert workflow.get("permissions") == {}
    for job_name, job in workflow["jobs"].items():
        expected = {"contents": "write"} if job_name == "publish" else None
        assert job.get("permissions") == expected
