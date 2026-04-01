"""Git branch / commit / draft PR execution for connector maintenance."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import urllib3

from gnat.agents.repo_maintenance.models import ExecutionResult, RepoMaintenancePlan, VerificationResult

_PROTECTED_BRANCHES = {"main", "master", "develop", "dev"}


class MaintenanceExecutor:
    """Perform guarded git and GitHub actions for a prepared maintenance plan."""

    def __init__(
        self,
        repo_root: str | Path = ".",
        github_token: str | None = None,
        upstream_repo: str | None = None,
        remote_name: str = "origin",
    ):
        self.repo_root = Path(repo_root)
        self.github_token = github_token
        self.upstream_repo = upstream_repo
        self.remote_name = remote_name
        self.http = urllib3.PoolManager()

    def execute(
        self,
        plan: RepoMaintenancePlan,
        verification: VerificationResult | None = None,
        push: bool = False,
        create_pr: bool = False,
        commit: bool = False,
    ) -> ExecutionResult:
        result = ExecutionResult(success=False, branch_name=plan.pull_request.branch_name)
        branch = plan.pull_request.branch_name
        if self._is_protected(branch):
            result.error = f"Refused to use protected branch name: {branch}"
            return result

        ok, err = self._git_create_branch(branch)
        if not ok:
            result.error = err
            return result
        result.steps_completed.append("branch")

        plan_path = self.repo_root / ".gnat" / "maintenance-plan.json"
        plan_path.parent.mkdir(parents=True, exist_ok=True)
        plan_path.write_text(json.dumps(_serialize_plan(plan, verification), indent=2), encoding="utf-8")
        result.steps_completed.append("plan")

        ok, err = self._git_stage([str(plan_path)])
        if not ok:
            result.error = err
            return result
        result.steps_completed.append("stage")

        if commit:
            ok, err = self._git_commit(plan.pull_request.title)
            if not ok:
                result.error = err
                return result
            sha, _ = self._git_head_sha()
            result.commit_sha = sha
            result.steps_completed.append("commit")

        if push:
            ok, err = self._git_push(branch)
            if not ok:
                result.error = err
                return result
            result.steps_completed.append("push")

        if create_pr:
            pr_url, err = self._create_github_pr(plan, verification)
            if not pr_url:
                result.error = err
                return result
            result.pr_url = pr_url
            result.steps_completed.append("pr")

        result.success = True
        return result

    def _git_create_branch(self, branch: str) -> tuple[bool, str]:
        proc = self._run(["git", "checkout", "-b", branch])
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()
        return True, ""

    def _git_stage(self, paths: list[str]) -> tuple[bool, str]:
        proc = self._run(["git", "add", *paths])
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()
        return True, ""

    def _git_commit(self, message: str) -> tuple[bool, str]:
        proc = self._run(["git", "commit", "-m", message])
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()
        return True, ""

    def _git_push(self, branch: str) -> tuple[bool, str]:
        proc = self._run(["git", "push", "-u", self.remote_name, branch])
        if proc.returncode != 0:
            return False, (proc.stderr or proc.stdout).strip()
        return True, ""

    def _git_head_sha(self) -> tuple[str | None, str]:
        proc = self._run(["git", "rev-parse", "HEAD"])
        if proc.returncode != 0:
            return None, (proc.stderr or proc.stdout).strip()
        return proc.stdout.strip(), ""

    def _create_github_pr(
        self,
        plan: RepoMaintenancePlan,
        verification: VerificationResult | None,
    ) -> tuple[str | None, str]:
        if not self.github_token:
            return None, "Missing GitHub token."
        if not self.upstream_repo or "/" not in self.upstream_repo:
            return None, "Missing upstream_repo in owner/repo form."

        owner, repo = self.upstream_repo.split("/", 1)
        head_owner = self._get_remote_owner(self.remote_name)
        api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        body = plan.pull_request.body
        if verification is not None:
            body += "\n\n### Verification\n"
            body += f"- Passed: `{verification.passed}`\n"
            for check in verification.checks:
                body += f"- {check.name}: {'pass' if check.passed else 'fail'}\n"

        payload = {
            "title": plan.pull_request.title,
            "body": body,
            "head": f"{head_owner}:{plan.pull_request.branch_name}",
            "base": "main",
            "draft": True,
        }
        response = self.http.request(
            "POST",
            api_url,
            body=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.github_token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        data = json.loads(response.data.decode("utf-8", errors="replace"))
        if response.status in {200, 201}:
            return data.get("html_url"), ""
        return None, f"GitHub API {response.status}: {data.get('message', 'unknown error')}"

    def _get_remote_owner(self, remote: str) -> str:
        proc = self._run(["git", "remote", "get-url", remote])
        if proc.returncode != 0:
            return "unknown"
        match = re.search(r"github\.com[/:]([^/]+)/", proc.stdout.strip())
        return match.group(1) if match else "unknown"

    def _is_protected(self, branch: str) -> bool:
        base = branch.split("/")[-1]
        return branch in _PROTECTED_BRANCHES or base in _PROTECTED_BRANCHES

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            cmd,
            cwd=self.repo_root,
            capture_output=True,
            text=True,
            check=False,
        )


def _serialize_plan(plan: RepoMaintenancePlan, verification: VerificationResult | None) -> dict:
    payload = {
        "connector": plan.connector,
        "impact": plan.impact.value,
        "confidence": plan.confidence,
        "pull_request": {
            "branch_name": plan.pull_request.branch_name,
            "title": plan.pull_request.title,
            "labels": plan.pull_request.labels,
            "draft": plan.pull_request.draft,
        },
        "files_to_touch": plan.files_to_touch,
    }
    if plan.repair is not None:
        payload["repair"] = {
            "actions": [action.__dict__ for action in plan.repair.actions],
            "notes": plan.repair.notes,
        }
    if verification is not None:
        payload["verification"] = {
            "passed": verification.passed,
            "summary": verification.summary,
            "checks": [check.__dict__ for check in verification.checks],
        }
    return payload
