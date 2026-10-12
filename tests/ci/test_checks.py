"""Proves the CI checks pass on good personas and fail on each violation.

Each case builds a personas/<org>/<team>/ tree in a temp dir and runs the real tools
against it (check-jsonschema for the schema, checks.py for the rest), so what is tested
is what CI runs.
"""
import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
CHECKS = REPO / ".github" / "ci" / "checks.py"

VALID = """\
org: infosec
team: isre
entitlement:
  gcp:
    grants:
      - permission_set:
          name: Readonly-test
          builtin_roles: [roles/viewer]
          custom_role:
            stage: GA
            permissions_file: permission.json
        assign_by:
          projects: [infosec-automation-dev]
"""

AWS = """\
org: infosec
team: isre
entitlement:
  aws:
    grants:
      - permission_set:
          name: Aws-test
{body}
        assign_by:
          accounts: ["111111111111"]
"""


@pytest.fixture
def repo(tmp_path):
    """A throwaway repo root with the real schema and limits, and one valid persona."""
    shutil.copytree(REPO / "schema", tmp_path / "schema")
    shutil.copytree(REPO / "policies", tmp_path / "policies")
    persona(tmp_path)
    return tmp_path


def persona(root, text=VALID, perms=None, org="infosec", team="isre"):
    folder = root / "personas" / org / team
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "config.yaml").write_text(text)
    if perms is not False:
        (folder / "permission.json").write_text(json.dumps(perms or {"permissions": ["compute.instances.get"]}))


def checks(repo, mode):
    return subprocess.run([sys.executable, str(CHECKS), mode], cwd=repo, capture_output=True, text=True)


def schema(repo, meta=False):
    args = ["--check-metaschema", "schema/persona.schema.json"] if meta else [
        "--schemafile", "schema/persona.schema.json", *map(str, repo.glob("personas/*/*/config.yaml"))
    ]
    return subprocess.run([sys.executable, "-m", "check_jsonschema", *args], cwd=repo, capture_output=True, text=True)


def passes_everything(repo):
    return all(r.returncode == 0 for r in (schema(repo), schema(repo, meta=True), checks(repo, "structure"), checks(repo, "policy")))


# ── schema (check-jsonschema) ────────────────────────────────────────────────

def test_valid_persona_passes_everything(repo):
    assert passes_everything(repo)


def test_real_personas_pass_everything():
    configs = [c for c in REPO.glob("personas/*/*/config.yaml") if not c.parts[-3].startswith("_")]
    assert configs, "expected at least one real persona"
    assert schema(REPO).returncode == 0
    assert checks(REPO, "structure").returncode == 0
    assert checks(REPO, "policy").returncode == 0


@pytest.mark.parametrize("mutate,needle", [
    (lambda t: t.replace("org: infosec\n", ""), "org"),
    (lambda t: t.replace("org: infosec", "org: Info-Sec"), "Info-Sec"),
    (lambda t: t.replace("builtin_roles: [roles/viewer]", "builtin_roles: [viewer]"), "viewer"),
    (lambda t: t.replace("infosec-automation-dev", "BAD"), "BAD"),
    (lambda t: t.replace("stage: GA", "stage: NOPE"), "NOPE"),
    (lambda t: t + "surprise: true\n", "surprise"),
    (lambda t: "", ""),
])
def test_schema_violations_fail(repo, mutate, needle):
    persona(repo, mutate(VALID))
    result = schema(repo)
    assert result.returncode != 0
    assert needle in result.stdout + result.stderr


def test_broken_schema_fails_metacheck(repo):
    (repo / "schema" / "persona.schema.json").write_text('{"type": 12}')
    assert schema(repo, meta=True).returncode != 0


# ── structure ────────────────────────────────────────────────────────────────

def test_org_team_must_match_folder(repo):
    shutil.rmtree(repo / "personas")
    persona(repo, VALID, team="other")  # file says team: isre
    r = checks(repo, "structure")
    assert r.returncode == 1 and "path-match" in r.stdout


def test_missing_permissions_file_fails(repo):
    persona(repo, VALID, perms=False)
    (repo / "personas/infosec/isre/permission.json").unlink(missing_ok=True)
    r = checks(repo, "structure")
    assert r.returncode == 1 and "not found" in r.stdout


@pytest.mark.parametrize("content", [{"permissions": []}, {"nope": 1}, ["a"], {"permissions": [1]}])
def test_bad_permissions_content_fails(repo, content):
    (repo / "personas/infosec/isre/permission.json").write_text(json.dumps(content))
    assert checks(repo, "structure").returncode == 1


# ── policy ───────────────────────────────────────────────────────────────────

def test_wildcard_in_permissions_file_fails(repo):
    persona(repo, VALID, perms={"permissions": ["compute.*"]})
    r = checks(repo, "policy")
    assert r.returncode == 1 and "no-wildcards" in r.stdout


def test_wildcard_in_builtin_role_fails(repo):
    persona(repo, VALID.replace("roles/viewer", "roles/*"))
    r = checks(repo, "policy")
    assert r.returncode == 1 and "no-wildcards" in r.stdout


def test_wildcard_in_inline_policy_fails(repo):
    body = textwrap.indent(textwrap.dedent("""\
        inline_policy:
          Statement:
            - Effect: Allow
              Action: ["s3:*"]
              Resource: "*"
        """), " " * 10)
    persona(repo, AWS.format(body=body.rstrip("\n")))
    r = checks(repo, "policy")
    assert r.returncode == 1 and r.stdout.count("no-wildcards") >= 2


@pytest.mark.parametrize("approver", ["alice@rubrik.com", "user:alice@rubrik.com"])
def test_user_approver_fails(repo, approver):
    persona(repo, VALID + f'access:\n  self_service: true\n  approval: ["{approver}"]\n')
    r = checks(repo, "policy")
    assert r.returncode == 1 and "no-users" in r.stdout


def test_group_approver_passes(repo):
    persona(repo, VALID + 'access:\n  self_service: true\n  approval: ["group:secarch@rubrik.com", "SECARCH-APPROVERS"]\n')
    assert checks(repo, "policy").returncode == 0


@pytest.mark.parametrize("count,ok", [(10, True), (11, False)])
def test_project_cap(repo, count, ok):
    projects = ", ".join(f"proj-number-{i:02d}" for i in range(count))
    persona(repo, VALID.replace("[infosec-automation-dev]", f"[{projects}]"))
    r = checks(repo, "policy")
    assert (r.returncode == 0) is ok
    assert ok or "capped-lists" in r.stdout


def test_missing_shared_ref_fails(repo):
    persona(repo, AWS.format(body='          shared_managed_policies: ["ghost-policy"]'))
    r = checks(repo, "policy")
    assert r.returncode == 1 and "refs-exist" in r.stdout


def test_existing_shared_ref_passes(repo):
    shared = repo / "personas" / "_shared" / "aws"
    shared.mkdir(parents=True)
    (shared / "real-policy.json").write_text("{}")
    persona(repo, AWS.format(body='          shared_managed_policies: ["real-policy"]'))
    assert checks(repo, "policy").returncode == 0


def test_shared_ref_cannot_escape(repo):
    persona(repo, AWS.format(body='          shared_managed_policies: ["../../infosec/isre/permission"]'))
    assert checks(repo, "policy").returncode == 1


# ── PR comment (node) ────────────────────────────────────────────────────────

NODE = shutil.which("node")


def render(results, plan="", url="https://example/run/1"):
    # Input goes over stdin: a single argv entry is capped (~128 KB on Linux), and the
    # truncation test feeds a plan far larger than that.
    script = "const {build}=require(process.argv[1]);" \
             "const input=JSON.parse(require('fs').readFileSync(0,'utf8'));" \
             "process.stdout.write(build({results:input.results,planText:input.plan,runUrl:input.url}))"
    out = subprocess.run([NODE, "-e", script, str(REPO / ".github/ci/comment.js")],
                         input=json.dumps({"results": results, "plan": plan, "url": url}),
                         check=True, capture_output=True, text=True)
    return out.stdout


OK = dict(schema="success", policy="success", terraform="success", plan="success")


@pytest.mark.skipif(not NODE, reason="node not installed")
class TestComment:
    def test_marker_summary_and_pass(self):
        body = render(OK, "+ resource x\n\nPlan: 1 to add, 0 to change, 0 to destroy.")
        assert body.startswith("<!-- rbac-pr-validation -->")
        assert "Plan: 1 to add" in body and "All checks passed" in body

    def test_blocking_failure_is_called_out(self):
        body = render({**OK, "schema": "failure", "plan": "skipped"})
        assert "Blocked" in body and "schema" in body and "Plan preview" not in body

    def test_failed_plan_is_expanded(self):
        body = render({**OK, "plan": "failure"}, "Error: boom")
        assert "<details open>" in body and "Error: boom" in body and "plan failed" in body

    def test_huge_plan_is_truncated_under_github_limit(self):
        body = render(OK, "x\n" * 200_000)
        assert len(body) < 65_536 and "truncated" in body and "https://example/run/1" in body

    def test_backticks_in_plan_cannot_break_the_fence(self):
        assert "````hcl" in render(OK, "before\n```\ninside\n```\nafter")
