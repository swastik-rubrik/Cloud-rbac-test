#!/usr/bin/env python3
"""Persona checks that JSON Schema cannot express. Run from the repo root.

  checks.py structure   folder/file hygiene
      path-match        org/team in the file match personas/<org>/<team>/
      permissions-file  custom_role.permissions_file exists, stays in the persona
                        folder, and holds a non-empty "permissions" array of strings
  checks.py policy      least-privilege guardrails (policies/README.md)
      no-users          access.approval entries are groups, never individuals
      no-wildcards      no '*' in roles, policies or custom-role permissions
      capped-lists      assign_by/assign_at lists stay within policies/limits.yaml
      refs-exist        shared_managed_policies resolve under personas/_shared/<cloud>/

Both modes check every personas/<org>/<team>/config.yaml. Malformed shapes are skipped:
reporting them is check-jsonschema's job. Exit 1 on any finding.
"""
import json
import re
import sys
from pathlib import Path

import yaml

PERSONAS = Path("personas")
LIMITS = Path("policies/limits.yaml")
USER_PRINCIPAL = re.compile(r"^user:|^[^@\s:]+@[^@\s]+$", re.IGNORECASE)


def strings(node, path=""):
    """Yield (path, value) for every string in a nested structure."""
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from strings(v, f"{path}[{i}]")


def grants(persona):
    """Yield (where, grant) for every well-formed grant, any cloud."""
    for cloud, block in (persona.get("entitlement") or {}).items():
        for i, grant in enumerate((block or {}).get("grants") or []):
            if isinstance(grant, dict):
                yield f"entitlement.{cloud}.grants[{i}]", cloud, grant


def permissions_path(config, grant):
    custom = (grant.get("permission_set") or {}).get("custom_role")
    name = custom.get("permissions_file") if isinstance(custom, dict) else None
    return config.parent / name if isinstance(name, str) and name else None


def structure(config, persona):
    org, team = config.parts[-3], config.parts[-2]
    for key, want in (("org", org), ("team", team)):
        if key in persona and persona[key] != want:
            yield config, "path-match", f"{key} is '{persona[key]}' but the folder says '{want}'"

    for where, _, grant in grants(persona):
        path = permissions_path(config, grant)
        if path is None:
            continue
        if not path.resolve().is_relative_to(config.parent.resolve()):
            yield config, "permissions-file", f"{where}: '{path.name}' escapes the persona folder"
        elif not path.is_file():
            yield config, "permissions-file", f"{where}: {path} not found"
        else:
            try:
                perms = json.loads(path.read_text()).get("permissions")
            except (json.JSONDecodeError, AttributeError):
                perms = None
            if not (isinstance(perms, list) and perms and all(isinstance(p, str) and p for p in perms)):
                yield path, "permissions-file", '"permissions" must be a non-empty array of strings'


def policy(config, persona):
    limits = yaml.safe_load(LIMITS.read_text())["max_scope_entries"]
    shared = next(p for p in (config, *config.parents) if p.name == "personas") / "_shared"

    approvals = (persona.get("access") or {}).get("approval")
    for path, value in strings(approvals, "access.approval"):
        if USER_PRINCIPAL.search(value):
            yield config, "no-users", f"{path}: '{value}' looks like an individual. Use a group."

    for where, cloud, grant in grants(persona):
        pset = grant.get("permission_set") or {}
        for path, value in strings({k: v for k, v in pset.items() if k != "custom_role"}, f"{where}.permission_set"):
            if "*" in value:
                yield config, "no-wildcards", f"{path}: '{value}' contains a wildcard. Name each role/action."

        perms = permissions_path(config, grant)
        if perms and perms.is_file():
            try:
                for path, value in strings(json.loads(perms.read_text())):
                    if "*" in value:
                        yield perms, "no-wildcards", f"{path}: '{value}' contains a wildcard. List every permission."
            except json.JSONDecodeError:
                pass

        for scope in ("assign_by", "assign_at"):
            for key, values in (grant.get(scope) or {}).items():
                if isinstance(values, list) and key in limits and len(values) > limits[key]:
                    yield config, "capped-lists", f"{where}.{scope}.{key} has {len(values)} entries; limit is {limits[key]} (policies/limits.yaml)."

        for ref in pset.get("shared_managed_policies") or []:
            base = shared / cloud
            ok = isinstance(ref, str) and ".." not in Path(ref).parts and not ref.startswith("/") and any(
                (base / f"{ref}{ext}").is_file() for ext in (".json", ".yaml", ".yml")
            )
            if not ok:
                yield config, "refs-exist", f"{where}: shared_managed_policies '{ref}' not found under {base}/"


def main():
    modes = {"structure": structure, "policy": policy}
    if len(sys.argv) != 2 or sys.argv[1] not in modes:
        sys.exit(__doc__)
    check = modes[sys.argv[1]]

    configs = sorted(p for p in PERSONAS.glob("*/*/config.yaml") if not p.parts[1].startswith("_"))
    findings = []
    for config in configs:
        try:
            persona = yaml.safe_load(config.read_text())
        except yaml.YAMLError:
            continue  # check-jsonschema reports unparseable files
        if isinstance(persona, dict):
            findings += check(config, persona)

    for file, rule, message in findings:
        print(f"::error file={file},title={rule}::{message}")
    summary = f"{len(findings)} finding(s)" if findings else "no findings"
    print(f"{sys.argv[1]}: {len(configs)} persona(s) checked, {summary}")
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
