#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
OBSERVATION_KEYS = {
    "schema_version", "kind", "repository", "canonical_ref",
    "prior_release_sha", "target_release_sha", "source_tree_sha", "ci",
    "final_review", "observed_at",
}
CI_OBSERVATION_KEYS = {
    "name", "app_slug", "check_run_id", "conclusion", "completed_at",
    "workflow_run_id", "workflow_run_attempt", "workflow_path",
}
REVIEW_OBSERVATION_KEYS = {
    "name", "app_slug", "check_run_id", "conclusion", "completed_at",
}


class CandidateError(RuntimeError):
    pass


def run(*argv: str, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise CandidateError(f"command failed: {' '.join(argv)}")
    return completed.stdout.strip()


def load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CandidateError(f"JSON is not a regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateError(f"invalid JSON: {path}") from error
    if not isinstance(value, dict):
        raise CandidateError(f"JSON must be an object: {path}")
    return value


def write_object(path: Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="ascii",
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_observation(value: dict[str, Any]) -> None:
    if set(value) != OBSERVATION_KEYS:
        raise CandidateError("observation fields are not exact")
    if (
        value.get("schema_version") != 1
        or value.get("kind") != "AIEDU_FOUNDATION_GITHUB_OBSERVATION"
        or value.get("repository") != "code-CogLearn/coglearn-platform"
        or value.get("canonical_ref") != "refs/heads/main"
    ):
        raise CandidateError("observation authority is invalid")
    for field in ("prior_release_sha", "target_release_sha", "source_tree_sha"):
        if not isinstance(value.get(field), str) or not SHA_RE.fullmatch(value[field]):
            raise CandidateError(f"observation {field} is invalid")
    if value["prior_release_sha"] == value["target_release_sha"]:
        raise CandidateError("candidate does not supersede its predecessor")
    for field in ("ci", "final_review"):
        check = value.get(field)
        if not isinstance(check, dict) or check.get("conclusion") != "success":
            raise CandidateError(f"{field} did not pass")
        if not all(
            isinstance(check.get(key), str) and check[key]
            for key in ("name", "app_slug", "check_run_id", "completed_at")
        ):
            raise CandidateError(f"{field} identity is invalid")
    if set(value["ci"]) != CI_OBSERVATION_KEYS:
        raise CandidateError("CI observation fields are not exact")
    if set(value["final_review"]) != REVIEW_OBSERVATION_KEYS:
        raise CandidateError("final review observation fields are not exact")
    if (
        not isinstance(value["ci"].get("workflow_run_id"), str)
        or not value["ci"]["workflow_run_id"].isdigit()
        or type(value["ci"].get("workflow_run_attempt")) is not int
        or value["ci"]["workflow_run_attempt"] < 1
        or not isinstance(value["ci"].get("workflow_path"), str)
        or not value["ci"]["workflow_path"]
    ):
        raise CandidateError("CI workflow observation is invalid")


def build(source: Path, observation_path: Path, output: Path, evidence_id: str) -> None:
    observation = load_object(observation_path)
    require_observation(observation)
    if not evidence_id:
        raise CandidateError("evidence ID is required")
    if output.exists():
        raise CandidateError("candidate output already exists")
    if source.is_symlink() or not source.is_dir():
        raise CandidateError("source checkout is invalid")

    target = observation["target_release_sha"]
    prior = observation["prior_release_sha"]
    tree = observation["source_tree_sha"]
    if run("git", "rev-parse", "HEAD", cwd=source) != target:
        raise CandidateError("source HEAD is not the observed target")
    if run("git", "rev-parse", "HEAD^{tree}", cwd=source) != tree:
        raise CandidateError("source tree is not the observed tree")
    if run("git", "status", "--porcelain=v1", cwd=source):
        raise CandidateError("source checkout is dirty")
    run("git", "cat-file", "-e", f"{prior}^{{commit}}", cwd=source)
    run("git", "merge-base", "--is-ancestor", prior, target, cwd=source)
    run("git", "update-ref", "refs/heads/main", target, cwd=source)

    output.mkdir(mode=0o700)
    bundle = output / "SOURCE.bundle"
    run("git", "bundle", "create", str(bundle.resolve()), "refs/heads/main", cwd=source)
    bundle_hash = sha256(bundle)
    published_at = datetime.now(timezone.utc).isoformat()

    ci = observation["ci"]
    ci_receipt = {
        "schema_version": 1,
        "kind": "AIEDU_FOUNDATION_RELEASE_CI",
        "repository": observation["repository"],
        "canonical_ref": observation["canonical_ref"],
        "conclusion": "PASS",
        "release_sha": target,
        "source_tree_sha": tree,
        "source_bundle_sha256": bundle_hash,
        "workflow_run_id": ci["workflow_run_id"],
        "workflow_run_attempt": ci["workflow_run_attempt"],
        "completed_at": ci["completed_at"],
    }
    ci_path = output / "CI_RECEIPT.json"
    write_object(ci_path, ci_receipt)

    review = observation["final_review"]
    review_receipt = {
        "schema_version": 1,
        "kind": "AIEDU_FOUNDATION_RELEASE_REVIEW",
        "decision": "PASS",
        "reviewed_release_sha": target,
        "source_tree_sha": tree,
        "review_id": f"check-run:{review['check_run_id']}",
        "reviewed_at": review["completed_at"],
    }
    review_path = output / "REVIEW_RECEIPT.json"
    write_object(review_path, review_receipt)

    evidence = {
        "schema_version": 1,
        "kind": "AIEDU_FOUNDATION_TARGET_EVIDENCE",
        "repository": observation["repository"],
        "prior_release_sha": prior,
        "target_release_sha": target,
        "source_tree_sha": tree,
        "source_bundle_sha256": bundle_hash,
        "ci_receipt_sha256": sha256(ci_path),
        "review_receipt_sha256": sha256(review_path),
        "evidence_id": evidence_id,
        "published_at": published_at,
    }
    write_object(output / "RELEASE_EVIDENCE.json", evidence)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an unsigned foundation candidate")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--observation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--evidence-id", required=True)
    args = parser.parse_args()
    try:
        build(
            args.source.absolute(), args.observation.absolute(), args.output.absolute(),
            args.evidence_id,
        )
    except CandidateError as error:
        parser.exit(1, f"candidate build failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
