#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
EVIDENCE_KEYS = {
    "schema_version", "kind", "repository", "prior_release_sha",
    "target_release_sha", "source_tree_sha", "source_bundle_sha256",
    "ci_receipt_sha256", "review_receipt_sha256", "evidence_id", "published_at",
}
CI_KEYS = {
    "schema_version", "kind", "repository", "canonical_ref", "conclusion",
    "release_sha", "source_tree_sha", "source_bundle_sha256", "workflow_run_id",
    "workflow_run_attempt", "completed_at",
}
REVIEW_KEYS = {
    "schema_version", "kind", "decision", "reviewed_release_sha",
    "source_tree_sha", "review_id", "reviewed_at",
}


class CandidateError(RuntimeError):
    pass


def load_object(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise CandidateError(f"candidate file is not regular: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateError(f"invalid JSON: {path.name}") from error
    if not isinstance(value, dict):
        raise CandidateError(f"JSON must be an object: {path.name}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def exact(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise CandidateError(f"{label} fields are not exact")


def command(*argv: str, cwd: Path | None = None) -> str:
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


def verify_bundle(bundle: Path, target: str, tree: str, prior: str, canonical_ref: str) -> None:
    if bundle.is_symlink() or not bundle.is_file():
        raise CandidateError("source bundle is not regular")
    heads = command("git", "bundle", "list-heads", str(bundle))
    if heads.splitlines() != [f"{target} {canonical_ref}"]:
        raise CandidateError("source bundle does not expose only the exact canonical ref")
    with tempfile.TemporaryDirectory(prefix="foundation-candidate-") as temporary:
        repository = Path(temporary) / "source.git"
        command("git", "clone", "--quiet", "--bare", str(bundle), str(repository))
        if command("git", "rev-parse", f"{target}^{{commit}}", cwd=repository) != target:
            raise CandidateError("source bundle target commit changed")
        if command("git", "rev-parse", f"{target}^{{tree}}", cwd=repository) != tree:
            raise CandidateError("source bundle tree changed")
        command("git", "cat-file", "-e", f"{prior}^{{commit}}", cwd=repository)
        command("git", "merge-base", "--is-ancestor", prior, target, cwd=repository)


def verify(candidate: Path, observation_path: Path, policy_path: Path, signature: bool) -> None:
    if candidate.is_symlink() or not candidate.is_dir():
        raise CandidateError("candidate directory is invalid")
    observation = load_object(observation_path)
    policy = load_object(policy_path)
    evidence = load_object(candidate / "RELEASE_EVIDENCE.json")
    ci = load_object(candidate / "CI_RECEIPT.json")
    review = load_object(candidate / "REVIEW_RECEIPT.json")
    exact(evidence, EVIDENCE_KEYS, "release evidence")
    exact(ci, CI_KEYS, "CI receipt")
    exact(review, REVIEW_KEYS, "review receipt")

    repository = policy.get("repository")
    canonical_ref = policy.get("canonical_ref")
    target = observation.get("target_release_sha")
    prior = observation.get("prior_release_sha")
    tree = observation.get("source_tree_sha")
    if (
        policy.get("schema_version") != 1
        or repository != "code-CogLearn/coglearn-platform"
        or canonical_ref != "refs/heads/main"
        or not isinstance(target, str) or not SHA_RE.fullmatch(target)
        or not isinstance(prior, str) or not SHA_RE.fullmatch(prior)
        or not isinstance(tree, str) or not SHA_RE.fullmatch(tree)
        or target == prior
    ):
        raise CandidateError("candidate authority identity is invalid")

    observed_ci = observation.get("ci")
    observed_review = observation.get("final_review")
    if not isinstance(observed_ci, dict) or not isinstance(observed_review, dict):
        raise CandidateError("observed checks are missing")
    if (
        observed_ci.get("name") != policy.get("ci", {}).get("check_name")
        or observed_ci.get("app_slug") != policy.get("ci", {}).get("app_slug")
        or observed_ci.get("workflow_path") != policy.get("ci", {}).get("workflow_path")
        or observed_ci.get("conclusion") != "success"
        or observed_review.get("name") != policy.get("final_review", {}).get("check_name")
        or observed_review.get("app_slug") != policy.get("final_review", {}).get("app_slug")
        or observed_review.get("conclusion") != "success"
    ):
        raise CandidateError("required GitHub checks are not exact PASS observations")

    bundle = candidate / "SOURCE.bundle"
    if bundle.is_symlink() or not bundle.is_file():
        raise CandidateError("source bundle is not regular")
    bundle_hash = sha256(bundle)
    if (
        evidence.get("schema_version") != 1
        or evidence.get("kind") != "AIEDU_FOUNDATION_TARGET_EVIDENCE"
        or evidence.get("repository") != repository
        or evidence.get("prior_release_sha") != prior
        or evidence.get("target_release_sha") != target
        or evidence.get("source_tree_sha") != tree
        or evidence.get("source_bundle_sha256") != bundle_hash
        or evidence.get("ci_receipt_sha256") != sha256(candidate / "CI_RECEIPT.json")
        or evidence.get("review_receipt_sha256") != sha256(candidate / "REVIEW_RECEIPT.json")
        or not isinstance(evidence.get("evidence_id"), str) or not evidence["evidence_id"]
        or not isinstance(evidence.get("published_at"), str) or not evidence["published_at"]
    ):
        raise CandidateError("release evidence does not bind exact candidate bytes")
    for field in ("source_bundle_sha256", "ci_receipt_sha256", "review_receipt_sha256"):
        if not HASH_RE.fullmatch(str(evidence.get(field, ""))):
            raise CandidateError(f"release evidence {field} is invalid")

    if (
        ci.get("schema_version") != 1
        or ci.get("kind") != "AIEDU_FOUNDATION_RELEASE_CI"
        or ci.get("repository") != repository
        or ci.get("canonical_ref") != canonical_ref
        or ci.get("conclusion") != "PASS"
        or ci.get("release_sha") != target
        or ci.get("source_tree_sha") != tree
        or ci.get("source_bundle_sha256") != bundle_hash
        or ci.get("workflow_run_id") != observed_ci.get("workflow_run_id")
        or type(ci.get("workflow_run_attempt")) is not int
        or ci.get("workflow_run_attempt") != observed_ci.get("workflow_run_attempt")
        or ci.get("completed_at") != observed_ci.get("completed_at")
    ):
        raise CandidateError("CI receipt is not exact PASS")
    if (
        review.get("schema_version") != 1
        or review.get("kind") != "AIEDU_FOUNDATION_RELEASE_REVIEW"
        or review.get("decision") != "PASS"
        or review.get("reviewed_release_sha") != target
        or review.get("source_tree_sha") != tree
        or review.get("review_id") != f"check-run:{observed_review.get('check_run_id')}"
        or review.get("reviewed_at") != observed_review.get("completed_at")
    ):
        raise CandidateError("review receipt is not exact PASS")

    verify_bundle(bundle, target, tree, prior, canonical_ref)
    signature_path = candidate / "RELEASE_EVIDENCE.sig"
    if signature and (
        signature_path.is_symlink()
        or not signature_path.is_file()
        or signature_path.stat().st_size == 0
    ):
        raise CandidateError("release evidence signature is missing")
    if signature:
        namespace = policy.get("signature", {}).get("namespace")
        if namespace != "aiedu-foundation-target":
            raise CandidateError("signature namespace policy is invalid")
        checked = subprocess.run(
            [
                "ssh-keygen", "-Y", "check-novalidate", "-n", namespace,
                "-s", str(signature_path),
            ],
            input=(candidate / "RELEASE_EVIDENCE.json").read_bytes(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if checked.returncode != 0:
            raise CandidateError("release evidence signature is malformed")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a foundation candidate bundle")
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--observation", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--require-signature", action="store_true")
    args = parser.parse_args()
    try:
        verify(
            args.candidate.absolute(), args.observation.absolute(), args.policy.absolute(),
            args.require_signature,
        )
    except CandidateError as error:
        parser.exit(1, f"candidate verification failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
