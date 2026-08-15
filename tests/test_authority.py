from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(*argv: str, cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=cwd,
        text=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


class AuthorityPolicyTests(unittest.TestCase):
    def test_signer_is_dispatch_only_and_environment_gated(self) -> None:
        workflow = (ROOT / ".github/workflows/sign-release.yml").read_text(encoding="ascii")
        self.assertIn("repository_dispatch:", workflow)
        self.assertIn("types: [foundation-release-candidate]", workflow)
        for forbidden in ("workflow_call:", "schedule:", "pull_request:", "push:"):
            self.assertNotIn(forbidden, workflow)
        self.assertIn("environment: foundation-release", workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("permission-contents: read", workflow)
        self.assertIn("permission-checks: read", workflow)
        self.assertIn("permission-actions: read", workflow)
        self.assertNotIn("permission-contents: write", workflow)
        self.assertNotIn("permission-checks: write", workflow)
        self.assertIn("secrets.FOUNDATION_SOURCE_APP_ID", workflow)
        self.assertIn("secrets.FOUNDATION_SOURCE_APP_PRIVATE_KEY", workflow)
        self.assertEqual(workflow.count("secrets.FOUNDATION_RELEASE_SSH_PRIVATE_KEY"), 1)
        self.assertEqual(workflow.count("scripts/collect-source-observation.sh"), 3)
        self.assertIn("candidate-observation-after-sign.json", workflow)
        self.assertIn("ssh-add -", workflow)
        self.assertNotIn("aiedu_v5", workflow)

    def test_main_policy_requires_codeowners_and_checks(self) -> None:
        protection = json.loads(
            (ROOT / "policy/main-branch-protection.json").read_text(encoding="ascii")
        )
        reviews = protection["required_pull_request_reviews"]
        self.assertTrue(protection["enforce_admins"])
        self.assertTrue(protection["required_status_checks"]["strict"])
        self.assertEqual(
            protection["required_status_checks"]["contexts"],
            ["Authority policy / policy"],
        )
        self.assertTrue(reviews["require_code_owner_reviews"])
        self.assertTrue(reviews["dismiss_stale_reviews"])
        self.assertTrue(reviews["require_last_push_approval"])
        self.assertGreaterEqual(reviews["required_approving_review_count"], 2)
        self.assertFalse(protection["allow_force_pushes"])
        self.assertFalse(protection["allow_deletions"])
        codeowners = (ROOT / ".github/CODEOWNERS").read_text(encoding="ascii")
        self.assertIn("* @code-CogLearn/foundation-release-owners", codeowners)

    def test_repository_contains_no_embedded_key_or_trust_root(self) -> None:
        excluded = {".git"}
        content = []
        for path in ROOT.rglob("*"):
            if (
                not path.is_file()
                or any(part in excluded or part == "__pycache__" for part in path.parts)
            ):
                continue
            content.append(path.read_text(encoding="utf-8", errors="replace"))
        repository_text = "\n".join(content)
        marker_parts = (
            ("BEGIN", "OPENSSH PRIVATE KEY"),
            ("BEGIN", "PRIVATE KEY"),
            ("BEGIN", "PUBLIC KEY"),
            ("ssh-ed25519", "AAAA"),
            ("ssh-rsa", "AAAA"),
        )
        for marker in (" ".join(parts) for parts in marker_parts):
            self.assertNotIn(marker, repository_text)
        self.assertFalse((ROOT / "TRUSTED_SIGNERS").exists())


class CandidateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="foundation-authority-")
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        run("git", "init", "-q", str(self.source))
        run("git", "symbolic-ref", "HEAD", "refs/heads/main", cwd=self.source)
        run("git", "config", "user.name", "Authority Test", cwd=self.source)
        run("git", "config", "user.email", "authority@test.invalid", cwd=self.source)
        (self.source / "prior.txt").write_text("prior\n", encoding="ascii")
        run("git", "add", "prior.txt", cwd=self.source)
        run("git", "commit", "-q", "-m", "prior", cwd=self.source)
        self.prior = run("git", "rev-parse", "HEAD", cwd=self.source).stdout.strip()
        (self.source / "target.txt").write_text("target\n", encoding="ascii")
        run("git", "add", "target.txt", cwd=self.source)
        run("git", "commit", "-q", "-m", "target", cwd=self.source)
        self.target = run("git", "rev-parse", "HEAD", cwd=self.source).stdout.strip()
        self.tree = run("git", "rev-parse", "HEAD^{tree}", cwd=self.source).stdout.strip()
        self.observation = self.root / "observation.json"
        self.observation.write_text(json.dumps({
            "schema_version": 1,
            "kind": "AIEDU_FOUNDATION_GITHUB_OBSERVATION",
            "repository": "code-CogLearn/coglearn-platform",
            "canonical_ref": "refs/heads/main",
            "prior_release_sha": self.prior,
            "target_release_sha": self.target,
            "source_tree_sha": self.tree,
            "ci": {
                "name": "Foundation Release CI",
                "app_slug": "github-actions",
                "check_run_id": "101",
                "conclusion": "success",
                "completed_at": "2026-08-15T08:00:00Z",
                "workflow_run_id": "201",
                "workflow_run_attempt": 2,
                "workflow_path": ".github/workflows/foundation-release-ci.yml",
            },
            "final_review": {
                "name": "Foundation Final Review",
                "app_slug": "coglearn-foundation-review",
                "check_run_id": "102",
                "conclusion": "success",
                "completed_at": "2026-08-15T08:01:00Z",
            },
            "observed_at": "2026-08-15T08:02:00Z",
        }, sort_keys=True), encoding="ascii")
        self.candidate = self.root / "candidate"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self) -> subprocess.CompletedProcess[str]:
        return run(
            "python3", str(ROOT / "scripts/build_candidate.py"),
            "--source", str(self.source),
            "--observation", str(self.observation),
            "--output", str(self.candidate),
            "--evidence-id", "authority-run:test:1",
        )

    def verify(self, *extra: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return run(
            "python3", str(ROOT / "scripts/verify_candidate.py"),
            "--candidate", str(self.candidate),
            "--observation", str(self.observation),
            "--policy", str(ROOT / "policy/source-attestations.json"),
            *extra,
            check=check,
        )

    def test_real_bundle_binds_target_tree_receipts_and_predecessor(self) -> None:
        self.build()
        self.verify()
        evidence = json.loads(
            (self.candidate / "RELEASE_EVIDENCE.json").read_text(encoding="ascii")
        )
        self.assertEqual(evidence["target_release_sha"], self.target)
        self.assertEqual(evidence["prior_release_sha"], self.prior)
        self.assertEqual(evidence["source_tree_sha"], self.tree)
        heads = run(
            "git", "bundle", "list-heads", str(self.candidate / "SOURCE.bundle")
        ).stdout.strip()
        self.assertEqual(heads, f"{self.target} refs/heads/main")

    def test_changed_pass_receipt_fails_closed(self) -> None:
        self.build()
        receipt_path = self.candidate / "REVIEW_RECEIPT.json"
        receipt = json.loads(receipt_path.read_text(encoding="ascii"))
        receipt["decision"] = "CHANGES_REQUIRED"
        receipt_path.write_text(json.dumps(receipt), encoding="ascii")
        result = self.verify(check=False)
        self.assertNotEqual(result.returncode, 0)

    def test_signature_is_required_only_at_final_boundary(self) -> None:
        self.build()
        self.verify()
        result = self.verify("--require-signature", check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature is missing", result.stderr)

    def test_read_only_github_observation_joins_exact_api_facts(self) -> None:
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        fake_curl = fake_bin / "curl"
        fake_curl.write_text("""#!/usr/bin/env python3
import json
import os
import sys
from urllib.parse import unquote

url = unquote(sys.argv[-1])
target = os.environ["FAKE_TARGET"]
prior = os.environ["FAKE_PRIOR"]
tree = os.environ["FAKE_TREE"]
if url.endswith("/git/ref/heads/main"):
    value = {"object": {"type": "commit", "sha": target}}
elif url.endswith("/git/commits/" + target):
    value = {"sha": target, "tree": {"sha": tree}}
elif url.endswith("/git/commits/" + prior):
    value = {"sha": prior, "tree": {"sha": "3" * 40}}
elif "/compare/" in url:
    value = {
        "status": "ahead", "ahead_by": 1, "behind_by": 0,
        "base_commit": {"sha": prior}, "merge_base_commit": {"sha": prior},
        "head_commit": {"sha": target},
    }
elif "check-runs?check_name=Foundation Release CI" in url:
    value = {"check_runs": [{
        "id": 101, "name": "Foundation Release CI", "head_sha": target,
        "status": "completed", "conclusion": "success",
        "completed_at": "2026-08-15T08:00:00Z",
        "details_url": (
            "https://github.com/code-CogLearn/coglearn-platform/actions/runs/201/job/301"
        ),
        "app": {"slug": "github-actions"},
    }]}
elif "check-runs?check_name=Foundation Final Review" in url:
    value = {"check_runs": [{
        "id": 102, "name": "Foundation Final Review", "head_sha": target,
        "status": "completed", "conclusion": "success",
        "completed_at": "2026-08-15T08:01:00Z", "details_url": "https://invalid",
        "app": {"slug": "coglearn-foundation-review"},
    }]}
elif url.endswith("/actions/runs/201"):
    value = {
        "id": 201, "head_sha": target, "head_branch": "main", "event": "push",
        "status": "completed", "conclusion": "success", "run_attempt": 2,
        "path": ".github/workflows/foundation-release-ci.yml",
    }
else:
    raise SystemExit("unexpected API URL: " + url)
json.dump(value, sys.stdout)
""", encoding="ascii")
        fake_curl.chmod(0o755)
        output = self.root / "collected.json"
        environment = os.environ.copy()
        environment.update({
            "PATH": f"{fake_bin}:{environment['PATH']}",
            "SOURCE_GITHUB_TOKEN": "fixture-only",
            "WAKEUP_TARGET_SHA": self.target,
            "WAKEUP_PREDECESSOR_SHA": self.prior,
            "FAKE_TARGET": self.target,
            "FAKE_PRIOR": self.prior,
            "FAKE_TREE": self.tree,
        })
        subprocess.run([
            str(ROOT / "scripts/collect-source-observation.sh"),
            str(ROOT / "policy/source-attestations.json"), str(output),
        ], env=environment, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        collected = json.loads(output.read_text(encoding="ascii"))
        self.assertEqual(collected["target_release_sha"], self.target)
        self.assertEqual(collected["prior_release_sha"], self.prior)
        self.assertEqual(collected["source_tree_sha"], self.tree)
        self.assertEqual(collected["ci"]["workflow_run_id"], "201")
        self.assertEqual(collected["ci"]["workflow_run_attempt"], 2)
        self.assertEqual(collected["final_review"]["check_run_id"], "102")


if __name__ == "__main__":
    unittest.main()
