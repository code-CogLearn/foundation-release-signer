# Foundation release candidate bundle contract

Version 1 is a private directory artifact named
`foundation-release-candidate-<target SHA>`. It is transport, not authority.
The signature over `RELEASE_EVIDENCE.json` is the only signing-authority
statement.

## Required files

The directory contains exactly these consumer files:

```text
SOURCE.bundle
CI_RECEIPT.json
REVIEW_RECEIPT.json
RELEASE_EVIDENCE.json
RELEASE_EVIDENCE.sig
```

All JSON is ASCII. SHA values are lowercase, full 40-hex Git object IDs and
SHA-256 values are lowercase 64-hex strings. JSON objects reject missing or
additional fields. `SOURCE.bundle` is a self-contained Git bundle exposing
exactly `refs/heads/main` at `target_release_sha`; the target tree must equal
`source_tree_sha`, and `prior_release_sha` must be a distinct strict ancestor.

### `CI_RECEIPT.json`

```json
{
  "schema_version": 1,
  "kind": "AIEDU_FOUNDATION_RELEASE_CI",
  "repository": "code-CogLearn/coglearn-platform",
  "canonical_ref": "refs/heads/main",
  "conclusion": "PASS",
  "release_sha": "<target SHA>",
  "source_tree_sha": "<target tree SHA>",
  "source_bundle_sha256": "<SOURCE.bundle SHA-256>",
  "workflow_run_id": "<GitHub Actions run ID>",
  "workflow_run_attempt": 1,
  "completed_at": "<GitHub check completion time>"
}
```

The authority obtains both workflow fields from the GitHub Actions API and
requires the configured workflow path, push event, `main` branch, exact head
SHA, completed state, and successful conclusion. The separately observed check
run must bind to that Actions run.

### `REVIEW_RECEIPT.json`

```json
{
  "schema_version": 1,
  "kind": "AIEDU_FOUNDATION_RELEASE_REVIEW",
  "decision": "PASS",
  "reviewed_release_sha": "<target SHA>",
  "source_tree_sha": "<target tree SHA>",
  "review_id": "check-run:<GitHub check run ID>",
  "reviewed_at": "<GitHub check completion time>"
}
```

### `RELEASE_EVIDENCE.json`

```json
{
  "schema_version": 1,
  "kind": "AIEDU_FOUNDATION_TARGET_EVIDENCE",
  "repository": "code-CogLearn/coglearn-platform",
  "prior_release_sha": "<predecessor SHA>",
  "target_release_sha": "<target SHA>",
  "source_tree_sha": "<target tree SHA>",
  "source_bundle_sha256": "<SOURCE.bundle SHA-256>",
  "ci_receipt_sha256": "<CI_RECEIPT.json SHA-256>",
  "review_receipt_sha256": "<REVIEW_RECEIPT.json SHA-256>",
  "evidence_id": "authority-run:<run ID>:<run attempt>",
  "published_at": "<UTC authority time>"
}
```

`RELEASE_EVIDENCE.sig` is an OpenSSH `sshsig` signature of the exact evidence
bytes, namespace `aiedu-foundation-target`. No public key or allowed-signers
content is part of this repository at `TRUST_ROOT_COMMIT`.

## Wakeup and independent observations

`repository_dispatch` payload fields `target_release_sha` and
`prior_release_sha` are untrusted hints. The authority workflow independently
requires all of the following through its read-only GitHub App installation:

- `refs/heads/main` equals the target hint exactly;
- GitHub's Git database reports the same target tree;
- GitHub compare reports the predecessor as a strict ancestor with no reverse
  divergence;
- the exact CI check name and App in `policy/source-attestations.json` completed
  successfully on the target;
- the exact independent final-review check name and App completed successfully
  on the same target.

It then checks out that exact object, creates the bundle itself, and rechecks
the commit, tree, bundle ref, hashes, receipts, and predecessor ancestry before
the signing-key step. The complete GitHub observation is repeated immediately
before and after signing; any canonical-ref, check, workflow-run, tree, or
predecessor drift prevents artifact publication. The existing foundation target
producer must separately require its actual current release to equal
`prior_release_sha`; strict ancestry alone never authorizes host activation.

## Delivery pointer

The portable artifact deliberately omits the host-local `CANDIDATE.json` because
its paths cannot be valid on a GitHub runner and a target host simultaneously.
An independently approved later delivery step may place the five files in the
producer's private `candidates/<target SHA>/` directory and atomically create
the existing version-1 pointer with absolute evidence/signature paths and their
SHA-256 values. This repository neither performs that delivery nor activates a
release.
