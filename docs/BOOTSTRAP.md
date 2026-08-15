# Signing authority bootstrap

This repository is complete only through `TRUST_ROOT_COMMIT`: versioned policy,
validation mechanics, and a protected workflow exist. No keypair was generated,
no secret was configured or inspected, no public trust root was installed, and
no release was signed or delivered.

## 1. Protect `main`

Create the organization team `code-CogLearn/foundation-release-owners` with the
smallest practical membership and grant it maintain access to this repository.
Apply `policy/main-branch-protection.json` to `main` through the GitHub branch
protection endpoint
`PUT /repos/code-CogLearn/foundation-release-signer/branches/main/protection`
only after reviewing the payload. This commit does not call that endpoint. The
policy requires:

- pull requests and two approvals;
- stale-review dismissal, last-push approval, and CODEOWNER approval;
- `Authority policy / policy` against the current head;
- resolved conversations and linear history;
- enforcement for administrators, with force-push and deletion disabled.

Do not weaken the policy merely to bootstrap. If two independent approvers are
not available, the authority remains unactivated.

## 2. Source observation GitHub App

Create a dedicated GitHub App for this authority. Install it only on the private
repository `code-CogLearn/coglearn-platform`. Its repository permissions are:

| Permission | Level | Purpose |
| --- | --- | --- |
| Metadata | Read | Required GitHub App repository metadata access |
| Actions | Read | Bind CI check to its exact workflow path, run, and attempt |
| Contents | Read | Resolve canonical ref/commit/tree and clone exact Git objects |
| Checks | Read | Read exact target-bound CI and final-review check runs |

Grant no Administration, Deployments, Environments, Issues, Pull requests,
Secrets, Statuses, or Workflows permission. The App cannot dispatch
the authority workflow, mutate either repository, publish checks, merge, or
read secrets.

The source repository must publish these exact target-bound checks before it
sends a wakeup:

| Check | Publisher App |
| --- | --- |
| `Foundation Release CI` | `github-actions` |
| `Foundation Final Review` | `coglearn-foundation-review` |

The CI check must represent the approved release suite, not the current
placeholder lint job. The final-review publisher is independent of mutable V5
runtime and emits success only for literal final-review `PASS`. Any name, App,
SHA, state, or conclusion mismatch fails closed. Changes to these names require
an authority pull request updating `policy/source-attestations.json`.

## 3. Protected Environment

Create the Environment `foundation-release` in this repository with:

- at least two required reviewers and self-review prevention;
- deployment branches restricted to protected `main` only;
- administrator bypass disabled;
- no custom deployment rule controlled by `coglearn-platform` or mutable V5;
- these Environment secrets, and no repository-level copies:

| Environment secret name | Runtime use |
| --- | --- |
| `FOUNDATION_SOURCE_APP_ID` | Mint the read-only source installation token |
| `FOUNDATION_SOURCE_APP_PRIVATE_KEY` | Authenticate that dedicated App |
| `FOUNDATION_RELEASE_SSH_PRIVATE_KEY` | Load one ephemeral signing agent after validation |

The workflow references only these names. The source token is scoped to the one
repository and revoked by the token action after the job. The release private
key is step-scoped, piped directly to a fresh `ssh-agent`, unset immediately,
and never written to a file or uploaded. The derived temporary public line is
removed before artifact publication.

Creating the App credential, creating or importing the Foundation signing key,
and entering secret values are later human bootstrap actions. They are not
performed or evidenced by this commit.

## 4. Trigger and trust-root boundary

The only signing trigger is `repository_dispatch` type
`foundation-release-candidate` delivered to this independent authority
repository. The wakeup body contains only untrusted `target_release_sha` and
`prior_release_sha` hints. There is no `workflow_call`, source-repository push,
schedule, or V5 signing entrypoint.

Environment reviewers must inspect the requested pair before approval. The job
then independently reconstructs the facts described in
`contracts/CANDIDATE_BUNDLE.md`. A successful future run publishes a private
one-day artifact but does not deliver it to a host or activate it.

The following remain explicitly beyond `TRUST_ROOT_COMMIT` and require a
separate approved task: creating/importing the private signing identity,
installing reviewed public allowed-signers content in the immutable target
producer, configuring any secret value, triggering a signing run, delivering a
candidate, or activating/rolling back a release.
