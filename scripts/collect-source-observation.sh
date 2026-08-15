#!/usr/bin/env bash
set -euo pipefail

policy_path="${1:?policy path is required}"
output_path="${2:?output path is required}"
: "${SOURCE_GITHUB_TOKEN:?SOURCE_GITHUB_TOKEN is required}"
: "${WAKEUP_TARGET_SHA:?WAKEUP_TARGET_SHA is required}"
: "${WAKEUP_PREDECESSOR_SHA:?WAKEUP_PREDECESSOR_SHA is required}"

sha_pattern='^[0-9a-f]{40}$'
[[ "$WAKEUP_TARGET_SHA" =~ $sha_pattern ]]
[[ "$WAKEUP_PREDECESSOR_SHA" =~ $sha_pattern ]]
[[ "$WAKEUP_TARGET_SHA" != "$WAKEUP_PREDECESSOR_SHA" ]]

jq -e '
  type == "object" and
  .schema_version == 1 and
  (.repository | type == "string") and
  (.canonical_ref | type == "string") and
  (.ci.check_name | type == "string") and
  (.ci.app_slug | type == "string") and
  (.ci.workflow_path | type == "string") and
  (.final_review.check_name | type == "string") and
  (.final_review.app_slug | type == "string")
' "$policy_path" >/dev/null

repository="$(jq -r '.repository' "$policy_path")"
canonical_ref="$(jq -r '.canonical_ref' "$policy_path")"
ci_name="$(jq -r '.ci.check_name' "$policy_path")"
ci_app="$(jq -r '.ci.app_slug' "$policy_path")"
ci_workflow="$(jq -r '.ci.workflow_path' "$policy_path")"
review_name="$(jq -r '.final_review.check_name' "$policy_path")"
review_app="$(jq -r '.final_review.app_slug' "$policy_path")"
[[ "$repository" == "code-CogLearn/coglearn-platform" ]]
[[ "$canonical_ref" == "refs/heads/main" ]]

api() {
  local endpoint="$1"
  curl --silent --show-error --fail-with-body \
    --header 'Accept: application/vnd.github+json' \
    --header "Authorization: Bearer $SOURCE_GITHUB_TOKEN" \
    --header 'X-GitHub-Api-Version: 2022-11-28' \
    "https://api.github.com$endpoint"
}

ref_json="$(api "/repos/$repository/git/ref/heads/main")"
[[ "$(jq -er '.object.type' <<<"$ref_json")" == "commit" ]]
observed_target="$(jq -er '.object.sha' <<<"$ref_json")"
[[ "$observed_target" == "$WAKEUP_TARGET_SHA" ]]

commit_json="$(api "/repos/$repository/git/commits/$WAKEUP_TARGET_SHA")"
[[ "$(jq -er '.sha' <<<"$commit_json")" == "$WAKEUP_TARGET_SHA" ]]
tree_sha="$(jq -er '.tree.sha' <<<"$commit_json")"
[[ "$tree_sha" =~ $sha_pattern ]]

predecessor_json="$(api "/repos/$repository/git/commits/$WAKEUP_PREDECESSOR_SHA")"
[[ "$(jq -er '.sha' <<<"$predecessor_json")" == "$WAKEUP_PREDECESSOR_SHA" ]]

compare_json="$(api "/repos/$repository/compare/$WAKEUP_PREDECESSOR_SHA...$WAKEUP_TARGET_SHA")"
jq -e \
  --arg prior "$WAKEUP_PREDECESSOR_SHA" \
  --arg target "$WAKEUP_TARGET_SHA" '
    .status == "ahead" and
    .ahead_by >= 1 and
    .behind_by == 0 and
    .base_commit.sha == $prior and
    .merge_base_commit.sha == $prior and
    .head_commit.sha == $target
  ' <<<"$compare_json" >/dev/null

read_check() {
  local check_name="$1"
  local app_slug="$2"
  local encoded_name response count
  encoded_name="$(jq -nr --arg value "$check_name" '$value | @uri')"
  response="$(api "/repos/$repository/commits/$WAKEUP_TARGET_SHA/check-runs?check_name=$encoded_name&filter=latest&per_page=100")"
  count="$(jq \
    --arg name "$check_name" \
    --arg app "$app_slug" '
      [.check_runs[] | select(.name == $name and .app.slug == $app)] | length
    ' <<<"$response")"
  [[ "$count" -eq 1 ]]
  jq -ce \
    --arg name "$check_name" \
    --arg app "$app_slug" \
    --arg target "$WAKEUP_TARGET_SHA" '
      [.check_runs[] | select(.name == $name and .app.slug == $app)][0]
      | select(
          .head_sha == $target and
          .status == "completed" and
          .conclusion == "success" and
          (.id | type == "number") and
          (.completed_at | type == "string") and
          (.completed_at | length > 0)
        )
      | {
          name: .name,
          app_slug: .app.slug,
          check_run_id: (.id | tostring),
          conclusion: .conclusion,
          completed_at: .completed_at,
          details_url: .details_url
        }
    ' <<<"$response"
}

ci_check_json="$(read_check "$ci_name" "$ci_app")"
review_json="$(read_check "$review_name" "$review_app" | jq -c 'del(.details_url)')"
ci_details="$(jq -er '.details_url' <<<"$ci_check_json")"
ci_run_id="$(sed -nE \
  's#^https://github.com/code-CogLearn/coglearn-platform/actions/runs/([0-9]+)(/job/[0-9]+)?$#\1#p' \
  <<<"$ci_details")"
[[ "$ci_run_id" =~ ^[0-9]+$ ]]
ci_run_json="$(api "/repos/$repository/actions/runs/$ci_run_id")"
jq -e \
  --arg target "$WAKEUP_TARGET_SHA" \
  --arg workflow "$ci_workflow" \
  --arg run_id "$ci_run_id" '
    (.id | tostring) == $run_id and
    .head_sha == $target and
    .head_branch == "main" and
    .event == "push" and
    .status == "completed" and
    .conclusion == "success" and
    .path == $workflow and
    (.run_attempt | type == "number") and
    .run_attempt >= 1
  ' <<<"$ci_run_json" >/dev/null
ci_json="$(jq -c \
  --arg workflow_run_id "$ci_run_id" \
  --arg workflow_path "$ci_workflow" \
  --argjson workflow_run_attempt "$(jq '.run_attempt' <<<"$ci_run_json")" '
    del(.details_url) + {
      workflow_run_id: $workflow_run_id,
      workflow_run_attempt: $workflow_run_attempt,
      workflow_path: $workflow_path
    }
  ' <<<"$ci_check_json")"
observed_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

jq -nS \
  --arg repository "$repository" \
  --arg canonical_ref "$canonical_ref" \
  --arg target "$WAKEUP_TARGET_SHA" \
  --arg tree "$tree_sha" \
  --arg prior "$WAKEUP_PREDECESSOR_SHA" \
  --arg observed_at "$observed_at" \
  --argjson ci "$ci_json" \
  --argjson final_review "$review_json" '
    {
      schema_version: 1,
      kind: "AIEDU_FOUNDATION_GITHUB_OBSERVATION",
      repository: $repository,
      canonical_ref: $canonical_ref,
      prior_release_sha: $prior,
      target_release_sha: $target,
      source_tree_sha: $tree,
      ci: $ci,
      final_review: $final_review,
      observed_at: $observed_at
    }
  ' >"$output_path"
