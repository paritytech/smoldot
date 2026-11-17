#!/usr/bin/env bash
# Checks the prdoc of a PR without checking out the PR's code, then creates,
# updates or deletes the PR comment that explains how to fix a failure.
#
# Env: GH_TOKEN, REPO, PR_NUMBER, HEAD_REPO, HEAD_REF, HEAD_SHA, SKIP (true|false)
set -euo pipefail

MARKER='<!-- prdoc-check -->'
SCRIPTS="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPTS/../.." && pwd)"
PRDOC="prdoc/pr_$PR_NUMBER.prdoc"
WORK="$(mktemp -d)"

errors=()
missing=false

if [ "$SKIP" != "true" ]; then
    gh api --paginate "repos/$REPO/pulls/$PR_NUMBER/files" \
        --jq '.[] | select(.status != "removed") | "\(.status) \(.filename)"' > "$WORK/files"

    if grep -qx '[a-z]* wasm-node/CHANGELOG.md' "$WORK/files"; then
        errors+=("This PR edits \`wasm-node/CHANGELOG.md\`. Revert that change and put the entry in a prdoc file instead.")
    fi

    grep -E '^[a-z]+ prdoc/[^./][^/]*\.prdoc$' "$WORK/files" > "$WORK/prdocs" || true
    if ! grep -qE '^(added|renamed|copied) ' "$WORK/prdocs"; then
        missing=true
        errors+=("This PR adds no \`prdoc/<name>.prdoc\` file.")
    fi

    mkdir "$WORK/prdoc"
    while read -r _ file; do
        name="${file#prdoc/}"
        if [[ ! "$name" =~ ^[a-z0-9][a-z0-9._-]*\.prdoc$ ]]; then
            errors+=("\`$file\`: file name must match \`[a-z0-9][a-z0-9._-]*.prdoc\`.")
            continue
        fi
        gh api -H 'Accept: application/vnd.github.raw' \
            "repos/$HEAD_REPO/contents/$file?ref=$HEAD_SHA" > "$WORK/$file"
        if ! python3 "$SCRIPTS/prdoc.py" check "$WORK/$file" 2> "$WORK/check.err" > /dev/null; then
            errors+=("\`$file\` is invalid:"$'\n\n~~~~\n'"$(sed "s|$WORK/||" "$WORK/check.err" | tr -d '~')"$'\n~~~~')
        fi
    done < "$WORK/prdocs"
fi

existing="$(gh api --paginate "repos/$REPO/issues/$PR_NUMBER/comments" \
    --jq ".[] | select(.user.login == \"github-actions[bot]\" and (.body | startswith(\"$MARKER\"))) | .id" | head -n1)"

if [ ${#errors[@]} -eq 0 ]; then
    if [ -n "$existing" ]; then
        gh api -X DELETE "repos/$REPO/issues/comments/$existing" > /dev/null
    fi
    echo "prdoc check passed"
    exit 0
fi

{
    echo "$MARKER"
    echo "### Changelog entry needed"
    echo
    echo "Changes to \`wasm-node/CHANGELOG.md\` are written at release time from \`prdoc/<name>.prdoc\` files added by each PR, so that PRs don't conflict on it. See [\`prdoc/README.md\`](https://github.com/$REPO/blob/main/prdoc/README.md)."
    echo
    for e in "${errors[@]}"; do
        echo "- $e"
    done
    echo
    if [ "$missing" = true ]; then
        url="$(python3 - "$ROOT/prdoc/.template.prdoc" <<'EOF'
import os, sys, urllib.parse
template = "".join(l for l in open(sys.argv[1]) if not l.startswith("#"))
q = urllib.parse.urlencode({"filename": f"prdoc/pr_{os.environ['PR_NUMBER']}.prdoc", "value": template}, quote_via=urllib.parse.quote)
head_ref = urllib.parse.quote(os.environ["HEAD_REF"])
print(f"https://github.com/{os.environ['HEAD_REPO']}/new/{head_ref}?{q}")
EOF
)"
        echo "[Create \`$PRDOC\` from the template]($url), then edit the description. Any other name works too, for example the branch name."
        echo
    fi
    echo "If this PR has no user-visible change (refactor, tests, CI, docs), a maintainer can add the \`no-changelog\` label instead."
} > "$WORK/comment.md"

if [ -n "$existing" ]; then
    gh api -X PATCH "repos/$REPO/issues/comments/$existing" -F "body=@$WORK/comment.md" > /dev/null
else
    gh api -X POST "repos/$REPO/issues/$PR_NUMBER/comments" -F "body=@$WORK/comment.md" > /dev/null
fi

cat "$WORK/comment.md" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
for e in "${errors[@]}"; do
    echo "::error::${e%%$'\n'*}"
done
exit 1
