#!/bin/bash

LABEL="area/ci"


# Get the current branch name
BRANCH=$(git rev-parse --abbrev-ref HEAD)

# Get the PR number corresponding to the current branch
PR_NUMBER=$(gh pr list --head "$BRANCH" --json number --jq '.[0].number')

if [ -n "$PR_NUMBER" ]; then
        echo "Adding label '$LABEL' to PR #$PR_NUMBER"
        gh pr edit "$PR_NUMBER" --add-label "$LABEL"
else
        echo "No PR found for branch: $BRANCH"
fi

