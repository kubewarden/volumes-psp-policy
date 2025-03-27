#!/bin/bash

PROJECT_ID=6
COLUMN_NAME="Pending review"
OWNER="kubewarden"  # Change this to your GitHub username or organization if needed



# Get the current branch name
BRANCH=$(git rev-parse --abbrev-ref HEAD)

# Get the PR URL corresponding to the current branch
PR_URL=$(gh pr list --head "$BRANCH" --json url --jq '.[0].url')

if [ -n "$PR_URL" ]; then
    echo "Assigning PR $PR_URL to project $PROJECT_ID in column '$COLUMN_NAME'"
    gh project item-add "$PROJECT_ID" --owner "$OWNER" --url "$PR_URL"
else
    echo "No PR found for branch: $BRANCH"
fi

