---
name: codespace-feedback-collaboration
description: Enforce MCP-based cross-code-space collaboration. Use when work spans apps/packages, when a needed change is outside your code space, when resolving agent identity for MCP operations, when running startup or liveness queue checks, and when routing, reviewing, or updating cross-team issues.
---

# Codespace Feedback Collaboration

Apply this workflow whenever work crosses code-space boundaries.

## MCP Tools

### Issue Tools

- `issues.create` - Create a new issue
- `issues.list` - List issues with filters
- `issues.get` - Get a single issue
- `issues.update_status` - Change issue status
- `issues.change_assignee` - Reassign an issue
- `issues.set_blocked_by` - Set blocker issue dependencies
- `issues.increase_priority` - Raise issue priority by one level (up to `P0`)
- `issues.add_reviewers` - Add reviewers
- `issues.submit_review` - Submit review outcome
- `issues.my_queue` - Get agent's actionable queue


## Usage Examples

### Create an Issue

```json
{
  "name": "issues.create",
  "arguments": {
    "actor_id": "agent-1",
    "title": "Implement login feature",
    "body_markdown": "## Summary\nAdd authentication...",
    "assignee_agent_id": "agent-2",
    "blocked_by": ["#12", "6b95e9f5-4f08-4ec2-b126-4a39f2a2f6f2"]
  }
}
```

`issues.create` always starts with status `todo`.
`assignee_agent_id` is required.
The creator is automatically included in the reviewers list.
`assigned_by_agent_id` is managed internally and is not accepted as input.
`blocked_by` MAY be provided on create as a single issue ref or an array of issue refs.

### Set blockers for an existing issue

```json
{
  "name": "issues.set_blocked_by",
  "arguments": {
    "issue_ref": "#42",
    "actor_id": "agent-2",
    "blocked_by": "#91"
  }
}
```

Use this when work has started and the issue becomes blocked by newly created cross-space work.

### List Issues

```json
{
  "name": "issues.list",
  "arguments": {
    "filters": {
      "open_only": true
    },
    "page": 1,
    "page_size": 20
  }
}
```

### Update Status

```json
{
  "name": "issues.update_status",
  "arguments": {
    "issue_ref": "#1",
    "actor_id": "agent-2",
    "new_status": "in_progress"
  }
}
```

### Get My Queue

```json
{
  "name": "issues.my_queue",
  "arguments": {
    "agent_id": "agent-2",
    "include_assigned_open": true,
    "include_review_required": true
  }
}
```

## Enforce Runtime Boundaries

- Edit files only inside the assigned code space.
- Verify every target path is inside the assigned boundary before writing.
- Never create, modify, rename, or delete files outside the assigned code space.
- Route all cross-space requests through MCP issues instead of direct edits.

## Resolve Agent Identity First (Mandatory)

1. Resolve identity before any MCP queue read or mutation.
2. Use workspace assignment identifier, or package `name` from `package.json` in monorepos.
3. If no workspace identity exists, create `.identity` in the current code space and store project role as plain text.
4. Reuse the resolved value unchanged for the full run.
5. Use the value as:
- `agent_id` for queue tools
- `actor_id` for mutation tools

## Fast MCP Access Path (Mandatory, Timeboxed)

Run this before reading MCP server docs or source code.
Timebox total discovery to 2 minutes.

1. Use the known issue tracker server first:
- `codex mcp get issue_tracker_mcp`
2. If that server is not configured, immediately run fallback discovery:
- `codex mcp list`
- `codex mcp get <name-from-list>`
3. As soon as the issue server is identified, run a minimal end-to-end smoke call sequence:
- `issues.my_queue` with resolved `agent_id`
4. Only inspect MCP server code/docs if and only if tool calls fail due to unknown tool names or schema errors.
5. Do not deep-read codebases to confirm behavior that a direct tool call can confirm faster.

## Run Mandatory MCP Queue Checks (After Fast MCP Access Path)

### Startup Check (Every Run)

Run before implementation work:

1. Fetch assigned open issues and review-required issues for the resolved `agent_id`.
2. Treat open issues as statuses: `todo`, `in_progress`, `for_acceptance`.
3. Prioritize:
- Review-required items blocking other teams
- Assigned items already `in_progress`
- Newly assigned open issues
- Local untracked work only when queue is empty
4. Report identity and actionable summary in collaboration updates.
5. If any of your issues is marked as blocked_by use critical thinking. 
- In case you don't see how it affects other teams, remove the block and proceed on implementation.
- In case you are indeed blocked but the issue is in `for_acceptance` stage, perform a code review and the acceptance yourself (even if not the assignee).
  - if it passes acceptance proceed with the implementation of your own issue.
  - otherwise enrich the description of the failed acceptance ticket with your findings, return it to `todo`.

### Liveness Or Feedback Sync Check

Run on liveness probes or explicit health/sync requests:

1. Re-check assigned open issues and review-required issues.
2. Summarize waiting dependencies and blockers caused by external teams.


## Execute Cross-Space Request Protocol

When needed work is outside the assigned code space:

1. Stop any direct external edit attempt.
2. Identify owner team/code space and exact requested scope.
3. Find existing issue tracking the dependency; update it if found.
4. Otherwise create a new issue with:
- `actor_id`
- `title`
- `body_markdown`
- `assignee_agent_id` when known
5. Mark local work as blocked or partially blocked truthfully.
6. Monitor the dependency through startup and liveness checks.

## Use Required MCP Operations By Situation

- Startup queue: `issues.my_queue` or `issues.list` with filters for assigned open plus review-required.
- External dependency: `issues.create` or `issues.list` followed by update operations.
- Work progression: `issues.update_status`.
- Priority escalation: `issues.increase_priority`.
- Handoff for acceptance: `issues.add_reviewers` then set status to `for_acceptance`.
- Rework after failed acceptance: move status from `for_acceptance` back to `todo`.
- Wrong routing: `issues.change_assignee`.

Note:
- `issues.create` starts in `todo`; do not send `status` on create.
- Keep all mutation `actor_id` values equal to resolved identity.

## Apply Status Discipline

Use statuses truthfully:

- `todo`: not started, or rework required after review feedback
- `in_progress`: assignee is actively implementing
- `for_acceptance`: implementation is complete and ready for validation
- `resolved`: accepted and complete
- `rejected`: intentionally declined/cancelled

Never:

- Leave completed work in `in_progress`
- Mark `resolved` before required acceptance
- Use `rejected` to hide incomplete work

## Follow Reviewer Policy

1. Add a reviewer as assignee when moving work to `for_acceptance`. You should always assign someone for review. Usually the team blocked by your task, if this doesn't exist the team found on `assigned_by_agent_id`.
2. Select reviewers tied to impacted contracts/interfaces/dependencies.
3. Validate acceptance criteria and keep review scope focused.
4. Submit explicit review outcome:
- `approved`: criteria satisfied
- `changes_requested`: return issue to `todo` and implement rework. Moreover update the issue by filling the `Review feedback` section with the reason

If the assignee discovers work is blocked by another issue after starting, the agent MUST set blockers using `issues.set_blocked_by`.
The agent SHOULD create the dependency issue first (if missing), then set `blocked_by` on the current issue.


### When blocked by external work

- The agent SHOULD set status to `todo` when blocked work cannot proceed.
- The agent MUST track blocking links via `issues.set_blocked_by`.
- The agent SHOULD monitor blocker statuses and resume only when blockers are `resolved`.

## Author Actionable Cross-Team Issues

Write concrete markdown with enough detail to execute without guesswork:

- Summary of requested change
- Context and why it matters
- Current behavior
- Expected behavior
- Scope boundaries (in/out)
- Acceptance criteria
- Impact on requesting team
- References (paths, interfaces, logs, examples, issue IDs)

Use this template:

```md
# <Short title>

## Summary
<Requested change or fix>

## Context
<Why this is needed>

## Current Behavior
<Observed behavior>

## Expected Behavior
<Desired behavior>

## Scope
<In scope and out of scope>

## Acceptance Criteria
- [ ] Criterion 1
- [ ] Criterion 2

## Impact on Requesting Team
<Blocker or dependency impact>

## References
<Paths, interfaces, issue refs, logs>

## Work done so far
<Leave it blank for the assignee>

## Review feedback
<Leave it blank for the reviewer>
```

## Required Completion Report

When finishing a task that used this skill you update the task with a short description regarding the work done so far (section `Work done so far`). In case there was none needed, you should state that.

Finally provide a report to the human:

- Resolved identity used for `agent_id`/`actor_id`
- MCP queue checks performed and key actionable items
- Cross-space issues created/updated/rerouted
- Review outcomes sent or pending
- Remaining blockers and owning teams