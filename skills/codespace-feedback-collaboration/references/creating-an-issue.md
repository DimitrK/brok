# 

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

### When blocked by external work
  Most of the times you would need to create an issue because your work is blocked by another agent, team or code-space. The steps you need to take in that case are:

- The agent SHOULD set status to `todo` when blocked work cannot proceed.
- The agent MUST track blocking links via `issues.set_blocked_by`.
- The agent SHOULD monitor blocker statuses and resume only when blockers are `resolved`.

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
