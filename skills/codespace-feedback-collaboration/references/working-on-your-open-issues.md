
Use this when work has started and the issue becomes blocked by newly created cross-space work.


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
