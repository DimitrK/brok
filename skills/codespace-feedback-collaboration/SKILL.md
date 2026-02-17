---
name: codespace-feedback-collaboration
description: Coordinate cross-team feedback workflows for broker-interceptor code spaces. Use when requesting dependencies or clarifications from other apps/packages, responding to feedback requests received in your code space, tracking pending feedback in README, following up on unresolved responses, and cleaning up resolved feedback artifacts.
---

# Codespace Feedback Collaboration

Follow this workflow whenever a task spans multiple code spaces.

Rule #1. Your readme file is the point of reference for other teams as well. Whenever you change part of the logic in your codespace keep it update it.
Describe what your app or package is doing, API endpoints or interfaces it exposes and how could someone use it. If there are depenedencies, env vars or requirements please include these too.

## Enforce Code Space Boundaries

- Treat each `apps/<name>` or `packages/<name>` as a separate code space.
- Edit implementation files only inside your assigned code space.
- Write outside your code space only as Markdown in `external_feedback` folders.
- Keep every request and response scoped to the current implementation task.

## Run Feedback Loop In This Order

1. Process incoming feedback requests in your code space.
2. Check responses for your own pending feedback requests.
3. Create new outgoing requests for missing dependencies or clarifications.
4. Update your own codespace `README.md` status and clean up resolved feedback artifacts.

## Process Incoming Requests In Your Code Space

1. Scan `<your_codespace>/external_feedback/broker-interceptor/<requester_codespace>/*.md`.
2. Read request files that do not end with `_response.md`.
3. Decide whether to implement, clarify, or reject with rationale. If there is already a `_response.md` file for the request, skip providing feedback response again.
4. Create a response file next to the request using the same basename plus `_response.md`.
5. If implementation changed, update your code and `README.md` accordingly.

Use this response filename rule:

- Request file: `missing_methods.md`
- Response file: `missing_methods_response.md`

## Request Changes Or Clarifications From Another Code Space

1. Open target code space: `apps/<target>` or `packages/<target>`.
2. Create target folder if missing: `external_feedback/broker-interceptor/<your_codespace_name>/`.
3. Create a request file named for the reason, such as `missing_methods.md`.
4. Write:
- What is missing.
- Why it is needed now.
- How you will use it.
- Expected method signatures and behavior.
5. Mark dependent local methods as `*_INCOMPLETE` in your code space.
6. Add or update `README.md` section `Pending feedback` with:
- Target code space.
- Request filename.
- Waiting reason.
- Related `*_INCOMPLETE` methods.

When missing methods drive the request, always use `missing_methods.md`.

## Check Responses To Your Pending Requests

1. Read `README.md` section `Pending feedback`.
2. For each entry, check target path:
`<target_codespace>/external_feedback/broker-interceptor/<your_codespace_name>/<request_name>_response.md`.
3. Apply received guidance to code, tests, and interfaces.
4. If follow-up is needed, run the follow-up procedure.
5. If resolved, run cleanup and remove waiting entry from `README.md`.

## Follow Up On Unresolved Feedback

1. Archive prior request and response files in the same feedback folder under a new archive subfolder.
2. If filename collision exists in archive, append `_1`, `_2`, `_3`, and continue incrementing.
3. Create a new request file with the original filename.
4. Include:
- Short summary of previous request.
- Summary of received response.
- New follow-up questions or constraints.
5. Keep `README.md` pending entry updated to the latest request status.

## Clean Up Resolved Feedback

1. Remove resolved item from `README.md` section `Pending feedback`.
2. Move to archive obsolete request files from the target code space `external_feedback` folder.
3. Remove `*_INCOMPLETE` suffixes from methods that are now complete.
4. Keep response files only when audit history is explicitly required.

## Required Output Checklist For Agent Responses

When finishing a task that used this skill, report:

- Which code spaces were contacted.
- Which code spaces you responded to.
- Which request files were created or answered.
- Which pending items remain in `README.md`.
- Which `*_INCOMPLETE` methods remain and why.
