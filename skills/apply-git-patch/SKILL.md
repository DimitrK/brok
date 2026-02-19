---
name: apply-git-patch
description: Teaches how to properly apply one or more git patch files into the codebase.
---


## Agent Skill Guide: Applying Patches Safely with Git (`git am` / `git apply`)

### What this skill covers

An agent should be able to take **one patch** or a **patch series** (possibly touching many files) and apply it correctly, with predictable handling of:

* clean application
* path-prefix mismatches
* whitespace and line-ending pitfalls
* conflicts (3-way fallback where possible)
* partial application and rejects (`*.rej`)
* safe rollback of failed patch sessions

Core primitives are `git am` (preferred for `format-patch` mailboxes) and `git apply` (for raw diffs / “legacy” patches). ([Git][1])

---

## 1) Safety invariants (must-do every time)

### 1.1 Work on a dedicated branch

```bash
git switch -c patch/apply-$(date +%Y%m%d-%H%M%S)
```

### 1.2 Require a clean working tree (unless you *intend* to stack changes)

```bash
git status --porcelain
```

If non-empty, either commit/stash first or abort the operation.

### 1.3 Inspect the patch before applying

For `git apply`, use stats/summary/check modes:

```bash
git apply --stat  path/to/changes.patch
git apply --summary path/to/changes.patch
git apply --check path/to/changes.patch
```

These are explicitly supported modes (`--stat`, `--summary`, `--check`). ([Git][2])

---

## 2) Choose the correct mechanism: `git am` vs `git apply`

### Use `git am` when…

The patch is in **mailbox format** (commonly produced by `git format-patch`) and includes commit message/author metadata. This preserves authorship, subject, and creates commits automatically. ([Git][3])

Typical indicators:

* file begins with `From <sha> ...`
* contains email-style headers like `Subject: [PATCH ...]`

### Use `git apply` when…

The patch is a **raw unified diff** (e.g., exported from `diff -u`, GitHub “.patch” that’s not a mailbox, or a snippet) and you will create the commit yourself afterward. ([Git][2])

---

## 3) Standard workflows

# A) Mailbox patch / patch series: `git am`

### A.1 Apply with 3-way fallback (recommended default for agents)

```bash
git am --3way path/to/0001-something.patch
# or a series:
git am --3way path/to/patches/*.patch
# or from stdin:
cat path/to/series.mbox | git am --3way
```

`git am` supports `--3way` and a structured continue/skip/abort flow. ([Kernel][4])

### A.2 If a conflict occurs

Show the failed patch:

```bash
git am --show-current-patch=diff
```

Then resolve conflicts in files, stage resolutions, and continue:

```bash
git add -A
git am --continue
```

Or skip/abort:

```bash
git am --skip
git am --abort
```

These are first-class `git am` commands. ([Kernel][4])

---

# B) Raw diff patch: `git apply`

### B.1 Dry-run validation

```bash
git apply --check path/to/changes.patch
```

`--check` verifies applicability without applying. ([Git][2])

### B.2 Apply (two common modes)

**(1) Apply to working tree only (then stage/commit yourself):**

```bash
git apply path/to/changes.patch
git add -A
git commit -m "Apply patch: <summary>"
```

**(2) Apply directly to index + working tree (safer when you expect exact matches):**

```bash
git apply --index path/to/changes.patch
git commit -m "Apply patch: <summary>"
```

`--index` is explicitly defined and has stricter expectations about index vs working tree alignment. ([Git][2])

### B.3 If the patch doesn’t apply cleanly: try a 3-way fallback

```bash
git apply --3way path/to/changes.patch
```

`--3way` attempts a 3-way merge and may leave conflict markers for resolution; it also implies `--index` unless `--cached` is used. ([Git][2])

### B.4 If you need partial application (last resort): `--reject`

```bash
git apply --reject path/to/changes.patch
# review *.rej files and manually integrate
```

By default Git is atomic (fails whole patch). `--reject` applies what it can and writes rejected hunks to `*.rej`. ([Git][2])

---

## 4) Handling common patch mismatches (multi-file safe)

### 4.1 Wrong path prefixes: use `-p<n>`

If the patch paths don’t match your repo layout:

```bash
git apply -p0 path/to/changes.patch
# or
git apply -p2 path/to/changes.patch
```

`-p<n>` strips leading path components; default is `-p1`. ([Git][2])

`git am` passes `-p`, `--directory`, etc. through to `git apply` as well. ([Kernel][4])

### 4.2 Patch is for a subdirectory: use `--directory=<root>`

```bash
git apply --directory=modules/git-gui path/to/changes.patch
```

`--directory` prepends a root to filenames after any `-p` stripping. ([Git][2])

### 4.3 Whitespace policy

If whitespace warnings or errors block application, decide an explicit policy:

```bash
git apply --whitespace=fix path/to/changes.patch
# or stricter:
git apply --whitespace=error path/to/changes.patch
```

`--whitespace=<action>` supports `nowarn|warn|fix|error|error-all`. ([Git][2])

### 4.4 Line endings (CRLF/LF) pitfalls

If patches fail to match context unexpectedly across platforms, check `.gitattributes` and line-ending normalization (`core.autocrlf`). GitHub documents common configuration patterns for line endings. ([GitHub Docs][5])

---

## 5) Agent decision procedure (deterministic)

1. **Assert clean tree** (or explicitly stash/commit).
2. **Inspect** (`--stat`, `--summary`).
3. **Detect patch type**:

   * mailbox → prefer `git am --3way`
   * raw diff → prefer `git apply --check` then `git apply` (or `--3way`)
4. **If failure**:

   * for `git am`: resolve → `git am --continue` OR `--abort`
   * for `git apply`: try `--3way`; if still failing, consider `-p<n>` / `--directory`; only then `--reject`
5. **Post-apply**:

   * `git diff --stat`
   * run tests / build
   * commit message hygiene (especially for `git apply`)

---

## 6) Automation code (agent-ready)

### 6.1 Minimal Bash “apply patch” helper

```bash
#!/usr/bin/env bash
set -euo pipefail

patch="${1:?Usage: apply_patch.sh <patchfile>}"

# 1) Ensure we're in a git repo
git rev-parse --is-inside-work-tree >/dev/null

# 2) Ensure clean working tree
if [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: working tree not clean. Commit/stash first." >&2
  exit 2
fi

# 3) Heuristic: mailbox patches typically start with "From " and contain "Subject:"
is_mailbox=false
if head -n 5 "$patch" | grep -qE '^From [0-9a-f]{7,40} ' && grep -qE '^Subject:' "$patch"; then
  is_mailbox=true
fi

# 4) Apply
if $is_mailbox; then
  echo "Applying via git am --3way ..."
  git am --3way "$patch"
else
  echo "Checking via git apply --check ..."
  git apply --check "$patch"

  echo "Applying via git apply --3way (fallback-capable) ..."
  git apply --3way "$patch"

  echo "Committing ..."
  git commit -am "Apply patch $(basename "$patch")" || {
    git add -A
    git commit -m "Apply patch $(basename "$patch")"
  }
fi

echo "Done."
```

### 6.2 Python version (better for an agent pipeline)

```python
#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path

def run(*args: str) -> None:
    subprocess.run(args, check=True)

def capture(*args: str) -> str:
    return subprocess.check_output(args, text=True)

def is_clean_tree() -> bool:
    return capture("git", "status", "--porcelain").strip() == ""

def looks_like_mailbox(patch_path: Path) -> bool:
    head = patch_path.read_text(errors="replace").splitlines()[:10]
    head_txt = "\n".join(head)
    has_from = re.search(r"^From [0-9a-f]{7,40} ", head_txt, re.M) is not None
    has_subject = re.search(r"^Subject:", patch_path.read_text(errors="replace"), re.M) is not None
    return has_from and has_subject

def apply_patch(patch_path: Path) -> None:
    run("git", "rev-parse", "--is-inside-work-tree")

    if not is_clean_tree():
        raise SystemExit("ERROR: working tree not clean. Commit/stash first.")

    if looks_like_mailbox(patch_path):
        # Mailbox => preserve metadata, commit(s) produced automatically
        run("git", "am", "--3way", str(patch_path))
        return

    # Raw diff => verify then apply
    run("git", "apply", "--check", str(patch_path))

    # Try 3-way merge capable apply first
    run("git", "apply", "--3way", str(patch_path))

    # Commit result
    try:
        run("git", "commit", "-am", f"Apply patch {patch_path.name}")
    except subprocess.CalledProcessError:
        run("git", "add", "-A")
        run("git", "commit", "-m", f"Apply patch {patch_path.name}")

def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("Usage: apply_patch_agent.py <patch1> [patch2 ...]")

    for p in map(Path, sys.argv[1:]):
        apply_patch(p)

if __name__ == "__main__":
    main()
```

---

## 7) Explicit “don’ts” for agents

* **Don’t** use `--unsafe-paths` unless the patch is trusted and you are intentionally allowing writes outside the working area; Git rejects such patches by default for safety. ([Git][2])
* **Don’t** default to `--reject` (partial application) unless you’re intentionally entering a manual-repair workflow with `*.rej` files. ([Git][2])
* **Don’t** apply patches on `main/master` directly; always isolate in a branch to keep rollback trivial.

---

If you want this packaged as a single “skill.md” (agent-operational format: inputs/outputs, deterministic steps, failure handling, and test checklist), say so and I’ll emit it in that structure.

