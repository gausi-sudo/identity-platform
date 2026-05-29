# Niro

## What is Niro?

Niro is an AI-powered pentest agent. It runs test cases against your
authorized targets and returns the coverage map: which passed, which
failed (the bugs, with runnable PoCs), which were blocked waiting on
your input.

You don't invoke Niro directly. Your coding agent calls Niro (over MCP)
automatically after each push to a PR. Niro returns bugs; your agent
writes a regression test that fails on the unfixed code, drafts a fix
that makes it pass, re-runs to confirm closure, and surfaces any blocked
items as a punch-list. You review the diff and the punch-list, provide
what's needed, merge.

## How do I setup Niro?

- `niro.yaml` — Niro's runtime knobs (defaults are sensible; tweak only when needed).
- `scope.yaml` — your authorization for what Niro may have access to (must be set before first run).
- `credentials.yaml.example` — example credentials file (read before producing your own `credentials.yaml`).

## How do I block merge until Niro passes?

Every Niro pentest writes a `Security / Niro` status check on the PR's
head commit alongside the canonical comment. Add this check to your
branch protection rule so no PR merges with unaddressed security
issues — Niro must have run, finished, and passed before GitHub will
let the merge button enable.

You configure this on GitHub yourself; Niro doesn't modify your repo
settings.

1. Open your repo on github.com.
2. **Settings** → **Branches**.
3. Click **Add branch protection rule** (or edit the existing rule
   for your default branch).
4. Branch name pattern: `main` (or whatever your protected branch is).
5. Check **Require status checks to pass before merging**, add
   `Security / Niro` to the required-checks list, and save.

