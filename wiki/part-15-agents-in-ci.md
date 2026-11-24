---
title: "Part 15 — AI Coding Agents in CI (GitHub Actions)"
summary: "Coding agents now run inside CI: claude-code-action, the Codex action and CLI, the Copilot coding agent, and AI PR reviewers and fixers. In CI there is no human at the console, the prompt is built from text anyone can write (PR titles, issue comments, diffs), the trigger is often an event an outsider can cause, and the job holds write tokens, secrets and cloud OIDC trust. This part covers the risk, the controls as copy-ready workflow snippets, detection, and how to find every agent workflow across an enterprise."
part: 15
updated: 2026-11-24
---

# Part 15 — AI Coding Agents in CI (GitHub Actions)

The earlier parts put the agent on a laptop or in a workspace, with a person who started it. This part covers the same agents running in a CI pipeline. A workflow file runs an agent on every pull request, issue or comment. The agent reads the PR, writes a review, proposes a fix, or opens a branch on its own. Examples: `anthropics/claude-code-action`, `openai/codex-action` and `codex exec`, the GitHub Copilot coding agent, and the many AI PR-review and "AI fix" actions.

It gets its own part because four of the guide's controls fail at the same time here. [Part 14, Failure Mode 5](part-14-multi-agent-a2a.md#failure-mode-5-ask-has-no-human-headless-agent-driving) covers the first: there is no human to answer "ask". The other three are specific to CI. The prompt is built from text strangers can write. The run starts on an event strangers can cause. And the job's identity is the workflow token, plus whatever secrets and cloud trust the workflow has. An agent workflow is a CI supply-chain problem ([Part 6](part-6-extension-supply-chain.md)) and an identity problem ([Part 10](part-10-agent-identity.md)) at once.

## Why It Fits Here (and Not in Part 6 or Part 7)

[Part 6](part-6-extension-supply-chain.md) governs what you load *into* an agent. [Part 7](part-7-agentic-workflow-platforms.md) governs platforms built for agentic workflows (n8n, Gemini Enterprise). Agents in CI are neither. The platform is your CI system, the extension is a third-party action, and the controls are workflow settings: triggers, `permissions:`, refs, secrets and OIDC trust. Those controls live in a different place from the rest of the guide, so they get a page of their own. That page links back to Parts 6, 10 and 14 for the general principles.

## The Risk

An agent workflow is a chain. Each link is a place where an outsider gets closer to your credentials:

1. **Untrusted text reaches the prompt.** PR titles and bodies, issue and review comments, commit messages, branch names, file contents and code comments are all written by whoever opened the PR. The agent reads them on purpose, because that is its job. So indirect prompt injection ([Part 1](part-1-risk-surface-and-control-model.md)) is the normal case here, not an edge case. It gets worse when the workflow interpolates `${{ github.event.pull_request.title }}` or `${{ github.event.comment.body }}` straight into `with: prompt` or into a `run:` script. That is the classic Actions script-injection bug, plus a prompt-injection bug.
2. **Outsiders can trigger it.** `pull_request_target`, `issue_comment`, `issues`, `discussion` / `discussion_comment` and `workflow_run` (when it follows a fork's run) all run in the context of the *base* repository. They get its secrets and a token that can be write-capable, and anyone who can open an issue or comment can trigger them. A mention-triggered agent ("@agent fix this") on `issue_comment` runs for every commenter unless the workflow checks who the author is.
3. **The job holds write access.** `contents: write`, `pull-requests: write`, `issues: write` and `actions: write` let an injected agent push code, approve or merge, edit workflows, or post phishing links under a trusted bot name. Repository secrets (the model API key, deploy keys, package tokens) are in the environment.
4. **It has cloud trust through OIDC.** `id-token: write` lets the job mint a token that a cloud role trusts. If the trust condition is loose (any branch, any workflow, any repo in the org), an injected agent can reach production cloud credentials.
5. **Moving refs.** `uses: some-org/ai-review@main` or `@v1` runs whatever the action's owner (or whoever compromises them) pushes next. The agent CLI the action installs at runtime is usually a moving version too. An action that wraps an agent runs a model with your token, so it is a high-value tag-hijack target.
6. **Permission bypass flags.** `--dangerously-skip-permissions`, `--yolo`, `danger-full-access`, `safety-strategy: unsafe` and "auto-approve everything" settings remove the agent's own tool gate. In CI they are often added to stop the run from hanging, which is exactly the Part 14 headless anti-pattern.
7. **Shared runners.** On a persistent self-hosted runner, a compromised agent run can leave a backdoor for the next job, which may belong to another repository.

Put together, the worst case is easy to describe: **an outsider comments on an issue, an agent with a write token and secrets reads the comment as an instruction, and pushes a change or leaks the key.** Every control below removes one link of that chain.

## Controls (Copy-Ready Snippets)

A complete hardened workflow combining these is in [`templates/workflows/agent-ci-hardened.yml`](../templates/workflows/agent-ci-hardened.yml). The snippets use a synthetic `acme-org`. Verify every action input and CLI flag against the current vendor docs before relying on it; these surfaces change fast.

### 1. Restrict triggers; require approval for outside contributors

Prefer `pull_request` (fork PRs get a read-only token and no secrets) over `pull_request_target`. If you need a comment trigger, check the commenter before the agent starts:

```yaml
on:
  issue_comment:
    types: [created]

jobs:
  agent:
    # Only repo members, on a PR, with an explicit command. Everyone else is a no-op.
    if: >-
      github.event.issue.pull_request &&
      startsWith(github.event.comment.body, '/agent-review') &&
      contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
```

Then turn on the repository or organization Actions setting **"Require approval for all outside collaborators"** (not only first-time contributors), so a fork PR cannot start any workflow without a maintainer's click. Many agent actions also have their own gate: for example, claude-code-action skips fork PRs by default (`allow_fork_prs`) and lets only users with write access invoke it unless you widen `allowed_non_write_users` or `allowed_bots`. codex-action checks write access unless you widen `allow-users`. Leave those defaults alone, and treat `'*'` in any of them as a finding.

### 2. Read-only token for the agent; a separate job for writes

Set `permissions: {}` at the top level. Give the agent job read scopes only. Then let a second job, which never runs the agent, do the one write you need, using the agent's output strictly as data:

```yaml
permissions: {}

jobs:
  agent:
    permissions:
      contents: read
      pull-requests: read
    steps:
      # ... run the agent; save its output to review.md; upload as an artifact
  publish:
    needs: agent
    permissions:
      pull-requests: write   # the only write; no secrets, no checkout, no agent
    steps:
      # ... download review.md, then:
      - run: gh pr comment "$PR" --repo "$REPO" --body-file review.md
        env:
          GH_TOKEN: ${{ github.token }}
          REPO: ${{ github.repository }}
          PR: ${{ github.event.pull_request.number }}
```

If the agent must propose code, have it upload a patch as an artifact. A human-approved job (an `environment:` with required reviewers) can then apply it to a branch, and that branch still goes through normal review and CI. Never let the agent job push directly to a protected branch, approve a PR, or edit `.github/workflows/`.

### 3. Pin the action (and the agent CLI) to a full SHA

```yaml
# Moving: runs whatever is pushed to the tag next.
- uses: some-org/ai-review@v1
# Pinned: a full commit SHA, with the tag in a comment for humans and update bots.
- uses: anthropics/claude-code-action@eb56b6666facdbd501035f4a0269d8caee2e7a8b  # v1
```

A SHA pin only helps if everything under it is fixed too. A composite action that itself calls `other-org/setup@main` is still mutable. Pin the agent CLI version where the action allows it (for example codex-action's `codex-version`), and let a dependency bot propose SHA bumps as reviewed PRs. Enforce it with the organization policy "Require actions to be pinned to a full-length commit SHA" where your plan supports it, and with an allowlist of approved actions.

### 4. Scope the agent's tools; never bypass its gate

Give the agent the smallest tool set the task needs, and keep its own permission gate on. In CI, "ask" must resolve to deny ([Part 14](part-14-multi-agent-a2a.md#failure-mode-5-ask-has-no-human-headless-agent-driving)):

```yaml
# claude-code-action: read and inspect only
claude_args: >-
  --allowedTools "Read,Grep,Glob,Bash(git diff:*),Bash(git log:*)"
  --disallowedTools "Write,Edit,WebFetch,WebSearch"

# codex-action: read-only sandbox, privileges dropped
sandbox: read-only
safety-strategy: drop-sudo
```

Treat any of these in a workflow as a finding: `--dangerously-skip-permissions`, `--yolo`, `--permission-mode bypassPermissions`, `sandbox: danger-full-access`, `safety-strategy: unsafe`, `allowed_tools: "*"`, or an unrestricted `Bash`. For self-built agent steps, register the deny-by-default [headless permission gate](../templates/headless/README.md) as the PreToolUse hook.

### 5. No secrets on untrusted triggers

An agent job that an outsider can start must not reference secrets beyond what it strictly needs. Use the model key alone, ideally an org-scoped key with a spend cap, kept in an `environment:` limited to the default branch. Never put deploy keys, package-publish tokens or cloud credentials in a job that reads PR text. Don't expose `${{ secrets.* }}` or `toJSON(secrets)` to `run:` steps the agent can influence. Untrusted text belongs in `env:` and should be quoted as a shell variable, never interpolated with `${{ }}` inside `run:`:

```yaml
# Wrong: the PR title becomes shell code (and prompt text).
- run: echo "Reviewing ${{ github.event.pull_request.title }}"
# Right: it stays data.
- run: echo "Reviewing $TITLE"
  env:
    TITLE: ${{ github.event.pull_request.title }}
```

### 6. OIDC: tight trust conditions, and not in the agent job

Give `id-token: write` only to a job that does not run the agent. Pin the cloud trust to the exact repository, ref and workflow. Never trust `repo:acme-org/*`, and never trust a `pull_request` subject for a write role. AWS example:

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:acme-org/acme-app:environment:production",
      "token.actions.githubusercontent.com:job_workflow_ref": "acme-org/acme-app/.github/workflows/deploy.yml@refs/heads/main"
    }
  }
}
```

The same rule applies to the model provider. If the agent authenticates to its model API by OIDC federation instead of a static key, scope that federation rule to the repository and workflow, and to a role that can only call the model.

### 7. Ephemeral, egress-limited runners

Run agent jobs on GitHub-hosted or ephemeral (one job, then destroyed) runners, never on a long-lived shared self-hosted pool. Where you can, restrict runner egress to the model endpoint and GitHub. An egress-allowlisting step or network policy turns "the agent was talked into exfiltrating a token" into a blocked connection and an alert.

### 8. Hosted agents (Copilot coding agent and peers)

Some agents run in CI that the vendor manages for you. The GitHub Copilot coding agent, for example, works in its own Actions environment that you configure through `.github/workflows/copilot-setup-steps.yml`. The same questions apply. Who can assign it a task (keep it to users with write access)? What can its environment reach (keep the built-in firewall on, and add to its allowlist one host at a time)? What secrets are in its environment (only what the task needs)? Do workflows on the PRs it opens wait for a human's approval before they run (keep that on)? "Managed" does not mean "done" ([Part 13](part-13-managed-cloud-ai-stack.md)). Check these settings against the vendor's current docs.

## Detection

Prevention will miss something. Watch for the moments when the chain is being used ([Part 9](part-9-detection-monitoring-ir.md)):

- **Static, on every workflow change:** run a workflow linter (actionlint, zizmor, poutine) as a required check. It flags `pull_request_target`, template injection, unpinned refs and broad `permissions:`. Add a custom rule for the agent-specific findings above (bypass flags, wildcard tool or user lists, agent job with `id-token: write`). Require CODEOWNERS review from the security team on `.github/workflows/**`.
- **Audit log:** alert on agent workflows started by `issue_comment` / `pull_request_target` from non-members; on a bot or `github-actions[bot]` pushing to protected branches, approving PRs, or editing workflow files; and on new repository or environment secrets added to repos that run agents.
- **Run behavior:** alert on an agent job connecting anywhere other than the model endpoint and GitHub; on a run much longer or more token-hungry than its baseline (the [token-cost-spike detection](../templates/detections/README.md) fits here); and on secret-scanning hits in agent-authored comments, commits or logs.
- **Cloud:** alert on `AssumeRoleWithWebIdentity` (or the equivalent) from a GitHub OIDC token whose `sub` is a pull request or an unexpected workflow, and on any cloud call from a role that only the agent job should never reach.
- **Kill switch:** know in advance how to disable an agent workflow across the org (an Actions policy that blocks the action, or disabling the workflow by API), and how to revoke the model key. Rehearse it like the endpoint [kill switch](../templates/incident/README.md).

## Find Them Across Your Enterprise

Hardening one workflow is the easy part. The hard part is knowing every place an agent runs in CI, across every org, including the copy-pasted "AI review" workflow nobody owns. Discovery comes first here too ([Part 1](part-1-risk-surface-and-control-model.md)).

[gop](https://github.com/peleduri/gop) (GitHub Enterprise Org Posture) is an open-source, read-only CLI that maps a GitHub Enterprise as an evidence graph: who can make code run where, across orgs and nested actions, with which secrets, OIDC trusts and runners. It ranks the fewest changes that remove the most reach:

```sh
gop collect --enterprise acme --out graph.json   # read-only token or GitHub App
gop report  --graph graph.json --out report.html
```

An **"AI agents in CI"** report section is coming (tracked in [gop issue #139](https://github.com/peleduri/gop/issues/139)). It marks each workflow that runs a known agent action or agent CLI, and shows who can trigger it (outsiders, members or maintainers), what it reaches (write token, secrets, `id-token: write`), whether untrusted text reaches its prompt, and which bypass flags or tool scopes it uses. It ranks outsider-triggerable agents with write access first, and lists the fixes from this part. Until it ships, gop's existing report already surfaces the moving refs, write-default orgs and cross-org reach that an agent workflow inherits. The planned docs will live at [docs/agents-in-ci.md](https://github.com/peleduri/gop/blob/main/docs/agents-in-ci.md) in the gop repo.

## The Playbook

- **Inventory every agent workflow, enterprise-wide.** Find each workflow that runs an agent action or CLI, who can trigger it, and what it can reach (gop, above). Give each one an owner in the AI registry ([Part 12](part-12-governance-compliance.md)).
- **No agent on an outsider-triggerable event without an author gate.** Use `pull_request`, not `pull_request_target`. Gate comment and issue triggers on `author_association`. Require approval for all outside collaborators.
- **Read-only agent, separate write job.** Use `permissions: {}` by default, read scopes for the agent, and one narrow write in a job that never runs the agent and treats its output as data.
- **Pin actions and the agent CLI to full SHAs.** Allowlist approved actions, check nested composite actions, and update through reviewed bot PRs.
- **Scope tools; never bypass the gate.** Use explicit allowed tools, no web or shell beyond what the task needs, and treat `--dangerously-skip-permissions` and its relatives as findings.
- **No secrets or OIDC in the agent job.** Pass untrusted text through `env:`, not `${{ }}` in `run:`. Pin OIDC trust to repository, ref, environment and workflow.
- **Ephemeral, egress-limited runners.** Never run an agent on a shared persistent self-hosted pool.
- **Detect and rehearse.** Run a workflow linter as a required check, alert on agent runs from untrusted triggers and on unexpected egress or OIDC use, and keep an org-wide disable switch ready.

## Bottom Line

An AI agent in CI is a headless agent ([Part 14](part-14-multi-agent-a2a.md)) whose prompt is written by strangers, whose trigger strangers can pull, and whose identity is your workflow token. Treat the agent's input as hostile and its output as data. Keep the agent job read-only, put the write in a separate job, pin what it runs, scope what it can do, and keep secrets and cloud trust out of its reach. Then find every other agent workflow in your enterprise, because the one you didn't harden is the one somebody copied from a blog post.

## Sources

- https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
- https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-workflow-runs/approving-workflow-runs-from-public-forks
- https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/
- https://github.com/anthropics/claude-code-action/blob/main/docs/security.md
- https://github.com/openai/codex-action
- https://docs.github.com/en/copilot/using-github-copilot/coding-agent/about-assigning-tasks-to-copilot
- https://github.com/rhysd/actionlint
- https://github.com/zizmorcore/zizmor
- https://github.com/boostsecurityio/poutine
- https://github.com/peleduri/gop

---

Nav: **[← Index](../index.md)** · **[Glossary](../glossary.md)** · **[Start Here](../start-here.md)** · _Part 15 is the final part._
