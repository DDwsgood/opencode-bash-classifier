# opencode-bash-classifier

[简体中文](README.zh-CN.md)

Version 0.5.1 — an execution-boundary command safety classifier for OpenCode's native `bash` tool.

## What's new in 0.5.0 / 0.5.1 (security hardening)

0.5.1 syncs the v2 branch (`0.5.1-v2`) with the v1 fixes: it closes the `rmdir -Recurse -Force` forced-recursive hole in LOOSE and restores two PowerShell disposable-cleanup allowances. See the 0.5.0 section below and `CHANGELOG.md` for the full 190-finding hardening (M1–M4, documented in `bash-classifier-fix-plan.md` / `bash-classifier-exploits.md` in the repo).

- **Path safety layer** (new `src/security/paths.ts`): every read/write file argument of whitelisted commands is extracted (`--` aware) and checked against a sensitivity registry. Reading `/etc/shadow`, `base64 ~/.ssh/id_rsa`, `cat ~/.kube/config`, `git add .env` → **LOOSE ASK / HARD DENY**; writing system-write/credential paths (`> /etc/passwd`, `chmod`, `tee`, data exfiltration sinks) → **LOOSE ASK / HARD DENY**; writes inside the working tree (non-sensitive) are now **ALLOW**.
- **Provably-safe guard**: unquoted `$`/`` ` ``/glob/brace expansion, and sensitive inline env prefixes (`PATH=... , LD_*, DYLD_*, PYTHONPATH, BASH_ENV`, ...) disqualify a segment from static `ALLOW` (fail-closed → ASK).
- **Area assertions verified**: disposable / recycle-bin / backup-copy allowances now confirm every target lexically resolves (no `..`, no glob/var) inside the worktree or trustable temp.
- **M2 destructive rules**: find root-delete, fork bombs, device/disk writes, kernel triggers (`/proc/sysrq-trigger`, `core_pattern`), reverse shells, `curl|bash`, script one-liners (`python -c 'rmtree("/")'`), exfiltration, compression-destruction, `chmod`/setuid, firewall flush, kernel-module load, and WSL payloads — with quote-stripping, brace, ANSI-C and variable-indirection surfaces.
- **TOCTOU**: local-script fingerprints now also record the link identity (`dev/ino/mtime` + canonical path) and re-verify it before execution, closing the symlink-swap window.
- **Dynamic reviewer**: thinking-block suppression (`chat_template_kwargs.enable_thinking`, `_strip_thinking`), 429 exponential-backoff ×2 / 5xx ×1 retries, hardened LOOSE/HARD prompts, and a static-layer-self-sufficiency declaration. `PROMPT_VERSION` bumped to v2 so stale cache entries are not reused.
- **M3 usability with safety net**: HARD now allows `rm -rf` of in-worktree disposable dirs (`node_modules`, `dist`, `build`, `coverage`, `target`, `.cache`, `.venv`, `.next`, `out`, `.gradle`, `__pycache__`, ...); safe in-worktree redirects, https downloads to the worktree, `make clean`, `crontab -l`, `pip uninstall`, and more are statically allowed — all with the path layer + expansion guard in front.
- **M4 efficiency**: dynamic-ALLOW cache keys are normalized for known read-only patterns (`docker logs <name>`, `kubectl logs|get|describe <pod>`, read-only `psql -c`).

Behavior changes are intentional: some previously-`ASK` commands are now static `DENY` (sensitive reads/writes, destructive one-liners), and some previously-`ASK` commands are now static `ALLOW` (worktree writes, disposable cleanup, read-only inspection). No `DENY→ALLOW` relaxation was introduced for anything sensitive or destructive.

## Overview

The plugin leaves OpenCode's native Bash tool untouched and classifies every command **before** it runs by registering `tool.execute.before` / `tool.execute.after` hooks. Classification is **static-first**: a fast local classifier reviews each command, and only commands it cannot prove safe (`ASK`) — or commands forced into review by a previous rejection or failure in HARD mode — are sent to the optional dynamic OpenAI-compatible reviewer. That design is what keeps dynamic requests rare; the exact reduction depends on the workload, so no fixed percentage is promised.

The plugin exposes **two user policies**, `LOOSE` and `HARD`. The policy label and the `strictness` value are never sent to the model: the bundled auditor selects an **independent system prompt** for each policy and sends only that prompt together with the review data. Block messages likewise never reveal which policy is active.

It deliberately does **not** replace the built-in Bash tool, so OpenCode's shell selection, quoting, process handling, permission checks, output capture, and TUI rendering are all preserved. The command string itself is never rewritten for classification purposes; two optional hardening features may adjust the tool *arguments* (a default timeout and detached-start handle isolation), never the meaning of the command.

`apply_patch` patches containing a `*** Delete File:` line are blocked statically with a message telling the agent to delete files through bash instead, so both the classifier and OpenCode's permission layer can review the deletion.

```text
native Bash request
  -> local static classifier (per-segment, worst-case combine)
       ALLOW -> OpenCode native Bash
       DENY  -> blocked
       ASK or forced context -> dynamic LLM reviewer (tool-enhanced, OpenAI-compatible)
                  ALLOW -> OpenCode native Bash
                   DENY  -> blocked (HARD: bypass attempts also abort the session)
```

## Installation

### Option 1: let an agent install it (recommended)

In OpenCode, just ask the agent:

> Help me install and configure opencode-bash-classifier (帮我安装并配置opencode-bash-classifier)

The agent performs the installation, writes the `plugin` configuration, and walks you through the optional dynamic reviewer setup.

### Option 2: npm package

Reference the npm package name directly in the `plugin` array of `opencode.json` — OpenCode installs it from npm automatically, no manual global install needed:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    [
      "opencode-bash-classifier",
      {
        "strictness": "HARD",
        "failPolicy": "fail_open"
      }
    ]
  ]
}
```

### Option 3: clone and build locally

```bash
git clone https://github.com/DDwsgood/opencode-bash-classifier.git
cd opencode-bash-classifier
bun install
bun run build
```

Then reference the plugin folder by its absolute path in `opencode.json`:

```json
{
  "plugin": [
    [
      "<absolute-path-to-plugin>",
      {
        "strictness": "HARD",
        "failPolicy": "fail_open"
      }
    ]
  ]
}
```

`<absolute-path-to-plugin>` is the absolute path to the plugin folder on your machine. For a local install that also wants the Windows process supervisor, run `bun run build:supervisor` once before restarting (see below).

All three options require **restarting OpenCode** after installation or configuration changes. See [Configuration](#configuration) for the full option list. Without a `dynamicReview` block the dynamic reviewer is unavailable and the [`failPolicy`](#fail-policy) takes over — if you do not want a dynamic reviewer, `HARD + fail_open` is the recommended combination.

## Static classification

The local classifier splits chained commands into segments at `&&`, `||`, `;`, newlines, `|`, and `&`, then reviews each segment independently and aggregates with the **worst** result: any `DENY` blocks the whole command, any `ASK` defers the whole command to dynamic review, and only commands where every segment is `ALLOW` run without review. Common `timeout`, WSL, subshell, and heredoc forms are handled conservatively; complex or unparseable syntax falls back to `ASK`.

### Directory-change (`cd`) tracking

`cd`/`pushd`/`Set-Location` segments change the base directory used to resolve literal targets in the *following* segments, but the changed base is propagated **only through consecutive success-required `&&` chains**. After a `||`, `;`, newline, pipe (`|`), or background (`&`) connector, the next segment resolves against the original working directory again — the changed directory does not leak across those connectors. For example `cd /tmp && rm -rf x` resolves `x` against `/tmp`, while `cd /tmp; rm -rf x` resolves `x` against the original working directory.

### LOOSE (default) — good faith, but no accidental data loss

LOOSE assumes a well-intentioned developer and exists to prevent accidental, irreversible loss of durable data.

- **Named temp deletion**: a pure deletion command (`rm`, `Remove-Item`, and equivalents, through bash/PowerShell/WSL/cmd/encoded wrappers) is allowed only when **every** permanent deletion target resolves, against the current base directory, to a path that contains a complete, case-insensitive directory segment exactly `temp` or `tmp`. Substring matches such as `template`, `tmp-marker`, `attempt`, or `.tmp` inside a longer name do **not** qualify. A `..` segment in any target disqualifies it, and a mixed target list cannot be shielded — one temp target does not excuse the others.
- **User Local Temp**: pure delete/copy/move/rename operations strictly below the canonical `%LOCALAPPDATA%\Temp` directory (resolved with `realpath`, with `..` and junction/symlink escapes rejected) are allowed.
- **Backups**: a backup name (`.backup`, `-backup`, `.bak`, `-bak`, optionally followed by digits) may be created only by copying; moving/renaming into a backup name is denied. Permanent backup deletion is allowed only for a standalone, verified target where an exact same-directory original exists, filesystem types match, and the backup is older than two minutes.
- **Data files**: deleting `.csv`, `.json`, `.yaml`, `.db`, `.sqlite`, `.xlsx`, `.pdf`, and similar durable files is not statically denied — it becomes at least `ASK` and is evaluated on concrete scope and directory contents. Permanent deletion of critical credential material — `.env`, `.pem`, `.key`, `.p12`, and similar private-key files — is statically `DENY`.
- **Recycle bin**: a real, pure move to the OS trash/recycle bin is allowed, even for project-looking targets; emptying, purging, or directly deleting items inside the recycle bin is denied.
- **Normal work**: common test runners, builds, package installs, read-only inspection commands, everyday git operations (including non-forced `push`/`pull`/`switch`/`merge`; force pushes still require review), and narrowly scoped cleanup of disposable targets (`node_modules`, `dist`, `build`, `coverage`, caches) are statically allowed.
- **Local scripts**: local scripts inside the worktree are read (up to 256 KB each, up to 8), fingerprinted, and scanned for delete/kill/write primitives. A script that was fully read, fingerprinted, and contains no review-requiring behavior is statically allowed; a script containing `rm`, `pkill`, writes, or similar primitives sends the command to dynamic review.
- **Dynamic ALLOW cache**: successful dynamic `ALLOW` results may be cached for 30 minutes (bounded to 512 entries) so an identical command is not re-sent; the cache only applies in LOOSE mode, is skipped when the static context is not fully inspectable, and dynamic `DENY` is never cached.

### HARD — strictest, no relaxations

- All forced recursive deletions are statically `DENY` **except** the M3 disposable-dir exemption: `rm -rf` (and equivalent) of a recognized in-worktree disposable directory (`node_modules`, `dist`, `build`, `coverage`, `target`, `.cache`, `.venv`, `.next`, `.turbo`, `.nuxt`, `__pycache__`, `.pytest_cache`, `out`, `.gradle`) — literal, no `..`/glob/var — is `ALLOW`. The PowerShell `rmdir -Recurse -Force` alias form is *not* exempt and stays `DENY`.
- There is **no** temp/tmp, Local Temp, or backup exception in HARD mode; deleting any named temp, Local Temp, or backup target is denied.
- Permanently deleting **or moving to the recycle bin** a durable data file is denied; other genuine recycle-bin moves are statically allowed — moving an item to the OS recycle bin is recoverable and no longer consumes a dynamic review.
- Emptying, purging, or directly deleting items inside the recycle bin is denied.
- No caching of dynamic `ALLOW` results.
- After **any** rejection, the next bash command is forced through dynamic review with the previous rejection attached as context; the reviewer must return `{decision, reason, bypassing}`, and a detected bypass (`bypassing: true`) blocks the command and best-effort aborts the session via `session.abort`.
- The dynamic reviewer runs its most pessimistic prompt: no temp/backup/recycle-bin/rm-rf relaxations, and ambiguity leans toward `DENY`.

### Compound-command examples

| Command | LOOSE | HARD |
|---|---|---|
| `rm -rf ./tmp/x && rm -rf important` | DENY (second segment is a forced recursive delete) | DENY |
| `rm -rf ./tmp/x && echo removed` | ALLOW (temp segment + harmless tail) | DENY (forced recursive delete) |

### Blocked-command messages

Every **final** static, dynamic, and `fail_close` block appends the following suffix **verbatim**:

> DO NOT retry the same command or try using alternative method.Skip the step or stop and report the user if it's a essential step of the work

In HARD mode an additional, command-family-specific retry prohibition is inserted before the suffix when the block reason matches a deletion family (for example, "DO NOT retry any rm -rf, split -r/-f, recursive Remove-Item, or equivalent deletion commands."). The visible message never names the active policy.

`fail_ask` is **not** a final rejection: it explains the approval flow and asks the agent to call `bash_classifier_confirm` with the printed `requestId` (see below), and it does not carry the suffix. The separate `apply_patch` routing error instead tells the agent to delete files through bash.

## Dynamic LLM reviewer

The bundled `auditor.py` is an independent, provider-neutral reviewer that talks to any **OpenAI-compatible** endpoint. It uses only the Python standard library and runs with `-I -B` isolated flags. It requires an endpoint that supports:

- OpenAI-compatible **tool calling** (function calling) with a `tools` array;
- **JSON object** output mode (`response_format: {"type": "json_object"}`).

Only endpoints you have verified to support both requirements will work; no provider capability is claimed here.

> **Mind the terms of service**: the configured endpoint must allow calling the model through its **API/SDK**. Many subscription "coding plans" only permit using the model inside the provider's own designated coding tools; redirecting that allowance to a third-party caller like this plugin may violate the provider's terms and **can get your account banned**. Before enabling the dynamic reviewer, confirm that your provider explicitly allows this kind of usage.

### Round budget

`maxRounds` is the number of rounds in which tool calls are allowed: **LOOSE defaults to 1 (configurable 1–3), HARD defaults to 2 (configurable 1–5)**. Once the round budget is exhausted, the auditor makes one final request with tools disabled to force a conclusion, and the whole review may use at most **8 tool calls** in total. For reasonable latency prefer a low-latency, lightweight model without a thinking mode.

### Result contract

The model must return exactly one JSON object in every final answer:

- LOOSE: `{"decision": "ALLOW"|"DENY", "reason": "..."}` — `ALLOW` requires an empty reason.
- HARD: `{"decision": "ALLOW"|"DENY", "reason": "...", "bypassing": boolean}`.

Neither the policy label nor the `strictness` value is included in the model payload; the policy merely selects which system prompt the auditor sends.

### Configuration requirements

- There is **no default provider, URL, model, or API key**. `dynamicReview` must provide `baseURL`, `model`, and exactly one of `apiKey` or `apiKeyEnv`.
- `baseURL` is an OpenAI-compatible base URL; `/chat/completions` is appended if not already present. **HTTP is allowed only for loopback hosts** (`localhost`, `127.*`, `::1`); any remote endpoint must use **HTTPS**. URLs containing userinfo or a fragment are rejected.
- Redirects are **not** followed.
- `apiKeyEnv` names an environment variable the key is read from (the name must be a valid identifier). The plugin never reads `~/.env` and never falls back to `API_KEY`-style variables.
- Missing or invalid dynamic configuration makes the **reviewer unavailable** — the plugin still loads and runs normally; the configured fail policy then governs. An unconfigured reviewer is not a plugin startup failure.
- Config changes require restarting OpenCode.

### What the reviewer can see (data disclosure)

For `ASK` (or forced) commands the following is sent to the configured endpoint:

- the exact command, and the canonical `cwd` / worktree paths;
- up to 8 inspected local scripts (each ≤ 256 KB, at most 256,000 attached script characters total; the whole review package is capped at 1 MB);
- bounded, non-recursive directory-entry listings for deletion targets (≤ 4 directories, ≤ 200 entries each);
- paths explicitly referenced by the command (bounded, with a truncation flag);
- bounded context from a previous rejection (HARD) or a previous failure in the same session (including a short output tail).

The API key itself is sent **only** in the `Authorization` header of requests to the configured endpoint (redirects are not followed). Remember that command lines, paths, and local source code can be sensitive; weigh this before enabling a third-party reviewer, and prefer ZDR (as a privacy-conscious hosting choice), a self-hosted endpoint, or disabling the reviewer for sensitive work.

### Auditor read access and sensitive files

The reviewer has exactly two local, read-only tools — `read_file` and `list_directory`. There is **no glob** tool. Both tools stay read-only and bounded (256 KB per read, 200 entries per listing), treat results as untrusted data, and reject:

- sensitive paths: `.env`, `.env.*`, and `*.env` (for example `api-key.env`); private-key material (`.pem`, `.key`, `.p12`, `.pfx`, `.ppk`, `.jks`, `.keystore`, `.kdbx`, `.gpg`, `.age`); npm/pypi config (`.npmrc`, `.pypirc`); `.netrc`; and `.ssh`, `.gnupg`, and `.aws` — a path with any of these as a directory component is forbidden in full, including every descendant, so nothing inside those directories can be read or listed (not just `.aws/credentials`);
- symlinks, junctions, reparse points, devices, and other non-regular files.

`dynamicReview.allowFullReadAccess` (user-facing concept `ALLOW_FULL_READ_ACCESS`; the public JSON field is the camelCase name) defaults to `false`, in which case the tools may only inspect:

- the canonical working directory of the command, and below;
- system temporary roots — on Windows `os.tmpdir()` (the user's temp) plus `%LOCALAPPDATA%\Temp`; on Linux `/tmp` and `os.tmpdir()`;
- exact paths explicitly referenced by the command (an explicit file authorizes only that file; an explicit directory authorizes only listing that directory).

Setting it to `true` lets the bounded read-only tools inspect ordinary files and directories anywhere on the filesystem; sensitive files, links, reparse points, devices, and non-regular files remain forbidden either way. The broader the access, the more project data a third-party endpoint could receive — choose deliberately.

Inspection failure is mode-dependent: LOOSE decides from the remaining visible context with a good-faith bias, while HARD refuses `ALLOW` when a declared uninspected script or target cannot be inspected completely and reliably.

### Fail policy

When the reviewer is unconfigured, unavailable, times out, or returns an invalid result, the `failPolicy` decides:

| Policy | Meaning |
|---|---|
| `fail_open` (default) | Let the command proceed. |
| `fail_close` | Block the command. |
| `fail_ask` | Human-in-the-loop: the command is blocked and a `bash_classifier_confirm` tool is offered to request user approval. |

Recommended combinations:

- **No dynamic reviewer**: use **HARD + `fail_open`** — every strict static `DENY` still applies, `ASK` commands proceed while the reviewer is absent, and the agent is never interrupted.
- **`fail_ask` is not recommended**: every reviewer outage or failure turns a questionable command into a manual confirmation, which heavily disrupts agent activity. Choose it only when you truly need a human veto on every questionable command.
- **HARD + `fail_close`** is the strictest unattended configuration: every `ASK` command is blocked while the reviewer is absent.
- **LOOSE + `fail_open`** is the most permissive unattended configuration: a reviewer outage silently disables the semantic layer, leaving only the static classifier. Use only if you accept that risk.

The default is `fail_open`.

### Human approval (`fail_ask`)

Because a `before` hook cannot create a native permission prompt itself, the plugin registers a custom tool, `bash_classifier_confirm`, which calls OpenCode's `context.ask`. The blocked message tells the agent to call it with the printed `requestId`; the pending request expires after **5 minutes**. Before approval the agent must not retry the command or use an alternative; if the user approves, only the **exact** command — matching command, working directory, and strictness fingerprint — is allowed **once**; a stale approval for a different command is discarded. OpenCode's own permission configuration still applies afterwards and may approve or deny via UI or auto-approval settings.

### Rejection / failure escalation (session-scoped)

- **HARD only**: after **any** static, dynamic, or policy rejection, the next bash command in the session is forced through dynamic review regardless of its static result, with the previous rejection attached as context. The reviewer must return `{decision, reason, bypassing}`; if it judges the new command to be a bypass (`bypassing: true`), the command is blocked and the session is aborted via `session.abort`. LOOSE never records rejections and performs no bypass detection.
- **HARD only**: after a bash command **exits non-zero**, the **next** bash command in that session is forced through dynamic review with the failure context (command, exit code, bounded output tail) attached: a static `ALLOW` or `ASK` result is always handed to the reviewer, while a static `DENY` stays a static block and does not consume the failure record. An ordinary successful command does not clear a pending failure; only the forced review run that consumed it does. LOOSE never records failures and performs no failure escalation.
- All state (`lastRejected`, `lastFailed`, pending approvals, allow-cache) is per-session, expires after **30 minutes**, is bounded to **512 sessions**, and is discarded immediately when the session is deleted (`session.deleted`).
- Successful dynamic `ALLOW` results may be cached for 30 minutes (bounded to 512 entries) only in LOOSE mode when the static context is fully inspectable; dynamic `DENY` is never cached.

## Configuration

Options live in the OpenCode `plugin` tuple:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": [
    [
      "opencode-bash-classifier",
      {
        "strictness": "LOOSE",
        "failPolicy": "fail_open",
        "dynamicReview": {
          "baseURL": "https://api.example.com/v1",
          "model": "your-model-id",
          "apiKeyEnv": "MY_REVIEW_API_KEY",
          "timeoutMs": 30000,
          "maxRounds": 1,
          "allowFullReadAccess": false,
          "pythonPath": "python",
          "auditorPath": "src/security/auditor.py"
        }
      }
    ]
  ]
}
```

The first tuple element is the npm package name (installed automatically); for a local clone install, use the absolute path to the plugin folder instead. `pythonPath` may be a bare interpreter name (resolved through PATH at spawn time) or a package-relative path to an existing interpreter; `auditorPath` resolves against the package root. Restart OpenCode after changing any of these options.

| Option | Type | Default | Description |
|---|---|---|---|
| `shell` | string | OpenCode's shell | Real-shell override; also the classifier's dialect hint. |
| `securityEnabled` | boolean | `true` | Enable the classifier hooks entirely. |
| `strictness` | `"LOOSE" \| "HARD"` | `"LOOSE"` | Selects the static ruleset and the dynamic system prompt. |
| `failPolicy` | `"fail_ask" \| "fail_open" \| "fail_close"` | `"fail_open"` | Behavior when the reviewer is unavailable or fails. |
| `dynamicReview.baseURL` | string | — | OpenAI-compatible base URL (`/chat/completions` is appended). HTTP only for loopback hosts; remote endpoints must use HTTPS. |
| `dynamicReview.model` | string | — | Model ID. |
| `dynamicReview.apiKey` | string | — | API key (exactly one of `apiKey` / `apiKeyEnv`). |
| `dynamicReview.apiKeyEnv` | string | — | Name of the env var holding the API key. |
| `dynamicReview.timeoutMs` | number | `30000` | Python reviewer timeout (1–120000). |
| `dynamicReview.maxRounds` | number | LOOSE `1`, HARD `2` | Tool-enabled rounds (LOOSE 1–3, HARD 1–5). |
| `dynamicReview.allowFullReadAccess` | boolean | `false` | Let the auditor's bounded read-only tools inspect the whole filesystem (`ALLOW_FULL_READ_ACCESS`). |
| `dynamicReview.pythonPath` | string | PATH lookup | Python interpreter; a path is resolved against the package root. |
| `dynamicReview.auditorPath` | string | bundled `auditor.py` | Path to the auditor script. |
| `hardTimeoutMs` | number | `120000` | Default timeout applied to non-download/build commands without one; `0` disables. |
| `detachedStartIsolation` | boolean | `true` | Append handle isolation to `start`/`Start-Process` when the supervisor is inactive. |
| `supervisorEnabled` | boolean | `true` on Windows | Use the native shell supervisor when its executable exists. |
| `supervisorPath` | string | package default | Path to the supervisor `bash.exe`. |

The plugin also supports `reviewCommand` for programmatic test injection only; it is never wired by the plugin itself.

## Windows process supervisor

On Windows, OpenCode can keep waiting after a shell exits when a descendant inherits the stdout/stderr pipe. The optional native supervisor fixes that process boundary without changing the agent's command: the real shell starts suspended and enters a Windows Job Object before spawning descendants, inherits private relay pipes instead of OpenCode's pipe handles, and normal shell exit gets a bounded output drain that does not wait for a detached descendant.

The real shell comes **only** from OpenCode's configured shell, injected through the `shell.env` hook as `OPENCODE_REAL_BASH`. There is intentionally **no** hard-coded fallback (e.g. `C:\msys64\usr\bin\bash.exe`) — the supervisor never silently targets the wrong shell. If `OPENCODE_REAL_BASH` is missing, the supervisor exits with status **125**. All run paths used by the plugin are configuration- or package-relative; there is no hard-coded machine path. The injection is scoped to the `shell.env` output and never pollutes the global `process.env`.

Build it once before restarting OpenCode:

```bash
bun run build:supervisor
```

The release executable (`bash.exe`, named so OpenCode keeps Bash-specific argument behavior) is enabled automatically on Windows when it exists; set `supervisorEnabled: false` to disable or `supervisorPath` to point at another build.

## Security boundaries and limitations

- This plugin is a **defense-in-depth guardrail, not an OS sandbox**. It cannot contain a determined malicious payload.
- Build, test, install, and package-management commands can and will execute project code and third-party scripts.
- Static classification and LLM review both make mistakes; treat any `ALLOW` as a risk-reduced but not proven-safe decision.
- With `fail_open` (the current default), a reviewer outage silently widens the policy to static-only — the most permissive unattended posture.
- The dynamic reviewer receives commands, paths, and local script contents; see the disclosure section above before enabling a third-party endpoint.
- OpenCode's native permission system still runs after this plugin's hook and remains the final gate.

## Development

```bash
bun run build          # build the plugin to ./dist
bun run check          # build (alias)
bun run build:supervisor  # build the native Windows process supervisor (cargo)
```

The repository is intentionally kept clean for publishing: no committed test suite and no build caches. Test locally before a release and keep those files out of commits.
