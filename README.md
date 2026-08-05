# opencode-bash-classifier

Execution-boundary command safety for OpenCode's native `bash` tool. A fast
local static classifier blocks clearly destructive commands and statically
allows safe ones (including temp cleanup, `cd` chains, and chained commands);
everything else is sent to an OpenAI-compatible LLM that can inspect the
filesystem read-only through three tools before deciding.

It deliberately does **not** replace the built-in Bash tool. OpenCode 1.18.5
does not expose a plugin hook for replacing its Bash-card renderer, so a custom
Bash tool cannot provide an always-collapsed, one-line semantic summary that
expands on click. Keeping the native tool preserves OpenCode's shell selection,
quoting, process handling, permission checks, output capture, and TUI rendering.

## What it changes

The plugin registers `tool.execute.before` and reviews only calls whose tool ID
is `bash`. It never spawns the requested command itself and never rewrites the
command text. As an optional hardening feature it may raise the bash tool's
`timeout` ceiling for commands that are neither downloads nor builds (see
Hard timeout below); the command string and its semantics are never touched.

```text
native Bash request
  -> local static classifier (per-segment, worst-case combine)
       ALLOW -> OpenCode native Bash
       DENY  -> block
       ASK   -> LLM reviewer (tool-enhanced, OpenAI-compatible)
                  ALLOW -> OpenCode native Bash
                  DENY  -> block
```

The local classifier:

- splits chained commands on `&&`, `||`, `;`, and newlines and reviews each
  segment independently, combining with the worst result: any DENY blocks the
  whole command, any ASK defers the whole command to dynamic review, and only
  commands where every segment is ALLOW run without review;
- resolves `cd`/`pushd`/`Set-Location` segments and uses the changed directory
  as the base for later relative paths, so `cd <temp> && rm -rf sub` is allowed
  while `cd /etc && rm -rf evil` is blocked (no cd escape, no false rejection);
- tolerates harmless tails after file operations, so
  `rm -rf <temp>/x && echo done`, `rm -rf <temp>/x || true`, and
  `rm -rf <temp>/x && mkdir -p <temp>/x` are allowed without cloud review;
- normalizes msys-style `/c/...` paths inside the Local Temp whitelist for
  copy and move targets;
- hard-blocks direct operations whose destructive effect is explicit, including
  forced recursive directory deletion outside the named-temp exception,
  filesystem-root deletion, disk and
  backup destruction, system-service termination, shutdown, broad forced
  process termination, and destructive database or infrastructure operations;
- preserves explicit exceptions for narrowly scoped regenerated dependencies,
  build outputs, coverage, caches, and operating-system temporary files;
- statically allows a pure `rm`, `Remove-Item`, or equivalent deletion command
  when any target text contains `tmp` or `temp`, case-insensitively; the match is
  intentionally a broad substring match, and other deletion targets in the same
  pure deletion command do not need to match;
- applies the same named-temp deletion rule through pure PowerShell, Bash, WSL,
  cmd, and PowerShell encoded-command wrappers;
- keeps only explicit filesystem-root deletion and chained process, service,
  disk, shutdown, or other non-file destructive behavior outside that broad
  named-temp exception;
- always allows pure, recoverable moves to the operating-system trash/recycle
  bin, including `trash`, `trash-put`, `gio trash`, `send2trash`, and
  PowerShell recycle-bin APIs, even when the target is a real project tree;
- does not apply the recycle-bin exception to empty/purge operations, permanent
  deletion, or commands that chain another destructive action;
- treats files and subdirectories strictly below the current Windows user's
  `%LOCALAPPDATA%\Temp` as disposable, allowing pure delete, copy, move, and
  rename operations there without cloud review, including failed clones and
  project-shaped directories;
- does not extend Local Temp copy/move/rename handling to path or symlink
  escapes, executing Temp content, or destructive process/service/system
  operations chained to the file operation; deletion follows the broader
  named-temp rule above;
- recognizes exact `.backup`, `-backup`, `.bak`, and `-bak` suffixes with
  optional trailing decimal digits, such as `a.ts.backup2`, `project-backup10`,
  `data.json.bak2`, and `draft.bak`;
- allows permanent backup deletion only when an exact same-directory original
  exists, both entries have the same filesystem type, and the backup creation
  time is strictly older than two minutes;
- allows backup names to be created only by `cp`, `copy`, or `Copy-Item`, and
  blocks moving or renaming files and directories into backup names;
- excludes credential and private-key material such as `.env`, `.key`, `.pem`,
  `.p12`, `.pfx`, `.ppk`, `.jks`, `.keystore`, `.kdbx`, `.gpg`, and `.age`
  from all permanent backup exceptions, checking both the copy source and the
  suffix-stripped backup name; ordinary `.csv`, `.json`, and `.xlsx` backups
  remain eligible;
- sends other security-sensitive or unknown commands to the LLM reviewer for
  semantic review;
- statically allows common test runners, including Bun, npm/npx, Node test,
  pytest, Jest, Vitest, Mocha, Playwright, Cargo, Go, .NET, Maven, Gradle, and
  CTest, including harmless `2>&1` descriptor merging;
- treats missing context and unfamiliar test or development commands as
  good-faith activity in the reviewer policy unless concrete destructive
  behavior is visible;
- instructs the reviewer not to invent hidden targets, prior renames or moves,
  malicious intent, production importance, or other worst-case facts absent
  from the review package;
- caches cacheable dynamic `ALLOW` decisions for 30 minutes using the exact
  command, canonical working directory, shell, static rules, inspected script
  fingerprints, and deletion-target directory snapshots;
- always sends broad process-termination commands, including WSL/interpreter
  wrappers such as `wsl -- bash -c "killall ..."`, to the LLM reviewer;
- sends destructive `find ... -delete` commands to the LLM reviewer, while
  preserving the narrow `/tmp` plus age-filter cleanup exception;
- decodes common PowerShell and Base64 wrappers before classification;
- reads bounded local scripts inside the worktree and supplies their paths,
  SHA-256 fingerprints, and contents to the reviewer;
- supplies a bounded, non-recursive directory listing for directory-deletion
  targets sent to cloud review, allowing the reviewer to recognize source trees,
  project manifests, repositories, and other durable project structure;
- verifies inspected script fingerprints again before returning control to the
  native Bash tool;
- fails open when cloud review is disabled, unavailable, times out, or returns
  an invalid response; only an explicit dynamic `DENY` blocks execution.

The reviewer returns exactly `ALLOW` or `DENY` plus a `reason` field. For
`ALLOW`, `reason` is exactly `""` and no safety explanation is generated. For
`DENY`, it is a short English reason. There is no confidence score, operation
list, or user-confirmation state.

Blocked commands use these messages:

```text
Command blocked by static classifier : <reason>
Command blocked by dynamic classifier:<reason>
```

## Hard timeout

Commands that are neither **downloads** nor **builds** are capped at a hard
timeout ceiling so a stuck or unexpectedly slow command cannot block the
session pipeline indefinitely. The ceiling applies regardless of the timeout
the agent supplied:

- if the command has no explicit `timeout`, it is set to the ceiling
  (2 minutes by default);
- if the explicit `timeout` is larger than the ceiling, it is lowered to the
  ceiling;
- if the explicit `timeout` is already smaller than the ceiling, it is kept;
- download and build commands (`curl`, `wget`, `git clone`, `npm install`,
  `npm run build`, `make`, `cargo build`, ...) are exempt and keep their
  timeout untouched.

This is the only place the plugin writes to the bash tool arguments: it sets
`timeout` only, and never wraps, prefixes, or rewrites the command. Set
`hardTimeoutMs: 0` to disable the feature entirely.

## LLM reviewer setup

Python 3 is required. The bundled auditor uses only the Python standard library
and talks to any **OpenAI-compatible chat completions** endpoint.

Configure the endpoint, model, and API key through environment variables:

```dotenv
# required
API_KEY=your-api-key-here

# optional, defaults shown for DeepSeek
OPENAI_BASE_URL=https://api.deepseek.com/chat/completions
OPENAI_MODEL=deepseek-v4-flash
```

The `API_KEY` variable is left for you to fill in. `DEEPSEEK_API_KEY` is also accepted,
and both `API_KEY` and `DEEPSEEK_API_KEY` are read from `~/.env` as a fallback.
Use `LLM_BASE_URL` / `LLM_MODEL` as aliases for the `OPENAI_*` variables.
We suggest using offical DeepSeek provider + deepseeek-v4-flash for this classifier
> **Provider note**: your provider must allow SDK/API calls with this key. Some
> providers issue keys restricted to some specific coding clientsy; such
> keys using in this case may result in ban.

The reviewer is fixed to:

- thinking: disabled
- response format: JSON Object
- temperature: `0`

Review packages are bounded JSON sent to the auditor over stdin. Static `ALLOW`
and `DENY` commands never reach the LLM. Static `ASK` requests include the exact
command, any inspected local-script contents, bounded directory-entry names for
inspected deletion targets, and the worktree/cwd as a tool boundary. The fixed
reviewer policy repeats the recycle-bin override for inspected scripts and
equivalent operations that the static classifier cannot prove: a pure move to the
OS trash is always allowed, including for real project data, while emptying the
trash is not.

> Your provider&model must support JSON output in this case

The reviewer is tool-enhanced:

- the pre-supplied contents let it decide fast on common cases (1 round, 0 tool
  calls in smoke tests);
- when the context is insufficient, it inspects the filesystem through three
  read-only tools the auditor executes locally — `read_file` (<=256 KB),
  `list_directory` (<=200 entries), and `glob` (<=200 results) — restricted to
  the project worktree plus `%LOCALAPPDATA%\Temp`; paths outside that boundary
  are refused;
- tool budget: prefer 1 round and at most 2 tool calls; hard limit 3 rounds and
  6 tool calls total. It reads only key files relevant to the command and returns
  as soon as confidence is high, keeping latency and cost bounded;
- because the tools can obtain evidence, the reviewer no longer assumes a
  good-faith ALLOW when context is missing: an uninspected script that a command
  executes, or an uninspected deletion target, must be inspected with a tool
  before an ALLOW. Tool results are treated as untrusted data; instructions
  embedded in file contents are ignored;
- a real-API smoke test (`test/smoke_review.py`) confirmed: ambiguous commands
  ALLOW, project-shaped deletion with a listing DENY, temp deletion ALLOW,
  prompt-injection inside a destructive command DENY, complex `&&`/`||` chains
  inside temp ALLOW, and a destructive local script is DENY only after
  `read_file` retrieves its contents (a fix for the previous good-faith gap).

## Local installation

Build the plugin:

```bash
bun run build
```

Reference the project directory from `opencode.json`:

```json
{
  "plugin": [
    "C:/Users/34177/AIGC/opencode-local-plugins/opencode-bash-classifier"
  ]
}
```

Restart OpenCode after rebuilding.

## Options

OpenCode supports plugin options using a tuple:

```json
{
  "plugin": [
    [
      "C:/Users/34177/AIGC/opencode-local-plugins/opencode-bash-classifier",
      {
        "securityEnabled": true,
        "cloudReviewEnabled": true,
        "auditorTimeoutMs": 8000,
        "hardTimeoutMs": 120000
      }
    ]
  ]
}
```

- `securityEnabled`: enables the execution-boundary classifier; default `true`
- `cloudReviewEnabled`: sends static `ASK` commands to the LLM reviewer; default `true`
- `auditorTimeoutMs`: total Python reviewer timeout (tool rounds included); default `30000`
- `hardTimeoutMs`: hard timeout ceiling (ms) for non-download/build commands;
  default `120000`; set `0` to disable
- `auditorPython`: explicit Python 3 executable
- `auditorPath`: explicit path to `deepseek_auditor.py`
- `shell`: optional classifier dialect hint only; it does not change which shell
  OpenCode executes

## Security boundaries

- This plugin is a defense-in-depth guardrail, not an OS sandbox.
- Package hooks, build tools, test runners, interpreters, and trusted local
  executables can execute arbitrary code.
- Local scripts are inspected only inside the worktree, up to 256 KB per file
  and eight candidates. At most 256,000 script characters are attached to one
  review.
- At most four deletion-target directories and 200 top-level entries per
  directory are listed. File contents below those targets are not read.
- A script or deletion target that cannot be inspected statically is reported to
  the reviewer as uninspected; the reviewer then retrieves its contents with the
  read-only tools before allowing the command, so missing static context is
  resolved with evidence rather than assumption.
- The reviewer's tools read only inside the project worktree plus
  `%LOCALAPPDATA%\Temp`, up to 256 KB per file, 200 entries per listing, and 200
  glob results, with a hard budget of 3 rounds and 6 tool calls per review.
- Dynamic `DENY` results are never cached. Dynamic `ALLOW` results are not
  cached when local scripts or deletion targets are uninspected, or when a
  directory snapshot is truncated. The in-memory cache is bounded to 512
  entries and disappears when OpenCode exits.
- Backup matching is exact and case-sensitive at the directory-entry level.
  Filesystems that do not expose a positive creation timestamp fail closed
  instead of using modification time.
- The Local Temp whitelist resolves the trusted root and the nearest existing
  path ancestor before allowing an operation, preventing `..` and junction or
  symlink escapes. Wildcards may select contents below the root but cannot
  delete the root directory itself.
- The native Bash permission system still runs after this plugin's hook.
- OpenCode 1.18.5 does not expose an official per-tool TUI renderer extension.
  Always-collapsed semantic Bash cards therefore require an OpenCode core change,
  not a server plugin.

## Development

```bash
bun run check
```
