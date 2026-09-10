# Changelog

## 0.8.0-v2 (2026-09-10)

- Fix `/bypass-classifier` feedback channels. Previously state/usage was returned via
  `session.synthetic` without a `description`, which made it **model-visible but hidden from the
  TUI transcript** (v2 synthetic messages enter the model context; description-less ones are
  filtered from chat rows).
- Agent notification now goes through `session.hook("context")`: a short `<system_reminder>`
  warning is re-injected on every step while a bypass is active, and a one-shot "bypass ended"
  reminder fires on expiry. Neither wakes the session.
- Added a lease-expiry sweep (20s) so the expiry transition is observed; lease pruning was
  previously lazy and produced no notification.
- User notification now goes through an event-only RPC (`src/bypass-rpc.ts`) consumed by an
  optional TUI companion (`src/tui.ts`, package `exports["./tui"]`) that shows toasts. No sidebar.
- `/bypass-classifier <invalid>` now fails the command (TUI shows the usage) instead of echoing
  usage to the model. Removed all bypass-related session messages.
- Also fix the same visibility defect in the two adjacent alerts: the dynamic-reviewer outage
  notice and the prompt-injection alert now carry a `description`, so they render in the TUI chat
  (they were previously model-only despite comments claiming TUI visibility).
- State-machine hardening after review: re-arming clears a queued "bypass ended" notice; the
  expiry sweep reports "ended" only when no permanent/inherited bypass remains; notices are
  cleared on session deletion; `armed` vs `updated` now reflects prior state.

## 0.7.3-v2 (2026-09-08)

- Remove the unfinished `hardTimeoutMs` foreground/background timeout mechanism: delete the config option, resolution, and `applyPostChecks` injection. OpenCode's shell tool already applies a 120s foreground default timeout.
- Fix slow-command false positives: expensive home/system roots are now exact-root matches, so scoped directories such as `~/.cache/opencode` and `/proc/self` are no longer flagged.
- Raise the default `slowCommands.maxDepth` threshold from 3 to 16 so explicit bounded `find -maxdepth 4` scans are allowed.
- Fix `findRoots()` so `find -maxdepth 4 /path` and other path-option-before-root forms are parsed correctly instead of being missed.
- Update slow-command block hint to describe the actual bound requirement.

## 0.7.2-v2 (2026-09-05)

- Build dynamic policy from enabled categories; remove bypassed prohibitions and emphasize trusted BYPASS PERMISSION at both ends of the system prompt. Preserve the unconditional safety floor.
- Distinguish normal API/SSH authentication and probe data from credential theft; LOOSE no longer treats missing script evidence as sufficient grounds for rejection. Re-evaluate previous rejections against current permissions.
- Exempt deletion-directory mandatory inspection under HARD filesystem bypass, while retaining executed-script inspection and independent reviewer tool-access limits. Bump verdict cache prompt version to v5.
- Fix findings F1–F3: literal short sleep uses static ALLOW plus the existing duration guard; bounded worktree file globs for a small read-only command set use concrete-path checks; simple backticks share recursive read-only substitution review with $(). Keep dynamic/ambiguous substitutions, sensitive paths and symlink escapes conservative.
- Add Bun static/security regressions and Python policy-combination/inspection regressions.

## 0.7.1-v2 (2026-09-03)

### Changed
- **LOOSE backup-deletion relaxation (static)**: a backup file may now be deleted
  in LOOSE mode whenever it is obviously a backup — its name contains a complete
  separator-delimited backup word (`bak`, `backup`, `old`, `orig`; a substring
  inside a larger word like `bakery` does not count) and the same directory holds
  a similarly named file (the original or another dated copy). This replaces the
  exact-suffix-only rule (`.bak`/`.backup` with exact original, same kind, older
  than two minutes) for LOOSE; dated and prefixed backup names
  (`db-backup-20260813.sql`, `backup-config.json`) are now statically ALLOWed
  instead of falling to the dynamic reviewer. Credential/private-key backups
  (`.env.bak`, `id_rsa.backup`) remain DENY. HARD mode is unchanged.
- **Dynamic reviewer LOOSE prompt** updated to mirror the same rule, and
  `PROMPT_VERSION` bumped v3 → v4 to invalidate cached verdicts.

## 0.7.0-v2 (2026-09-01)

User-configured bypass escape hatches to cut false positives and over-caution, plus
reviewer prompt hardening. All findings from the post-implementation review round
(A1–A3, B1–B5, C1–C2, D1–D6, E1–E4) are fixed.

### Added
- **`BypassClassifier` (permanent)**: config field listing categories whose static
  checks are exempted — `filesystem` / `os` / `secret` / `dynamic` / `web`
  (unknown categories warn and are ignored).
- **`/bypass-classifier <category|all|off>` (temporary)**: server-registered slash
  command; arguments never enter model context. Implemented as an in-memory
  activity-renewed lease (TTL `bypassLeaseTtlMs`, default 20 min, range 1 min–24 h)
  renewed on session activity events, expiring when the TUI stays quiet or the
  service restarts. Arming is additive; `off` resets then arms.
- **Subagent propagation** (`bypassPropagateToSubagents`, default on): child
  sessions union all live ancestor leases; child activity renews ancestor leases.
- **Non-bypassable floor**: literal root/system-root deletion (`rm -rf /`,
  `rm -rf /etc`, brace/root-glob/find-root deletes), disk destruction, fork bombs,
  kernel triggers, and reverse shells stay DENY under every armed category.
- **Dynamic reviewer bypass rules**: per-category BYPASS RULE system-prompt blocks
  (filesystem/os/secret/web) telling the model what the user declared trusted,
  with the floor explicitly kept DENY. Environment line (OS name via
  /etc/os-release, shell) now sent with every review.

### Changed
- **Reviewer user prompt restructured** for injection resistance: header
  `Inspect the following command.` + environment line, command wrapped in
  `<data></data>` with XML-escaped content (a literal `</data>` can no longer break
  out) and `[DATA]` reminders every 1500 chars, tail anchor after the block.
  Context JSON no longer contains the raw command.
- **Prompt wording accuracy**: the marker claim now describes exactly which fields
  carry `[untrusted user data]` (command, local script contents, previous-command
  fields) instead of claiming every JSON string is marked.
- **`config.json` layering**: the package-root `config.json` is now always the base
  layer; `options.configFile` overlays it; `options` overlay both, field by field.
- **`operation.unknown` fallback**: with any bypass category armed, commands whose
  firing checks were all absorbed return `bypass.static-allow` ASK (consistent with
  the armed BYPASS RULE at the reviewer) instead of "cannot prove safe".
- **Network trigger matching**: network clients (`curl`/`wget`/`ssh`/`scp`/`rsync`/…)
  are matched as command words only, so paths like `~/.ssh/id_rsa` no longer wrongly
  defeat a `secret` bypass.

### Fixed
- Lease prune no longer drops child→parent links (only `session.deleted` clears
  them, and deletion now also removes links pointing to the deleted parent);
  `activeBypass` unions the whole ancestor chain; renewal covers ancestors.
- Credential rules (`data.critical-*`, `filesystem.critical-backup`,
  `permissions.sensitive-mode`, `filesystem.compression-sensitive`) follow the
  `secret` category; HARD/LOOSE deletion and backup policies gate each DENY
  per-rule, so `filesystem` alone no longer disables secret checks and `secret`
  alone clears `rm -f .env` style deletions at the dynamic reviewer. Recycle-bin
  findings and HARD recycle-block returns (`data.critical-delete`,
  `data.destructive-delete`, `filesystem.protected-target-delete`) are gated the
  same way.
- `network.`-prefixed rules (`destructive-api`, `firewall-mutate`) now follow `web`;
  `hard.named-temp-delete` / `hard.backup-target-delete` / `hard.local-temp-delete`
  follow `filesystem`; `filesystem.backup-destruction` maps to `filesystem`
  (snapshot/recovery destruction is data destruction); recycle-bin permanent
  delete maps to `filesystem`.
- Heredoc findings, `execution.local-script`, and `execution.local-script-signal`
  respect armed categories.
- **Floor hardening (segment-split evasion)**: fork bombs
  (`:(){ :|:& };:`, one-sided pipe recursion `f(){ f | g; }; f`, `while :; do
  $0& done`), kernel-trigger writes (`echo x | tee /proc/sysrq-trigger`,
  `cp x /proc/sysrq-trigger`, sysctl-style `kernel.core_pattern=`), and
  core_pattern writes are now judged on the full script, because the `&`/`|`
  inside these shapes previously split them into per-segment pieces the rules
  never saw — the fork-bomb rule did not fire on the canonical shape even
  without any bypass. The fork-bomb predicate now treats quoted spans as inert
  data, requires the function name as the command word of a pipe side
  (recursion core; `build(){ npm run build | tee log; }; build` stays allowed),
  and fixes the `while :`/`while [ … ]` boundary that made those alternatives
  dead. The kernel predicates are command-position anchored (so `echo tee
  /proc/…` inert text does not match) and accept quoted destinations with
  trailing comments/redirections.
- The system-root deletion floor (`rm -rf /etc`) now matches only the bare root
  or a direct glob over it (`/etc/*`, `/etc*`) — never deeper paths
  (`/var/tmp/...`, `/home/user/project/...`), which the filesystem bypass
  covers. One shared `SYSTEM_CRITICAL_ROOTS` list now drives both `rm -rf` and
  `find … -delete` floors (etc/usr/bin/sbin/boot/var/home/root/opt/lib/lib64/
  srv/sys/proc/mnt), so they cannot disagree; `/lib64` and `find /lib64
  -delete` are covered.
- Environment line reports the OS name (e.g. "Ubuntu 24.04 LTS WSL") instead of a
  kernel release, with WSL distro-name dedup.
- `userBypass` is sorted to match the dynamic cache key (one key ⇒ one prompt
  ordering).

### Known issues
- None currently. (The previous fork-bomb gap — `:(){ :|:& };:` evading the
  dedicated rule via segment splitting — was fixed with full-script floor checks.)

## 0.6.1-v2 (2026-08-26)

Comprehensive audit round (attack-surface gap analysis + adversarial LLM probing of
DeepSeek-V4-Flash and GLM on an OpenAI-compatible gateway). Findings and fixes:

### Fixed
- **Security (`git.remote-history-rewrite`)**: force-push / mirror push / remote
  branch & tag deletion / `update-ref` / `filter-branch`/`filter-repo` are now
  DEFINITE DENY in both policies (previously only an ASK signal, and several
  shapes — `--mirror`, `--delete`, `-C` prefix, delete-refspec — fell through to
  plain `operation.unknown`). `--force-with-lease` stays an ASK signal.
- **Security (`filesystem.root-glob-delete`)**: `rm -rf /*`, `rm -rf /etc*` and
  other absolute glob forced deletes are DENY (temp-area globs exempted).
- **Security (git hooks)**: writing into `/.git/hooks/` is ASK (LOOSE) / DENY
  (HARD); previously `cp evil.sh .git/hooks/pre-commit && chmod +x … && git commit`
  ran planted hooks through a fully ALLOWed chain.
- **Security (PowerShell pipeline delete)**: `… | Remove-Item` joins the
  destructive-pipeline rule (previously only `… | xargs …` was caught).
- **Security (at/systemd-run persistence)**: one-shot at/systemd-run timers join
  the persistence review signal.
- **Cache (dynamic-review poisoning)**: the psql cache-key normalizer no longer
  collapses `begin`/`prepare`/`values`/`with` SQL, and `select`/`show`/`describe`/
  `explain`/`vacuum`/`analyze` payloads are only collapsed when they contain no
  write keyword and no known side-effecting function. Previously a cached ALLOW
  for `psql -c "select 1"` was reused for `insert`/`prepare`/`pg_terminate_backend`
  payloads without review.
- **Security (local-script exfil)**: `hasExfilOrDangerousPerms` now also runs
  against inspected script content, so `bash script.sh` containing `curl -T` /
  `scp` uploads of sensitive data surfaces a review signal instead of ALLOW.
- **Security (named temp under /tmp worktrees)**: the named-temp whitelist no
  longer fires for every delete when the worktree itself lives under `/tmp` or
  contains a `tmp`/`temp` directory segment contributed by the worktree prefix.
- **FP (disposable cleanup)**: the disposable-directory whitelist now accepts
  quoted targets, long/split flag spellings, nested/ancestor paths
  (`some/pkg/node_modules`, `node_modules/.cache/puppeteer`, `src/generated`),
  brace-expanded targets, and additional generated-artifact names
  (venv, .tox, .mypy_cache, .ruff_cache, .nyc_output, .parcel-cache,
  .sass-cache, storybook-static, playwright-report, test-results, .angular,
  .dart_tool, htmlcov, .eggs).
- **FP (HARD inert echo)**: `echo 'rm -rf /'` no longer trips the HARD
  forced-recursive-delete deny.
- **FP (git clean flag order)**: `git clean -xdf` / `-dfx` are now matched
  regardless of flag order.
- **Budget (`slowCommands`, new option, default on)**: safe-but-wasteful commands
  — unbounded scans of system/mounted trees (`find`/`du`/`grep -r`/`rg`/`ls -R`
  over `/`, `/mnt/*`, `/home`, `/usr`, …), streaming commands (`tail -f`,
  `journalctl -f`, `docker/kubectl logs -f`, `watch`, unsteady `ping`/`tcpdump`,
  bare `yes`), and `sleep` at or beyond the 120-second default threshold — are
  DENYed statically with bound-it guidance, unless the caller passes an
  explicit timeout parameter.

### Cache (P2)
- **Global cross-session cache**: cache keys no longer carry the session ID —
  the payload already pins every security-relevant context (script, cwd, shell,
  static rules, fingerprints, directory listings, referenced paths, strictness,
  endpoint, model, prompt version), so identical contexts reuse a verdict across
  sessions. Allow-TTL reduced 30min → 15min to bound staleness.
- **Negative cache (90s)**: dynamic DENY results are replayed for 90 seconds so
  a stubborn model retrying the same denied command stops burning review calls.
- **In-flight dedup**: concurrent identical reviews share one auditor call.
- **Normalizer coverage**: `docker logs --tail N <id>` / `-n` / `--since` / `-q`
  / `-f` and `kubectl logs [-f] [-c container] <pod>` now share one cache entry
  with their bare forms.

### Hardening (P3)
- **`sed -i` durable-data overwrite** no longer rides the provably-safe early
  allow: `sed -i … file.csv|.json|.db|.sqlite|.xlsx|.parquet` is ASK.
- **Brace-expanded disposable cleanup**: `rm -rf src/{dist,output}` is ALLOWed
  when every expansion is an eligible disposable path inside the worktree.
- **Cross-segment variable tracking**: `D=rm; $D -rf ~/x` classifies the
  substituted surface too and keeps the worse verdict (now DENY).
- **Auditor transport resilience**: `_post_chat` retries fast-failing network
  errors (TLS/proxy resets) once within budget; 429 honors `Retry-After` and
  5xx retries with backoff, while other 4xx (auth/client errors) never retry.
  The prompt-injection detector separately retries 403 gateway jitter.

### Considered, intentionally not changed
- `git reset --hard` / `git checkout -- .` stay ASK signals: the dynamic layer
  denies them reliably, and a static DEFINITE deny would break routine
  discard-experimental-changes workflows.

### Auditor prompts (DeepSeek-oriented)
- LOOSE/HARD prompts now deny shared remote Git history rewriting explicitly.
- History clearing / history-file deletion is DENY in LOOSE (was a carve-out the
  model over-applied).
- Process termination is calibrated: PID- or scoped-`pkill` for the user's own
  dev process is ALLOW; broad/system termination is DENY.
- LOOSE adds slow-command guidance mirroring the static rule.

### Plugin shape (effect migration)
- **Effect plugin form**: the plugin is now `{ id, effect(ctx) }` whose `effect`
  returns an `Effect.Effect` (was the promise `{ id, setup(ctx) }`). Hook
  callbacks return `Effect`s: `execute.before` blocks route through
  `Effect.tryPromise`'s `catch` as a single-call typed `Tool.Error` failure
  (`catchTag("Tool.Error")` discriminates by `_tag`, so the rejection object
  need not be a real `Tool.Error` instance), `execute.after` swallows errors
  (`Effect.catchAll`), `shell.create.before` is `Effect.sync`, and the
  `session.deleted` consumer is `Stream.runForEach` + `Effect.forkScoped` tied
  to the plugin scope. `ctx.session.*` Effects run against the host-provided
  runtime captured inside `effect` (not a bare `Effect.runPromise`).
- **Fail-close protocol routing + injection detector**: under HARD, a
  protocol-class `ReviewError` (oversized payload, bad auditor shape/exit) is an
  **unconditional fail-close** regardless of `failPolicy`; under LOOSE every
  review failure — protocol or infra — honors the configured `failPolicy`
  (the auditor never enforces mandatory inspection under LOOSE). An infra-class
  error or unknown non-`ReviewError` honors `failPolicy` in both modes. On HARD
  + protocol with a configured
  reviewer endpoint, the prompt-injection detector is tripped: `injection:true`
  blocks + interrupts the session (with a `resume:false` synthetic warning);
  detector failure (`undefined`) fail-closes with a note; `false` still
  fail-closes (a protocol violation always denies). HARD bypass/abort timing
  fixed: the interrupt is fire-and-forget-delayed so the block message stays
  the visible outcome (was rewritten to STEP_INTERRUPTED when it landed first).
- **hardTimeoutMs no longer overrides background**: the `hardTimeoutMs`
  injection in `applyPostChecks` is skipped when `input.background === true`
  (v2 background runs have no default timeout and would otherwise be
  force-killed).

## 0.5.1-v2 (2025-08-18)

Synchronized with the v1 branch (`0.5.1`): the classifier and auditor sources are byte-identical to v1.

### Fixed
- **Security (`rmdir` forced-recursive hole)**: `rmdir` is `Remove-Item`'s alias on PowerShell/cmd, so `rmdir -Recurse -Force x`, `rmdir -R -F x`, and `rmdir /s /q x` are forced recursive deletes. 0.5.0 treated any `^rmdir` as known-safe in LOOSE, letting them through as `ALLOW`. Now only the plain empty-directory form is provably safe; recursive flag forms fall through to destructive-delete rules (`DENY`).
- **LOOSE false positives restored**: `Remove-Item -LiteralPath ".\dist" -Recurse -Force` and `rm -Force -Recurse .\node_modules` (in-worktree disposable cleanup) are `ALLOW` again.

### Chores
- Removed the local test script (`native/windows-bash-supervisor/test/integration.mjs`) and dropped it from the npm `files` list; removed build caches (`target/debug`, `__pycache__`). The compiled release supervisor binaries (`target/release/*.exe`) remain shipped in the npm tarball.
- Version `0.5.0-v2` → `0.5.1-v2` (the `-v2` marker keeps the v2 build distinct from v1 on npm under the shared package name).

## 0.5.0-v2 (2025-08-18)

v2 plugin API port (`{ id, setup(ctx) }` promise plugin) with the M1–M4 security hardening: path safety layer (`src/security/paths.ts`), provably-safe guard, verified area assertions, M2 destructive rules, TOCTOU fingerprint verification, hardened dynamic reviewer, M3 whitelist, M4 cache-key normalization. Details in `bash-classifier-fix-plan.md` / `bash-classifier-exploits.md`.
