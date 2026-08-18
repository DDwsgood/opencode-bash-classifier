# Changelog

## 0.5.1 (2025-08-18)

Synchronized with the v2 branch (`0.5.1-v2`). Fixes identified by the v1 test suite during the 0.5.0 port, now applied to **both** branches so the classifier/auditor sources are byte-identical.

### Fixed
- **Security (`rmdir` forced-recursive hole)**: `rmdir` is `Remove-Item`'s alias on PowerShell/cmd, so `rmdir -Recurse -Force x`, `rmdir -R -F x`, and `rmdir /s /q x` are forced recursive deletes. v0.5.0 treated any `^rmdir` as known-safe in LOOSE, letting them through as `ALLOW`. Now only the plain empty-directory form is provably safe; recursive flag forms fall through to destructive-delete rules (`DENY`).
- **LOOSE false positives restored**: `Remove-Item -LiteralPath ".\dist" -Recurse -Force` and `rm -Force -Recurse .\node_modules` (in-worktree disposable cleanup) are `ALLOW` again — the quote-stripped surface no longer suppresses disposable-cleanup recognition, and flag-interleaved PowerShell `rm` forms reach the generic parser.

### Chores
- Removed the local test suite and build caches from the repos per repository hygiene (`test/`, `native/.../test/integration.mjs`, `__pycache__`, `target/`); `package.json` test scripts dropped accordingly.
- Version: v1 `0.5.1`, v2 `0.5.1-v2` (the `-v2` marker keeps the two builds distinct on npm under the shared package name).

## 0.5.0 (2025-08-18)

v1 port of the M1–M4 security hardening from the opencode v2 build. The static classifier changed from "command name whitelisted => safe" to **provably safe** (path safety layer + expansion/env guards + verified area assertions). See `bash-classifier-fix-plan.md` for the full design and `bash-classifier-exploits.md` for the 190 finding audit that drove it.

### Added
- **`src/security/paths.ts`** — path safety layer: per-command read/write path extraction (`--` aware) against a sensitivity registry (critical reads, credentials, system-write) with LOOSE/HARD verdict matrix.
- **M2 destructive rules**: find root-delete, fork bombs, device/disk writes, kernel triggers (`/proc/sysrq-trigger`, `core_pattern`), reverse shells, `curl|bash`, interpreted one-liner destruction, exfiltration, compression destruction, `chmod`/setuid, firewall flush, kernel-module load, WSL payloads — with quote-stripping / brace / ANSI-C / variable-indirection surfaces.
- **TOCTOU**: local-script fingerprints record symlink identity (`dev`/`ino`/`mtime` + canonical path) and re-verify before execution.
- **M3 whitelist with safety net**: in-worktree writes, https downloads to the worktree, `rm -rf` of in-worktree disposable dirs (HARD exemption too), `make clean`, `crontab -l`, `pip uninstall`, safe chmod, tar/unzip into worktree, command-substitution nesting, heredoc-to-worktree.
- **M4 cache normalization**: dynamic-ALLOW cache keys normalized for `docker logs/inspect/top/stats`, `kubectl logs/top/get/describe`, read-only `psql -c`.
- **Dynamic reviewer hardening** in `auditor.py`: thinking-block suppression (`enable_thinking`, `_strip_thinking`), 429 ×2 / 5xx ×1 retries, hardened LOOSE/HARD prompts, `PROMPT_VERSION` v2.

### Changed (intended behavior)
- Sensitive reads (`cat /etc/shadow`, `base64 ~/.ssh/id_rsa`, `git add .env`): LOOSE `ASK` / HARD `DENY` (was static `ALLOW`).
- Sensitive/system-write targets: LOOSE `ASK` / HARD `DENY` (was often `ALLOW`/`ASK`).
- Unquoted `$`/glob/brace expansions: no longer statically `ALLOW` (fail-closed `ASK`).
- Interpreted one-liners deleting a root/system path: definite `DENY` (was `ASK`).
- Worktree-internal writes (`echo > file`, `jq > out.json`): `ALLOW` (was `ASK`).
- HARD: `rm -rf` of in-worktree disposable dirs is now `ALLOW` (was `DENY`).

### Fixed (v2 regressions caught by the richer v1 test suite, back-ported)
- `rmdir -Recurse -Force x` / `rmdir -R -F x` / `rmdir /s /q x` no longer slip through LOOSE as known-safe (`rmdir` is a `Remove-Item` alias on PowerShell/cmd) — restored to `DENY`.
- `Remove-Item -LiteralPath ".\dist" -Recurse -Force` and `rm -Force -Recurse .\node_modules` restore LOOSE `ALLOW` (in-worktree disposable cleanup) that hardening had turned into false-positive `DENY`.

### Notes
- Native `windows-bash-supervisor`, `config.ts`, `reviewer.ts`, and `shell-dialect.ts` are unchanged from 0.4.2.
- The v1 plugin API (`{ id, server }` function plugin, `bash_classifier_confirm`, `fail_ask`) is unchanged; this version does not use the v2 `{ id, setup(ctx) }` API.
