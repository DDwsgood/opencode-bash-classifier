# Changelog

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
