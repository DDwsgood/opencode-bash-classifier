// opencode-bash-classifier — opencode v2 plugin API port of the v1 `-next` plugin.
//
// v1 was a function plugin (`{ id, server }`) that registered `config` /
// `shell.env` / `tool.execute.before` / `tool.execute.after` / `event` hooks, a
// custom `bash_classifier_confirm` tool backed by `context.ask`, and used
// `pluginContext.directory/worktree`. v2 has none of those — the plugin is a
// promise plugin `{ id, setup(ctx) }` (see V2-PLUGIN-API.md). This file is the
// port. Every mapping below was verified against ~/src/opencode2 (branch v2):
//
//   1. Entry shape          v1 function plugin        -> { id, setup(ctx) }
//   2. Static+LLM review    v1 "tool.execute.before"  -> ctx.tool.hook("execute.before")
//        tool names         "bash" -> "shell" ("bash" still accepted); "apply_patch" -> "patch"
//        args mutation      output.args.timeout/command -> ev.input.timeout/command
//   3. Failure recording    v1 "tool.execute.after"   -> ctx.tool.hook("execute.after")
//        exit info          output.metadata.exit/exitCode -> ev.result.metadata.exit/exitCode
//        (verified: v2 shell result metadata = { truncated, exit?, shellID?, timeout? })
//   4. Supervisor injection v1 config hook + "shell.env" -> ctx.shell.hook("create.before")
//        (ev.env.OPENCODE_REAL_BASH = ev.shell; ev.shell = supervisorPath; Windows only)
//   5. fail_ask             v1 confirm tool + context.ask -> REMOVED; normalized to fail_close
//        (Tool.Context has no `ask`; a denial is thrown as a Tool.Error-shaped error)
//   6. HARD session abort   v1 client.session.abort   -> ctx.session.interrupt({ sessionID })
//   7. Session cleanup      v1 event hook             -> ctx.event.subscribe() consumer loop
//        (session.deleted wire event: { type, data: { sessionID } }, verified in
//         packages/schema/src/session-event.ts)
//   8. Config source        v1 factory rawOptions     -> ctx.options (+ options.configFile)
//   9. Build                compiled dist             -> plain .ts (no build step)
//
// Rejection semantics (verified in packages/core/src/tool.ts + session/runner/llm.ts):
// `execute.before` is the only fallible tool hook. The session runner only turns
// a failure whose `_tag` is "Tool.Error" into THIS tool call's error
// (catchTag("Tool.Error") -> failTool -> the model reads the message); a plain
// Error would instead fail the whole step. So every block throws a
// Tool.Error-shaped error.

import { createHash } from "node:crypto"
import { access, readFile, realpath } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"
import type { Plugin } from "@opencode-ai/plugin"
import { resolveClassifierShell } from "./shell-dialect"
import { resolvePluginConfig, type BashClassifierOptions } from "./config"
import {
  classifyShellCommand,
  isDownloadOrBuildCommand,
  isolateDetachedStartCommand,
  verifyScriptFingerprints,
  type StaticSecurityDecision,
} from "./security/classifier"
import {
  reviewCommandWithAuditor,
  type CloudReviewRequest,
  type CloudReviewResult,
  type PreviousFailedCommand,
  type PreviousRejectedCommand,
  type ReviewCommandOptions,
} from "./security/reviewer"

// Package root, derived from this module's own URL so relative paths (native
// supervisor, auditor) resolve no matter where the plugin is installed from.
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

const DYNAMIC_ALLOW_CACHE_TTL_MS = 30 * 60 * 1000
const MAX_DYNAMIC_ALLOW_CACHE_ENTRIES = 512
const PROMPT_VERSION = "v2"
const SESSION_STATE_TTL_MS = 30 * 60 * 1000
const MAX_SESSION_STATES = 512
const MAX_OUTPUT_TAIL_CHARS = 2000

const BLOCK_SUFFIX =
  "DO NOT retry the same command or try using alternative method.Skip the step or stop and report the user if it's a essential step of the work"

type SessionState = {
  version: number
  touchedAt: number
  lastRejected?: { value: PreviousRejectedCommand; generation: number }
  lastFailed?: { value: PreviousFailedCommand; generation: number; consumedBy?: string }
}

// --- v2 hook event shapes ---------------------------------------------------
// Local mirrors of the promise shapes in @opencode-ai/plugin/promise/*. The
// plugin must not import host packages at runtime (V2-PLUGIN-API.md §8.7), so
// these stay as plain structural types.

type ExecuteBeforeEvent = {
  readonly tool: string
  readonly sessionID: string
  readonly agent: string
  readonly messageID: string
  readonly id: string
  input: unknown
}

type ExecuteAfterEvent = ExecuteBeforeEvent &
  (
    | {
        readonly status: "completed"
        readonly result: {
          readonly output?: string
          readonly content?: unknown
          readonly metadata?: Record<string, unknown>
        }
      }
    | {
        readonly status: "error"
        readonly error: unknown
      }
  )

// ctx.shell.hook("create.before"): all fields mutable, fired before spawn.
type ShellCreateBeforeEvent = {
  command: string
  cwd: string
  timeout: number
  shell: string
  env: Record<string, string | undefined>
}

// --- blocking helpers -------------------------------------------------------

// A Tool.Error-shaped failure (see the header note on rejection semantics).
function rejectionError(message: string): Error & { readonly _tag: "Tool.Error" } {
  return Object.assign(new Error(message), { _tag: "Tool.Error", _op: "TaggedError" })
}

function conciseReason(reason: string, limit = 160) {
  const value = reason
    .replace(/\b(?:HARD|LOOSE)\b/gi, "policy")
    .replace(/\bdynamicReview(?:\.[A-Za-z][A-Za-z0-9]*)?\b/g, "review setting")
    .replace(/\b(?:strictness|failPolicy|reviewCommand|allowFullReadAccess|maxRounds)\b/g, "review setting")
    .trim()
    .replace(/\s+/g, " ")
    .replace(/[.!?]+$/, "")
  return (value || "Blocked by policy").slice(0, limit)
}

function strictRetryGuidance(reason: string, rules: string[], command: string) {
  if (/DO NOT retry/i.test(reason)) return ""
  if (
    rules.some((rule) => /forced-recursive-delete/.test(rule)) ||
    /\brm\s+(?:-[^\s]*r[^\s]*f|-[^\s]*f[^\s]*r)\b|\bRemove-Item\b[^\r\n]*\b-Recurse\b/i.test(command)
  ) {
    return " DO NOT retry any rm -rf, split -r/-f, recursive Remove-Item, or equivalent deletion commands."
  }
  if (
    rules.some((rule) => /recycle-bin-permanent-delete/.test(rule)) ||
    /\b(?:Clear-RecycleBin|trash[^\r\n]*(?:--empty|--purge)|recycle[^\r\n]*(?:empty|purge))\b/i.test(command)
  ) {
    return " DO NOT retry any recycle-bin empty, purge, permanent-delete, or equivalent commands."
  }
  if (rules.some((rule) => /data\.(?:critical|destructive)-delete/.test(rule))) {
    return " DO NOT retry any deletion, recycle, purge, or equivalent command targeting the same data."
  }
  return ""
}

function blockMessage(
  type: "static" | "dynamic" | "policy",
  reason: string,
  strict: boolean,
  rules: string[] = [],
  command = "",
) {
  const guidance = strict ? strictRetryGuidance(reason, rules, command) : ""
  return rejectionError(
    `Blocked by ${type} classifier: ${conciseReason(reason, type === "dynamic" ? 80 : 120)}.${guidance} ${BLOCK_SUFFIX}`,
  )
}

// failPolicy "fail_ask" normalized to "fail_close" (v2 cannot ask the user, so
// a reviewer outage is always a denial). `normalizedFromAsk` adds an explicit
// note to the message explaining that interactive confirmation is unavailable.
function failClosedBlock(
  reason: string,
  normalizedFromAsk: boolean,
  strict: boolean,
  rules: string[] = [],
  command = "",
) {
  const guidance = strict ? strictRetryGuidance(reason, rules, command) : ""
  const note = normalizedFromAsk
    ? ' Interactive user confirmation is unavailable in v2 (failPolicy "fail_ask" is normalized to "fail_close"); the command is denied.'
    : ""
  return rejectionError(
    `Blocked by policy classifier: ${conciseReason(reason, 120)}.${guidance}${note} ${BLOCK_SUFFIX}`,
  )
}

function applyPatchDeleteBlock() {
  return rejectionError(
    "patch cannot delete files. Use a shell command so the classifier and OpenCode permission layer can review the deletion.",
  )
}

// --- small helpers (ported unchanged) ---------------------------------------

async function canonicalOrResolved(value: string) {
  const resolved = path.resolve(value)
  try {
    return await realpath(resolved)
  } catch {
    return resolved
  }
}

function commandFromArgs(args: unknown) {
  if (!args || typeof args !== "object" || Array.isArray(args)) return
  const command = (args as Record<string, unknown>).command
  return typeof command === "string" ? command : undefined
}

function workdirFromArgs(args: unknown) {
  if (!args || typeof args !== "object" || Array.isArray(args)) return
  const workdir = (args as Record<string, unknown>).workdir
  return typeof workdir === "string" ? workdir : undefined
}

function sanitizeOutputTail(output: string) {
  const trimmed = (output ?? "").replace(/\0/g, "").trim()
  if (!trimmed) return ""
  return trimmed.slice(-MAX_OUTPUT_TAIL_CHARS).replace(/\s+/g, " ").trim()
}

/**
 * §4.10 (F36/F37): normalizes the variable identifiers of known read-only
 * parametrized commands so repeated inspections share a dynamic-ALLOW cache
 * entry. Only patterns whose parameters do NOT change security semantics are
 * rewritten; the dynamic reviewer always sees the RAW script.
 *
 * `kill <pid>` is deliberately NOT normalized: a cached ALLOW for an ordinary
 * PID could otherwise be reused for a critical system PID without review.
 * `sed -e '…'` (semantics-changing) is not normalized either.
 */
function normalizeCacheKeyScript(script: string): string {
  const text = script
    // bare reads only: `docker logs/inspect/top/stats <container>` (flags keep the raw form)
    .replace(/^docker\s+(logs|inspect|top|stats)\s+([A-Za-z0-9_.][A-Za-z0-9_.-]*)$/gi, "docker $1 <id>")
    // `kubectl logs/top <pod>`
    .replace(/^kubectl\s+(logs|top)\s+([A-Za-z0-9_.-]+)$/gi, "kubectl $1 <id>")
    // `kubectl get|describe <type> <name>` (secrets excluded: different security class)
    .replace(
      /^kubectl\s+(get|describe)\s+(?!(?:secret|secrets)\b)([A-Za-z0-9_.-]+)\s+([A-Za-z0-9_.-]+)$/gi,
      "kubectl $1 $2 <id>",
    )
    // psql … -c "SELECT…" / -c 'SELECT…' (read-only SQL payload)
    .replace(
      /(^|[\s;])(-c|--command)\s+(["'])(select|show|describe|explain|vacuum|analyze|begin|prepare|deallocate|values|with)[\s\S]*?\3/gi,
      "$1$2 $3<query>$3",
    )
  return text
}

function dynamicAllowCacheKey(
  sessionID: string,
  script: string,
  cwd: string,
  shell: string,
  decision: StaticSecurityDecision,
  endpoint: string,
  model: string,
  strictness: string,
) {
  const context = decision.reviewContext
  if (
    context?.uninspectedLocalScripts?.length ||
    context?.uninspectedTargetDirectories?.length ||
    context?.targetDirectories?.some((directory) => directory.truncated)
  ) {
    return undefined
  }

  const payload = {
    sessionID,
    script: normalizeCacheKeyScript(script),
    cwd,
    shell,
    rules: decision.rules,
    fingerprints: decision.fingerprints.map((fingerprint) => ({
      path: fingerprint.path,
      size: fingerprint.size,
      mtimeMs: fingerprint.mtimeMs,
      sha256: fingerprint.sha256,
      linkPath: fingerprint.linkPath ?? null,
    })),
    targetDirectories: context?.targetDirectories ?? [],
    referencedPaths: context?.referencedPaths ?? [],
    referencedPathsTruncated: context?.referencedPathsTruncated ?? false,
    strictness,
    endpoint,
    model,
    promptVersion: PROMPT_VERSION,
  }
  const digest = createHash("sha256").update(JSON.stringify(payload)).digest("hex")
  return `${sessionID}:${digest}`
}

function hasCachedDynamicAllow(cache: Map<string, number>, key: string, now: number) {
  const expiresAt = cache.get(key)
  if (expiresAt === undefined) return false
  if (expiresAt <= now) {
    cache.delete(key)
    return false
  }
  return true
}

function cacheDynamicAllow(cache: Map<string, number>, key: string, now: number) {
  for (const [cachedKey, expiresAt] of cache) {
    if (expiresAt <= now) cache.delete(cachedKey)
  }
  while (cache.size >= MAX_DYNAMIC_ALLOW_CACHE_ENTRIES) {
    const oldest = cache.keys().next().value
    if (typeof oldest !== "string") break
    cache.delete(oldest)
  }
  cache.set(key, now + DYNAMIC_ALLOW_CACHE_TTL_MS)
}

function isValidReviewResult(value: unknown, strict: boolean): value is CloudReviewResult {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false
  const record = value as Record<string, unknown>
  const expected = strict ? ["bypassing", "decision", "reason"] : ["decision", "reason"]
  const keys = Object.keys(record).sort()
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) return false
  if (record.decision !== "ALLOW" && record.decision !== "DENY") return false
  if (typeof record.reason !== "string") return false
  return !strict || typeof record.bypassing === "boolean"
}

const plugin: Plugin.Plugin = {
  id: "opencode-bash-classifier",
  setup: async (ctx) => {
    // --- 8. configuration ---------------------------------------------------
    // Source is ctx.options (the `plugins` entry `{ package, options }`).
    // Directory auto-discovery supplies no options, so a `configFile` option
    // (or, with empty options, <package root>/config.json) can back it up.
    const options = (ctx.options ?? {}) as Record<string, unknown>
    let source = options
    if (typeof options.configFile === "string") {
      const configPath = path.isAbsolute(options.configFile)
        ? options.configFile
        : path.resolve(process.cwd(), options.configFile)
      source = JSON.parse(await readFile(configPath, "utf8")) as Record<string, unknown>
    } else if (Object.keys(options).length === 0) {
      const fallbackPath = path.join(PACKAGE_ROOT, "config.json")
      try {
        source = JSON.parse(await readFile(fallbackPath, "utf8")) as Record<string, unknown>
      } catch {
        // No fallback config file; defaults apply.
      }
    }
    // `configFile` is a loader directive, not a plugin option — strip it before
    // resolvePluginConfig (whose whitelist rejects unknown fields).
    const { configFile: _ignored, ...pluginOptions } = source
    const resolved = resolvePluginConfig(pluginOptions as BashClassifierOptions | undefined)

    // --- 5. fail_ask normalization ------------------------------------------
    // v2's Tool.Context has no `ask`, so human-in-the-loop approval cannot be
    // implemented. `fail_ask` is normalized to `fail_close`: an unavailable or
    // failed reviewer becomes a denial, never a question.
    const failAskNormalized = resolved.failPolicy === "fail_ask"
    const effectiveFailPolicy = failAskNormalized ? "fail_close" : resolved.failPolicy
    if (failAskNormalized) {
      console.warn(
        '[opencode-bash-classifier] failPolicy "fail_ask" is not available in v2 and was normalized to "fail_close" (interactive confirmation unavailable)',
      )
    }

    // `shell` now comes solely from options.shell; v2 has no `config` hook to
    // learn opencode's configured shell. resolveClassifierShell falls back to
    // the SHELL env var and then the platform default (bash/pwsh).
    const configuredShell = resolved.shell
    const strictPolicy = resolved.strictness === "HARD"

    // v2 ctx has no `directory`/`worktree`; resolve them per session from
    // ctx.session.get(...).location.directory (cached, bounded, TTL-bounded),
    // falling back to process.cwd().
    const sessions = new Map<string, SessionState>()
    const dynamicAllowCache = new Map<string, number>()
    const sessionDirectories = new Map<string, { directory: string; worktree: string; at: number }>()

    function deleteSessionState(sessionID: string) {
      sessions.delete(sessionID)
      sessionDirectories.delete(sessionID)
      const prefix = `${sessionID}:`
      for (const key of dynamicAllowCache.keys()) {
        if (key.startsWith(prefix)) dynamicAllowCache.delete(key)
      }
    }

    function pruneSessionStates(now: number) {
      for (const [sessionID, state] of sessions) {
        if (state.touchedAt + SESSION_STATE_TTL_MS <= now) deleteSessionState(sessionID)
      }
      for (const [sessionID, entry] of sessionDirectories) {
        if (entry.at + SESSION_STATE_TTL_MS <= now) sessionDirectories.delete(sessionID)
      }
    }

    function getSessionState(sessionID: string): SessionState {
      const now = Date.now()
      pruneSessionStates(now)
      let state = sessions.get(sessionID)
      if (!state) {
        while (sessions.size >= MAX_SESSION_STATES) {
          const oldest = sessions.keys().next().value
          if (typeof oldest !== "string") break
          deleteSessionState(oldest)
        }
        state = { version: 0, touchedAt: now }
        sessions.set(sessionID, state)
      } else {
        state.touchedAt = now
        sessions.delete(sessionID)
        sessions.set(sessionID, state)
      }
      return state
    }

    async function sessionDirectory(sessionID: string): Promise<{ directory: string; worktree: string }> {
      const cached = sessionDirectories.get(sessionID)
      if (cached && cached.at + SESSION_STATE_TTL_MS > Date.now()) return cached
      try {
        const info = (await ctx.session.get({ sessionID })) as { location?: { directory?: string } }
        const raw = info?.location?.directory
        if (typeof raw === "string" && raw) {
          const directory = await canonicalOrResolved(raw)
          while (sessionDirectories.size >= MAX_SESSION_STATES) {
            let oldestKey: string | undefined
            let oldestAt = Infinity
            for (const [key, entry] of sessionDirectories) {
              if (entry.at < oldestAt) {
                oldestAt = entry.at
                oldestKey = key
              }
            }
            if (oldestKey === undefined) break
            sessionDirectories.delete(oldestKey)
          }
          const entry = { directory, worktree: directory, at: Date.now() }
          sessionDirectories.set(sessionID, entry)
          return entry
        }
      } catch {
        // Session lookup failed (e.g. already deleted); fall through to cwd.
      }
      const directory = await canonicalOrResolved(process.cwd())
      return { directory, worktree: directory }
    }

    function reviewerAvailable() {
      return Boolean(resolved.reviewCommand)
    }

    function nextGeneration(state: SessionState) {
      state.touchedAt = Date.now()
      return ++state.version
    }

    function recordRejection(state: SessionState, value: PreviousRejectedCommand) {
      if (!strictPolicy) return undefined
      const generation = nextGeneration(state)
      state.lastRejected = { value, generation }
      return generation
    }

    function rejectStatic(
      state: SessionState,
      command: string,
      reason: string,
      rules: string[] = [],
    ): never {
      recordRejection(state, { command, reason, classifier: "STATIC" })
      throw blockMessage("static", reason, strictPolicy, rules, command)
    }

    async function performDynamicReview(request: CloudReviewRequest): Promise<CloudReviewResult> {
      const reviewFn = resolved.reviewCommand
      if (!reviewFn) throw new Error("Dynamic review is not configured")
      const options: ReviewCommandOptions = {
        endpoint: resolved.dynamicReview.endpoint ?? "",
        model: resolved.dynamicReview.model ?? "",
        apiKey: resolved.dynamicReview.apiKey ?? "",
        maxRounds: resolved.dynamicReview.maxRounds,
        policy: resolved.strictness,
        allowFullReadAccess: resolved.dynamicReview.allowFullReadAccess,
        python: resolved.dynamicReview.pythonPath,
        auditorPath: resolved.dynamicReview.auditorPath,
        timeout: resolved.dynamicReview.timeoutMs,
      }
      return reviewFn(request, options)
    }

    // --- 6. HARD session interrupt (v1 client.session.abort) ----------------
    async function abortSession(sessionID: string) {
      try {
        await ctx.session.interrupt({ sessionID })
      } catch {
        // Interrupt failure must not allow the command — the caller still throws.
      }
    }

    function applyPostChecks(
      script: string,
      input: Record<string, unknown>,
      decision: StaticSecurityDecision,
      shell: string,
    ) {
      if (resolved.hardTimeoutMs > 0 && !isDownloadOrBuildCommand(script)) {
        const original = input.timeout
        const hasExplicit = typeof original === "number" && Number.isFinite(original) && original > 0
        if (!hasExplicit) {
          input.timeout = resolved.hardTimeoutMs
        }
      }

      if (resolved.detachedStartIsolation && !supervisorActive) {
        const isolated = isolateDetachedStartCommand(script, shell)
        if (isolated !== script) {
          input.command = isolated
        }
      }

      return verifyScriptFingerprints(decision.fingerprints)
    }

    // --- 4. supervisor injection (v1 config hook + shell.env) ---------------
    // On Windows only: when the supervisor binary exists, wrap the resolved
    // shell with it and tell it where the real shell is. Non-Windows platforms
    // never use the supervisor (it is a Windows-only Rust binary).
    let supervisorActive = false
    if (resolved.supervisorEnabled && process.platform === "win32") {
      try {
        await access(resolved.supervisorPath)
        supervisorActive = true
      } catch {
        supervisorActive = false
      }
    }

    await ctx.shell.hook("create.before", (ev: ShellCreateBeforeEvent) => {
      if (!supervisorActive) return
      // Idempotency: never wrap the supervisor with itself.
      if (path.resolve(ev.shell) === path.resolve(resolved.supervisorPath)) return
      ev.env.OPENCODE_REAL_BASH = ev.shell
      ev.shell = resolved.supervisorPath
    })

    // --- 2. static + LLM review pipeline (v1 tool.execute.before) -----------
    await ctx.tool.hook("execute.before", async (ev: ExecuteBeforeEvent) => {
      // apply_patch -> patch. Delete-file patches are blocked statically so the
      // deletion goes through the shell tool and its permission layer instead.
      if (ev.tool === "patch" || ev.tool === "apply_patch") {
        const input = ev.input as Record<string, unknown> | undefined
        const patchText = typeof input?.patchText === "string" ? input.patchText : undefined
        if (patchText && /^\*\*\* Delete File:/m.test(patchText)) {
          throw applyPatchDeleteBlock()
        }
        return
      }

      // bash -> shell (keep accepting "bash" for compatibility).
      if ((ev.tool !== "shell" && ev.tool !== "bash") || !resolved.securityEnabled) return

      const sessionID = ev.sessionID
      const sessionState = getSessionState(sessionID)
      const input = ev.input as Record<string, unknown>
      const script = commandFromArgs(input)
      if (!script?.trim()) {
        rejectStatic(sessionState, "", "Empty command")
      }

      const requestedWorkdir = workdirFromArgs(input)
      const { directory, worktree } = await sessionDirectory(sessionID)
      const cwd = await canonicalOrResolved(
        requestedWorkdir
          ? path.isAbsolute(requestedWorkdir)
            ? requestedWorkdir
            : path.resolve(directory, requestedWorkdir)
          : directory,
      )
      const shell = resolveClassifierShell(configuredShell)
      const staticDecision: StaticSecurityDecision = await classifyShellCommand({
        script,
        cwd,
        worktree,
        shell,
        strictness: resolved.strictness,
      })

      // Static DENY is absolute — cannot be overridden by approval or dynamic review.
      if (staticDecision.verdict === "DENY") {
        rejectStatic(sessionState, script, staticDecision.reason, staticDecision.rules)
      }

      // v1's approved-fingerprint path (confirm tool) is gone in v2: there is no
      // confirmation tool, so no approval can ever be recorded.

      const rejectionAtStart = strictPolicy ? sessionState.lastRejected : undefined
      const failureAtStart =
        strictPolicy && sessionState.lastFailed && !sessionState.lastFailed.consumedBy
          ? sessionState.lastFailed
          : undefined
      const forcedByRejection = Boolean(rejectionAtStart)
      const forcedByFailure = Boolean(failureAtStart)
      const forced = forcedByRejection || forcedByFailure

      if (staticDecision.verdict === "ALLOW" && !forced) {
        if (!(await applyPostChecks(script, input, staticDecision, shell))) {
          rejectStatic(sessionState, script, "Local script changed after review", staticDecision.rules)
        }
        return
      }

      const cacheable = !strictPolicy && !forcedByFailure
      let cacheKey: string | undefined
      if (cacheable) {
        cacheKey = dynamicAllowCacheKey(
          sessionID,
          script,
          cwd,
          shell,
          staticDecision,
          resolved.dynamicReview.endpoint ?? "",
          resolved.dynamicReview.model ?? "",
          resolved.strictness,
        )
        if (cacheKey && hasCachedDynamicAllow(dynamicAllowCache, cacheKey, Date.now())) {
          if (!(await applyPostChecks(script, input, staticDecision, shell))) {
            rejectStatic(sessionState, script, "Local script changed after review", staticDecision.rules)
          }
          return
        }
      }

      // v2 tool call id replaces v1's input.callID for failure-consumption tracking.
      const callID = ev.id
      if (
        failureAtStart &&
        sessionState.lastFailed?.generation === failureAtStart.generation &&
        !sessionState.lastFailed.consumedBy
      ) {
        sessionState.lastFailed.consumedBy = callID
      }

      const reviewRequest: CloudReviewRequest = {
        command: script,
        localScripts: staticDecision.reviewContext?.localScripts ?? [],
        uninspectedLocalScripts: staticDecision.reviewContext?.uninspectedLocalScripts ?? [],
        targetDirectories: staticDecision.reviewContext?.targetDirectories ?? [],
        uninspectedTargetDirectories: staticDecision.reviewContext?.uninspectedTargetDirectories ?? [],
        referencedPaths: staticDecision.reviewContext?.referencedPaths ?? [],
        referencedPathsTruncated: staticDecision.reviewContext?.referencedPathsTruncated ?? false,
        worktree,
        cwd,
      }
      if (rejectionAtStart) {
        reviewRequest.previousRejectedCommand = rejectionAtStart.value
      }
      if (failureAtStart) {
        reviewRequest.previousFailedCommand = failureAtStart.value
      }

      let cloudReview: CloudReviewResult | undefined
      let reviewError: Error | undefined
      if (reviewerAvailable()) {
        try {
          const result: unknown = await performDynamicReview(reviewRequest)
          if (!isValidReviewResult(result, strictPolicy)) {
            throw new Error("Dynamic review returned an invalid result")
          }
          cloudReview = result
        } catch (error) {
          reviewError = error instanceof Error ? error : new Error(String(error))
        }
      } else {
        reviewError = new Error(resolved.dynamicReview.reason ?? "Dynamic review is not configured")
      }

      if (cloudReview) {
        if (strictPolicy && cloudReview.bypassing === true) {
          const reason =
            cloudReview.decision === "DENY"
              ? cloudReview.reason
              : "The command appears to bypass a previous rejection"
          recordRejection(sessionState, { command: script, reason, classifier: "DYNAMIC" })
          await abortSession(sessionID)
          throw blockMessage("dynamic", reason, true, staticDecision.rules, script)
        }

        if (cloudReview.decision === "DENY") {
          recordRejection(sessionState, {
            command: script,
            reason: cloudReview.reason,
            classifier: "DYNAMIC",
          })
          throw blockMessage(
            "dynamic",
            cloudReview.reason,
            strictPolicy,
            staticDecision.rules,
            script,
          )
        }

        if (
          rejectionAtStart &&
          sessionState.lastRejected?.generation === rejectionAtStart.generation
        ) {
          sessionState.lastRejected = undefined
        }
        if (cacheKey) cacheDynamicAllow(dynamicAllowCache, cacheKey, Date.now())
        if (!(await applyPostChecks(script, input, staticDecision, shell))) {
          rejectStatic(sessionState, script, "Local script changed after review", staticDecision.rules)
        }
        return
      }

      const failReason = reviewError?.message ?? "Dynamic review failed"
      if (effectiveFailPolicy === "fail_open") {
        if (!(await applyPostChecks(script, input, staticDecision, shell))) {
          rejectStatic(sessionState, script, "Local script changed after review", staticDecision.rules)
        }
        return
      }
      // fail_close (including fail_ask normalized to fail_close).
      recordRejection(sessionState, {
        command: script,
        reason: failReason,
        classifier: "FAIL_POLICY",
      })
      throw failClosedBlock(failReason, failAskNormalized, strictPolicy, staticDecision.rules, script)
    })

    // --- 3. failure recording (v1 tool.execute.after) -----------------------
    await ctx.tool.hook("execute.after", async (ev: ExecuteAfterEvent) => {
      if ((ev.tool !== "shell" && ev.tool !== "bash") || !resolved.securityEnabled) return
      // A failed tool call carries no result; v1 read undefined metadata and
      // returned early — same behavior.
      if (ev.status !== "completed") return

      const sessionID = ev.sessionID
      const sessionState = getSessionState(sessionID)
      const metadata = ev.result?.metadata

      // v2 shell result metadata = { truncated, exit?, shellID?, timeout? }
      // (verified in packages/core/src/tool/plugin/shell.ts). `exitCode` is
      // kept as a defensive fallback for other shells/v1-shaped metadata.
      const rawExit = metadata?.exit ?? metadata?.exitCode
      const exitCode = typeof rawExit === "number" ? rawExit : undefined
      if (exitCode === undefined) return

      if (exitCode === 0) {
        if (sessionState.lastFailed?.consumedBy === ev.id) {
          sessionState.lastFailed = undefined
        }
        return
      }

      if (!strictPolicy) return

      const command = commandFromArgs(ev.input) ?? ""
      sessionState.lastFailed = {
        value: {
          command,
          exitCode,
          outputTail: sanitizeOutputTail(ev.result?.output ?? ""),
        },
        generation: nextGeneration(sessionState),
      }
    })

    // --- 7. session cleanup (v1 event hook) ---------------------------------
    // ctx.event.subscribe() returns an AsyncIterable of wire events; the wire
    // payload of the durable `session.deleted` event is { type, data: { sessionID } }
    // (verified in packages/schema/src/session-event.ts). Consume it in a
    // background loop that cleanup can stop.
    let eventRunning = true
    let eventIterator: AsyncIterator<unknown> | undefined
    try {
      const iterable = ctx.event.subscribe()
      const iterator = iterable[Symbol.asyncIterator]()
      eventIterator = iterator
      void (async () => {
        try {
          while (eventRunning) {
            const { value, done } = await iterator.next()
            if (done) break
            const event = value as { type?: string; data?: { sessionID?: string } }
            if (event?.type === "session.deleted") {
              const sessionID = event.data?.sessionID
              if (typeof sessionID === "string") deleteSessionState(sessionID)
            }
          }
        } catch {
          // Stream closed or interrupted during cleanup; session state pruning
          // (TTL + bounded maps) covers anything missed.
        }
      })()
    } catch {
      // Subscribe failed; state is still TTL-pruned and bounded.
    }

    return async () => {
      eventRunning = false
      try {
        await eventIterator?.return?.()
      } catch {
        // Ignore close errors.
      }
      sessions.clear()
      dynamicAllowCache.clear()
      sessionDirectories.clear()
    }
  },
}

export default plugin
export { classifyShellCommand, verifyScriptFingerprints } from "./security/classifier"
export { reviewCommandWithAuditor, reviewCommandWithAuditor as reviewCommandWithDeepSeek } from "./security/reviewer"
export { resolvePluginConfig } from "./config"
export type {
  BashClassifierOptions,
  FailPolicy,
  ResolvedDynamicReview,
  ResolvedPluginConfig,
  Strictness,
} from "./config"
export type {
  ClassifyShellCommandInput,
  DirectoryEntryReviewContext,
  LocalScriptReviewContext,
  ScriptFingerprint,
  SecurityVerdict,
  StaticReviewContext,
  StaticSecurityDecision,
  TargetDirectoryReviewContext,
} from "./security/classifier"
export type {
  CloudReviewDecision,
  CloudReviewRequest,
  CloudReviewResult,
  PreviousFailedCommand,
  PreviousRejectedCommand,
  ReviewCommandOptions,
} from "./security/reviewer"
