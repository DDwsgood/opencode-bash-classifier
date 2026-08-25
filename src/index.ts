// opencode-bash-classifier — opencode v2 plugin API port of the v1 `-next` plugin.
//
// v1 was a function plugin (`{ id, server }`) that registered `config` /
// `shell.env` / `tool.execute.before` / `tool.execute.after` / `event` hooks, a
// custom `bash_classifier_confirm` tool backed by `context.ask`, and used
// `pluginContext.directory/worktree`. v2 has none of those — the plugin is an
// effect plugin `{ id, effect(ctx) }` whose `effect` returns an `Effect.Effect`
// (see packages/plugin/src/effect/plugin.ts). This file is the port. Every
// mapping below was verified against ~/src/opencode2 (branch v2):
//
//   1. Entry shape          v1 function plugin        -> { id, effect(ctx) } (Effect)
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
// `execute.before` is the only fallible tool hook (failure channel `Tool.Error`;
// `execute.after` is `never`). In the effect form the host runs each hook
// callback's returned `Effect`; a `Tool.Error`-tagged failure from
// `execute.before` is caught by the runner's `catchTag("Tool.Error")` and turned
// into THIS tool call's error (the model reads the message). Every block
// therefore surfaces as an `Effect` that fails with a `Tool.Error`-shaped value
// (a plain `Error` carrying `_tag: "Tool.Error"`), produced by `rejectionError`
// and routed through `Effect.tryPromise`'s `catch`. `catchTag` discriminates by
// `_tag`, so the fake object matches without being a real `Tool.Error` instance;
// `toSessionError` then falls through to its `{ type: "unknown", message }` branch
// (message preserved) — acceptable, since the block message is what matters.

import { createHash } from "node:crypto"
import { access, appendFile, mkdir, readFile, realpath } from "node:fs/promises"
import { homedir } from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { Effect, Stream } from "effect"
import type { Plugin } from "@opencode-ai/plugin/effect/plugin"
import type { Scope } from "effect"
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
  normalizeReviewRequest,
  requestForPolicy,
  ReviewError,
  type CloudReviewRequest,
  type CloudReviewResult,
  type PreviousFailedCommand,
  type PreviousRejectedCommand,
  type ReviewCommandOptions,
} from "./security/reviewer"
import { analyzeSlowCommand } from "./security/slow-command"
import { detectInjection } from "./security/injection-detector"

// Package root, derived from this module's own URL so relative paths (native
// supervisor, auditor) resolve no matter where the plugin is installed from.
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

const DYNAMIC_ALLOW_CACHE_TTL_MS = 15 * 60 * 1000
const DYNAMIC_DENY_CACHE_TTL_MS = 90 * 1000
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

// v2's shell `result.output` is a structured object ({ output, cursor, size,
// truncated }), not a bare string — fields are optional/loose so the after-hook
// can extract text defensively (see runAfter) and so this type stays a supertype
// of ExecuteBeforeEvent (after = before + optional fields).
type ExecuteAfterEvent = ExecuteBeforeEvent & {
  readonly status?: "completed" | "error"
  readonly result?: {
    readonly output?: unknown
    readonly content?: unknown
    readonly metadata?: Record<string, unknown>
  }
  readonly error?: unknown
}

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

// `Effect.tryPromise`'s `catch` must always return the same shape. The
// execute.before body already throws `rejectionError` for every block, so a
// thrown Tool.Error-shaped error is passed through unchanged; any other thrown
// value (an unexpected non-block exception) is normalized into one so the host's
// `catchTag("Tool.Error")` still routes it to a tool-call error instead of a
// step-killing defect.
function toRejection(error: unknown): Error & { readonly _tag: "Tool.Error" } {
  if (error instanceof Error && (error as { _tag?: string })._tag === "Tool.Error") {
    return error as Error & { readonly _tag: "Tool.Error" }
  }
  return rejectionError(error instanceof Error ? error.message : String(error))
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

function softSlowMessage(reason: string) {
  // Soft interception for high-cost but optimizable commands: no BLOCK_SUFFIX, no DO NOT retry
  return rejectionError(conciseReason(reason, 300))
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
 *
 * SQL payloads collapse to `<query>` only for provably read-only leading
 * verbs (select/show/describe/explain/vacuum/analyze) whose payload carries
 * no write keyword and no known side-effecting function. `begin`/`prepare`/
 * `values`/`with` are no longer collapsed: they wrap data-modifying
 * statements that would otherwise inherit a benign query's cached ALLOW.
 */
const SQL_WRITE_HINT =
  /\b(?:insert|update|delete|drop|alter|create|grant|revoke|truncate|copy|call|do|set|reset|listen|notify|import|refresh|reindex|cluster|lock|comment|security\s+label)\b/i
const SQL_SIDE_EFFECT_FUNCTIONS =
  /\b(?:pg_terminate_backend|pg_reload_conf|pg_rotate_logfile|pg_create_restore_point|pg_logical_emit_message|lo_import|lo_export|lo_unlink|dblink|dblink_exec|setval|nextval|read_file|read_binary_file|pg_ls_dir|pg_sleep)\b/i

export function normalizeCacheKeyScript(script: string): string {
  const text = script
    // bare reads only: `docker logs/inspect/top/stats [flags] <container>`
    // (bounded read-only flag whitelist; -f streams and is slow-blocked upstream)
    .replace(
      /^docker\s+(logs|inspect|top|stats)(?:\s+(?:--tail|-n|--since|-q)\s+\S+|\s+-f)*\s+([A-Za-z0-9_.][A-Za-z0-9_.-]*)$/gi,
      "docker $1 <id>",
    )
    // `kubectl logs/top [-f] [-c container] <pod>`
    .replace(/^kubectl\s+(logs|top)(?:\s+-f)?(?:\s+-c\s+\S+)?\s+([A-Za-z0-9_./-]+)$/gi, "kubectl $1 <id>")
    // `kubectl get|describe <type> <name>` (secrets excluded: different security class)
    .replace(
      /^kubectl\s+(get|describe)\s+(?!(?:secret|secrets)\b)([A-Za-z0-9_.-]+)\s+([A-Za-z0-9_.-]+)$/gi,
      "kubectl $1 $2 <id>",
    )
    // psql … -c "SELECT…" / -c 'SELECT…' (read-only SQL payload)
    .replace(
      /(^|[\s;])(-c|--command)\s+(["'])((?:select|show|describe|explain|vacuum|analyze)[\s\S]*?)\3/gi,
      (match, lead: string, flag: string, quote: string, payload: string) =>
        SQL_WRITE_HINT.test(payload) || SQL_SIDE_EFFECT_FUNCTIONS.test(payload)
          ? match
          : `${lead}${flag} ${quote}<query>${quote}`,
    )
  return text
}

/**
 * Cache keys are GLOBAL (no session component): the payload already carries
 * every security-relevant context (script, cwd, shell, static rules, script
 * fingerprints, target-directory listings, referenced paths, strictness,
 * endpoint, model, prompt version), and cached entries are only written for
 * non-forced LOOSE reviews, so a verdict from another session for the exact
 * same context is sound to reuse. A shorter TTL bounds staleness.
 */
export function dynamicAllowCacheKey(
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
  return digest
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

// Short-lived negative cache: a stubborn model retrying an identical denied
// command re-burns a review call every attempt. Replaying the same DENY for
// 90s throttles that without meaningfully delaying legitimate state changes.
type DenyCacheEntry = { expiresAt: number; reason: string }

function cachedDynamicDenyReason(cache: Map<string, DenyCacheEntry>, key: string, now: number): string | undefined {
  const entry = cache.get(key)
  if (!entry) return undefined
  if (entry.expiresAt <= now) {
    cache.delete(key)
    return undefined
  }
  return entry.reason
}

function cacheDynamicDeny(cache: Map<string, DenyCacheEntry>, key: string, reason: string, now: number) {
  for (const [cachedKey, entry] of cache) {
    if (entry.expiresAt <= now) cache.delete(cachedKey)
  }
  while (cache.size >= MAX_DYNAMIC_ALLOW_CACHE_ENTRIES) {
    const oldest = cache.keys().next().value
    if (typeof oldest !== "string") break
    cache.delete(oldest)
  }
  cache.set(key, { expiresAt: now + DYNAMIC_DENY_CACHE_TTL_MS, reason })
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

// --- effect plugin context (local structural mirror) -----------------------
// The plugin must not import host packages at runtime (V2-PLUGIN-API.md §8.7),
// so the effect Context is mirrored as a plain structural interface — the same
// approach the promise port used for the hook event shapes. `ctx.session.*`
// return Effects here; they are run against the host-provided runtime captured
// inside `effect` (see `run`), not a bare `Effect.runPromise`, so the host
// services backing them stay available.
interface EffectPluginContext {
  readonly options: unknown
  readonly tool: {
    readonly hook: (
      name: "execute.before" | "execute.after",
      callback: (event: ExecuteBeforeEvent) => Effect.Effect<void, unknown>,
    ) => Effect.Effect<unknown, never, Scope.Scope>
  }
  readonly shell: {
    readonly hook: (
      name: "create.before",
      callback: (event: ShellCreateBeforeEvent) => Effect.Effect<void, never>,
    ) => Effect.Effect<unknown, never, Scope.Scope>
  }
  readonly session: {
    readonly get: (input: { sessionID: string }) => Effect.Effect<unknown, unknown>
    readonly interrupt: (input: { sessionID: string; continue?: boolean }) => Effect.Effect<unknown, unknown>
    readonly synthetic: (input: {
      sessionID: string
      text: string
      metadata?: Record<string, unknown>
      resume?: boolean
    }) => Effect.Effect<unknown, unknown>
  }
  readonly event: { readonly subscribe: () => Stream.Stream<unknown> }
}

// Async preamble (config discovery + fail_ask normalization + supervisor probe)
// extracted so the effect body can bridge it with one `Effect.promise`. A setup
// failure dies the plugin load (acceptable: a misconfigured plugin should not
// silently run with defaults).
async function resolveStartup(rawOptions: unknown) {
  const options = (rawOptions ?? {}) as Record<string, unknown>
  let source = options
  if (typeof options.configFile === "string") {
    const configPath = path.isAbsolute(options.configFile)
      ? options.configFile
      : path.resolve(process.cwd(), options.configFile)
    source = JSON.parse(await readFile(configPath, "utf8")) as Record<string, unknown>
  } else if (Object.keys(options).length === 0) {
    const fallbackPath = path.join(PACKAGE_ROOT, "config.json")
    let fallbackRaw: string | undefined
    try {
      fallbackRaw = await readFile(fallbackPath, "utf8")
    } catch (error) {
      const code = (error as NodeJS.ErrnoException | undefined)?.code
      if (code !== "ENOENT") {
        console.warn(
          `[opencode-bash-classifier] fallback config.json could not be read (${code ?? "unknown error"}); defaults apply`,
        )
      }
      // No fallback config file; defaults apply.
    }
    if (fallbackRaw !== undefined) {
      try {
        source = JSON.parse(fallbackRaw) as Record<string, unknown>
      } catch (error) {
        // A malformed config must be loud: silently ignoring it would leave the
        // user believing safety settings (reviewer, fail-close) are active.
        console.warn(
          `[opencode-bash-classifier] fallback config.json is not valid JSON and was ignored: ${(error as Error).message}`,
        )
      }
    }
  }
  // `configFile` is a loader directive, not a plugin option — strip it before
  // resolvePluginConfig (whose whitelist rejects unknown fields).
  const { configFile: _ignored, ...pluginOptions } = source
  const resolved = resolvePluginConfig(pluginOptions as BashClassifierOptions | undefined)
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
  const configuredShell = resolved.shell
  const strictPolicy = resolved.strictness === "HARD"
  let supervisorActive = false
  if (resolved.supervisorEnabled && process.platform === "win32") {
    try {
      await access(resolved.supervisorPath)
      supervisorActive = true
    } catch {
      supervisorActive = false
    }
  }
  return { resolved, failAskNormalized, effectiveFailPolicy, configuredShell, strictPolicy, supervisorActive }
}

const plugin: Plugin = {
  id: "opencode-bash-classifier",
  effect: (ctx: EffectPluginContext) => Effect.gen(function* () {
    // Capture the ambient context so `ctx.session.*` Effects (which need host
    // services despite their narrowed plugin-facing type) run with those
    // services — a bare `Effect.runPromise` would lose them. Mirrors the
    // promise adapter's `Effect.runPromiseWith(context)` bridge. effect 4 has
    // no `Effect.runtime`/`Runtime.runPromise`; context capture is the beta
    // API for this.
    const context = yield* Effect.context<never>()
    const run = <A>(effect: Effect.Effect<A, unknown>): Promise<A> =>
      Effect.runPromiseWith(context)(effect as Effect.Effect<A, unknown, never>)

    const { resolved, failAskNormalized, effectiveFailPolicy, configuredShell, strictPolicy, supervisorActive } =
      yield* Effect.promise(() => resolveStartup(ctx.options))

    // v2 ctx has no `directory`/`worktree`; resolve them per session from
    // ctx.session.get(...).location.directory (cached, bounded, TTL-bounded),
    // falling back to process.cwd().
    const sessions = new Map<string, SessionState>()
    const dynamicAllowCache = new Map<string, number>()
    const dynamicDenyCache = new Map<string, DenyCacheEntry>()
    const inflightReviews = new Map<string, Promise<CloudReviewResult>>()
    const sessionDirectories = new Map<string, { directory: string; worktree: string; at: number }>()
    let consecutiveDynamicFailures = 0
    let lastDynamicFailureToastAt = 0

    // Reviewer audit trail (logReviewerTrace): one JSONL line per dynamic
    // review verdict/error and per cache hit, appended to
    // ~/.opencode/reviewer-trace.jsonl. Fire-and-forget — a logging failure
    // must never alter the review outcome or block a command.
    const reviewerTraceFile = resolved.logReviewerTrace
      ? path.join(homedir(), ".opencode", "reviewer-trace.jsonl")
      : undefined
    function writeReviewerTrace(entry: Record<string, unknown>) {
      if (!reviewerTraceFile) return
      const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n"
      void mkdir(path.dirname(reviewerTraceFile), { recursive: true })
        .then(() => appendFile(reviewerTraceFile, line, "utf8"))
        .catch(() => {})
    }

    function deleteSessionState(sessionID: string) {
      sessions.delete(sessionID)
      sessionDirectories.delete(sessionID)
      // Review caches are global and context-addressed; TTL eviction covers them.
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
        const info = (await run(ctx.session.get({ sessionID }))) as { location?: { directory?: string } }
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

    function extractHttpStatus(message: string): string | undefined {
      const m = message.match(/HTTP\s*(\d{3})/i) ?? message.match(/\b(\d{3})\b/)
      if (m) {
        const code = m[1]
        if (code && /^4\d\d$|^5\d\d$/.test(code)) return code
      }
      return undefined
    }

    async function maybeNotifyDynamicConsecutiveFailures(sessionID: string, error: Error) {
      if (!reviewerAvailable()) return
      consecutiveDynamicFailures++
      if (consecutiveDynamicFailures < 3) return
      const now = Date.now()
      if (now - lastDynamicFailureToastAt < 60_000) return
      lastDynamicFailureToastAt = now
      const status = extractHttpStatus(error.message)
      const shortMsg = status
        ? `Dynamic review unavailable (HTTP ${status}), please check endpoint, network and auth`
        : `Dynamic review unavailable, please check endpoint, network and auth`
      console.error(`[opencode-bash-classifier] ${shortMsg}: ${error.message.slice(0, 300)}`)
      // Best-effort TUI toast via any available UI (server ctx has no ui, but try for future TUI companion)
      try {
        const anyCtx = ctx as unknown as { ui?: { toast?: { show?: (o: unknown) => void } } }
        anyCtx.ui?.toast?.show?.({ message: shortMsg, variant: "error", duration: 5000 })
      } catch {}
      // Also send synthetic message to the session that triggered it, visible in TUI chat.
      // resume:false (M11) — a reviewer-outage notice must never auto-resume the session.
      try {
        await run(
          ctx.session.synthetic({
            sessionID,
            text: shortMsg,
            metadata: { source: "bash-classifier-dynamic-review" },
            resume: false,
          }),
        )
      } catch {}
    }

    function resetDynamicFailureCounter() {
      consecutiveDynamicFailures = 0
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
        await run(ctx.session.interrupt({ sessionID }))
      } catch {
        // Interrupt failure must not allow the command — the caller still throws.
      }
    }

    // Fire-and-forget the interrupt ~100ms AFTER throwing the block. If the
    // interrupt lands first it rewrites the block reason to STEP_INTERRUPTED,
    // hiding why the command was denied; scheduling it after the throw keeps the
    // block message as the visible outcome.
    function scheduleAbort(sessionID: string) {
      setTimeout(() => void abortSession(sessionID), 100)
    }

    // S14: the four analyzeSlowCommand call sites share one helper so the
    // enabled/background/explicit-timeout gating stays in sync.
    function maybeBlockSlow(
      script: string,
      input: Record<string, unknown>,
      shell: string,
      cwd: string,
      worktree: string,
    ): void {
      if (!resolved.slowCommands.enabled) return
      if (input.background === true) return
      const explicitTimeout = input.timeout
      const hasExplicitTimeout =
        typeof explicitTimeout === "number" && Number.isFinite(explicitTimeout) && explicitTimeout > 0
      if (hasExplicitTimeout && resolved.slowCommands.allowExplicitTimeout) return
      const slow = analyzeSlowCommand(script, shell, {
        cwd,
        worktree,
        maxDepth: resolved.slowCommands.maxDepth,
        sleepThresholdSeconds: resolved.slowCommands.sleepThresholdSeconds,
      })
      if (slow) throw softSlowMessage(slow.reason)
    }

    function applyPostChecks(
      script: string,
      input: Record<string, unknown>,
      decision: StaticSecurityDecision,
      shell: string,
    ) {
      // M15: v2 background runs have no default timeout, so hardTimeoutMs must not
      // be injected for them (it would force-kill long-running background work).
      if (resolved.hardTimeoutMs > 0 && !isDownloadOrBuildCommand(script) && input.background !== true) {
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
    // never use the supervisor (it is a Windows-only Rust binary). The probe
    // runs in resolveStartup; create.before only mutates the event synchronously.
    yield* ctx.shell.hook("create.before", (ev: ShellCreateBeforeEvent) =>
      Effect.sync(() => {
        if (!supervisorActive) return
        // Idempotency: never wrap the supervisor with itself.
        if (path.resolve(ev.shell) === path.resolve(resolved.supervisorPath)) return
        ev.env.OPENCODE_REAL_BASH = ev.shell
        ev.shell = resolved.supervisorPath
      }),
    )

    // --- 2. static + LLM review pipeline (v1 tool.execute.before) -----------
    async function runBefore(ev: ExecuteBeforeEvent): Promise<void> {
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

      // Slow-command soft interception for high-cost optimizable commands (S14).
      if (staticDecision.verdict === "ALLOW") maybeBlockSlow(script, input, shell, cwd, worktree)

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
          script,
          cwd,
          shell,
          staticDecision,
          resolved.dynamicReview.endpoint ?? "",
          resolved.dynamicReview.model ?? "",
          resolved.strictness,
        )
        if (cacheKey && hasCachedDynamicAllow(dynamicAllowCache, cacheKey, Date.now())) {
          maybeBlockSlow(script, input, shell, cwd, worktree)
          writeReviewerTrace({ kind: "cache_allow", sessionID, command: script, cacheKey })
          if (!(await applyPostChecks(script, input, staticDecision, shell))) {
            rejectStatic(sessionState, script, "Local script changed after review", staticDecision.rules)
          }
          return
        }
        if (cacheKey) {
          const denyReason = cachedDynamicDenyReason(dynamicDenyCache, cacheKey, Date.now())
          if (denyReason !== undefined) {
            writeReviewerTrace({ kind: "cache_deny", sessionID, command: script, cacheKey, reason: denyReason })
            throw blockMessage("dynamic", denyReason, strictPolicy, staticDecision.rules, script)
          }
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
          // Concurrent identical reviews share one in-flight call instead of
          // racing duplicate auditor processes at the endpoint.
          let pending = cacheKey ? inflightReviews.get(cacheKey) : undefined
          if (!pending) {
            pending = performDynamicReview(reviewRequest)
            if (cacheKey) {
              inflightReviews.set(cacheKey, pending)
              void pending
                .catch(() => {})
                .finally(() => {
                  if (inflightReviews.get(cacheKey) === pending) inflightReviews.delete(cacheKey)
                })
            }
          }
          const result: unknown = await pending
          if (!isValidReviewResult(result, strictPolicy)) {
            throw new Error("Dynamic review returned an invalid result")
          }
          cloudReview = result
        } catch (error) {
          reviewError = error instanceof Error ? error : new Error(String(error))
          writeReviewerTrace({
            kind: "review_error",
            sessionID,
            command: script,
            endpoint: resolved.dynamicReview.endpoint,
            model: resolved.dynamicReview.model,
            error: reviewError.message.slice(0, 1000),
          })
        }
      } else {
        reviewError = new Error(resolved.dynamicReview.reason ?? "Dynamic review is not configured")
      }

      if (cloudReview) {
        resetDynamicFailureCounter()
        writeReviewerTrace({
          kind: "review_verdict",
          sessionID,
          command: script,
          endpoint: resolved.dynamicReview.endpoint,
          model: resolved.dynamicReview.model,
          decision: cloudReview.decision,
          reason: cloudReview.reason,
          bypassing: cloudReview.bypassing,
        })
        if (strictPolicy && cloudReview.bypassing === true) {
          const reason =
            cloudReview.decision === "DENY"
              ? cloudReview.reason
              : "The command appears to bypass a previous rejection"
          recordRejection(sessionState, { command: script, reason, classifier: "DYNAMIC" })
          scheduleAbort(sessionID)
          throw blockMessage("dynamic", reason, true, staticDecision.rules, script)
        }

        if (cloudReview.decision === "DENY") {
          recordRejection(sessionState, {
            command: script,
            reason: cloudReview.reason,
            classifier: "DYNAMIC",
          })
          if (cacheKey) cacheDynamicDeny(dynamicDenyCache, cacheKey, cloudReview.reason, Date.now())
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
        // Re-run slow-command soft check after dynamic ALLOW to avoid FN via static
        // ASK -> dynamic ALLOW path. Must run before caching so soft-blocked
        // commands do not pollute the ALLOW cache.
        maybeBlockSlow(script, input, shell, cwd, worktree)
        if (!(await applyPostChecks(script, input, staticDecision, shell))) {
          rejectStatic(sessionState, script, "Local script changed after review", staticDecision.rules)
        }
        if (cacheKey) cacheDynamicAllow(dynamicAllowCache, cacheKey, Date.now())
        return
      }

      // Consecutive dynamic review failure tracking for TUI notification (3 times)
      if (!cloudReview && reviewerAvailable() && reviewError) {
        await maybeNotifyDynamicConsecutiveFailures(sessionID, reviewError)
      }

      const failReason = reviewError?.message ?? "Dynamic review failed"

      // Fail routing (HARD only): a protocol-class ReviewError (oversized payload,
      // bad auditor shape/exit, mandatory-inspection violation) is an UNCONDITIONAL
      // fail-close — a defensive failure must close the gate regardless of
      // failPolicy. LOOSE performs no protocol special-casing: the auditor never
      // enforces mandatory inspection under LOOSE (auditor.py gates that check on
      // POLICY == "HARD"), and every review failure — protocol or infra — simply
      // honors the configured failPolicy. An infra-class error (HTTP/network) or
      // any unknown non-ReviewError honors the configured failPolicy in both modes.
      const protocolViolation = reviewError instanceof ReviewError && reviewError.kind === "protocol"
      if (protocolViolation && strictPolicy) {
        // HARD + protocol: trip the prompt-injection detector when a reviewer
        // endpoint is configured. The detector is a tripwire on top of the
        // unconditional deny, not a replacement for it.
        const endpoint = resolved.dynamicReview.endpoint ?? ""
        const model = resolved.dynamicReview.model ?? ""
        const apiKey = resolved.dynamicReview.apiKey ?? ""
        if (endpoint && model && apiKey) {
          // Reconstruct the exact JSON the auditor received so the detector judges
          // the real payload (reviewer.ts stringifies the same requestForPolicy
          // shape). The recovered transcript is added as secondary context.
          const reviewJson = JSON.stringify(
            requestForPolicy(normalizeReviewRequest(reviewRequest), resolved.strictness),
          )
          const transcript = reviewError instanceof ReviewError ? reviewError.transcript : undefined
          let detector: { injection: boolean; evidence?: string } | undefined
          try {
            detector = await detectInjection(
              { reviewJson, transcript },
              { endpoint, model, apiKey, timeoutMs: resolved.dynamicReview.timeoutMs },
            )
          } catch {
            // The detector never becomes a false allow: treat like fail_close.
            detector = undefined
          }
          if (detector && detector.injection === true) {
            recordRejection(sessionState, {
              command: script,
              reason: "Prompt injection detected in command or review data",
              classifier: "FAIL_POLICY",
            })
            scheduleAbort(sessionID)
            // Fire-and-forget the alert: awaiting it here could outlast the 100ms
            // abort delay, letting STEP_INTERRUPTED overwrite this block reason.
            void run(
              ctx.session.synthetic({
                sessionID,
                text: "Prompt injection detected in command or review data; command denied and session interrupted.",
                metadata: { source: "bash-classifier-injection-detector" },
                resume: false,
              }),
            ).catch(() => {})
            throw blockMessage(
              "policy",
              "Prompt injection detected in command or review data",
              true,
              staticDecision.rules,
              script,
            )
          }
          if (detector === undefined) {
            recordRejection(sessionState, {
              command: script,
              reason: failReason,
              classifier: "FAIL_POLICY",
            })
            throw failClosedBlock(
              `${failReason} (injection detector unavailable; fail-close)`,
              failAskNormalized,
              strictPolicy,
              staticDecision.rules,
              script,
            )
          }
          // detector === { injection: false } → still unconditional fail-close.
        }
        recordRejection(sessionState, { command: script, reason: failReason, classifier: "FAIL_POLICY" })
        throw failClosedBlock(failReason, failAskNormalized, strictPolicy, staticDecision.rules, script)
      }

      // infra ReviewError or unknown non-ReviewError → honor failPolicy.
      if (effectiveFailPolicy === "fail_open") {
        // Even on fail_open, still soft-enforce slow-command for default-timeout high-resource commands.
        maybeBlockSlow(script, input, shell, cwd, worktree)
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
    }

    yield* ctx.tool.hook("execute.before", (ev: ExecuteBeforeEvent) =>
      Effect.tryPromise({ try: () => runBefore(ev), catch: toRejection }),
    )

    // --- 3. failure recording (v1 tool.execute.after) -----------------------
    // execute.after failure channel is `never`: any exception is swallowed so a
    // post-check error never fails the tool step.
    async function runAfter(ev: ExecuteAfterEvent): Promise<void> {
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
      // H2: v2's result.output is a structured object ({ output, cursor, size,
      // truncated }), not a bare string — extract the text defensively.
      const rawOutput = ev.result?.output
      const outputText =
        typeof rawOutput === "string"
          ? rawOutput
          : rawOutput &&
              typeof rawOutput === "object" &&
              typeof (rawOutput as Record<string, unknown>).output === "string"
            ? ((rawOutput as Record<string, unknown>).output as string)
            : ""
      sessionState.lastFailed = {
        value: {
          command,
          exitCode,
          outputTail: sanitizeOutputTail(outputText),
        },
        generation: nextGeneration(sessionState),
      }
    }

    yield* ctx.tool.hook("execute.after", (ev: ExecuteAfterEvent) =>
      Effect.tryPromise({ try: () => runAfter(ev), catch: (error: unknown) => error }).pipe(
        Effect.catch(() => Effect.void),
      ),
    )

    // --- 7. session cleanup (v1 event hook) ---------------------------------
    // ctx.event.subscribe() returns a Stream of wire events; the durable
    // `session.deleted` payload is { type, data: { sessionID } } (verified in
    // packages/schema/src/session-event.ts). The consumer is forked onto the
    // plugin scope: unloading the plugin interrupts the fiber, replacing the old
    // manual `eventRunning`/iterator cleanup.
    yield* ctx.event
      .subscribe()
      .pipe(
        Stream.runForEach((event: unknown) =>
          Effect.sync(() => {
            const e = event as { type?: string; data?: { sessionID?: string } }
            if (e?.type === "session.deleted") {
              const sessionID = e.data?.sessionID
              if (typeof sessionID === "string") deleteSessionState(sessionID)
            }
          }),
        ),
      )
      .pipe(Effect.forkScoped)

    // Clear in-memory caches when the plugin scope finalizes (unload). The
    // forked event fiber is interrupted by the same scope close.
    yield* Effect.addFinalizer(() =>
      Effect.sync(() => {
        sessions.clear()
        dynamicAllowCache.clear()
        dynamicDenyCache.clear()
        inflightReviews.clear()
        sessionDirectories.clear()
      }),
    )
  }),
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
