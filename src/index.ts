import { createHash, randomUUID } from "node:crypto"
import path from "node:path"
import { access, realpath } from "node:fs/promises"
import type { Plugin } from "@opencode-ai/plugin"
import { tool } from "@opencode-ai/plugin"
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

const DYNAMIC_ALLOW_CACHE_TTL_MS = 30 * 60 * 1000
const MAX_DYNAMIC_ALLOW_CACHE_ENTRIES = 512
const PROMPT_VERSION = "v1"
const PENDING_REQUEST_TTL_MS = 5 * 60 * 1000
const SESSION_STATE_TTL_MS = 30 * 60 * 1000
const MAX_SESSION_STATES = 512
const MAX_OUTPUT_TAIL_CHARS = 2000

const BLOCK_SUFFIX =
  "DO NOT retry the same command or try using alternative method.Skip the step or stop and report the user if it's a essential step of the work"

type SessionState = {
  version: number
  touchedAt: number
  lastRejected?: { value: PreviousRejectedCommand; generation: number }
  lastFailed?: {
    value: PreviousFailedCommand
    generation: number
    consumedBy?: string
  }
  pending?: {
    requestId: string
    generation: number
    command: string
    cwd: string
    policy: string
    reason: string
    createdAt: number
    expiresAt: number
  }
  approved?: { fingerprint: string; rejectionGeneration?: number }
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
  return new Error(
    `Blocked by ${type} classifier: ${conciseReason(reason, type === "dynamic" ? 80 : 120)}.${guidance} ${BLOCK_SUFFIX}`,
  )
}

function failAskBlock(reason: string, requestId: string) {
  return new Error(
    `Blocked by policy classifier: ${conciseReason(
      reason,
      120,
    )}. Call the bash_classifier_confirm tool with requestId "${requestId}" to request user approval. Before approval, do not retry this command or use an alternative method; after approval, retry only the exact same command.`,
  )
}

function applyPatchDeleteBlock() {
  return new Error(
    "apply_patch cannot delete files. Use a bash command so the bash classifier and OpenCode permission layer can review the deletion.",
  )
}

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

function commandFingerprint(command: string, cwd: string, strictness: string) {
  return createHash("sha256").update(JSON.stringify({ command, cwd, strictness })).digest("hex")
}

function sanitizeOutputTail(output: string) {
  const trimmed = (output ?? "").replace(/\0/g, "").trim()
  if (!trimmed) return ""
  return trimmed.slice(-MAX_OUTPUT_TAIL_CHARS).replace(/\s+/g, " ").trim()
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
    script,
    cwd,
    shell,
    rules: decision.rules,
    fingerprints: decision.fingerprints.map((fingerprint) => ({
      path: fingerprint.path,
      size: fingerprint.size,
      mtimeMs: fingerprint.mtimeMs,
      sha256: fingerprint.sha256,
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

function isLocalScriptExecution(decision: StaticSecurityDecision) {
  if (decision.rules.some((rule) => rule.startsWith("execution.local-script"))) return true
  const ctx = decision.reviewContext
  return Boolean(ctx && ((ctx.localScripts?.length ?? 0) > 0 || (ctx.uninspectedLocalScripts?.length ?? 0) > 0))
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

function generateRequestId() {
  return `bc_${randomUUID().replace(/-/g, "").slice(0, 24)}`
}

export const BashSummaryPlugin: Plugin = async (pluginContext, rawOptions) => {
  const resolved = resolvePluginConfig(rawOptions as BashClassifierOptions | undefined)
  let configuredShell = resolved.shell
  const directory = await canonicalOrResolved(pluginContext.directory)
  const worktree = await canonicalOrResolved(pluginContext.worktree)
  const sessions = new Map<string, SessionState>()
  const dynamicAllowCache = new Map<string, number>()
  const strictPolicy = resolved.strictness === "HARD"
  let supervisorActive = false

  function deleteSessionState(sessionID: string) {
    sessions.delete(sessionID)
    const prefix = `${sessionID}:`
    for (const key of dynamicAllowCache.keys()) {
      if (key.startsWith(prefix)) dynamicAllowCache.delete(key)
    }
  }

  function pruneSessionStates(now: number) {
    for (const [sessionID, state] of sessions) {
      if (state.touchedAt + SESSION_STATE_TTL_MS <= now) deleteSessionState(sessionID)
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

  function reviewerAvailable() {
    return Boolean(resolved.reviewCommand)
  }

  function nextGeneration(state: SessionState) {
    state.touchedAt = Date.now()
    return ++state.version
  }

  function recordRejection(
    state: SessionState,
    value: PreviousRejectedCommand,
  ) {
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

  async function abortSession(sessionID: string) {
    try {
      await pluginContext.client.session.abort({
        path: { id: sessionID },
        query: { directory: pluginContext.directory },
        throwOnError: true,
      })
    } catch {
      // abort failure must not allow the command — the caller still throws
    }
  }

  function applyPostChecks(
    script: string,
    args: Record<string, unknown>,
    decision: StaticSecurityDecision,
    shell: string,
  ) {
    if (
      resolved.hardTimeoutMs > 0 &&
      !isDownloadOrBuildCommand(script)
    ) {
      const original = args.timeout
      const hasExplicit = typeof original === "number" && Number.isFinite(original) && original > 0
      if (!hasExplicit) {
        args.timeout = resolved.hardTimeoutMs
      }
    }

    if (resolved.detachedStartIsolation && !supervisorActive) {
      const isolated = isolateDetachedStartCommand(script, shell)
      if (isolated !== script) {
        args.command = isolated
      }
    }

    return verifyScriptFingerprints(decision.fingerprints)
  }

  return {
    config: async (config) => {
      if (!configuredShell && typeof (config as { shell?: unknown }).shell === "string") {
        configuredShell = (config as { shell: string }).shell
      }
      if (
        !resolved.supervisorEnabled ||
        !configuredShell ||
        path.resolve(configuredShell) === resolved.supervisorPath
      ) {
        return
      }
      try {
        await access(resolved.supervisorPath)
      } catch {
        return
      }
      ;(config as { shell?: string }).shell = resolved.supervisorPath
      supervisorActive = true
    },
    "shell.env": async (_input, output) => {
      if (!supervisorActive || !configuredShell) return
      output.env.OPENCODE_REAL_BASH = configuredShell
    },
    "tool.execute.before": async (input, output) => {
      if (input.tool === "apply_patch") {
        const args = output.args as Record<string, unknown>
        const patchText =
          typeof args.patchText === "string"
            ? args.patchText
            : typeof args.patch === "string"
              ? args.patch
              : typeof args.diff === "string"
                ? args.diff
                : undefined
        if (patchText && /^\*\*\* Delete File:/m.test(patchText)) {
          throw applyPatchDeleteBlock()
        }
        return
      }

      if (input.tool !== "bash" || !resolved.securityEnabled) return

      const sessionID = input.sessionID
      const sessionState = getSessionState(sessionID)
      const args = output.args as Record<string, unknown>
      const script = commandFromArgs(args)
      if (!script?.trim()) {
        rejectStatic(sessionState, "", "Empty command")
      }

      const requestedWorkdir = workdirFromArgs(args)
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

      if (sessionState.approved) {
        const fp = commandFingerprint(script, cwd, resolved.strictness)
        const approved = sessionState.approved
        sessionState.approved = undefined
        if (approved.fingerprint === fp) {
          if (
            approved.rejectionGeneration !== undefined &&
            sessionState.lastRejected?.generation === approved.rejectionGeneration
          ) {
            sessionState.lastRejected = undefined
          }
          if (!(await applyPostChecks(script, args, staticDecision, shell))) {
            rejectStatic(sessionState, script, "Local script changed after review", staticDecision.rules)
          }
          return
        }
      }

      const rejectionAtStart = strictPolicy ? sessionState.lastRejected : undefined
      const failureAtStart =
        sessionState.lastFailed &&
        !sessionState.lastFailed.consumedBy &&
        isLocalScriptExecution(staticDecision)
          ? sessionState.lastFailed
          : undefined
      const forcedByRejection = Boolean(rejectionAtStart)
      const forcedByFailure = Boolean(failureAtStart)
      const forced = forcedByRejection || forcedByFailure

      if (staticDecision.verdict === "ALLOW" && !forced) {
        if (!(await applyPostChecks(script, args, staticDecision, shell))) {
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
          if (!(await applyPostChecks(script, args, staticDecision, shell))) {
            rejectStatic(sessionState, script, "Local script changed after review", staticDecision.rules)
          }
          return
        }
      }

      const callID = typeof input.callID === "string" ? input.callID : generateRequestId()
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
        if (!(await applyPostChecks(script, args, staticDecision, shell))) {
          rejectStatic(sessionState, script, "Local script changed after review", staticDecision.rules)
        }
        return
      }

      const failReason = reviewError?.message ?? "Dynamic review failed"
      switch (resolved.failPolicy) {
        case "fail_open":
          if (!(await applyPostChecks(script, args, staticDecision, shell))) {
            rejectStatic(sessionState, script, "Local script changed after review", staticDecision.rules)
          }
          return
        case "fail_close":
          recordRejection(sessionState, {
            command: script,
            reason: failReason,
            classifier: "FAIL_POLICY",
          })
          throw blockMessage("policy", failReason, strictPolicy, staticDecision.rules, script)
        case "fail_ask": {
          const requestId = generateRequestId()
          const rejectionGeneration = recordRejection(sessionState, {
            command: script,
            reason: failReason,
            classifier: "FAIL_POLICY",
          })
          const generation = rejectionGeneration ?? nextGeneration(sessionState)
          const now = Date.now()
          sessionState.pending = {
            requestId,
            generation,
            command: script,
            cwd,
            policy: resolved.strictness,
            reason: failReason,
            createdAt: now,
            expiresAt: now + PENDING_REQUEST_TTL_MS,
          }
          throw failAskBlock(failReason, requestId)
        }
      }
    },
    "tool.execute.after": async (input, output) => {
      if (input.tool !== "bash" || !resolved.securityEnabled) return

      const sessionID = input.sessionID
      const sessionState = getSessionState(sessionID)
      const metadata = output.metadata as Record<string, unknown> | undefined

      const rawExit = metadata?.exit ?? metadata?.exitCode
      const exitCode = typeof rawExit === "number" ? rawExit : undefined
      if (exitCode === undefined) return

      if (exitCode === 0) {
        const callID = typeof input.callID === "string" ? input.callID : undefined
        if (callID && sessionState.lastFailed?.consumedBy === callID) {
          sessionState.lastFailed = undefined
        }
        return
      }

      const command = commandFromArgs(input.args) ?? ""
      sessionState.lastFailed = {
        value: {
          command,
          exitCode,
          outputTail: sanitizeOutputTail(output.output),
        },
        generation: nextGeneration(sessionState),
      }
    },
    event: async (input) => {
      const event = input.event as { type: string; properties?: { info?: { id?: string } } }
      if (event.type === "session.deleted") {
        const sessionID = event.properties?.info?.id
        if (typeof sessionID === "string") {
          deleteSessionState(sessionID)
        }
      }
    },
    dispose: async () => {
      sessions.clear()
      dynamicAllowCache.clear()
    },
    tool: {
      bash_classifier_confirm: tool({
        description: [
          "Request user approval for a bash command that was blocked by the fail_ask policy.",
          "Only call this tool when a bash command is blocked with a message instructing you",
          'to call bash_classifier_confirm with a specific requestId. Pass that requestId exactly.',
          "If the user approves, retry the exact same bash command. Do not modify the command.",
        ].join(" "),
        args: {
          requestId: tool.schema
            .string()
            .describe("The pending request ID from the block message"),
        },
        async execute(args, context) {
          pruneSessionStates(Date.now())
          const sessionState = sessions.get(context.sessionID)
          if (!sessionState?.pending) {
            return {
              title: "No pending request",
              output:
                "No pending approval request for this session. The blocked command may have expired or was already processed.",
            }
          }

          const pending = sessionState.pending
          if (pending.requestId !== args.requestId) {
            return {
              title: "Request ID mismatch",
              output: `The request ID "${args.requestId}" does not match the pending request ID "${pending.requestId}".`,
            }
          }

          if (Date.now() > pending.expiresAt) {
            if (
              sessionState.pending?.requestId === pending.requestId &&
              sessionState.pending.generation === pending.generation
            ) {
              sessionState.pending = undefined
            }
            return {
              title: "Request expired",
              output:
                "The approval request has expired. Retry the original bash command to get a new request ID.",
            }
          }

          try {
            await context.ask({
              permission: "bash-classifier-confirm",
              patterns: [pending.requestId],
              always: [],
              metadata: {
                command: pending.command,
                reason: pending.reason,
                cwd: pending.cwd,
              },
            })
            const current = sessions.get(context.sessionID)
            if (
              current !== sessionState ||
              current.pending?.requestId !== pending.requestId ||
              current.pending.generation !== pending.generation
            ) {
              return {
                title: "Request superseded",
                output: "A newer approval request replaced this one; no approval was recorded.",
              }
            }
            sessionState.approved = {
              fingerprint: commandFingerprint(pending.command, pending.cwd, pending.policy),
              rejectionGeneration: strictPolicy ? pending.generation : undefined,
            }
            sessionState.pending = undefined
            return {
              title: "Approved",
              output: `User approved the command: ${pending.command}. Retry the exact same bash command now.`,
            }
          } catch {
            const current = sessions.get(context.sessionID)
            if (
              current === sessionState &&
              current.pending?.requestId === pending.requestId &&
              current.pending.generation === pending.generation
            ) {
              sessionState.pending = undefined
            } else {
              return {
                title: "Request superseded",
                output: "A newer approval request replaced this one; the newer request remains pending.",
              }
            }
            return {
              title: "Denied",
              output: "User denied the command. Do not retry the command.",
            }
          }
        },
      }),
    },
  }
}

export default BashSummaryPlugin
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
