import { createHash } from "node:crypto"
import path from "node:path"
import { access, realpath } from "node:fs/promises"
import { fileURLToPath } from "node:url"
import type { Plugin, PluginOptions } from "@opencode-ai/plugin"
import { resolveClassifierShell } from "./shell-dialect"
import {
  classifyShellCommand,
  isDownloadOrBuildCommand,
  isolateDetachedStartCommand,
  verifyScriptFingerprints,
  type StaticSecurityDecision,
} from "./security/classifier"
import {
  reviewCommandWithDeepSeek,
  type CloudReviewRequest,
  type CloudReviewResult,
  type ReviewCommandOptions,
} from "./security/reviewer"

type BashSecurityOptions = PluginOptions & {
  shell?: string
  securityEnabled?: boolean
  cloudReviewEnabled?: boolean
  auditorTimeoutMs?: number
  auditorPython?: string
  auditorPath?: string
  hardTimeoutMs?: number
  detachedStartIsolation?: boolean
  supervisorEnabled?: boolean
  supervisorPath?: string
  reviewCommand?: (request: CloudReviewRequest, options: ReviewCommandOptions) => Promise<CloudReviewResult>
}

const DYNAMIC_ALLOW_CACHE_TTL_MS = 30 * 60 * 1000
const MAX_DYNAMIC_ALLOW_CACHE_ENTRIES = 512
const DEFAULT_HARD_TIMEOUT_MS = 120_000
const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const DEFAULT_SUPERVISOR_PATH = path.join(
  PACKAGE_ROOT,
  "native",
  "windows-bash-supervisor",
  "target",
  "release",
  "bash.exe",
)

function positiveInteger(value: unknown, fallback: number) {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : fallback
}

function conciseReason(reason: string, limit = 160) {
  const value = reason.trim().replace(/\s+/g, " ").replace(/[.!?]+$/, "")
  return (value || "Blocked by policy").slice(0, limit)
}

function staticBlock(reason: string) {
  return new Error(`Command blocked by static classifier : ${conciseReason(reason, 120)}`)
}

function dynamicBlock(reason: string) {
  return new Error(`Command blocked by dynamic classifier:${conciseReason(reason, 80)}`)
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

function dynamicAllowCacheKey(
  script: string,
  cwd: string,
  shell: string,
  decision: StaticSecurityDecision,
) {
  const context = decision.reviewContext
  if (
    context?.uninspectedLocalScripts.length ||
    context?.uninspectedTargetDirectories.length ||
    context?.targetDirectories.some((directory) => directory.truncated)
  ) {
    return undefined
  }

  const payload = {
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
  }
  return createHash("sha256").update(JSON.stringify(payload)).digest("hex")
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

export const BashSummaryPlugin: Plugin = async (pluginContext, rawOptions) => {
  const options = (rawOptions ?? {}) as BashSecurityOptions
  let configuredShell = typeof options.shell === "string" ? options.shell : undefined
  const securityEnabled = options.securityEnabled !== false
  const cloudReviewEnabled = options.cloudReviewEnabled !== false
  const auditorTimeoutMs = positiveInteger(options.auditorTimeoutMs, 30_000)
  const hardTimeoutMs =
    typeof options.hardTimeoutMs === "number" && Number.isFinite(options.hardTimeoutMs) && options.hardTimeoutMs >= 0
      ? options.hardTimeoutMs
      : DEFAULT_HARD_TIMEOUT_MS
  const detachedStartIsolation = options.detachedStartIsolation !== false
  const supervisorEnabled = process.platform === "win32" && options.supervisorEnabled !== false
  const supervisorPath = path.resolve(
    typeof options.supervisorPath === "string" ? options.supervisorPath : DEFAULT_SUPERVISOR_PATH,
  )
  const auditorPython = typeof options.auditorPython === "string" ? options.auditorPython : undefined
  const auditorPath = typeof options.auditorPath === "string" ? options.auditorPath : undefined
  const reviewCommand = options.reviewCommand ?? reviewCommandWithDeepSeek
  const directory = await canonicalOrResolved(pluginContext.directory)
  const worktree = await canonicalOrResolved(pluginContext.worktree)
  const dynamicAllowCache = new Map<string, number>()
  let supervisorActive = false

  return {
    config: async (config) => {
      if (!configuredShell && typeof (config as { shell?: unknown }).shell === "string") {
        configuredShell = (config as { shell: string }).shell
      }
      if (!supervisorEnabled || !configuredShell || path.resolve(configuredShell) === supervisorPath) return
      try {
        await access(supervisorPath)
      } catch {
        return
      }
      ;(config as { shell?: string }).shell = supervisorPath
      process.env.OPENCODE_REAL_BASH = configuredShell
      supervisorActive = true
    },
    "shell.env": async (_input, output) => {
      if (!supervisorActive || !configuredShell) return
      output.env.OPENCODE_REAL_BASH = configuredShell
    },
    "tool.execute.before": async (input, output) => {
      if (input.tool !== "bash" || !securityEnabled) return

      const script = commandFromArgs(output.args)
      if (!script?.trim()) {
        throw staticBlock("Empty command")
      }

      const requestedWorkdir = workdirFromArgs(output.args)
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
      })

      if (staticDecision.verdict === "DENY") {
        throw staticBlock(staticDecision.reason)
      }

      if (staticDecision.verdict === "ASK") {
        if (cloudReviewEnabled) {
          const cacheKey = dynamicAllowCacheKey(script, cwd, shell, staticDecision)
          const now = Date.now()
          if (!cacheKey || !hasCachedDynamicAllow(dynamicAllowCache, cacheKey, now)) {
            let cloudReview: CloudReviewResult | undefined
            try {
              cloudReview = await reviewCommand(
                {
                  command: script,
                  localScripts: staticDecision.reviewContext?.localScripts ?? [],
                  uninspectedLocalScripts: staticDecision.reviewContext?.uninspectedLocalScripts ?? [],
                  targetDirectories: staticDecision.reviewContext?.targetDirectories ?? [],
                  uninspectedTargetDirectories: staticDecision.reviewContext?.uninspectedTargetDirectories ?? [],
                  worktree,
                  cwd,
                },
                {
                  python: auditorPython,
                  auditorPath,
                  timeoutMs: auditorTimeoutMs,
                },
              )
            } catch {
              // Dynamic review is an optimization guardrail. Availability failures fail open.
            }

            if (cloudReview?.decision === "DENY") {
              throw dynamicBlock(cloudReview.reason)
            }
            if (cloudReview?.decision === "ALLOW" && cacheKey) {
              cacheDynamicAllow(dynamicAllowCache, cacheKey, now)
            }
          }
        }
      }

      if (!(await verifyScriptFingerprints(staticDecision.fingerprints))) {
        throw staticBlock("Local script changed after review")
      }

      if (hardTimeoutMs > 0 && !isDownloadOrBuildCommand(script)) {
        const original = (output.args as Record<string, unknown>).timeout
        const hasExplicit = typeof original === "number" && Number.isFinite(original) && original > 0
        if (!hasExplicit) {
          ;(output.args as Record<string, unknown>).timeout = hardTimeoutMs
        }
      }

      if (detachedStartIsolation && !supervisorActive) {
        const isolated = isolateDetachedStartCommand(script, shell)
        if (isolated !== script) {
          ;(output.args as Record<string, unknown>).command = isolated
        }
      }
    },
  }
}

export default BashSummaryPlugin
export { classifyShellCommand, verifyScriptFingerprints } from "./security/classifier"
export { reviewCommandWithDeepSeek } from "./security/reviewer"
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
  ReviewCommandOptions,
} from "./security/reviewer"
