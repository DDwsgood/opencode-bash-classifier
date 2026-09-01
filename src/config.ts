import { lstatSync } from "node:fs"
import { isIP } from "node:net"
import path from "node:path"
import { fileURLToPath } from "node:url"
import {
  reviewCommandWithAuditor,
  type CloudReviewRequest,
  type CloudReviewResult,
  type ReviewCommandOptions,
} from "./security/reviewer"

export type Strictness = "LOOSE" | "HARD"
export type FailPolicy = "fail_ask" | "fail_open" | "fail_close"

/** Escape-hatch categories the user can arm permanently (config.json
 * `BypassClassifier`) or per-session (`/bypass-classifier`). `dynamic` skips the
 * dynamic reviewer entirely; the others disable matching static rule groups
 * and relax the dynamic reviewer's prompt for that session. */
export const BYPASS_CATEGORIES = ["filesystem", "os", "secret", "dynamic", "web"] as const
export type BypassCategory = (typeof BYPASS_CATEGORIES)[number]

const DEFAULT_BYPASS_LEASE_TTL_MS = 20 * 60 * 1000
const MIN_BYPASS_LEASE_TTL_MS = 60_000
const MAX_BYPASS_LEASE_TTL_MS = 24 * 60 * 60 * 1000

export type DynamicReviewOptions = {
  baseURL?: string
  model?: string
  apiKey?: string
  apiKeyEnv?: string
  timeoutMs?: number
  maxRounds?: number
  /** Allow the auditor's bounded read-only tools to inspect the full filesystem. */
  allowFullReadAccess?: boolean
  /** Python interpreter for the auditor. A bare command name (no path separator)
   * defers to PATH lookup at spawn time; a path containing a separator is resolved
   * relative to the package root and must be an existing regular file. */
  pythonPath?: string
  /** Path to the auditor script. Relative paths resolve against the package root
   * and must point to an existing regular file (directories are rejected). */
  auditorPath?: string
  [key: string]: unknown
}

export type ReviewCommand = (
  request: CloudReviewRequest,
  options: ReviewCommandOptions,
) => Promise<CloudReviewResult>

export type SlowCommandsOptions = {
  enabled?: boolean
  maxDepth?: number
  sleepThresholdSeconds?: number
  allowExplicitTimeout?: boolean
  [key: string]: unknown
}

export type BashClassifierOptions = {
  shell?: string
  securityEnabled?: boolean
  hardTimeoutMs?: number
  detachedStartIsolation?: boolean
  supervisorEnabled?: boolean
  supervisorPath?: string
  strictness?: Strictness
  failPolicy?: FailPolicy
  dynamicReview?: DynamicReviewOptions
  /** Block (static DENY) safe-but-wasteful commands: unbounded scans of
   * system/mounted trees, streaming commands, and over-long sleeps.
   * When `true` (default) enables the slow-command classifier. When an object,
   * `enabled` toggles it independently. */
  slowCommands?: boolean | SlowCommandsOptions
  /** Append one JSONL line to ~/.opencode/reviewer-trace.jsonl for every
   * dynamic review (verdict or error) and every dynamic cache hit. */
  logReviewerTrace?: boolean
  /** Permanently armed escape-hatch categories (all sessions, all clients). */
  BypassClassifier?: BypassCategory[]
  /** Activity-renewed lease TTL for temporary per-session bypass entries, in
   * milliseconds. Default 20 minutes. */
  bypassLeaseTtlMs?: number
  /** Whether a session's temporary bypass also covers its subagent children
   * (default true). */
  bypassPropagateToSubagents?: boolean
  /** Test-injection only; never wired by the plugin itself. */
  reviewCommand?: ReviewCommand
  [key: string]: unknown
}

export type ResolvedDynamicReview = {
  available: boolean
  endpoint?: string
  model?: string
  apiKey?: string
  timeoutMs: number
  maxRounds: number
  pythonPath?: string
  auditorPath?: string
  allowFullReadAccess: boolean
  /** Human-readable unavailability reason; never contains secrets. */
  reason?: string
}

export type ResolvedSlowCommands = {
  enabled: boolean
  maxDepth: number
  sleepThresholdSeconds: number
  allowExplicitTimeout: boolean
}

export type ResolvedPluginConfig = {
  shell?: string
  securityEnabled: boolean
  hardTimeoutMs: number
  detachedStartIsolation: boolean
  supervisorEnabled: boolean
  supervisorPath: string
  strictness: Strictness
  failPolicy: FailPolicy
  slowCommands: ResolvedSlowCommands
  logReviewerTrace: boolean
  bypassClassifier: ReadonlySet<BypassCategory>
  bypassLeaseTtlMs: number
  bypassPropagateToSubagents: boolean
  /** Non-fatal BypassClassifier validation warnings (unknown categories). */
  bypassWarnings: readonly string[]
  dynamicReview: ResolvedDynamicReview
  reviewCommand?: ReviewCommand
}

const ALLOWED_TOP_LEVEL = new Set([
  "shell",
  "securityEnabled",
  "hardTimeoutMs",
  "detachedStartIsolation",
  "supervisorEnabled",
  "supervisorPath",
  "strictness",
  "failPolicy",
  "dynamicReview",
  "slowCommands",
  "logReviewerTrace",
  "BypassClassifier",
  "bypassLeaseTtlMs",
  "bypassPropagateToSubagents",
  "reviewCommand",
])

const ALLOWED_SLOW_FIELDS = new Set(["enabled", "maxDepth", "sleepThresholdSeconds", "allowExplicitTimeout"])

const ALLOWED_DYNAMIC_FIELDS = new Set([
  "baseURL",
  "model",
  "apiKey",
  "apiKeyEnv",
  "timeoutMs",
  "maxRounds",
  "allowFullReadAccess",
  "pythonPath",
  "auditorPath",
])

const DEFAULT_HARD_TIMEOUT_MS = 120_000
const DEFAULT_TIMEOUT_MS = 30_000
const MIN_TIMEOUT_MS = 1
const MAX_TIMEOUT_MS = 120_000
const MIN_MAX_ROUNDS = 1

const API_KEY_ENV_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/
const FORBIDDEN_KEY_CHARS = /[\r\n\0]/
const MAX_MODEL_LENGTH = 256
const URL_CONTROL_CHARS = /[\u0000-\u001F\u007F]/

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const DEFAULT_SUPERVISOR_PATH = path.join(
  PACKAGE_ROOT,
  "native",
  "windows-bash-supervisor",
  "target",
  "release",
  "bash.exe",
)

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

function resolveTimeoutMs(raw: unknown): { value: number; reason?: string } {
  if (raw === undefined) return { value: DEFAULT_TIMEOUT_MS }
  if (typeof raw !== "number" || !Number.isFinite(raw) || !Number.isInteger(raw)) {
    return { value: DEFAULT_TIMEOUT_MS, reason: "dynamicReview.timeoutMs must be an integer" }
  }
  if (raw < MIN_TIMEOUT_MS || raw > MAX_TIMEOUT_MS) {
    return {
      value: DEFAULT_TIMEOUT_MS,
      reason: `dynamicReview.timeoutMs must be between ${MIN_TIMEOUT_MS} and ${MAX_TIMEOUT_MS}`,
    }
  }
  return { value: raw }
}

function resolveMaxRounds(raw: unknown, strictness: Strictness): { value: number; reason?: string } {
  const fallback = strictness === "LOOSE" ? 1 : 2
  const limit = strictness === "LOOSE" ? 3 : 5
  if (raw === undefined) return { value: fallback }
  if (typeof raw !== "number" || !Number.isFinite(raw) || !Number.isInteger(raw)) {
    return { value: fallback, reason: "dynamicReview.maxRounds must be an integer" }
  }
  if (raw < MIN_MAX_ROUNDS || raw > limit) {
    return {
      value: fallback,
      reason: `dynamicReview.maxRounds must be between ${MIN_MAX_ROUNDS} and ${limit} for the selected policy`,
    }
  }
  return { value: raw }
}

function resolveEndpoint(raw: unknown): { endpoint?: string; reason?: string } {
  if (typeof raw !== "string" || !raw.trim()) {
    return { reason: "dynamicReview.baseURL is not configured" }
  }
  const trimmed = raw.trim()
  if (URL_CONTROL_CHARS.test(trimmed)) {
    return { reason: "dynamicReview.baseURL must not contain control characters" }
  }
  let parsed: URL
  try {
    parsed = new URL(trimmed)
  } catch {
    return { reason: "dynamicReview.baseURL is not a valid URL" }
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { reason: "dynamicReview.baseURL must use http or https" }
  }
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "")
  const ipVersion = isIP(hostname)
  const loopback =
    hostname === "localhost" ||
    (ipVersion === 4 && hostname.startsWith("127.")) ||
    (ipVersion === 6 && hostname === "::1")
  if (parsed.protocol === "http:" && !loopback) {
    return { reason: "dynamicReview.baseURL may use http only for a loopback host" }
  }
  if (parsed.username || parsed.password) {
    return { reason: "dynamicReview.baseURL must not contain userinfo" }
  }
  if (parsed.hash) {
    return { reason: "dynamicReview.baseURL must not contain a fragment" }
  }
  const query = parsed.search
  let pathname = parsed.pathname.replace(/\/+$/, "")
  if (!pathname.endsWith("/chat/completions")) pathname += "/chat/completions"
  const endpoint = `${parsed.protocol}//${parsed.host}${pathname}${query}`
  return { endpoint }
}

function resolveModel(raw: unknown): { model?: string; reason?: string } {
  if (typeof raw !== "string" || !raw.trim()) {
    return { reason: "dynamicReview.model is not configured" }
  }
  const trimmed = raw.trim()
  if (trimmed.length > MAX_MODEL_LENGTH) {
    return { reason: "dynamicReview.model exceeds the length limit" }
  }
  return { model: trimmed }
}

function resolveApiKey(dynamic: Record<string, unknown>): { apiKey?: string; reason?: string } {
  const hasApiKey = dynamic.apiKey !== undefined
  const hasApiKeyEnv = dynamic.apiKeyEnv !== undefined
  if (hasApiKey && hasApiKeyEnv) {
    return { reason: "provide exactly one of dynamicReview.apiKey or apiKeyEnv" }
  }
  if (!hasApiKey && !hasApiKeyEnv) {
    return { reason: "dynamicReview requires apiKey or apiKeyEnv" }
  }

  let rawKey: string
  if (hasApiKey) {
    if (typeof dynamic.apiKey !== "string") {
      return { reason: "dynamicReview.apiKey must be a string" }
    }
    rawKey = dynamic.apiKey
  } else {
    const envName = dynamic.apiKeyEnv
    if (typeof envName !== "string" || !envName.trim()) {
      return { reason: "dynamicReview.apiKeyEnv must be a non-empty string" }
    }
    if (!API_KEY_ENV_PATTERN.test(envName)) {
      return { reason: "dynamicReview.apiKeyEnv is not a valid environment variable name" }
    }
    const value = process.env[envName]
    if (typeof value !== "string") {
      return { reason: `dynamicReview.apiKeyEnv "${envName}" did not resolve to a value` }
    }
    rawKey = value
  }

  if (FORBIDDEN_KEY_CHARS.test(rawKey)) {
    return { reason: "dynamicReview api key contains forbidden control characters" }
  }
  const key = rawKey.trim()
  if (!key) {
    return { reason: "dynamicReview api key is empty" }
  }
  return { apiKey: key }
}

function isRegularFile(filePath: string): boolean {
  try {
    return lstatSync(filePath).isFile()
  } catch {
    return false
  }
}

function resolveAuditorPath(raw: unknown): { auditorPath?: string; reason?: string } {
  if (raw === undefined) return {}
  if (typeof raw !== "string" || !raw.trim()) {
    return { reason: "dynamicReview.auditorPath must be a non-empty string" }
  }
  const resolved = path.resolve(PACKAGE_ROOT, raw.trim())
  if (!isRegularFile(resolved)) {
    return { reason: "dynamicReview.auditorPath is not an existing regular file" }
  }
  return { auditorPath: resolved }
}

function resolvePythonPath(raw: unknown): { pythonPath?: string; reason?: string } {
  if (raw === undefined) return {}
  if (typeof raw !== "string" || !raw.trim()) {
    return { reason: "dynamicReview.pythonPath must be a non-empty string" }
  }
  const trimmed = raw.trim()
  // A bare command name (no path separator) is left as-is so the reviewer can
  // resolve it through PATH at spawn time; a path with a directory component is
  // resolved against the package root and must be an existing regular file.
  if (!trimmed.includes("/") && !trimmed.includes("\\")) {
    return { pythonPath: trimmed }
  }
  const resolved = path.resolve(PACKAGE_ROOT, trimmed)
  if (!isRegularFile(resolved)) {
    return { reason: "dynamicReview.pythonPath is not an existing regular file" }
  }
  return { pythonPath: resolved }
}

function resolveDynamicReview(raw: unknown, strictness: Strictness): ResolvedDynamicReview {
  const defaultRounds = strictness === "LOOSE" ? 1 : 2
  if (raw === undefined) {
    return {
      available: false,
      timeoutMs: DEFAULT_TIMEOUT_MS,
      maxRounds: defaultRounds,
      allowFullReadAccess: false,
      reason: "dynamic review is not configured",
    }
  }
  if (!isPlainObject(raw)) {
    return {
      available: false,
      timeoutMs: DEFAULT_TIMEOUT_MS,
      maxRounds: defaultRounds,
      allowFullReadAccess: false,
      reason: "dynamicReview must be an object",
    }
  }
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_DYNAMIC_FIELDS.has(key)) {
      return {
        available: false,
        timeoutMs: DEFAULT_TIMEOUT_MS,
        maxRounds: defaultRounds,
        allowFullReadAccess: false,
        reason: `dynamicReview contains an unknown field: ${key}`,
      }
    }
  }

  const dynamic = raw as Record<string, unknown>
  const timeout = resolveTimeoutMs(dynamic.timeoutMs)
  const rounds = resolveMaxRounds(dynamic.maxRounds, strictness)
  const allowFullReadAccess = dynamic.allowFullReadAccess
  const endpointResult = resolveEndpoint(dynamic.baseURL)
  const modelResult = resolveModel(dynamic.model)
  const keyResult = resolveApiKey(dynamic)
  const auditorResult = resolveAuditorPath(dynamic.auditorPath)
  const pythonResult = resolvePythonPath(dynamic.pythonPath)

  const reason =
    endpointResult.reason ??
    modelResult.reason ??
    keyResult.reason ??
    timeout.reason ??
    rounds.reason ??
    auditorResult.reason ??
    pythonResult.reason
  const accessReason =
    allowFullReadAccess === undefined || typeof allowFullReadAccess === "boolean"
      ? undefined
      : "dynamicReview.allowFullReadAccess must be a boolean"
  const unavailableReason = reason ?? accessReason
  if (unavailableReason) {
    return {
      available: false,
      timeoutMs: timeout.value,
      maxRounds: rounds.value,
      allowFullReadAccess: false,
      reason: unavailableReason,
    }
  }

  return {
    available: true,
    endpoint: endpointResult.endpoint,
    model: modelResult.model,
    apiKey: keyResult.apiKey,
    timeoutMs: timeout.value,
    maxRounds: rounds.value,
    pythonPath: pythonResult.pythonPath,
    auditorPath: auditorResult.auditorPath,
    allowFullReadAccess: allowFullReadAccess === true,
  }
}

function resolveBypassCategories(raw: unknown): { value: ReadonlySet<BypassCategory>; warnings: string[] } {
  if (raw === undefined) return { value: new Set(), warnings: [] }
  if (!Array.isArray(raw)) throw new Error("BypassClassifier must be an array of category strings")
  const warnings: string[] = []
  const value = new Set<BypassCategory>()
  for (const item of raw) {
    if (typeof item !== "string") {
      warnings.push("BypassClassifier contains a non-string entry that was ignored")
      continue
    }
    const category = BYPASS_CATEGORIES.find((entry) => entry === item.trim())
    if (!category) {
      warnings.push(`BypassClassifier contains an unknown category "${item.trim()}" that was ignored`)
      continue
    }
    value.add(category)
  }
  return { value, warnings }
}

function resolveBypassLeaseTtlMs(raw: unknown): number {
  if (raw === undefined) return DEFAULT_BYPASS_LEASE_TTL_MS
  if (
    typeof raw !== "number" ||
    !Number.isFinite(raw) ||
    !Number.isInteger(raw) ||
    raw < MIN_BYPASS_LEASE_TTL_MS ||
    raw > MAX_BYPASS_LEASE_TTL_MS
  ) {
    throw new Error(
      `bypassLeaseTtlMs must be an integer between ${MIN_BYPASS_LEASE_TTL_MS} and ${MAX_BYPASS_LEASE_TTL_MS}`,
    )
  }
  return raw
}

export function resolvePluginConfig(raw?: BashClassifierOptions): ResolvedPluginConfig {
  const source = raw ?? {}

  for (const key of Object.keys(source)) {
    if (!ALLOWED_TOP_LEVEL.has(key)) {
      throw new Error(`unknown option: ${key}`)
    }
  }

  let shell: string | undefined
  if (source.shell !== undefined) {
    if (typeof source.shell !== "string") throw new Error("shell must be a string")
    shell = source.shell
  }

  let securityEnabled = true
  if (source.securityEnabled !== undefined) {
    if (typeof source.securityEnabled !== "boolean") {
      throw new Error("securityEnabled must be a boolean")
    }
    securityEnabled = source.securityEnabled
  }

  let hardTimeoutMs = DEFAULT_HARD_TIMEOUT_MS
  if (source.hardTimeoutMs !== undefined) {
    if (
      typeof source.hardTimeoutMs !== "number" ||
      !Number.isFinite(source.hardTimeoutMs) ||
      source.hardTimeoutMs < 0
    ) {
      throw new Error("hardTimeoutMs must be a non-negative finite number")
    }
    hardTimeoutMs = source.hardTimeoutMs
  }

  let detachedStartIsolation = true
  if (source.detachedStartIsolation !== undefined) {
    if (typeof source.detachedStartIsolation !== "boolean") {
      throw new Error("detachedStartIsolation must be a boolean")
    }
    detachedStartIsolation = source.detachedStartIsolation
  }

  let slowCommands: ResolvedSlowCommands
  if (source.slowCommands === undefined) {
    slowCommands = { enabled: true, maxDepth: 3, sleepThresholdSeconds: 120, allowExplicitTimeout: true }
  } else if (typeof source.slowCommands === "boolean") {
    slowCommands = {
      enabled: source.slowCommands,
      maxDepth: 3,
      sleepThresholdSeconds: 120,
      allowExplicitTimeout: true,
    }
  } else if (isPlainObject(source.slowCommands)) {
    const raw = source.slowCommands as Record<string, unknown>
    for (const key of Object.keys(raw)) {
      if (!ALLOWED_SLOW_FIELDS.has(key)) throw new Error(`unknown slowCommands option: ${key}`)
    }
    const enabled = raw.enabled === undefined ? true : raw.enabled
    const maxDepth = raw.maxDepth === undefined ? 3 : raw.maxDepth
    const sleepThresholdSeconds = raw.sleepThresholdSeconds === undefined ? 120 : raw.sleepThresholdSeconds
    const allowExplicitTimeout = raw.allowExplicitTimeout === undefined ? true : raw.allowExplicitTimeout
    if (typeof enabled !== "boolean") throw new Error("slowCommands.enabled must be a boolean")
    if (typeof maxDepth !== "number" || !Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > 32)
      throw new Error("slowCommands.maxDepth must be an integer between 0 and 32")
    if (
      typeof sleepThresholdSeconds !== "number" ||
      !Number.isFinite(sleepThresholdSeconds) ||
      sleepThresholdSeconds < 0
    )
      throw new Error("slowCommands.sleepThresholdSeconds must be a non-negative number")
    if (typeof allowExplicitTimeout !== "boolean")
      throw new Error("slowCommands.allowExplicitTimeout must be a boolean")
    slowCommands = { enabled, maxDepth, sleepThresholdSeconds, allowExplicitTimeout }
  } else {
    throw new Error("slowCommands must be a boolean or an object")
  }

  if (source.supervisorEnabled !== undefined && typeof source.supervisorEnabled !== "boolean") {
    throw new Error("supervisorEnabled must be a boolean")
  }
  const supervisorEnabled = process.platform === "win32" && source.supervisorEnabled !== false

  let supervisorPath: string
  if (source.supervisorPath !== undefined) {
    if (typeof source.supervisorPath !== "string") {
      throw new Error("supervisorPath must be a string")
    }
    supervisorPath = path.resolve(source.supervisorPath)
  } else {
    supervisorPath = path.resolve(DEFAULT_SUPERVISOR_PATH)
  }

  let strictness: Strictness = "LOOSE"
  if (source.strictness !== undefined) {
    if (source.strictness !== "LOOSE" && source.strictness !== "HARD") {
      throw new Error('strictness must be "LOOSE" or "HARD"')
    }
    strictness = source.strictness
  }

  let failPolicy: FailPolicy = "fail_open"
  if (source.failPolicy !== undefined) {
    if (
      source.failPolicy !== "fail_ask" &&
      source.failPolicy !== "fail_open" &&
      source.failPolicy !== "fail_close"
    ) {
      throw new Error('failPolicy must be "fail_ask", "fail_open", or "fail_close"')
    }
    failPolicy = source.failPolicy
  }

  let configuredReviewCommand: ReviewCommand | undefined
  if (source.reviewCommand !== undefined) {
    if (typeof source.reviewCommand !== "function") {
      throw new Error("reviewCommand must be a function")
    }
    configuredReviewCommand = source.reviewCommand as ReviewCommand
  }

  let logReviewerTrace = false
  if (source.logReviewerTrace !== undefined) {
    if (typeof source.logReviewerTrace !== "boolean") {
      throw new Error("logReviewerTrace must be a boolean")
    }
    logReviewerTrace = source.logReviewerTrace
  }

  const bypass = resolveBypassCategories(source.BypassClassifier)
  const bypassLeaseTtlMs = resolveBypassLeaseTtlMs(source.bypassLeaseTtlMs)
  let bypassPropagateToSubagents = true
  if (source.bypassPropagateToSubagents !== undefined) {
    if (typeof source.bypassPropagateToSubagents !== "boolean") {
      throw new Error("bypassPropagateToSubagents must be a boolean")
    }
    bypassPropagateToSubagents = source.bypassPropagateToSubagents
  }

  const dynamicReview = resolveDynamicReview(source.dynamicReview, strictness)
  const routeReview = configuredReviewCommand ?? (dynamicReview.available ? reviewCommandWithAuditor : undefined)
  const reviewCommand: ReviewCommand | undefined = routeReview
    ? (request, options) => routeReview(request, {
        ...options,
        policy: strictness,
        allowFullReadAccess: dynamicReview.allowFullReadAccess,
      })
    : undefined

  return {
    shell,
    securityEnabled,
    hardTimeoutMs,
    detachedStartIsolation,
    supervisorEnabled,
    supervisorPath,
    strictness,
    failPolicy,
    slowCommands,
    logReviewerTrace,
    bypassClassifier: bypass.value,
    bypassLeaseTtlMs,
    bypassPropagateToSubagents,
    dynamicReview,
    reviewCommand,
    bypassWarnings: bypass.warnings,
  }
}
