import { spawn } from "node:child_process"
import { lstatSync, realpathSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"

export type CloudReviewDecision = "ALLOW" | "DENY"

export type CloudReviewResult = {
  decision: CloudReviewDecision
  reason: string
  /** Present only for the strict policy, which performs bypass detection. */
  bypassing?: boolean
}

export type PreviousRejectedCommand = {
  command: string
  reason: string
  classifier: "STATIC" | "DYNAMIC" | "FAIL_POLICY"
}

export type PreviousFailedCommand = {
  command: string
  exitCode: number
  outputTail?: string
}

export type CloudReviewRequest = {
  command: string
  localScripts: Array<{
    path: string
    content: string
    sha256: string
  }>
  uninspectedLocalScripts: string[]
  targetDirectories: Array<{
    path: string
    entries: Array<{
      name: string
      type: "directory" | "file" | "symlink" | "other"
    }>
    truncated: boolean
  }>
  uninspectedTargetDirectories: string[]
  referencedPaths: string[]
  referencedPathsTruncated: boolean
  worktree: string
  cwd: string
  previousRejectedCommand?: PreviousRejectedCommand
  previousFailedCommand?: PreviousFailedCommand
}

export type ReviewCommandOptions = {
  endpoint: string
  model: string
  apiKey: string
  maxRounds: number
  policy: "LOOSE" | "HARD"
  allowFullReadAccess?: boolean
  python?: string
  auditorPath?: string
  timeout?: number
  signal?: AbortSignal
}

type PythonCandidate = {
  executable: string
  prefixArgs: string[]
}

const MAX_STDOUT_CHARS = 64_000
const MAX_STDERR_CHARS = 8_000
const MAX_REVIEW_INPUT_BYTES = 1_000_000
const DEFAULT_TIMEOUT_MS = 30_000
const ISOLATED_FLAGS = ["-I", "-B"]

function isRegularFile(filePath: string): boolean {
  try {
    return lstatSync(filePath).isFile()
  } catch {
    return false
  }
}

function bundledAuditorPath() {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url))
  const candidates = [
    path.join(moduleDirectory, "auditor.py"),
    path.join(moduleDirectory, "security", "auditor.py"),
    path.join(moduleDirectory, "..", "src", "security", "auditor.py"),
  ]
  // existsSync would accept directories; require a regular file so a stray
  // directory never gets handed to the Python interpreter.
  return candidates.find((candidate) => isRegularFile(candidate))
}

function pythonCandidates(configured?: string): PythonCandidate[] {
  if (configured) return [{ executable: configured, prefixArgs: [...ISOLATED_FLAGS] }]
  if (process.platform === "win32") {
    return [
      { executable: "python", prefixArgs: [...ISOLATED_FLAGS] },
      { executable: "py", prefixArgs: ["-3", ...ISOLATED_FLAGS] },
      { executable: "python3", prefixArgs: [...ISOLATED_FLAGS] },
    ]
  }
  return [
    { executable: "python3", prefixArgs: [...ISOLATED_FLAGS] },
    { executable: "python", prefixArgs: [...ISOLATED_FLAGS] },
  ]
}

function reviewerEnvironment(options: {
  endpoint: string
  model: string
  apiKey: string
  maxRounds: number
  policy: "LOOSE" | "HARD"
  allowFullReadAccess?: boolean
}): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {}
  // Minimal whitelist: no HOME/USERPROFILE or legacy provider/key/model variables.
  const names = [
    "PATH",
    "Path",
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
  ]
  for (const name of names) {
    if (process.env[name] !== undefined) result[name] = process.env[name]
  }
  result.PYTHONIOENCODING = "utf-8"
  result.PYTHONUTF8 = "1"
  result.OPENCODE_BASH_REVIEW_ENDPOINT = options.endpoint
  result.OPENCODE_BASH_REVIEW_MODEL = options.model
  result.OPENCODE_BASH_REVIEW_API_KEY = options.apiKey
  result.OPENCODE_BASH_REVIEW_MAX_ROUNDS = String(options.maxRounds)
  result.OPENCODE_BASH_REVIEW_POLICY = options.policy
  result.OPENCODE_BASH_REVIEW_FULL_READ = options.allowFullReadAccess === true ? "1" : "0"
  const tempRoots = [os.tmpdir()]
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA
    if (localAppData) tempRoots.push(path.join(localAppData, "Temp"))
  } else if (process.platform === "linux") {
    tempRoots.push("/tmp")
  }
  result.OPENCODE_BASH_REVIEW_TEMP_ROOTS = JSON.stringify([...new Set(tempRoots.map((root) => {
    const resolved = path.resolve(root)
    try { return realpathSync.native(resolved) } catch { return resolved }
  }))])
  return result
}

// JSON.parse silently keeps the last value for duplicate keys, so the three-field
// check alone could not detect them. This scanner walks only the top-level object
// members (string-aware, depth-aware) and returns every member key, letting callers
// compare the raw count against Object.keys(parsed).length to flag duplicates.
function collectTopLevelJsonKeys(text: string): string[] | null {
  const keys: string[] = []
  let pos = 0
  const len = text.length

  const skipWs = () => {
    while (pos < len) {
      const code = text.charCodeAt(pos)
      if (code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d) pos++
      else break
    }
  }
  const readString = (): string => {
    pos++ // opening quote
    let result = ""
    while (pos < len) {
      const c = text[pos]
      if (c === "\\") {
        pos++
        if (pos >= len) return result
        const e = text[pos]
        switch (e) {
          case '"': result += '"'; break
          case "\\": result += "\\"; break
          case "/": result += "/"; break
          case "b": result += "\b"; break
          case "f": result += "\f"; break
          case "n": result += "\n"; break
          case "r": result += "\r"; break
          case "t": result += "\t"; break
          case "u": {
            const code = parseInt(text.slice(pos + 1, pos + 5), 16)
            if (Number.isFinite(code)) result += String.fromCharCode(code)
            pos += 4
            break
          }
          default: result += e
        }
        pos++
      } else if (c === '"') {
        pos++
        return result
      } else {
        result += c
        pos++
      }
    }
    return result
  }
  const skipValue = () => {
    skipWs()
    if (pos >= len) return
    const c = text[pos]
    if (c === '"') { readString(); return }
    if (c === "{" || c === "[") {
      const close = c === "{" ? "}" : "]"
      let depth = 0
      while (pos < len) {
        const cc = text[pos]
        if (cc === '"') { readString(); continue }
        if (cc === "{" || cc === "[") { depth++; pos++; continue }
        if (cc === "}" || cc === "]") {
          depth--
          pos++
          if (depth === 0 && cc === close) return
          continue
        }
        pos++
      }
      return
    }
    while (pos < len) {
      const cc = text[pos]
      if (cc === "," || cc === "}" || cc === "]" || cc === " " || cc === "\t" || cc === "\n" || cc === "\r") break
      pos++
    }
  }

  skipWs()
  if (text[pos] !== "{") return null
  pos++ // consume '{'
  skipWs()
  if (text[pos] === "}") { pos++; return keys }
  while (pos < len) {
    skipWs()
    if (text[pos] !== '"') return null
    keys.push(readString())
    skipWs()
    if (text[pos] !== ":") return null
    pos++ // ':'
    skipValue()
    skipWs()
    if (text[pos] === ",") { pos++; continue }
    if (text[pos] === "}") { pos++; break }
    return null
  }
  return keys
}

function parseReviewResult(stdout: string, policy: "LOOSE" | "HARD"): CloudReviewResult {
  if (policy !== "LOOSE" && policy !== "HARD") throw new Error("Invalid review policy")
  const trimmed = stdout.trim()
  const parsed = JSON.parse(trimmed) as Partial<CloudReviewResult>
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("The auditor returned a non-object result")
  }
  const rawKeys = collectTopLevelJsonKeys(trimmed)
  if (rawKeys !== null && rawKeys.length !== Object.keys(parsed).length) {
    throw new Error("The auditor returned duplicate JSON keys")
  }
  const keys = Object.keys(parsed).sort()
  const expectedKeys = policy === "HARD" ? ["bypassing", "decision", "reason"] : ["decision", "reason"]
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) {
    throw new Error("The auditor returned unexpected fields")
  }
  if (!["ALLOW", "DENY"].includes(parsed.decision ?? "")) {
    throw new Error("The auditor returned an invalid decision")
  }
  if (typeof parsed.reason !== "string") {
    throw new Error("The auditor returned a non-string reason")
  }
  if (policy === "HARD" && typeof parsed.bypassing !== "boolean") {
    throw new Error("The auditor returned a non-boolean bypassing")
  }
  const decision = parsed.decision as CloudReviewDecision
  // ALLOW must carry an empty reason. The strict policy additionally carries
  // bypassing; the caller decides whether to interrupt. DENY needs a reason.
  if (decision === "ALLOW" && parsed.reason !== "") {
    throw new Error("The auditor returned a reason for ALLOW")
  }
  if (decision === "DENY" && !parsed.reason.trim()) {
    throw new Error("The auditor returned an empty reason for DENY")
  }
  const result: CloudReviewResult = {
    decision,
    reason:
      decision === "ALLOW" ? "" : parsed.reason.trim().replace(/\s+/g, " ").slice(0, 80),
  }
  if (policy === "HARD") result.bypassing = parsed.bypassing
  return result
}

async function runCandidate(
  candidate: PythonCandidate,
  auditorPath: string,
  reviewInput: string,
  timeoutMs: number,
  options: {
    endpoint: string
    model: string
    apiKey: string
    maxRounds: number
    policy: "LOOSE" | "HARD"
    signal?: AbortSignal
  },
) {
  return await new Promise<CloudReviewResult>((resolve, reject) => {
    const child = spawn(candidate.executable, [...candidate.prefixArgs, auditorPath], {
      env: reviewerEnvironment(options),
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
      cwd: path.dirname(auditorPath),
      shell: false,
    })

    let stdout = ""
    let stderr = ""
    let settled = false
    let timedOut = false
    const signal = options.signal

    const finish = (callback: () => void) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener("abort", abort)
      callback()
    }
    const abort = () => {
      child.kill()
      finish(() => reject(new Error("The auditor was aborted")))
    }
    const timer = setTimeout(() => {
      timedOut = true
      child.kill()
    }, timeoutMs)

    signal?.addEventListener("abort", abort, { once: true })
    if (signal?.aborted) {
      abort()
      return
    }

    child.stdout?.on("data", (chunk: Buffer | string) => {
      stdout += chunk.toString()
      if (stdout.length > MAX_STDOUT_CHARS) {
        child.kill()
        finish(() => reject(new Error("The auditor returned too much output")))
      }
    })
    child.stderr?.on("data", (chunk: Buffer | string) => {
      stderr = (stderr + chunk.toString()).slice(-MAX_STDERR_CHARS)
    })
    child.stdin?.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code !== "EPIPE") finish(() => reject(error))
    })
    child.stdin?.end(reviewInput)
    child.once("error", (error) => finish(() => reject(error)))
    child.once("close", (code) => {
      finish(() => {
        if (timedOut) {
          reject(new Error(`The auditor timed out after ${timeoutMs}ms`))
          return
        }
        if (code !== 0) {
          const detail = stderr.trim().replace(/\s+/g, " ").slice(0, 500)
          reject(new Error(detail || `The auditor exited with code ${code}`))
          return
        }
        try {
          resolve(parseReviewResult(stdout, options.policy))
        } catch (error) {
          reject(error)
        }
      })
    })
  })
}

function normalizeReviewRequest(request: CloudReviewRequest | string): CloudReviewRequest {
  if (typeof request === "string") {
    const cwd = process.cwd()
    return {
      command: request,
      localScripts: [],
      uninspectedLocalScripts: [],
      targetDirectories: [],
      uninspectedTargetDirectories: [],
      referencedPaths: [],
      referencedPathsTruncated: false,
      worktree: cwd,
      cwd,
    }
  }
  return request
}

function requestForPolicy(request: CloudReviewRequest, policy: "LOOSE" | "HARD"): CloudReviewRequest {
  const legacy = request as CloudReviewRequest & { strictness?: unknown }
  const { strictness: _ignoredMode, previousRejectedCommand, ...rest } = legacy
  const normalized: CloudReviewRequest = {
    ...rest,
    referencedPaths: Array.isArray(rest.referencedPaths) ? rest.referencedPaths : [],
    referencedPathsTruncated:
      typeof rest.referencedPathsTruncated === "boolean" ? rest.referencedPathsTruncated : false,
  }
  if (policy === "HARD" && previousRejectedCommand) {
    normalized.previousRejectedCommand = previousRejectedCommand
  }
  return normalized
}

export async function reviewCommandWithAuditor(
  request: CloudReviewRequest | string,
  options: ReviewCommandOptions,
) {
  if (!options || typeof options.endpoint !== "string" || !options.endpoint) {
    throw new Error("reviewCommandWithAuditor requires a valid endpoint")
  }
  if (typeof options.model !== "string" || !options.model) {
    throw new Error("reviewCommandWithAuditor requires a valid model")
  }
  if (typeof options.apiKey !== "string" || !options.apiKey) {
    throw new Error("reviewCommandWithAuditor requires a valid apiKey")
  }
  if (typeof options.maxRounds !== "number" || !Number.isInteger(options.maxRounds)) {
    throw new Error("reviewCommandWithAuditor requires an integer maxRounds")
  }
  if (options.policy !== "LOOSE" && options.policy !== "HARD") {
    throw new Error("reviewCommandWithAuditor requires a valid policy")
  }
  const maxRoundsLimit = options.policy === "LOOSE" ? 3 : 5
  if (options.maxRounds < 1 || options.maxRounds > maxRoundsLimit) {
    throw new Error(`reviewCommandWithAuditor maxRounds must be between 1 and ${maxRoundsLimit}`)
  }
  const routedOptions = { ...options, policy: options.policy }

  const auditorPath = options.auditorPath ?? bundledAuditorPath()
  if (!auditorPath) {
    throw new Error("The bundled auditor script could not be found or is not a regular file")
  }
  const timeoutMs = options.timeout ?? DEFAULT_TIMEOUT_MS
  const reviewInput = JSON.stringify(requestForPolicy(normalizeReviewRequest(request), routedOptions.policy))
  if (Buffer.byteLength(reviewInput, "utf8") > MAX_REVIEW_INPUT_BYTES) {
    throw new Error("The review input exceeded the safety limit")
  }

  const failures: Error[] = []
  for (const candidate of pythonCandidates(options.python)) {
    try {
      return await runCandidate(candidate, auditorPath, reviewInput, timeoutMs, routedOptions)
    } catch (error) {
      const failure = error instanceof Error ? error : new Error(String(error))
      failures.push(failure)
      const code = (failure as NodeJS.ErrnoException).code
      if (options.python || code !== "ENOENT") throw failure
    }
  }

  throw failures.at(-1) ?? new Error("No Python 3 interpreter was found for the auditor")
}

/**
 * @deprecated Use {@link reviewCommandWithAuditor} instead. This alias is kept only
 * for backwards-compatible imports and will be removed in a future release.
 */
export const reviewCommandWithDeepSeek = reviewCommandWithAuditor

export { bundledAuditorPath, normalizeReviewRequest, parseReviewResult, requestForPolicy, reviewerEnvironment }
