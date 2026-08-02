import { spawn } from "node:child_process"
import { existsSync } from "node:fs"
import path from "node:path"
import { fileURLToPath } from "node:url"

export type CloudReviewDecision = "ALLOW" | "DENY"

export type CloudReviewResult = {
  decision: CloudReviewDecision
  reason: string
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
  worktree?: string
  cwd?: string
}

export type ReviewCommandOptions = {
  python?: string
  auditorPath?: string
  timeoutMs?: number
  signal?: AbortSignal
}

type PythonCandidate = {
  executable: string
  prefixArgs: string[]
}

const MAX_STDOUT_CHARS = 64_000
const MAX_STDERR_CHARS = 8_000
const MAX_REVIEW_INPUT_BYTES = 1_000_000

function bundledAuditorPath() {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url))
  const candidates = [
    path.join(moduleDirectory, "deepseek_auditor.py"),
    path.join(moduleDirectory, "security", "deepseek_auditor.py"),
    path.join(moduleDirectory, "..", "src", "security", "deepseek_auditor.py"),
  ]
  return candidates.find((candidate) => existsSync(candidate))
}

function pythonCandidates(configured?: string): PythonCandidate[] {
  if (configured) return [{ executable: configured, prefixArgs: [] }]
  if (process.platform === "win32") {
    return [
      { executable: "python", prefixArgs: [] },
      { executable: "py", prefixArgs: ["-3"] },
      { executable: "python3", prefixArgs: [] },
    ]
  }
  return [
    { executable: "python3", prefixArgs: [] },
    { executable: "python", prefixArgs: [] },
  ]
}

function reviewerEnvironment(): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = {}
  const names = [
    "PATH",
    "Path",
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "SystemRoot",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LOCALAPPDATA",
    "APPDATA",
    "HTTPS_PROXY",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "REQUESTS_CA_BUNDLE",
    "API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENAI_BASE_URL",
    "LLM_BASE_URL",
    "OPENAI_MODEL",
    "LLM_MODEL",
  ]
  for (const name of names) {
    if (process.env[name] !== undefined) result[name] = process.env[name]
  }
  result.PYTHONIOENCODING = "utf-8"
  result.PYTHONUTF8 = "1"
  return result
}

function parseReviewResult(stdout: string): CloudReviewResult {
  const parsed = JSON.parse(stdout.trim()) as Partial<CloudReviewResult>
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("The DeepSeek auditor returned a non-object result")
  }
  const keys = Object.keys(parsed).sort()
  if (keys.length !== 2 || keys[0] !== "decision" || keys[1] !== "reason") {
    throw new Error("The DeepSeek auditor returned unexpected fields")
  }
  if (!["ALLOW", "DENY"].includes(parsed.decision ?? "")) {
    throw new Error("The DeepSeek auditor returned an invalid decision")
  }
  if (typeof parsed.reason !== "string") {
    throw new Error("The DeepSeek auditor returned a non-string reason")
  }
  if (parsed.decision === "ALLOW" && parsed.reason !== "") {
    throw new Error("The DeepSeek auditor returned a reason for ALLOW")
  }
  if (parsed.decision === "DENY" && !parsed.reason.trim()) {
    throw new Error("The DeepSeek auditor returned an empty reason for DENY")
  }
  return {
    decision: parsed.decision as CloudReviewDecision,
    reason: parsed.decision === "ALLOW" ? "" : parsed.reason.trim().replace(/\s+/g, " ").slice(0, 80),
  }
}

async function runCandidate(
  candidate: PythonCandidate,
  auditorPath: string,
  reviewInput: string,
  timeoutMs: number,
  signal?: AbortSignal,
) {
  return await new Promise<CloudReviewResult>((resolve, reject) => {
    const child = spawn(candidate.executable, [...candidate.prefixArgs, auditorPath], {
      env: reviewerEnvironment(),
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    })

    let stdout = ""
    let stderr = ""
    let settled = false
    let timedOut = false

    const finish = (callback: () => void) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      signal?.removeEventListener("abort", abort)
      callback()
    }
    const abort = () => {
      child.kill()
      finish(() => reject(new Error("The DeepSeek auditor was aborted")))
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
        finish(() => reject(new Error("The DeepSeek auditor returned too much output")))
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
          reject(new Error(`The DeepSeek auditor timed out after ${timeoutMs}ms`))
          return
        }
        if (code !== 0) {
          const detail = stderr.trim().replace(/\s+/g, " ").slice(0, 500)
          reject(new Error(detail || `The DeepSeek auditor exited with code ${code}`))
          return
        }
        try {
          resolve(parseReviewResult(stdout))
        } catch (error) {
          reject(error)
        }
      })
    })
  })
}

function normalizeReviewRequest(request: CloudReviewRequest | string): CloudReviewRequest {
  if (typeof request === "string") {
    return {
      command: request,
      localScripts: [],
      uninspectedLocalScripts: [],
      targetDirectories: [],
      uninspectedTargetDirectories: [],
    }
  }
  return request
}

export async function reviewCommandWithDeepSeek(
  request: CloudReviewRequest | string,
  options: ReviewCommandOptions = {},
) {
  const auditorPath = options.auditorPath ?? bundledAuditorPath()
  if (!auditorPath) throw new Error("The bundled DeepSeek auditor script could not be found")
  const timeoutMs = options.timeoutMs ?? 8_000
  const reviewInput = JSON.stringify(normalizeReviewRequest(request))
  if (Buffer.byteLength(reviewInput, "utf8") > MAX_REVIEW_INPUT_BYTES) {
    throw new Error("The DeepSeek review input exceeded the safety limit")
  }

  const failures: Error[] = []
  for (const candidate of pythonCandidates(options.python)) {
    try {
      return await runCandidate(candidate, auditorPath, reviewInput, timeoutMs, options.signal)
    } catch (error) {
      const failure = error instanceof Error ? error : new Error(String(error))
      failures.push(failure)
      const code = (failure as NodeJS.ErrnoException).code
      if (options.python || code !== "ENOENT") throw failure
    }
  }

  throw failures.at(-1) ?? new Error("No Python 3 interpreter was found for the DeepSeek auditor")
}

export { bundledAuditorPath, normalizeReviewRequest, parseReviewResult }
