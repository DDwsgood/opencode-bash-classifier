import { createHash } from "node:crypto"
import type { Dirent } from "node:fs"
import { lstat, readFile, readdir, realpath, stat } from "node:fs/promises"
import path from "node:path"
import type { BypassCategory } from "../config"
import { ruleBypassed } from "./bypass"
import {
  analyzeSegmentPaths,
  checkPathSensitivity,
  extractReadPaths,
  hasSensitiveEnvPrefix,
  hasUnquotedExpansion,
  resolveLexical,
  isWithinLexical,
  classifyPathTarget,
  sensitivePathFinding,
  segmentCommandLeaf,
  stripOutputRedirects,
  stripTrailingFdMerges,
  type PathContext,
} from "./paths"

export type SecurityVerdict = "ALLOW" | "DENY" | "ASK"

export type ScriptFingerprint = {
  path: string
  size: number
  mtimeMs: number
  sha256: string
  /**
   * Present when the executed path was a symlink at classification time.
   * The post-check then verifies the link itself (dev/ino/mtime) is unchanged
   * and still resolves to the same canonical file, closing the symlink-swap
   * TOCTOU window.
   */
  linkPath?: string
  linkDev?: number
  linkIno?: number
  linkMtimeMs?: number
}

export type LocalScriptReviewContext = {
  path: string
  content: string
  sha256: string
}

export type DirectoryEntryReviewContext = {
  name: string
  type: "directory" | "file" | "symlink" | "other"
}

export type TargetDirectoryReviewContext = {
  path: string
  entries: DirectoryEntryReviewContext[]
  truncated: boolean
}

export type StaticReviewContext = {
  localScripts: LocalScriptReviewContext[]
  uninspectedLocalScripts: string[]
  targetDirectories: TargetDirectoryReviewContext[]
  uninspectedTargetDirectories: string[]
  referencedPaths: string[]
  referencedPathsTruncated: boolean
}

export type StaticSecurityDecision = {
  verdict: SecurityVerdict
  rules: string[]
  reason: string
  fingerprints: ScriptFingerprint[]
  reviewContext?: StaticReviewContext
}

export type Strictness = "LOOSE" | "HARD"

export type ClassifyShellCommandInput = {
  script: string
  cwd: string
  worktree: string
  shell: string
  nowMs?: number
  trustedTempRoot?: string
  strictness?: Strictness
  /** Bypass categories armed for this session; matching rule groups are
   * skipped except for the unconditional floor (root destruction, disk
   * destruction, fork bombs, kernel primitives, reverse shells). */
  bypassedCategories?: ReadonlySet<BypassCategory>
}

type InternalClassifyInput = ClassifyShellCommandInput & {
  /** The effective working directory of this segment is not statically known. */
  cwdUnknown?: boolean
}

const MAX_COMMAND_CHARS = 32_768
const MAX_LOCAL_SCRIPT_BYTES = 256_000
const MAX_CLOUD_LOCAL_SCRIPT_CHARS = 256_000
const MAX_LOCAL_SCRIPTS = 8
const MAX_DECODED_PAYLOADS = 8
const MAX_TARGET_DIRECTORIES = 4
const MAX_REFERENCED_PATHS = 32
const MAX_DIRECTORY_ENTRIES = 200
const MAX_DIRECTORY_ENTRY_NAME_CHARS = 512
const MIN_BACKUP_AGE_MS = 2 * 60 * 1000
const PERMANENT_DELETE_GUIDANCE =
  "DO NOT retry with rm, Remove-Item, recycle-bin deletion, or an equivalent deletion command"

type Rule = {
  id: string
  reason: string
  test: (text: string) => boolean
}

const DATA_EXTENSION = /\.(?:csv|jsonl?|ya?ml|toml|ini|db|sqlite(?:3)?|sql|parquet|avro|xlsx?|docx?|pptx?|pdf|pem|key|p12|pfx|ppk|jks|keystore|kdbx|gpg|age|env|bak|backup)\b/i
const CRITICAL_DATA_EXTENSION = /\.(?:pem|key|p12|pfx|ppk|jks|keystore|kdbx|gpg|age)\b/i
const GENERAL_DATA_EXTENSION =
  /\.(?:csv|jsonl?|ya?ml|toml|ini|db|sqlite(?:3)?|sql|parquet|avro|xlsx?|docx?|pptx?|pdf)(?=$|[\s"';&|)])/i
const DELETE_PRIMITIVE =
  /\b(?:rm|ri|del|erase|rmdir|rd|remove-item|clear-content|unlink|unlinkSync|rmSync|rmtree|os\.remove|os\.unlink|shutil\.rmtree|shred|srm|wipe)\b|(?:^|\s)-delete(?:\s|$)|\.unlink\s*\(/i
const SCRIPT_DESTRUCTIVE_PRIMITIVE = new RegExp(
  [
    // Shell deletion / process-kill commands, matched on raw text including inside quoted string literals
    String.raw`\b(?:rm|rmdir|rd|del|erase|ri|remove-item|clear-content|shred|unlink|unlinksync|rmsync|rmtree|removedirs|rimraf|send2trash|kill|pkill|killall|taskkill|stop-process)\b`,
    String.raw`\b(?:trash-put|trash-cli|trash-empty|trash-rm)\b|\bgio\s+trash\b`,
    // Python / Node deletion and kill APIs
    String.raw`\bos\.(?:remove|unlink|rmdir|removedirs|kill)\b`,
    String.raw`\bshutil\.rmtree\b`,
    String.raw`\bfs(?:\.promises)?\.(?:rm|unlink|rmdir)(?:sync)?\s*\(`,
    String.raw`\.(?:unlink|rmdir|rmSync|unlinkSync|kill|terminate)\s*\(`,
    String.raw`(?:^|\s)-delete(?:\s|$)`,
  ].join("|"),
  "i",
)
const WRAPPER_PRIMITIVE =
  /\b(?:eval|invoke-expression|iex)\b|(?:\b(?:bash|sh|zsh|cmd(?:\.exe)?|powershell|pwsh|python(?:3)?(?:\.exe)?|py(?:\.exe)?|node)\b[^\n]{0,80}(?:\s-c|\s\/c|\s-command|\s-encodedcommand|\s-enc|\s-e))\b/i
const SENSITIVE_ENV_FILE =
  /(?:^|[\\/\s"'=])(?:\.env(?:\.[A-Za-z0-9_-]+)*|[A-Za-z0-9_.-]+\.env)(?=$|[\\/\s"';&|)])/i
const BACKUP_SUFFIX_REFERENCE = /(?:\.backup|-backup|\.bak|-bak)\d*(?=$|[\\/\s"';&|])/m

const FORCED_RECURSIVE_COMMANDS = ["remove-item", "ri", "rm", "del", "erase", "rmdir", "rd"]
const CMD_STYLE_DELETE_COMMANDS = ["rmdir", "rd", "del", "erase"]
const CMD_DELETE_FLAGS = /^\/[sfq]+$/i

function forcedRecursiveShape(tokens: string[]) {
  const command = commandLeaf(stripMatchingQuotes(tokens[0] ?? ""))
  const flags = tokens
    .slice(1)
    .filter((token) => token.startsWith("-"))
    .map((token) => token.toLowerCase())
  const cmdFlags = CMD_STYLE_DELETE_COMMANDS.includes(command ?? "")
    ? tokens
        .slice(1)
        .filter((token) => CMD_DELETE_FLAGS.test(token))
        .map((token) => token.toLowerCase())
    : []
  const hasPowerShellPair =
    FORCED_RECURSIVE_COMMANDS.includes(command ?? "") &&
    flags.some((flag) => /^-r(?:e(?:c(?:u(?:r(?:s(?:e)?)?)?)?)?)?$/.test(flag)) &&
    flags.some((flag) => /^-f(?:o(?:r(?:c(?:e)?)?)?)?$/.test(flag))
  const hasLongPair = flags.includes("--recursive") && flags.includes("--force")
  const shortLetters = command === "rm"
    ? flags.filter((flag) => /^-[dfirvR]+$/.test(flag)).join("")
    : ""
  const hasShortPair =
    (/r/i.test(shortLetters) || flags.includes("--recursive")) &&
    (/f/i.test(shortLetters) || flags.includes("--force"))
  const cmdHasS = cmdFlags.some((flag) => flag.includes("s"))
  const cmdHasQ = cmdFlags.some((flag) => flag.includes("q"))
  const cmdHasF = cmdFlags.some((flag) => flag.includes("f"))
  const hasCmdPair =
    ((command === "rmdir" || command === "rd") && cmdHasS && cmdHasQ) ||
    ((command === "del" || command === "erase") && cmdHasS && cmdHasQ && cmdHasF)
  const forced = hasPowerShellPair || hasLongPair || hasShortPair || hasCmdPair

  const targets: string[] = []
  if (forced) {
    for (let index = 1; index < tokens.length; index += 1) {
      const token = tokens[index]
      if (token === "--") continue
      if (token.startsWith("-")) continue
      if (CMD_STYLE_DELETE_COMMANDS.includes(command ?? "") && CMD_DELETE_FLAGS.test(token)) continue
      if (isRedirectToken(token)) continue
      if (/^(?:\d*|&)>{1,2}$/.test(token)) { index += 1; continue }
      targets.push(token)
    }
  }
  return { forced, targets }
}

function hasForcedRecursiveDelete(text: string) {
  const invocations =
    text.match(/\b(?:remove-item|ri|rm|del|erase|rmdir|rd)\b(?:(?!"|'|`)[^\r\n;&|]|"(?:[^"]|"")*"|'[^']*'|`.)*/gi) ?? []

  return invocations.some((invocation) => {
    const tokens = invocation.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
    if (tokens.length < 2) return false
    const shape = forcedRecursiveShape(tokens)
    return shape.forced && shape.targets.length > 0
  })
}

function hasForcedRecursiveDeleteLiteralTarget(text: string): boolean {
  const invocations =
    text.match(/\b(?:remove-item|ri|rm|del|erase|rmdir|rd)\b(?:(?!"|'|`)[^\r\n;&|]|"(?:[^"]|"")*"|'[^']*'|`.)*/gi) ?? []

  return invocations.some((invocation) => {
    const tokens = invocation.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
    if (tokens.length < 2) return false
    const shape = forcedRecursiveShape(tokens)
    if (!shape.forced || shape.targets.length === 0) return false
    return shape.targets.every((t) => literalPathToken(t) !== undefined)
  })
}

function hasNamedTempPathSegment(target: string): boolean {
  const cleaned = stripMatchingQuotes(target).replaceAll("\\", "/")
  if (cleaned.split("/").some((segment) => segment === "..")) return false
  return cleaned
    .split("/")
    .filter((segment) => segment.length > 0)
    .some((segment) => {
      const lower = segment.toLowerCase()
      return lower === "temp" || lower === "tmp"
    })
}

async function canonicalProjectedPath(candidate: string) {
  let current = path.resolve(candidate)
  const suffix: string[] = []
  for (let index = 0; index < 128; index += 1) {
    try {
      const canonical = await realpath(current)
      return suffix.length === 0 ? canonical : path.join(canonical, ...suffix.reverse())
    } catch {
      const parent = path.dirname(current)
      if (parent === current) return undefined
      suffix.push(path.basename(current))
      current = parent
    }
  }
  return undefined
}

/**
 * Removes the worktree prefix from a canonical path so named-temp checks judge
 * only the target's own segments. Without this, a worktree that itself lives
 * under /tmp (sandboxes, scratch projects) contributes a `tmp` segment to every
 * candidate and the whole whitelist fires for arbitrary deletes.
 */
async function withoutWorktreePrefix(canonical: string, worktree: string | undefined): Promise<string> {
  if (!worktree) return canonical
  const bases = [path.resolve(worktree)]
  try {
    bases.push(await realpath(path.resolve(worktree)))
  } catch {
    // Lexical worktree path only.
  }
  const norm = canonical.replaceAll("\\", "/")
  for (const base of bases) {
    const b = base.replaceAll("\\", "/").replace(/\/+$/, "")
    if (b && norm.toLowerCase() === b.toLowerCase()) return ""
    if (b && norm.toLowerCase().startsWith((b + "/").toLowerCase())) return norm.slice(b.length + 1)
  }
  return norm
}

async function isNamedTempTargetResolved(target: string, base: string | undefined, worktree?: string) {
  if (base === undefined) return false
  const literal = literalPathToken(target)
  if (!literal) return false
  const cleaned = literal.replaceAll("\\", "/")
  if (cleaned.split("/").some((segment) => segment === "..")) return false
  const lexical = normalizeMsysPath(path.resolve(normalizeMsysPath(base), cleaned))
  const lexicalOwn = await withoutWorktreePrefix(lexical, worktree)
  if (!hasNamedTempPathSegment(lexicalOwn)) {
    // The target carries no temp segment of its own; accept it only when it
    // resolves OUTSIDE the worktree into a real temp location.
    const outside = await canonicalProjectedPath(lexical)
    if (!outside || !hasNamedTempPathSegment(outside) || isWithin(worktree ?? base, outside)) return false
    // Prevent symlink escape: lexical path within worktree that resolves outside
    if (isWithinLexical(worktree ?? base, lexical)) return false
    return true
  }
  const canonical = await canonicalProjectedPath(lexical)
  if (!canonical) return false
  // Prevent symlink escape: lexical path within worktree that resolves outside
  if (isWithinLexical(worktree ?? base, lexical) && !isWithin(worktree ?? base, canonical)) return false
  return hasNamedTempPathSegment(await withoutWorktreePrefix(canonical, worktree))
}

function isRedirectToken(token: string): boolean {
  if (/^\d*>&\d+$/.test(token)) return true
  if (/^(?:\d*|&)>{1,2}\S+$/.test(token)) return true
  if (/^(?:\d*|&)>{1,2}$/.test(token)) return true
  return false
}

function hasHostShutdownCommand(text: string): boolean {
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("#")) continue
    let stripped = trimmed.replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*/, "")
    stripped = stripped.replace(/^(?:sudo\s+|runas\s+)/i, "")
    const firstToken = stripped.match(/^(\S+)/)?.[1] ?? ""
    const command = firstToken.replace(/\.(?:exe|cmd|bat|ps1)$/i, "").toLowerCase()
    if (["shutdown", "reboot", "poweroff", "halt"].includes(command)) return true
    if (/^stop-computer\b/i.test(stripped)) return true
    if (/\binit\s+[06]\b/i.test(stripped)) return true
    if (/\bsystemctl\s+(?:reboot|poweroff|halt|emergency|rescue)\b/i.test(stripped)) return true
  }
  return false
}

/** Network clients matched as command words only: a bare `\bssh\b` would also
 * hit paths like `~/.ssh/id_rsa` and wrongly defeat a secret bypass, while a
 * command-position anchor (line start or a separator before the word) keeps
 * `nohup curl`, `xargs curl`, and `echo a && curl` detected. */
const NETWORK_CLIENT_WORD = /(?:^|[\s;&|(])(?:curl|wget|invoke-webrequest|iwr|irm|rsync|ssh|scp)\b/i

function hasDeletePrimitive(text: string): boolean {
  const stripped = text.replace(/'[^']*'/g, "").replace(/"(?:[^"]|"")*"/g, "")
  return DELETE_PRIMITIVE.test(stripped)
}

// --- M2 (P1) helper predicates ---------------------------------------------

function isDangerousFindRoot(root: string): boolean {
  const r = root.replaceAll("\\", "/")
  if (r === "~" || r.startsWith("~/")) return true
  if (r === ".." || r.startsWith("../")) return true
  const lower = r.toLowerCase()
  if (lower === "/") return true
  return [
    "/etc",
    "/var",
    "/boot",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/home",
    "/root",
    "/opt",
    "/srv",
    "/sys",
    "/proc",
    "/mnt",
  ].some((p) => lower === p || lower.startsWith(p + "/"))
}

function findDangerousDeleteRoot(text: string): boolean {
  const match = text.match(/\bfind\s+(\S+)[\s\S]*?(?:\s|^)-(?:delete|exec|execdir|ok|okdir)(?:\s|$)/im)
  if (!match) return false
  return isDangerousFindRoot(match[1] ?? "")
}

function hasForkBomb(text: string): boolean {
  const stripped = text.replace(/["']/g, "")
  // Linear scan for name(){ ...|...name...&... }...name fork-bomb patterns.
  const nameChars = /[\w:.*-]/
  let pos = 0
  for (;;) {
    const parenIdx = stripped.indexOf("(", pos)
    if (parenIdx === -1) break
    pos = parenIdx + 1
    if (stripped[parenIdx + 1] !== ")") continue
    let nameEnd = parenIdx
    while (nameEnd > 0 && /[\s]/.test(stripped[nameEnd - 1])) nameEnd -= 1
    let nameStart = nameEnd
    while (nameStart > 0 && nameChars.test(stripped[nameStart - 1])) nameStart -= 1
    const name = stripped.slice(nameStart, nameEnd)
    if (!name) continue
    let braceIdx = parenIdx + 2
    while (braceIdx < stripped.length && /[\s]/.test(stripped[braceIdx])) braceIdx += 1
    if (braceIdx >= stripped.length || stripped[braceIdx] !== "{") continue
    let depth = 1
    let closeIdx = braceIdx + 1
    while (closeIdx < stripped.length && depth > 0) {
      if (stripped[closeIdx] === "{") depth += 1
      else if (stripped[closeIdx] === "}") depth -= 1
      if (depth === 0) break
      closeIdx += 1
    }
    if (depth !== 0 || closeIdx >= stripped.length) continue
    const body = stripped.slice(braceIdx + 1, closeIdx)
    // Recursion core: the function's own name on BOTH sides of a pipe inside
    // the body (`:(){ :|:& };:`, `bomb(){ bomb|bomb& };bomb`). A name that
    // merely appears elsewhere in the body (`npm run build | tee log`) is not
    // recursion.
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    const pipeRecursion = new RegExp(`${escaped}\\s*\\|\\s*${escaped}(?![\\w:.*-])`)
    if (!body.includes("|") || !pipeRecursion.test(body)) continue
    if (body.includes("&")) return true
    const after = stripped.slice(closeIdx + 1).replace(/^[\s;&]*/, "")
    if (new RegExp(`^${escaped}(?![\\w:.*-])`).test(after)) return true
  }
  if (/\bwhile\s+(?:true|1|:|\[[^\]]*\])\b[^;]*;\s*do\s+[^;]*\$0\s*&/.test(stripped)) return true
  // pipe self-reference: name | name & (linear scan, no backreference)
  let pipePos = 0
  for (;;) {
    const pipeIdx = stripped.indexOf("|", pipePos)
    if (pipeIdx === -1) break
    pipePos = pipeIdx + 1
    let leftEnd = pipeIdx
    while (leftEnd > 0 && /[\s]/.test(stripped[leftEnd - 1])) leftEnd -= 1
    let leftStart = leftEnd
    while (leftStart > 0 && nameChars.test(stripped[leftStart - 1])) leftStart -= 1
    const leftName = stripped.slice(leftStart, leftEnd)
    if (!leftName) continue
    let rightStart = pipeIdx + 1
    while (rightStart < stripped.length && /[\s]/.test(stripped[rightStart])) rightStart += 1
    let rightEnd = rightStart
    while (rightEnd < stripped.length && nameChars.test(stripped[rightEnd])) rightEnd += 1
    const rightName = stripped.slice(rightStart, rightEnd)
    if (!rightName || leftName !== rightName) continue
    let afterIdx = rightEnd
    while (afterIdx < stripped.length && /[\s]/.test(stripped[afterIdx])) afterIdx += 1
    if (afterIdx < stripped.length && stripped[afterIdx] === "&") return true
  }
  return false
}

function hasDestructiveOneLiner(text: string): boolean {
  const interpreter =
    /\b(?:python(?:3(?:\.\d+)?)?|py|node|perl|ruby|php)\b[^\n]{0,60}\s-(?:c|e|r|pe|escript)\b/i.test(text)
  if (!interpreter) return false
  const destructiveApi =
    /(?:shutil\.rmtree|os\.(?:remove|unlink|rmdir|removedirs)\s*\(|fs(?:\.promises)?\.(?:rm|unlink|rmdir)(?:Sync)?\s*\(|rmSync\s*\(|File\.delete\s*\(|File\.unlink\s*\(|unlinkSync\s*\(|\bunlink\s+)/i.test(
      text,
    )
  if (!destructiveApi) return false
  return /['"`](\/|\/\*|\\|[\\/]etc[\\/]|[\\/]var[\\/]|[\\/]boot[\\/]|[\\/]usr[\\/]|[\\/]bin[\\/]|[\\/]sbin[\\/]|[\\/]home[\\/]|[\\/]root[\\/])/.test(
    text,
  )
}

function commandTokenUnquote(token: string): string {
  return token.replace(/^(["'])([\s\S]*)\1$/, "$2")
}

/** Conservative unescape/quote-removal for command name matching only (`r'm'`, `r\m`, `"r"m` → `rm`). */
function normalizeCommandNameToken(token: string): string {
  return token.replace(/['"\\]/g, "")
}

/**
 * Re-surfaces a segment whose first token, after removing quotes, is a
 * destructive command, so `'rm' -rf /` / `rm '-rf' /` / `r'm' -rf /` / `r\m -rf /`
 * are caught without flagging `echo 'rm -rf /'`.
 */
function quoteStrippedDeleteSurface(segment: string): string | undefined {
  const trimmed = segment.trim()
  if (!trimmed) return undefined
  const firstSpace = trimmed.search(/\s/)
  const firstWordRaw = firstSpace === -1 ? trimmed : trimmed.slice(0, firstSpace)
  const firstWord = normalizeCommandNameToken(firstWordRaw)
  const leaf = firstWord
    .split("/")
    .at(-1)
    ?.replace(/\.(?:exe|cmd|bat|ps1)$/i, "")
    .toLowerCase()
  if (!leaf || !/^(?:rm|rmdir|rd|del|erase|remove-item|ri|shred|srm|wipe|unlink)\b/.test(leaf)) {
    return undefined
  }
  const rest = firstSpace === -1 ? "" : trimmed.slice(firstSpace)
  const tokens = simpleInvocationTokens(rest.trim())
  const stripped = firstWord + (tokens.length > 0 ? " " + tokens.map(commandTokenUnquote).join(" ") : "")
  return stripped.trim() === trimmed ? undefined : stripped
}

function decodeAnsiCContent(script: string): string[] {
  const decoded: string[] = []
  const matches = script.matchAll(/\$'([^']*)'/g)
  for (const match of matches) {
    const raw = match[1] ?? ""
    let out = ""
    for (let i = 0; i < raw.length; i += 1) {
      const ch = raw[i]
      if (ch !== "\\" || i + 1 >= raw.length) {
        out += ch
        continue
      }
      const next = raw[i + 1]
      if (next === "x" && i + 3 < raw.length) {
        const hex = raw.slice(i + 2, i + 4)
        if (/^[0-9a-fA-F]{2}$/.test(hex)) {
          out += String.fromCharCode(parseInt(hex, 16))
          i += 3
          continue
        }
      }
      const oct = raw.slice(i + 1).match(/^[0-7]{1,3}/)?.[0]
      if (oct) {
        out += String.fromCharCode(parseInt(oct, 8))
        i += oct.length
        continue
      }
      const escapes: Record<string, string> = { "\\": "\\", "'": "'", '"': '"', n: "\n", t: "\t", r: "\r", a: "\u0007", b: "\b", f: "\f", v: "\v" }
      out += escapes[next] ?? next
      i += 1
    }
    if (out.trim()) decoded.push(out)
  }
  return decoded
}

/** Expands `/{a,b}`/`src/{a,b}` style brace candidates used by a delete target. */
function braceExpansionCandidates(target: string): string[] {
  const open = target.indexOf("{")
  if (open === -1) {
    const close = target.indexOf("}")
    if (close === -1) return [target]
  }
  const close = target.indexOf("}", open + 1)
  if (open === -1 || close === -1) return [target]
  const prefix = target.slice(0, open)
  const suffix = target.slice(close + 1)
  return (target.slice(open + 1, close) ?? "")
    .split(",")
    .filter((item) => item.length > 0)
    .map((item) => `${prefix}${item}${suffix}`)
}

/** `rm -rf /{etc,var,home}` expands to a sensitive/root target. */
function hasDangerousBraceDelete(text: string): boolean {
  const invocations =
    text.match(/\b(?:rm|remove-item|ri|del|erase|rmdir|rd)\b[^\r\n;&|]*/gi) ?? []
  for (const invocation of invocations) {
    const tokens = invocation.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
    const shape = forcedRecursiveShape(tokens)
    if (!shape.forced || shape.targets.length === 0) continue
    for (const target of shape.targets) {
      if (!target.includes("{")) continue
      for (const candidate of braceExpansionCandidates(target)) {
        if (isDangerousFindRoot(candidate)) return true
      }
    }
  }
  return false
}

/** `D=rm; $D -rf /tmp/x` → surface with the variable substituted back. */
function substituteDeleteVars(script: string): string | undefined {
  const deleteCmds = ["rm", "shred", "srm", "wipe", "rmdir", "remove-item", "del", "erase", "unlink"]
  let result = script
  let changed = false
  let pos = 0
  for (;;) {
    const eq = script.indexOf("=", pos)
    if (eq === -1) break
    pos = eq + 1
    let start = eq
    while (start > 0 && /[\w]/.test(script[start - 1])) start -= 1
    if (start === eq || !/[A-Za-z_]/.test(script[start])) continue
    const name = script.slice(start, eq)
    const after = script.slice(eq + 1)
    for (const cmd of deleteCmds) {
      if (!after.toLowerCase().startsWith(cmd)) continue
      const nextChar = after[cmd.length]
      if (nextChar !== undefined && /[\w]/.test(nextChar)) continue
      if (new RegExp(`(?:^|[\\s;&|])[\\$]\\{?${name}\\}?(?=[\\s;&|])`, "i").test(script)) {
        result = result.replace(new RegExp(`[\\$]\\{?${name}\\}?`, "g"), cmd.toLowerCase())
        changed = true
      }
      break
    }
  }
  return changed ? result : undefined
}

function hasTarRemoveFiles(text: string): boolean {
  return /\btar\b[^\n;]*--remove-files\b/i.test(text)
}

/**
 * Remote Git history rewrite: force-push, mirror push, remote branch/tag
 * deletion, low-level ref rewrites, and history filters. These change shared
 * state beyond the machine, so they are definite denials in both policies.
 */
function hasGitRemoteHistoryRewrite(text: string): boolean {
  if (/\bgit\b[^\n;|&]*\bpush\b[^\n;|&]*(?:--force(?!-with-lease)\b|--mirror\b|--delete\b|\s-[a-zA-Z]*f[a-zA-Z]*\b)/i.test(text)) return true
  if (/\bgit\b[^\n;|&]*\bpush\b[^\n;|&]*\s:[\w.-]+/.test(text)) return true
  // force-push refspec: +main or +refs/heads/main:refs/heads/main
  if (/\bgit\b[^\n;|&]*\bpush\b[^\n;|&]*\s\+[^\s:]+(?::[^\s]+)?/i.test(text)) return true
  // low-level ref rewrite (allows global options like -C, --work-tree)
  if (/\bgit\b[^\n;|&]*\b(?:update-ref|filter-branch|filter-repo)\b/i.test(text)) {
    if (/(?:\s|^)--help(?:\s|$)/i.test(text) || /(?:\s|^)-h(?:\s|$)/i.test(text)) return false
    return true
  }
  return false
}

/** Forced deletion whose target is an absolute or home glob outside temp areas (`rm -rf /etc*`, `rm -rf ~/*`). */
function hasRootGlobDelete(text: string): boolean {
  const invocations =
    text.match(/\b(?:rm|remove-item|ri|del|erase|rmdir|rd)\b(?:(?!"|'|`)[^\r\n;&|]|"(?:[^"]|"")*"|'[^']*'|`.)*/gi) ?? []
  return invocations.some((invocation) => {
    const tokens = invocation.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
    if (tokens.length < 2) return false
    const shape = forcedRecursiveShape(tokens)
    if (!shape.forced || shape.targets.length === 0) return false
    return shape.targets.some((target) => {
      const literal = stripMatchingQuotes(target).replaceAll("\\", "/").toLowerCase()
      if (!/[*?\[]/.test(literal)) return false
      if (literal.startsWith("/")) {
        return !(literal === "/tmp*" || literal.startsWith("/tmp/*") || literal === "/var/tmp*" || literal.startsWith("/var/tmp/*"))
      }
      if (literal.startsWith("~/") || literal.startsWith("$home/")) return true
      return false
    })
  })
}

/** DENY-both rules that need filesystem context: compression of sensitive files, tar --remove-files. */
function compressionDestructionFinding(segment: string, ctx: PathContext): SegmentDecision | undefined {
  const command = segmentCommandLeaf(segment)
  if (["gzip", "bzip2", "xz", "zip", "7z", "rar"].includes(command)) {
    for (const raw of extractReadPaths(segment)) {
      if (checkPathSensitivity(raw, ctx).sensitive) {
        return {
          verdict: "DENY",
          rules: ["filesystem.compression-sensitive"],
          reason: "Compressing or archiving credential or system files is forbidden",
        }
      }
    }
    return undefined
  }
  if (hasTarRemoveFiles(segment)) {
    for (const raw of extractReadPaths(segment)) {
      if (checkPathSensitivity(raw, ctx).sensitive) {
        return {
          verdict: "DENY",
          rules: ["data.critical-delete"],
          reason: "tar --remove-files on credential or system files is forbidden",
        }
      }
    }
    return {
      verdict: "ASK",
      rules: ["filesystem.tar-remove-files"],
      reason: "tar --remove-files permanently removes the archived files and requires review",
    }
  }
  return undefined
}

function hasExfilOrDangerousPerms(segment: string, text: string, ctx: PathContext): string | undefined {
  // curl/wget upload of a sensitive file
  const uploadPaths: string[] = []
  const uploadPatterns = [
    /(?:-d|--data|--data-binary|--data-raw)(?:=|\s+)@?(['"]?)([^\s'"=<]+)\1/gi,
    /(?:-F|--form)[^\n]*?=@(['"]?)([^\s'"]+)\1/gi,
    /--post-file(?:=|\s+)(['"]?)([^\s'"]+)\1/gi,
    /(?:\s|^)(?:-T|--upload-file)(?:\s+|=[^\s]+)/gi,
  ]
  for (const pattern of uploadPatterns) {
    for (const match of text.matchAll(pattern)) {
      if (pattern === uploadPatterns[3]) {
        // -T/--upload-file form: inline value or next token; skip a following URL.
        const matchText = match[0]
        const afterMatch = text.slice((match.index ?? 0) + matchText.length)
        const inline = /(?:-T|--upload-file)=([^\s]+)/i.exec(matchText.trim())
        if (inline) {
          uploadPaths.push(stripMatchingQuotes(inline[1] ?? ""))
        } else {
          const next = afterMatch.match(/^\s*("[^"]*"|'[^']*'|[^\s'"]+)/)
          const value = next ? stripMatchingQuotes(next[1] ?? "") : ""
          if (value && !/^https?:/i.test(value)) uploadPaths.push(value)
        }
        continue
      }
      uploadPaths.push(match[2] ?? "")
    }
  }
  if (uploadPaths.some((p) => checkPathSensitivity(p, ctx).sensitive)) return "exfiltration.sensitive-data"

  // scp: local sources before the `user@host:` token
  if (/\bscp\b/i.test(text)) {
    const tokens = simpleInvocationTokens(segment)
    let hostIndex = -1
    for (let i = 0; i < tokens.length; i += 1) {
      if (/^[^@\s]+@[^:\s]+:/.test(tokens[i] ?? "")) {
        hostIndex = i
        break
      }
    }
    if (hostIndex > 0) {
      for (let i = 1; i < hostIndex; i += 1) {
        const token = tokens[i] ?? ""
        if (token.startsWith("-")) continue
        if (checkPathSensitivity(token, ctx).sensitive) return "exfiltration.sensitive-data"
      }
    }
  }

  // nc/ncat stream from a sensitive file
  if (/\b(?:nc|ncat|netcat)\b/i.test(text)) {
    const stream = text.match(/\b(?:nc|ncat|netcat)\b[^\n]*<\s*['"]?([^\s'";|&]+)/i)
    if (stream && checkPathSensitivity(stream[1] ?? "", ctx).sensitive) return "exfiltration.sensitive-data"
  }

  // chmod 000/777 on a sensitive/credential path
  if (/\bchmod\b[^\n]*\s(?:0{3}|777)\b/i.test(text)) {
    const tokens = simpleInvocationTokens(segment)
    const args = tokens
      .slice(1)
      .filter(
        (token) =>
          !/^-(?:R|v|c|f|h)$/.test(token) &&
          !/^\d{3,4}$/.test(token) &&
          !/^(?:u|g|o|a)?[+-]=?[rwxXst]{1,3}$/.test(token),
      )
    if (args.some((p) => checkPathSensitivity(p, ctx).sensitive)) return "permissions.sensitive-mode"
  }

  return undefined
}

// ===== M3 (P2) §4.9 dedicated-safe whitelist helpers =======================

function tarOrUnzipBaseWorktree(segment: string, cwd: string, worktree: string): boolean {
  // returns true when every -C / -d target (or the default cwd) is inside the worktree
  const dirs = [...segment.matchAll(/\s-C\s+("([^"]*)"|'([^']*)'|(\S+))/gi)].map((m) => m[2] ?? m[3] ?? m[4] ?? ".")
  const unzipDirs = [...segment.matchAll(/\s-d\s+("([^"]*)"|'([^']*)'|(\S+))/gi)].map((m) => m[2] ?? m[3] ?? m[4] ?? ".")
  const bases = dirs.length > 0 ? dirs : unzipDirs.length > 0 ? unzipDirs : ["."]
  if (bases.length === 0) return false
  return bases.every((dir) => {
    const resolved = resolveLexical(dir, cwd, expandHome("~"))
    return Boolean(resolved.absolute && isWithinLexical(worktree, resolved.absolute))
  })
}

function classifyTarExtractOrUnzip(
  segment: string,
  ctx: PathContext,
  strictness: "LOOSE" | "HARD",
  isUnzip: boolean,
): SegmentDecision | undefined {
  const isExtract = isUnzip ? /^unzip\b/i.test(segment) : /^tar\b/i.test(segment)
  if (!isExtract) return undefined
  if (!isUnzip && /(?:--absolute-names|--remove-files)\b/i.test(segment)) return undefined
  if (!tarOrUnzipBaseWorktree(segment, ctx.cwd, ctx.worktree)) {
    if (strictness === "HARD") {
      return {
        verdict: "DENY",
        rules: ["filesystem.tar-extract-system"],
        reason: "Extracting an archive into a non-worktree location is forbidden",
      }
    }
    return {
      verdict: "ASK",
      rules: ["filesystem.tar-extract-system"],
      reason: "Extracting an archive outside the working tree requires review",
    }
  }
  // Check -C/-d targets (or default ".") with classifyPathTarget for git-hooks/sensitive writes
  const dirs = [...segment.matchAll(/\s-C\s+("([^"]*)"|'([^']*)'|(\S+))/gi)].map((m) => m[2] ?? m[3] ?? m[4] ?? ".")
  const unzipDirs = [...segment.matchAll(/\s-d\s+("([^"]*)"|'([^']*)'|(\S+))/gi)].map((m) => m[2] ?? m[3] ?? m[4] ?? ".")
  const hasExplicitTarget = isUnzip ? unzipDirs.length > 0 : dirs.length > 0
  const targets = hasExplicitTarget ? (isUnzip ? unzipDirs : dirs) : ["."]
  for (const dir of targets) {
    const targetFinding = classifyPathTarget(dir, "write", ctx)
    if (targetFinding.kind === "deny") return { verdict: "DENY", rules: [targetFinding.rule], reason: targetFinding.reason }
    if (targetFinding.kind === "ask") return { verdict: "ASK", rules: [targetFinding.rule], reason: targetFinding.reason }
  }
  // Extract without explicit -C/-d: archive content can't be proven safe, so don't ALLOW
  const isExtractMode = isUnzip || /^tar\s+x/i.test(segment) || /(?:^|\s)-\w*x/i.test(segment) || /--extract|--get/i.test(segment)
  if (isExtractMode && !hasExplicitTarget) {
    return { verdict: "ASK", rules: ["operation.archive-extract"], reason: "Archive extraction target is unscoped; contents cannot be verified" }
  }
  const finding = analyzeSegmentPaths(segment, ctx)
  if (finding.kind === "pass") {
    return {
      verdict: "ALLOW",
      rules: ["operation.archive-extract"],
      reason: "Archive extracts into a recognized working-tree location",
    }
  }
  return { verdict: finding.kind === "deny" ? "DENY" : "ASK", rules: [finding.rule], reason: finding.reason }
}

function isSafeDownloadTarget(segment: string, ctx: PathContext): boolean {
  // curl/wget writing a worktree file from an https URL, no upload / eval flags
  if (!/^curl\b|^wget\b/i.test(segment)) return false
  if (/\b(?:-d|--data(?:\-raw|\-binary)?|-F|--form|--post-file|--upload-file|-T)\b/i.test(segment)) return false
  if (/-A\b|--user-agent\b/.test(segment)) return false
  if (!/\shttp(s)?:\/\/|^curl\b[^\n]*https?:\/\//i.test(segment)) return false
  if (!/(?:^|\s)-(?:o|O)\b|\s--(?:output|remote-name)\b/.test(segment)) return false
  if (!tarOrUnzipBaseWorktree(segment, ctx.cwd, ctx.worktree)) return false
  return analyzeSegmentPaths(segment, ctx).kind === "pass"
}

function safeChmodSegment(segment: string, cwd: string, worktree: string): boolean {
  const tokens = simpleInvocationTokens(segment.trim())
  if (commandLeaf(tokens[0] ?? "") !== "chmod") return false
  if (/\b-R\b|--recursive\b/i.test(segment)) return false
  const modeIndex = tokens.findIndex((t) => /^[0-7]{3,4}$/.test(t) || /^[ugoa]*[+-=][rwxXst]+$/.test(t))
  if (modeIndex === -1) return false
  const mode = tokens[modeIndex] ?? ""
  const safeOctal = /^(?:600|640|644|700|750|755|660)$/.test(mode)
  const safeSymbolic = /^\+x$/.test(mode) || /^-[xw]+$/.test(mode)
  if (!safeOctal && !safeSymbolic) return false
  const targets = tokens.slice(modeIndex + 1).filter((t) => !/^-[A-Za-z]/.test(t) && !t.startsWith("--"))
  if (targets.length === 0) return false
  return targets.every((t) => {
    if (t.startsWith("~") || t.startsWith("$HOME")) return true
    const resolved = resolveLexical(t, cwd, expandHome("~"))
    return Boolean(resolved.absolute && isWithinLexical(worktree, resolved.absolute))
  })
}

function commandSubstitutionBodies(text: string): string[] {
  const bodies: string[] = []
  let i = 0
  while (i < text.length) {
    const start = text.indexOf("$(", i)
    if (start === -1) break
    let depth = 1
    let j = start + 2
    while (j < text.length && depth > 0) {
      if (text[j] === "(") depth += 1
      else if (text[j] === ")") depth -= 1
      if (depth > 0) j += 1
    }
    bodies.push(text.slice(start + 2, j))
    i = j + 1
  }
  return bodies
}

function maskCommandSubstitutions(text: string): string {
  let out = ""
  let i = 0
  while (i < text.length) {
    const start = text.indexOf("$(", i)
    if (start === -1) {
      out += text.slice(i)
      break
    }
    out += text.slice(i, start) + "x"
    let depth = 1
    let j = start + 2
    while (j < text.length && depth > 0) {
      if (text[j] === "(") depth += 1
      else if (text[j] === ")") depth -= 1
      if (depth > 0) j += 1
    }
    i = j + 1
  }
  return out
}

function isSafeSubstitutionSurface(text: string, shell: string, ctx: PathContext, depth = 0): boolean {
  if (depth > 6) return false
  const subs = commandSubstitutionBodies(text)
  const masked = maskCommandSubstitutions(text)
  const stripped = stripOutputRedirects(masked) ?? masked
  if (!isKnownSafeSegment(stripped)) return false
  if (hasUnquotedExpansion(maskHeredocBody(stripped), shell)) return false
  if (hasSensitiveEnvPrefix(stripped)) return false
  if (analyzeSegmentPaths(stripped, ctx).kind !== "pass") return false
  for (const body of subs) {
    if (!isSafeSubstitutionSurface(body, shell, ctx, depth + 1)) return false
  }
  return true
}

const DISPOSABLE_DIR_NAMES = [
  "node_modules", "dist", "build", "coverage", "target", ".cache", ".pytest_cache",
  "__pycache__", ".venv", ".next", ".turbo", ".nuxt", "out", ".gradle",
  // Generated-artifact directories commonly produced by toolchains.
  "venv", ".tox", ".mypy_cache", ".ruff_cache", ".nyc_output", ".parcel-cache",
  ".sass-cache", "storybook-static", "playwright-report", "test-results",
  ".angular", ".dart_tool", "htmlcov", ".eggs",
]
const DISPOSABLE_NAME_SOURCE = DISPOSABLE_DIR_NAMES.join("|")
const DISPOSABLE_TARGET_PATTERN = new RegExp(
  `^(?:\\.?[\\\\/])?(?:${DISPOSABLE_NAME_SOURCE})[\\\\/]?$`,
  "i",
)

type RecursiveForceDeletion = { targets: string[] }

/**
 * Parses `rm`/`Remove-Item` invocations that are provably recursive+force,
 * whatever the flag spelling (`-rf`, `-r -f`, `--recursive --force`,
 * `-Recurse -Force`, interleaved clusters). Unknown flags make the whole
 * invocation unparseable so it can never reach the cleanup exemption.
 */
function parseRecursiveForceDeletion(segment: string): RecursiveForceDeletion | undefined {
  const match = segment.match(/^(?:rm|remove-item|ri)\s+([^;&|]+)$/i)
  if (!match) return undefined
  const tokens = match[1].match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
  let sawRecursive = false
  let sawForce = false
  const targets: string[] = []
  const valueFlags = new Set([
    "-erroraction", "-warningaction", "-informationaction",
    "-errorvariable", "-warningvariable", "-outvariable", "-outbuffer", "-pipelinevariable",
  ])
  for (let index = 0; index < tokens.length; index += 1) {
    const raw = tokens[index] ?? ""
    const flag = raw.toLowerCase()
    if (flag === "--") continue
    if (flag === "-path" || flag === "-literalpath") {
      const next = tokens[index + 1]
      if (!next) return undefined
      targets.push(next)
      index += 1
      continue
    }
    if (raw.startsWith("-")) {
      if (flag === "-r" || flag === "-recurse" || flag === "--recursive") sawRecursive = true
      else if (flag === "-f" || flag === "-force" || flag === "--force") sawForce = true
      else if (/^-[dfirvRI]+$/.test(raw)) {
        if (/[rR]/.test(raw.slice(1))) sawRecursive = true
        if (/f/i.test(raw.slice(1))) sawForce = true
      } else if (flag === "-confirm:$false") {
        // PowerShell confirmation suppressor, no value.
      } else if (valueFlags.has(flag)) {
        if (!tokens[index + 1]) return undefined
        index += 1
      } else {
        return undefined
      }
      continue
    }
    targets.push(raw)
  }
  if (!sawRecursive || !sawForce || targets.length === 0) return undefined
  return { targets }
}

/** A target qualifies when any of its own path segments is a disposable name. */
function disposableTargetEligible(literal: string): boolean {
  const normalizedTarget = literal.replaceAll("\\", "/").replace(/\/+$/, "")
  if (DISPOSABLE_TARGET_PATTERN.test(normalizedTarget)) return true
  return normalizedTarget.split("/").some((segment) => DISPOSABLE_DIR_NAMES.includes(segment.toLowerCase()))
}

async function validateDisposableLiteral(literal: string, cwd: string, worktree: string): Promise<boolean> {
  if (literal.split(/[\\/]/).includes("..")) return false
  if (!disposableTargetEligible(literal)) return false
  const resolved = resolveLexical(literal, cwd, expandHome("~"))
  if (resolved.absolute === undefined || !isWithinLexical(worktree, resolved.absolute)) return false
  // Require the realpath of the target to be strictly within realpath(worktree),
  // preventing symlink-prefix escapes (link→/tmp then rm -rf link/node_modules).
  const canonical = await canonicalProjectedPath(resolved.absolute)
  if (!canonical) return false
  const worktreeReal = await canonicalProjectedPath(worktree)
  if (!worktreeReal) return false
  return isWithin(worktreeReal, canonical)
}

async function isDisposableCleanupTarget(target: string, cwd: string, worktree: string): Promise<boolean> {
  const trimmed = target.trim()
  const literal = literalPathToken(trimmed)
  if (literal) return validateDisposableLiteral(literal, cwd, worktree)
  // Brace-expanded targets fail literalPathToken ({} are rejected there);
  // expand and require every candidate to be an eligible disposable path.
  if (trimmed.includes("{") && trimmed.includes("}")) {
    const candidates = braceExpansionCandidates(trimmed)
    if (candidates.length === 0) return false
    for (const candidate of candidates) {
      const expanded = literalPathToken(candidate)
      if (expanded === undefined || !(await validateDisposableLiteral(expanded, cwd, worktree))) return false
    }
    return true
  }
  return false
}

async function isDisposableDirectoryDelete(script: string, cwd: string, worktree: string): Promise<boolean> {
  const value = stripLeadingDirectoryChanges(script).replace(/\s+/g, " ").trim()
  const deletion = parseRecursiveForceDeletion(value)
  if (!deletion) return false
  for (const t of deletion.targets) {
    if (!(await isDisposableCleanupTarget(t, cwd, worktree))) return false
  }
  return true
}

function classifySafeChmod(segment: string, ctx: PathContext, strictness: "LOOSE" | "HARD"): SegmentDecision | undefined {
  const tokens = simpleInvocationTokens(segment.trim())
  if (commandLeaf(tokens[0] ?? "") !== "chmod") return undefined
  if (safeChmodSegment(segment, ctx.cwd, ctx.worktree)) {
    return { verdict: "ALLOW", rules: ["permissions.lockdown"], reason: "Setting safe, standard file permissions" }
  }
  return undefined
}

const SECURITY_SIGNAL_RULES: Rule[] = [
  {
    id: "filesystem.find-delete",
    reason: "Recursive find deletion requires review",
    test: (text) => /\bfind\b[^\r\n;&|]*(?:^|\s)-delete(?:\s|$)/im.test(text),
  },
  {
    id: "process.termination",
    reason: "Process termination requires review",
    test: (text) => /\b(?:kill|pkill|killall|taskkill|stop-process)\b/i.test(text),
  },
  {
    id: "filesystem.forced-recursive-delete",
    reason: "Force-recursive directory deletion",
    test: hasForcedRecursiveDeleteLiteralTarget,
  },
  {
    id: "filesystem.root-delete",
    reason: "Attempts broad recursive deletion at a filesystem, home, or system-critical root",
    test: (text) =>
      // `rm -rf /`, `/etc`, `/usr`, `/boot`, ... — system-critical roots are
      // floor: never bypassable by the filesystem category.
      /\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+(?:--no-preserve-root\s+)?(?:\/|~\/?|\.\.?\/?|\*|\/(?:etc|usr|bin|sbin|boot|var|home|root|opt|lib|srv)(?:\/|\*|$))(?:\s|$|[;&|])/im.test(
        text,
      ) ||
      /\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+(?:--no-preserve-root\s+)?\/(?:etc|usr|bin|sbin|boot|var|home|root|opt|lib|srv)(?:[/*\s]|$)/im.test(
        text,
      ) ||
      /\b(?:rmdir|rd)\s+\/s\s+\/q\s+(?:[a-z]:\\|\\|\/|\.\.?|\*)(?:\s|$)/im.test(text) ||
      /\bdel\s+\/[a-z]*s[a-z]*\s+\/[a-z]*q[a-z]*\s+(?:[a-z]:\\|\\|\/|\*)(?:\s|$)/im.test(text) ||
      /\bremove-item\b[^\n]*(?:-recurse[^\n]*-force|-force[^\n]*-recurse)[^\n]*(?:[a-z]:\\(?:\*|$)|\/(?:\*|$)|~(?:\/|\s|$)|\.\.?(?:\/|\s|$)|\*)(?:\s|$)/im.test(
        text,
      ),
  },
  {
    id: "filesystem.disk-destruction",
    reason: "Attempts to format, overwrite, destroy a disk/filesystem, or create a device node",
    test: (text) =>
      /\b(?:mkfs(?:\.\w+)?|wipefs|fdisk|parted)\b/i.test(text) ||
      /\bmknod\b/i.test(text) ||
      /\bshred\b[^\n]*\/dev\/(?:sd|nvme|vd|hd|xvd|mmcblk|dasd)[a-z0-9-]*\b/i.test(text) ||
      /\bformat(?:\.com)?\s+[a-z]:/i.test(text) ||
      /\bdiskpart\b[\s\S]{0,500}\bclean(?:\s+all)?\b/i.test(text) ||
      /\bdd\b[^\n]*(?:if=\/dev\/(?:zero|urandom|random))[^\n]*of=\/dev\/(?:sd|nvme|vd|xvd)/i.test(text),
  },
  {
    id: "filesystem.backup-destruction",
    reason: "Attempts to delete snapshots, recovery data, or backup catalogs",
    test: (text) =>
      /\bvssadmin\b[^\n]*\bdelete\s+shadows\b/i.test(text) ||
      /\bwmic\b[^\n]*shadowcopy[^\n]*\bdelete\b/i.test(text) ||
      /\bwbadmin\b[^\n]*\bdelete\b/i.test(text) ||
      /\b(?:zfs\s+destroy|btrfs\s+subvolume\s+delete)\b/i.test(text),
  },
  {
    id: "system.service-destruction",
    reason: "Attempts to stop, disable, delete, or mask an operating-system service",
    test: (text) =>
      /\bsystemctl\s+(?:stop|disable|mask)\b/i.test(text) ||
      /\bservice\s+\S+\s+(?:stop|disable)\b/i.test(text) ||
      /\bsc(?:\.exe)?\s+(?:stop|delete|config)\b/i.test(text) ||
      /\b(?:stop-service|set-service)\b/i.test(text) ||
      /\blaunchctl\s+(?:unload|bootout|disable)\b/i.test(text),
  },
  {
    id: "system.shutdown",
    reason: "Attempts to shut down or reboot the host",
    test: hasHostShutdownCommand,
  },
  {
    id: "system.critical-process-kill",
    reason: "Attempts broad or critical forced process termination",
    test: (text) =>
      /\bkill\s+-(?:[a-z]*9|[A-Z]*KILL|TERM|INT|HUP)\s+(?:-1|0|1)\b/i.test(text) ||
      /\b(?:pkill|killall)\b[^\n]*(?:-9|-KILL)\b/i.test(text) ||
      /\b(?:pkill|killall)\b[^\n]*\s(?:systemd|init)\b/i.test(text) ||
      /\btaskkill\b[^\n]*\/f[^\n]*(?:\/im\s+\*|\/pid\s+(?:0|4)\b)/i.test(text),
  },
  {
    id: "database.destructive-statement",
    reason: "Attempts destructive database operations",
    test: (text) =>
      /\b(?:drop\s+(?:database|schema|table)|truncate\s+table|delete\s+from)\b/i.test(text) ||
      /\b(?:flushall|flushdb)\b/i.test(text) ||
      /\bdropDatabase\s*\(/i.test(text),
  },
  {
    id: "infrastructure.destructive-operation",
    reason: "Attempts destructive container, cluster, cloud, or infrastructure operations",
    test: (text) =>
      /\bterraform\s+destroy\b/i.test(text) ||
      /\bkubectl\s+delete\s+(?:namespace|ns|persistentvolume|pv|persistentvolumeclaim|pvc)\b/i.test(text) ||
      /\bdocker\s+(?:volume\s+rm|system\s+prune[^\n]*-a)\b/i.test(text) ||
      /\bdocker\s+(?:volume\s+prune\s+-a|image\s+prune\s+-a|rmi\s+-f\b)\b/i.test(text) ||
      /\baws\s+s3\s+rm\b[^\n]*--recursive\b/i.test(text) ||
      /\bgcloud\s+[^\n]*\bdelete\b[^\n]*(?:project|cluster|instance)\b/i.test(text),
  },
  {
    id: "filesystem.find-delete-root",
    reason: "Recursive find deletion under a system, home, or filesystem root",
    test: findDangerousDeleteRoot,
  },
  {
    id: "execution.xargs-destructive",
    reason: "Pipes files into a destructive command via xargs",
    test: (text) =>
      /\|\s*xargs\b[^\n]*\b(?:rm|shred|srm|wipe|unlink|rmdir|rd|del|erase|remove-item)\b/i.test(text) ||
      /\|\s*(?:remove-item|ri)\b/i.test(text),
  },
  {
    id: "execution.fork-bomb",
    reason: "Contains a shell fork-bomb (process storm) primitive",
    test: hasForkBomb,
  },
  {
    id: "filesystem.kernel-trigger",
    reason: "Attempts to write the kernel sysrq trigger or crash mechanisms",
    // Redirect / dd-of writes (baseline form) plus pipe/copy writers; `tee`
    // always writes to its file argument, copy commands only when the trigger
    // is the destination (trailing path, not a source). Pipe forms span `|`
    // segment splits.
    test: (text) =>
      /(?:>\s*|\bof=)[^\n]*\/proc\/sysrq-trigger\b/i.test(text) ||
      /\btee\b[^\n]*\/proc\/sysrq-trigger\b/i.test(text) ||
      /\b(?:cp|mv|rsync|install)\b[^\n|;&]*\s\/proc\/sysrq-trigger\s*(?:[|;&\n]|$)/i.test(text),
  },
  {
    id: "filesystem.kernel-core-pattern",
    reason: "Attempts to set a piped core_pattern (kernel code execution)",
    // Any write to core_pattern is the floor: redirect/dd-of, tee, or copy
    // commands with it as the trailing destination. Piping INTO a program
    // (`| /usr/bin/crash`) is the code-exec form and is covered by the same
    // write markers.
    test: (text) =>
      /(?:>\s*|\bof=)[^\n]*\/proc\/sys\/kernel\/core_pattern\b/i.test(text) ||
      /\btee\b[^\n]*\/proc\/sys\/kernel\/core_pattern\b/i.test(text) ||
      /\b(?:cp|mv|rsync|install)\b[^\n|;&]*\s\/proc\/sys\/kernel\/core_pattern\s*(?:[|;&\n]|$)/i.test(text),
  },
  {
    id: "permissions.root-recursive",
    reason: "Recursively locks or opens permissions on a system/root directory",
    test: (text) =>
      /\bchmod\b\s+-R\s+(?:0|000|777)\b[^\n]*\s+(?:\/|~\/?|\/etc\b|\/usr\b|\/bin\b|\/sbin\b|\/boot\b|\/var\b|\/home\b|\/root\b|\/opt\b)/i.test(
        text,
      ),
  },
  {
    id: "execution.kernel-module-load",
    reason: "Loads a kernel module into the running kernel",
    test: (text) =>
      /\binsmod\b/i.test(text) || /(?:^|[\s;])modprobe\b[^\n]*(?:\s+-\w+)*\s+(?!-)([A-Za-z0-9_+.:-]+)/i.test(text),
  },
  {
    id: "filesystem.compression-root",
    reason: "Recursively compressing the filesystem root is destructive",
    test: (text) => /\bgzip\b\s+(?:-\w+\s+)*-r\b\s+\//i.test(text),
  },
  {
    id: "execution.script-one-liner-destructive",
    reason: "A script one-liner performs destructive filesystem operations",
    test: hasDestructiveOneLiner,
  },
  {
    id: "filesystem.brace-root-delete",
    reason: "Forced-recursive deletion of brace-expanded system roots",
    test: hasDangerousBraceDelete,
  },
  {
    id: "git.irrecoverable-change",
    reason: "Attempts to discard local work or rewrite shared Git history",
    test: (text) =>
      /\bgit\s+clean\b(?=[^\n;|&]*\s-[a-z]*f)(?=[^\n;|&]*\s-[a-z]*d)(?=[^\n;|&]*\s-[a-z]*x)/i.test(text) ||
      /\bgit\s+reset\s+--hard\b/i.test(text) ||
      /\bgit\s+(?:checkout|restore)\s+--?\s*(?:\.|\*)\b/i.test(text) ||
      /\bgit\s+push\b[^\n]*(?:--force(?:-with-lease)?\b|\s-[a-zA-Z]*f[a-zA-Z]*\b)/i.test(text),
  },
  {
    id: "git.remote-history-rewrite",
    reason: "Attempts to rewrite or delete shared remote Git history",
    test: hasGitRemoteHistoryRewrite,
  },
  {
    id: "filesystem.root-glob-delete",
    reason: "Forced recursive deletion of an absolute glob path outside temp areas",
    test: hasRootGlobDelete,
  },
  {
    id: "execution.remote-pipe",
    reason: "Downloads remote content and immediately executes it",
    test: (text) =>
      /\b(?:curl|wget|invoke-webrequest|iwr|irm)\b[\s\S]{0,1000}(?:\||&&|;|\r?\n)[\s\S]{0,300}\b(?:bash|sh|zsh|python(?:3)?(?:\.exe)?|py(?:\.exe)?|node|powershell|pwsh|invoke-expression|iex)\b/i.test(
        text,
      ),
  },
  {
    id: "permissions.world-writable",
    reason: "Attempts to grant dangerously broad filesystem permissions",
    test: (text) =>
      /\bchmod\b[^\n]*(?:-R\s+)?777\b/i.test(text) ||
      /\bicacls\b[^\n]*\/grant[^\n]*(?:Everyone|Users):\(?(?:F|M)\)?/i.test(text),
  },
  {
    id: "persistence.backdoor",
    reason: "Attempts to create a persistent scheduled or startup execution mechanism",
    test: (text) =>
      hasCrontabPersistence(text) ||
      /\bschtasks\b[^\n]*\/create\b/i.test(text) ||
      /\\CurrentVersion\\Run(?:Once)?\b/i.test(text) ||
      /\b(?:systemctl\s+enable|launchctl\s+enable)\b/i.test(text) ||
      /\b(?:at|systemd-run)\s+(?:now\b|--on-)/i.test(text),
  },
  {
    id: "network.reverse-shell",
    reason: "Contains a reverse-shell or remote-control primitive",
    test: (text) =>
      /\/dev\/tcp\/|\/dev\/udp\//i.test(text) ||
      /\b(?:nc|ncat|netcat)\b[^\n]*(?:\s-e\s|\s--exec\s)/i.test(text) ||
      /\bsocat\b[^\n]*(?:\s(?:EXEC|SYSTEM|EXEC):)/i.test(text) ||
      /\bmkfifo\b[^\n]*(?:\|\s*(?:cat|sh|bash)[^\n]*\|\s*(?:nc|ncat|netcat))/i.test(text) ||
      /\bsocket\.connect\s*\([^)]*\)[^\n]{0,200}(?:subprocess|dup2|os\.system|popen)/i.test(text) ||
      /(?:subprocess\.(?:Popen|call|run)\s*\([^\n]*\/bin\/(?:sh|bash)|cp\.spawn\s*\(\s*["']sh["']|TCPSocket\.new\s*\([^)]*\)[^\n]{0,120}(?:IO\.popen|Kernel\.(?:system|exec))|fsockopen\s*\([^)]*\)[^\n]{0,120}(?:exec|system|popen)|TCPClient|Socket::And|exec\s*\(\s*["']\/bin\/sh[^)]*\))/i.test(
        text,
      ),
  },
  {
    id: "credentials.sensitive-access",
    reason: "Attempts to access credentials, private keys, process secrets, or credential material",
    test: hasSensitiveCredentialReference,
  },
  {
    id: "network.destructive-api",
    reason: "Attempts to invoke a destructive remote API operation",
    test: (text) =>
      /\brequests\.delete\s*\(/i.test(text) ||
      /\b(?:curl|Invoke-RestMethod|irm)\b[^\n]*(?:-X|--request|-Method)\s+DELETE\b/i.test(text),
  },
]

const DEFINITE_DESTRUCTIVE_RULES = new Set([
  "filesystem.forced-recursive-delete",
  "filesystem.root-delete",
  "filesystem.root-glob-delete",
  "filesystem.disk-destruction",
  "filesystem.backup-destruction",
  "system.service-destruction",
  "system.shutdown",
  "system.critical-process-kill",
  "database.destructive-statement",
  "infrastructure.destructive-operation",
  "network.reverse-shell",
  "filesystem.find-delete-root",
  "execution.xargs-destructive",
  "execution.fork-bomb",
  "filesystem.kernel-trigger",
  "filesystem.kernel-core-pattern",
  "permissions.root-recursive",
  "execution.kernel-module-load",
  "filesystem.compression-root",
  "execution.script-one-liner-destructive",
  "filesystem.brace-root-delete",
  "git.remote-history-rewrite",
])

/**
 * Rules that DENY in HARD mode and downgrade to an ASK review signal in LOOSE.
 * Mirrors the plan: destructive operations the HARD (injected-agent) model must
 * never auto-run, but good-faith LOOSE work may still be reviewed by the
 * dynamic layer (e.g. official installers).
 */
const HARD_DENY_LOOSE_ASK_RULES: { id: string; reason: string; test: (text: string) => boolean }[] = [
  {
    id: "execution.remote-pipe",
    reason: "Downloads remote content and immediately executes it",
    test: (text) =>
      /\b(?:curl|wget|invoke-webrequest|iwr|irm)\b[\s\S]{0,1000}(?:\||&&|;|\r?\n)[\s\S]{0,300}\b(?:bash|sh|zsh|python(?:3)?(?:\.exe)?|py(?:\.exe)?|node|powershell|pwsh|invoke-expression|iex)\b/i.test(
        text,
      ),
  },
  {
    id: "kernel.sysctl-write",
    reason: "Modifying kernel parameters requires review",
    test: (text) => /\bsysctl\b[^\n]*\s-w\b/i.test(text),
  },
  {
    id: "infrastructure.privileged-container",
    reason: "Running a privileged container or mounting the Docker socket requires review",
    test: (text) =>
      /\bdocker\s+run\b[^\n]*(?:--privileged\b|--pid=host\b|-v\s+\/var\/run\/docker\.sock\b|--host=unix:\/\/\/var\/run\/docker\.sock\b)/i.test(
        text,
      ),
  },
  {
    id: "infrastructure.cluster-delete",
    reason: "Destructive cluster/container/cloud operation requires review",
    test: (text) =>
      /\bkubectl\s+delete\b[^\n]*(?:\sall\b|\s--all\b)|\bkubectl\s+drain\b[^\n]*--force\b|\bhelm\s+uninstall\b/i.test(text),
  },
  {
    id: "infrastructure.cloud-delete",
    reason: "Destructive cloud resource deletion requires review",
    test: (text) =>
      /\baws\s+s3\s+rb\b[^\n]*--force\b|\baws\s+(?:iam\s+delete-|ec2\s+terminate-instances|rds\s+delete-db-instance)\b|\bgcloud\b[^\n]*\bdelete\b[^\n]*(?:project|cluster|instance)\b|\baz\b[^\n]*\bdelete\b[^\n]*--yes\b/i.test(
        text,
      ),
  },
  {
    id: "permissions.setuid",
    reason: "Granting setuid/setcap capabilities requires review",
    test: (text) =>
      /\bchmod\b[^\n]*(?:\s[2467][0-7]{3}\b|\+s\b|u\+s\b|g\+s\b)|\bsetcap\b[^\n]*(?:cap_setuid|cap_all|cap_dac_read_search|cap_sys_admin)\+ep\b|\binstall\s+-m\s+[24][0-7]{3}\b/i.test(
        text,
      ),
  },
  {
    id: "network.firewall-mutate",
    reason: "Mutating firewall or network configuration requires review",
    test: (text) =>
      /\biptables\b[^\n]*\s-[FP]\b|\bnft\s+flush\s+ruleset\b|\bufw\s+(?:disable|reset)\b|\bip\s+(?:addr|route)\s+flush\b|\bifconfig\b[^\n]*\s+down\b/i.test(
        text,
      ),
  },
  {
    id: "namespace.escape",
    reason: "Entering or creating isolated namespaces requires review",
    test: (text) =>
      /\bnsenter\s+-t\s+1\b|\bunshare\b[^\n]*(?:--mount\b|--pid\b|--user\b|--mount-proc\b)/i.test(text),
  },
  {
    id: "filesystem.tar-extract-system",
    reason: "Extracting an archive into a system directory requires review",
    test: (text) =>
      /\btar\b[^\n]*(?:-C\s+\/(?:etc|var|boot|usr|bin|sbin|home|root)\b|--absolute-names\b)/i.test(text),
  },
  {
    id: "forensic.history-clear",
    reason: "Clearing command history or disabling history recording requires review",
    test: (text) =>
      /\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bexport\s+HISTFILE\s*=\s*(?:\/dev\/null|:)?\b|HISTSIZE\s*=\s*0\b/i.test(text),
  },
  {
    id: "forensic.journal-vacuum",
    reason: "Vacuuming or deleting journal/log data requires review",
    test: (text) => /\bjournalctl\b[^\n]*--vacuum/i.test(text),
  },
  {
    id: "exfiltration.dns",
    reason: "DNS-exfiltrating command output requires review",
    test: (text) => /\b(?:nslookup|dig|host)\b[^\n]*\$\(/i.test(text),
  },
  {
    id: "execution.encoded-shell",
    reason: "Executing an encoded PowerShell payload requires review",
    test: (text) => /\b(?:pwsh|powershell)(?:\.exe)?\b[^\n]*-(?:EncodedCommand|EncodedArguments|enc)\b/i.test(text),
  },
  {
    id: "forensic.var-log-delete",
    reason: "Deleting log output requires review",
    test: (text) => /\b(?:rm|shred|find)\b[^\n]*\/var\/log\b/i.test(text),
  },
]

function normalized(value: string) {
  return value.normalize("NFKC").replace(/[\u200B-\u200D\u2060\uFEFF]/g, "")
}

function hasSensitiveCredentialReference(text: string) {
  return (
    SENSITIVE_ENV_FILE.test(text) ||
    /(?:^|[\\/\s])\.ssh(?:[\\/\s]|$)|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|\/proc\/(?:self|\d+)\/environ|\blsass\b|\.aws[\\/](?:credentials|config)|\.npmrc\b|\.vercel[\\/]token/i.test(
      text,
    )
  )
}

function hasCrontabPersistence(text: string) {
  const invocations = text.match(/\bcrontab\b[^\r\n;&|]*/gi) ?? []
  return invocations.some((invocation) => {
    const args = invocation.trim().split(/\s+/).slice(1)
    let listsOnly = false
    for (let index = 0; index < args.length; index += 1) {
      const arg = args[index]
      if (arg === "-l" || arg === "--list") {
        listsOnly = true
        continue
      }
      if (arg === "-u" || arg === "--user") {
        if (!args[index + 1]) return true
        index += 1
        continue
      }
      if (/^\d*(?:>{1,2}|<)/.test(arg)) continue
      return true
    }
    return !listsOnly
  })
}

function expandHome(value: string) {
  if (value === "~") return process.env.USERPROFILE ?? process.env.HOME ?? value
  if (value.startsWith("~/") || value.startsWith("~\\")) {
    const home = process.env.USERPROFILE ?? process.env.HOME
    return home ? path.join(home, value.slice(2)) : value
  }
  return value
}

function isWithin(base: string, target: string) {
  const relative = path.relative(path.resolve(base), path.resolve(target))
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))
}

function commandLeaf(value: string) {
  return stripMatchingQuotes(value)
    .replaceAll("\\", "/")
    .split("/")
    .at(-1)
    ?.replace(/\.(?:exe|cmd|bat|ps1)$/i, "")
    .toLowerCase()
}

function simpleInvocationTokens(segment: string) {
  return segment.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
}

function literalPathToken(value: string) {
  const candidate = stripMatchingQuotes(value.trim())
  if (!candidate || /[*?[\]`$%{}]/.test(candidate) || /[<>|]/.test(candidate)) return undefined
  return candidate
}

function backupPathIdentity(candidate: string) {
  const normalizedPath = candidate.replace(/[\\/]+$/, "")
  const name = path.basename(normalizedPath)
  const match = name.match(/^(.*?)(?:\.backup|-backup|\.bak|-bak)\d*$/)
  if (!match?.[1]) return undefined
  return {
    backupName: name,
    originalName: match[1],
  }
}

function isCriticalOriginalPath(candidate: string) {
  const original = path.basename(candidate.replace(/[\\/]+$/, "")).toLowerCase()
  return (
    /(?:^|\.)env(?:\.|$)/.test(original) ||
    /\.(?:key|pem|p12|pfx|ppk|jks|keystore|kdbx|gpg|age)$/.test(original) ||
    /^(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)$/.test(original) ||
    /^(?:\.ssh|\.gnupg)$/.test(original)
  )
}

function isCriticalBackupTarget(candidate: string) {
  const identity = backupPathIdentity(candidate)
  if (!identity) return false
  return isCriticalOriginalPath(identity.originalName)
}

type ParsedDeleteInvocation = {
  parseable: boolean
  targets: string[]
}

function parseDeleteInvocation(segment: string): ParsedDeleteInvocation | undefined {
  const tokens = simpleInvocationTokens(segment.trim())
  const command = commandLeaf(tokens[0] ?? "")
  if (!["rm", "remove-item", "del", "erase", "unlink", "rmdir", "rd", "ri", "shred", "srm", "wipe"].includes(command ?? "")) {
    return undefined
  }

  const targets: string[] = []
  const optionsWithValues = new Set([
    "-erroraction",
    "-warningaction",
    "-informationaction",
    "-errorvariable",
    "-warningvariable",
    "-outvariable",
    "-outbuffer",
    "-pipelinevariable",
    "-n",
    "--iterations",
    "-s",
    "--size",
  ])
  const optionsWithoutValues = new Set([
    "-f",
    "--force",
    "-r",
    "-R",
    "--recursive",
    "-d",
    "--dir",
    "-i",
    "-I",
    "-v",
    "--verbose",
    "--one-file-system",
    "-force",
    "-recurse",
    "-confirm:$false",
    "-u",
    "--remove",
    "-z",
    "--zero",
    "-x",
    "--exact",
  ])
  let optionsEnded = false

  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index]
    const lower = token.toLowerCase()
    if (!optionsEnded && lower === "--") {
      optionsEnded = true
      continue
    }
    if (!optionsEnded && (lower === "-path" || lower === "-literalpath")) {
      const target = tokens[index + 1]
      if (!target) return { parseable: false, targets }
      targets.push(target)
      index += 1
      continue
    }
    if (!optionsEnded && optionsWithValues.has(lower)) {
      if (!tokens[index + 1]) return { parseable: false, targets }
      index += 1
      continue
    }
    if (/^\d*>&\d+$/.test(token)) continue
    if (/^(?:\d*|&)>{1,2}\S+$/.test(token)) continue
    if (/^(?:\d*|&)>{1,2}$/.test(token)) {
      if (index + 1 < tokens.length) index += 1
      continue
    }
    if (!optionsEnded && (optionsWithoutValues.has(token) || optionsWithoutValues.has(lower))) continue
    if (!optionsEnded && /^-[firdvR]+$/.test(token)) continue
    if (!optionsEnded && CMD_STYLE_DELETE_COMMANDS.includes(command ?? "") && CMD_DELETE_FLAGS.test(token)) continue
    if (!optionsEnded && token.startsWith("-")) return { parseable: false, targets }
    targets.push(token)
  }

  return { parseable: targets.length > 0, targets }
}

type ParsedTransferInvocation = {
  source: string
  target: string
}

function parsePositionalTransfer(tokens: string[], allowedFlags: RegExp) {
  const operands: string[] = []
  let optionsEnded = false
  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index]
    if (!optionsEnded && token === "--") {
      optionsEnded = true
      continue
    }
    if (!optionsEnded && token.startsWith("-")) {
      if (!allowedFlags.test(token)) return undefined
      continue
    }
    operands.push(token)
  }
  if (operands.length !== 2) return undefined
  return { source: operands[0], target: operands[1] }
}

function parsePowerShellTransfer(tokens: string[], destinationNames: Set<string>) {
  let source: string | undefined
  let target: string | undefined
  const positional: string[] = []
  const switches = new Set(["-recurse", "-force", "-container", "-confirm:$false"])
  const optionsWithValues = new Set([
    "-erroraction",
    "-warningaction",
    "-informationaction",
    "-errorvariable",
    "-warningvariable",
    "-outvariable",
    "-outbuffer",
    "-pipelinevariable",
  ])

  for (let index = 1; index < tokens.length; index += 1) {
    const token = tokens[index]
    const lower = token.toLowerCase()
    if (lower === "-path" || lower === "-literalpath") {
      if (source || !tokens[index + 1]) return undefined
      source = tokens[index + 1]
      index += 1
      continue
    }
    if (destinationNames.has(lower)) {
      if (target || !tokens[index + 1]) return undefined
      target = tokens[index + 1]
      index += 1
      continue
    }
    if (switches.has(lower)) continue
    if (optionsWithValues.has(lower)) {
      if (!tokens[index + 1]) return undefined
      index += 1
      continue
    }
    if (token.startsWith("-")) return undefined
    positional.push(token)
  }

  if (!source) source = positional.shift()
  if (!target) target = positional.shift()
  if (!source || !target || positional.length > 0) return undefined
  return { source, target }
}

function parseCopyInvocation(segment: string): ParsedTransferInvocation | undefined {
  const tokens = simpleInvocationTokens(segment.trim())
  const command = commandLeaf(tokens[0] ?? "")
  if (command === "cp") {
    if (tokens.some((token) => ["-path", "-literalpath", "-destination"].includes(token.toLowerCase()))) {
      return parsePowerShellTransfer(tokens, new Set(["-destination"]))
    }
    return parsePositionalTransfer(
      tokens,
      /^(?:-[aAbdfHilLnPpRrSsuvx]+|--(?:archive|force|interactive|link|no-clobber|no-dereference|recursive|update|verbose|preserve(?:=.+)?|no-preserve=.+|reflink(?:=.+)?|sparse=.+))$/,
    )
  }
  if (command === "copy") return parsePositionalTransfer(tokens, /^\/[abdvyn]+$/i)
  if (command === "copy-item") {
    return parsePowerShellTransfer(tokens, new Set(["-destination"]))
  }
  return undefined
}

function parseMoveInvocation(segment: string): ParsedTransferInvocation | undefined {
  const tokens = simpleInvocationTokens(segment.trim())
  const command = commandLeaf(tokens[0] ?? "")
  if (command === "mv" || command === "move") {
    if (tokens.some((token) => ["-path", "-literalpath", "-destination"].includes(token.toLowerCase()))) {
      return parsePowerShellTransfer(tokens, new Set(["-destination"]))
    }
    return parsePositionalTransfer(tokens, /^(?:-[finTuv]+|--(?:force|interactive|no-clobber|update|verbose|no-target-directory))$/)
  }
  if (command === "move-item") {
    return parsePowerShellTransfer(tokens, new Set(["-destination"]))
  }
  if (command === "rename-item" || command === "ren") {
    return parsePowerShellTransfer(tokens, new Set(["-newname"]))
  }
  return undefined
}

function expandTrustedTempVariables(value: string) {
  const replacements: Array<[RegExp, string | undefined]> = [
    [/^%LOCALAPPDATA%(?=$|[\\/])/i, process.env.LOCALAPPDATA],
    [/^%TEMP%(?=$|[\\/])/i, process.env.TEMP],
    [/^\$env:LOCALAPPDATA(?=$|[\\/])/i, process.env.LOCALAPPDATA],
    [/^\$env:TEMP(?=$|[\\/])/i, process.env.TEMP],
    [/^\$\{env:LOCALAPPDATA\}(?=$|[\\/])/i, process.env.LOCALAPPDATA],
    [/^\$\{env:TEMP\}(?=$|[\\/])/i, process.env.TEMP],
  ]
  let expanded = stripMatchingQuotes(value.trim())
  for (const [pattern, replacement] of replacements) {
    if (replacement && pattern.test(expanded)) {
      expanded = expanded.replace(pattern, replacement)
      break
    }
  }
  return expandHome(expanded)
}

function normalizeMsysPath(value: string) {
  if (process.platform !== "win32") return value
  return value.replace(/^\/([a-zA-Z])(?=\/|$)/, "$1:/")
}

function resolveTempPathCandidate(candidate: string, base: string) {
  const expanded = normalizeMsysPath(expandTrustedTempVariables(candidate))
  if (!expanded || /[`$%{}<>|]/.test(expanded)) return undefined

  const wildcardIndex = expanded.search(/[*?[]/)
  if (wildcardIndex >= 0) {
    const wildcardSuffix = expanded.slice(wildcardIndex)
    if (/[\\/]/.test(wildcardSuffix)) return undefined
    const prefix = expanded.slice(0, wildcardIndex)
    const anchorText = prefix.endsWith("/") || prefix.endsWith("\\") ? prefix : path.dirname(prefix)
    if (!anchorText) return undefined
    const anchor = path.isAbsolute(anchorText) ? path.normalize(anchorText) : path.resolve(base, anchorText)
    return { absolute: anchor, contentsOnly: true }
  }

  const absolute = path.isAbsolute(expanded) ? path.normalize(expanded) : path.resolve(base, expanded)
  return { absolute, contentsOnly: false }
}

function isStrictlyWithin(base: string, target: string) {
  const relative = path.relative(path.resolve(base), path.resolve(target))
  return Boolean(relative && !relative.startsWith("..") && !path.isAbsolute(relative))
}

async function canonicalExistingAnchor(candidate: string) {
  let current = path.resolve(candidate)
  for (let index = 0; index < 64; index += 1) {
    try {
      return await realpath(current)
    } catch {
      const parent = path.dirname(current)
      if (parent === current) return undefined
      current = parent
    }
  }
  return undefined
}

async function trustedUserLocalTempRoots(input: ClassifyShellCommandInput) {
  const candidates = input.trustedTempRoot
    ? [input.trustedTempRoot]
    : [
        process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, "Temp") : undefined,
        process.env.USERPROFILE ? path.join(process.env.USERPROFILE, "AppData", "Local", "Temp") : undefined,
      ]
  const roots: string[] = []
  for (const candidate of candidates) {
    if (!candidate) continue
    try {
      const canonical = await realpath(path.resolve(candidate))
      if (!roots.some((root) => path.resolve(root).toLowerCase() === path.resolve(canonical).toLowerCase())) {
        roots.push(canonical)
      }
    } catch {
      // A missing or inaccessible temp root cannot qualify for the whitelist.
    }
  }
  return roots
}

async function isTrustedTempPath(
  candidate: string,
  base: string,
  roots: string[],
) {
  const resolved = resolveTempPathCandidate(candidate, base)
  if (!resolved) return false

  for (const root of roots) {
    const lexicalMatch =
      isStrictlyWithin(root, resolved.absolute) ||
      (resolved.contentsOnly && path.resolve(root).toLowerCase() === path.resolve(resolved.absolute).toLowerCase())
    if (!lexicalMatch) continue

    const canonicalAnchor = await canonicalExistingAnchor(resolved.absolute)
    if (!canonicalAnchor) continue
    const canonicalMatch =
      isStrictlyWithin(root, canonicalAnchor) ||
      path.resolve(root).toLowerCase() === path.resolve(canonicalAnchor).toLowerCase()
    if (canonicalMatch) return true
  }
  return false
}

function isHarmlessTailSegment(segment: string) {
  const value = segment.trim()
  if (/[<>]/.test(value)) return false
  if (/^(?:echo|printf|Write-Output|true|false|:|cd|popd)\b/i.test(value)) return true
  if (/^set\b/i.test(value)) {
    const tokens = value.split(/\s+/).slice(1)
    const safeOptions = new Set([
      "pipefail", "errexit", "nounset", "xtrace", "verbose",
      "noclobber", "ignoreeof", "allexport", "nolog", "privileged",
    ])
    if (tokens.every((t) => /^[-+][a-zA-Z]+$/.test(t) || safeOptions.has(t.toLowerCase()) || t === "--" || t === "-")) {
      return true
    }
  }
  return false
}

async function classifyUserLocalTempSegment(
  source: string,
  input: ClassifyShellCommandInput,
): Promise<StaticSecurityDecision | undefined> {
  const roots = await trustedUserLocalTempRoots(input)
  if (roots.length === 0) return undefined

  const wrappedPowerShell = unwrapPowerShellCommand(source)
  const wrappedNamedShell = wrappedPowerShell
    ? undefined
    : unwrapNamedTempDeletionShell(source, input.shell)
  const payload = wrappedPowerShell ?? wrappedNamedShell?.payload ?? source
  const payloadShell = wrappedPowerShell
    ? "powershell"
    : wrappedNamedShell?.shell ?? input.shell
  const segments = splitCommandSegments(payload, payloadShell)
  if (!segments?.length) return undefined

  let base: string | undefined = input.cwd
  let operations = 0
  for (const item of segments) {
    base = segmentBase(item, base, input.cwd)
    const segment = item.text
    const cd = parseCdSegment(segment)
    if (cd) {
      base = resolveCdBase(cd.dir, base)
      continue
    }
    if (base === undefined) return undefined

    const deletion = parseDeleteInvocation(segment)
    if (deletion) {
      if (!deletion.parseable || deletion.targets.length === 0) return undefined
      for (const target of deletion.targets) {
        if (!(await isTrustedTempPath(target, base, roots))) return undefined
      }
      operations += 1
      if (input.strictness === "HARD") {
        return {
          verdict: "DENY",
          rules: ["hard.local-temp-delete"],
          reason: `Permanent deletion inside the trusted Local Temp directory is forbidden. ${PERMANENT_DELETE_GUIDANCE}`,
          fingerprints: [],
        }
      }
      continue
    }

    const move = parseMoveInvocation(segment)
    if (move) {
      const sourcePath = resolveTempPathCandidate(move.source, base)
      if (!sourcePath || !(await isTrustedTempPath(move.source, base, roots))) return undefined
      const command = commandLeaf(simpleInvocationTokens(segment)[0] ?? "")
      const targetBase =
        (command === "rename-item" || command === "ren") && !path.isAbsolute(expandTrustedTempVariables(move.target))
          ? path.dirname(sourcePath.absolute)
          : base
      if (!(await isTrustedTempPath(move.target, targetBase, roots))) return undefined
      operations += 1
      continue
    }

    const copy = parseCopyInvocation(segment)
    if (copy) {
      if (!literalPathToken(copy.source)) return undefined
      if (!(await isTrustedTempPath(copy.target, base, roots))) return undefined
      operations += 1
      continue
    }

    if (isHarmlessTailSegment(segment)) continue
    return undefined
  }

  if (operations === 0) return undefined
  if (input.strictness === "HARD") return undefined
  return {
    verdict: "ALLOW",
    rules: ["cleanup.user-local-temp"],
    reason: "Filesystem operation is strictly confined to the trusted user Local Temp directory",
    fingerprints: [],
  }
}

function unwrapNamedTempDeletionShell(
  source: string,
  shell: string,
): { payload: string; shell: string } | undefined {
  const value = stripLeadingDirectoryChanges(source)
  if (splitSimpleSegments(value, shell)?.length !== 1) return undefined

  const tokens = simpleInvocationTokens(value)
  let commandIndex = 0
  if (commandLeaf(tokens[0] ?? "") === "wsl") {
    commandIndex = 1
    while (commandIndex < tokens.length) {
      const lower = tokens[commandIndex].toLowerCase()
      if (lower === "-d" || lower === "--distribution" || lower === "-u" || lower === "--user") {
        commandIndex += 2
        continue
      }
      if (lower === "--") {
        commandIndex += 1
        break
      }
      break
    }
  }

  const wrapper = commandLeaf(tokens[commandIndex] ?? "")
  let commandFlagIndex = -1
  let wrappedShell = shell
  if (["bash", "sh", "zsh"].includes(wrapper ?? "")) {
    commandFlagIndex = tokens.findIndex(
      (token, index) => index > commandIndex && /^-[a-z]*c[a-z]*$/i.test(token),
    )
    wrappedShell = wrapper ?? shell
  } else if (wrapper === "cmd") {
    commandFlagIndex = tokens.findIndex((token, index) => index > commandIndex && /^\/c$/i.test(token))
    wrappedShell = "cmd"
  } else {
    return undefined
  }

  const quotedPayload = tokens[commandFlagIndex + 1]
  if (commandFlagIndex < 0 || !quotedPayload) return undefined
  if (tokens.slice(commandFlagIndex + 2).some((token) => !/^\d*>&\d+$/.test(token))) return undefined
  const payload = stripMatchingQuotes(quotedPayload).trim()
  return payload ? { payload, shell: wrappedShell } : undefined
}

function namedTempDeletionPayload(source: string, input: ClassifyShellCommandInput) {
  let payload = source
  let payloadShell = input.shell
  for (let depth = 0; depth < 4; depth += 1) {
    const wrappedPowerShell = unwrapPowerShellCommand(payload)
    if (wrappedPowerShell) {
      payload = wrappedPowerShell
      payloadShell = "powershell"
      continue
    }
    const wrappedShell = unwrapNamedTempDeletionShell(payload, payloadShell)
    if (!wrappedShell) break
    payload = wrappedShell.payload
    payloadShell = wrappedShell.shell
  }
  return { payload, payloadShell }
}

function decodedPowerShellDeletionPayloads(source: string, shell: string) {
  const value = stripLeadingDirectoryChanges(source)
  if (splitSimpleSegments(value, shell)?.length !== 1) return []

  const tokens = simpleInvocationTokens(value)
  if (!["powershell", "pwsh"].includes(commandLeaf(tokens[0] ?? "") ?? "")) return []
  const encodedIndex = tokens.findIndex((token) => /^-(?:encodedcommand|enc)$/i.test(token))
  const encoded = tokens[encodedIndex + 1]
  if (encodedIndex < 1 || !encoded) return []

  const switchesWithoutValues = new Set(["-noprofile", "-noninteractive", "-nologo", "-sta", "-mta"])
  const switchesWithValues = new Set(["-executionpolicy", "-ep", "-windowstyle"])
  for (let index = 1; index < encodedIndex; index += 1) {
    const token = tokens[index].toLowerCase()
    if (switchesWithoutValues.has(token)) continue
    if (switchesWithValues.has(token) && index + 1 < encodedIndex) {
      index += 1
      continue
    }
    return []
  }
  if (tokens.slice(encodedIndex + 2).some((token) => !/^\d*>&\d+$/.test(token))) return []
  return decodePowerShellBase64(stripMatchingQuotes(encoded))
}

async function classifyNamedTempDeletionPolicy(
  source: string,
  input: ClassifyShellCommandInput,
): Promise<StaticSecurityDecision | undefined> {
  const candidates = [
    namedTempDeletionPayload(source, input),
    ...decodedPowerShellDeletionPayloads(source, input.shell).map((payload) => ({
      payload,
      payloadShell: "powershell",
    })),
  ]
  const rootDeleteRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "filesystem.root-delete")

  for (const { payload, payloadShell } of candidates) {
    const segments = splitCommandSegments(payload, payloadShell)
    if (!segments?.length || rootDeleteRule?.test(payload)) continue

    let hasNamedTempTarget = false
    let pureDeletion = true
    let base = input.cwd
    for (const item of segments) {
      base = segmentBase(item, base, input.cwd)
      const segment = item.text
      const cd = parseCdSegment(segment)
      if (cd) {
        base = resolveCdBase(cd.dir, base)
        continue
      }
      const stripped = stripHarmlessPrefixes(segment)
      const tokens = simpleInvocationTokens(stripped.trim())
      const command = commandLeaf(tokens[0] ?? "")
      if (!DELETE_COMMANDS.has(command ?? "")) {
        if (isHarmlessTailSegment(stripped)) continue
        pureDeletion = false
        break
      }

      const deletion = parseDeleteInvocation(stripped)
      if (!deletion?.parseable || deletion.targets.length === 0) {
        pureDeletion = false
        break
      }
      if (base === undefined || !(await deletionTargetsAreNamedTemp(deletion.targets, base, input.worktree))) {
        pureDeletion = false
        break
      }
      hasNamedTempTarget = true
    }

    if (pureDeletion && hasNamedTempTarget) {
      if (input.strictness === "HARD") {
        return {
          verdict: "DENY",
          rules: ["hard.named-temp-delete"],
          reason: `Permanent deletion of named temp/tmp targets is forbidden. ${PERMANENT_DELETE_GUIDANCE}`,
          fingerprints: [],
        }
      }
      return {
        verdict: "ALLOW",
        rules: ["cleanup.named-temp"],
        reason: "Every deletion target is confined to a named temp or tmp directory",
        fingerprints: [],
      }
    }
  }

  return undefined
}

async function deletionTargetsAreNamedTemp(targets: string[], base: string, worktree?: string) {
  for (const target of targets) {
    if (!(await isNamedTempTargetResolved(target, base, worktree))) return false
  }
  return true
}

function hasExplicitNonCopyBackupCreation(segment: string) {
  const value = segment.trim()
  if (!BACKUP_SUFFIX_REFERENCE.test(value)) return false
  if (/^(?:mkdir|New-Item\s+[^\n]*-ItemType\s+Directory)\b/i.test(value)) return false
  if (/^(?:touch|new-item|set-content|out-file|tee|install)\b/i.test(value)) return true
  if (
    /^tar\b[^\r\n;&|]*(?:-[A-Za-z]*f\s+|--file(?:=|\s+))(?:"[^"]*(?:\.backup|-backup|\.bak|-bak)\d*"|'[^']*(?:\.backup|-backup|\.bak|-bak)\d*'|[^\s;&|]*(?:\.backup|-backup|\.bak|-bak)\d*)(?:\s|$)/i.test(
      value,
    )
  ) {
    return true
  }
  if (
    /^zip\b(?:\s+-\S+)*\s+(?:"[^"]*(?:\.backup|-backup|\.bak|-bak)\d*"|'[^']*(?:\.backup|-backup|\.bak|-bak)\d*'|[^\s;&|]*(?:\.backup|-backup|\.bak|-bak)\d*)(?:\s|$)/i.test(
      value,
    )
  ) {
    return true
  }
  return /(?:^|[^>])>\s*(?:"[^"]*(?:\.backup|-backup|\.bak|-bak)\d*"|'[^']*(?:\.backup|-backup|\.bak|-bak)\d*'|[^\s;&|]*(?:\.backup|-backup|\.bak|-bak)\d*)(?:\s|$)/i.test(
    value,
  )
}

function filesystemEntryKind(info: Awaited<ReturnType<typeof lstat>>) {
  if (info.isFile()) return "file"
  if (info.isDirectory()) return "directory"
  if (info.isSymbolicLink()) return "symlink"
  return "other"
}

async function inspectBackupDeletionTarget(
  candidate: string,
  input: ClassifyShellCommandInput,
): Promise<{ allowed: boolean; reason: string }> {
  const literal = literalPathToken(candidate)
  if (!literal) return { allowed: false, reason: "Backup deletion target is not a literal path" }
  const identity = backupPathIdentity(literal)
  if (!identity) return { allowed: false, reason: "Deletion target is not an exact backup suffix" }
  if (isCriticalBackupTarget(literal)) {
    return { allowed: false, reason: "Critical credential backups cannot be deleted" }
  }

  const expanded = expandHome(literal)
  const absolute = path.isAbsolute(expanded) ? path.normalize(expanded) : path.resolve(input.cwd, expanded)
  if (!isWithin(input.worktree, absolute)) {
    return { allowed: false, reason: "Backup deletion target is outside the worktree" }
  }

  const parent = path.dirname(absolute)
  let canonicalWorktree: string
  let canonicalParent: string
  let entries: Dirent[]
  try {
    canonicalWorktree = await realpath(input.worktree)
    canonicalParent = await realpath(parent)
    entries = await readdir(canonicalParent, { withFileTypes: true })
  } catch {
    return { allowed: false, reason: "Backup directory metadata is unavailable" }
  }
  if (!isWithin(canonicalWorktree, canonicalParent)) {
    return { allowed: false, reason: "Backup deletion target resolves outside the worktree" }
  }

  const exactBackup = entries.find((entry) => entry.name === identity.backupName)
  const exactOriginal = entries.find((entry) => entry.name === identity.originalName)
  if (!exactBackup) return { allowed: false, reason: "Backup target does not exist with an exact name" }
  if (!exactOriginal) return { allowed: false, reason: "Backup has no exact same-directory original" }

  let backupInfo: Awaited<ReturnType<typeof lstat>>
  let originalInfo: Awaited<ReturnType<typeof lstat>>
  try {
    backupInfo = await lstat(path.join(canonicalParent, identity.backupName))
    originalInfo = await lstat(path.join(canonicalParent, identity.originalName))
  } catch {
    return { allowed: false, reason: "Backup or original metadata is unavailable" }
  }
  if (filesystemEntryKind(backupInfo) !== filesystemEntryKind(originalInfo)) {
    return { allowed: false, reason: "Backup and original filesystem types do not match" }
  }

  const createdAt = backupInfo.birthtimeMs
  if (!Number.isFinite(createdAt) || createdAt <= 0) {
    return { allowed: false, reason: "Backup creation time is unavailable" }
  }
  const ageMs = (input.nowMs ?? Date.now()) - createdAt
  if (ageMs <= MIN_BACKUP_AGE_MS) {
    return { allowed: false, reason: "Backup is not older than two minutes" }
  }
  return { allowed: true, reason: "Backup has an exact original and is older than two minutes" }
}

async function classifyBackupPolicy(
  source: string,
  input: ClassifyShellCommandInput,
): Promise<StaticSecurityDecision | undefined> {
  const wrappedPowerShell = unwrapPowerShellCommand(source)
  const payload = wrappedPowerShell ?? source
  const payloadShell = wrappedPowerShell ? "powershell" : input.shell
  const segments = splitSimpleSegments(payload, payloadShell)
  if (!segments?.length) return undefined

  for (const segment of segments) {
    const move = parseMoveInvocation(segment)
    const moveTarget = move && literalPathToken(move.target)
    const command = commandLeaf(simpleInvocationTokens(segment)[0] ?? "")
    const unixRenameToBackup = command === "rename" && BACKUP_SUFFIX_REFERENCE.test(segment)
    if ((moveTarget && backupPathIdentity(moveTarget)) || unixRenameToBackup) {
      return {
        verdict: "DENY",
        rules: ["filesystem.backup-move"],
        reason: "Moving or renaming data into a backup name is forbidden",
        fingerprints: [],
      }
    }
    const copy = parseCopyInvocation(segment)
    const copySource = copy && literalPathToken(copy.source)
    const copyTarget = copy && literalPathToken(copy.target)
    if (
      copyTarget &&
      backupPathIdentity(copyTarget) &&
      (isCriticalBackupTarget(copyTarget) || Boolean(copySource && isCriticalOriginalPath(copySource)))
    ) {
      return {
        verdict: "DENY",
        rules: ["filesystem.critical-backup"],
        reason: "Critical credential files cannot use the backup exception",
        fingerprints: [],
      }
    }
    if (hasExplicitNonCopyBackupCreation(segment)) {
      return {
        verdict: "DENY",
        rules: ["filesystem.backup-noncopy"],
        reason: "Backup names may only be created by copying",
        fingerprints: [],
      }
    }
  }

  if (segments.length !== 1) {
    if (segments.some((segment) => parseDeleteInvocation(segment) && BACKUP_SUFFIX_REFERENCE.test(segment))) {
      return {
        verdict: "DENY",
        rules: ["filesystem.backup-delete-unverified"],
        reason: "Backup deletion must be a standalone verified operation",
        fingerprints: [],
      }
    }
    return undefined
  }

  const segment = segments[0]
  const copy = parseCopyInvocation(segment)
  const copyTarget = copy && literalPathToken(copy.target)
  if (copyTarget && backupPathIdentity(copyTarget)) {
    const copySource = copy && literalPathToken(copy.source)
    const ctx: PathContext = { cwd: input.cwd, worktree: input.worktree, strictness: input.strictness ?? "LOOSE" }
    const targetResolved = resolveLexical(copyTarget, input.cwd, expandHome("~"))
    const absolute = targetResolved.absolute
    const inWorktree = absolute !== undefined && isWithinLexical(input.worktree, absolute)
    const lower = absolute?.toLowerCase() ?? ""
    const inTemp = lower === "/tmp" || lower.startsWith("/tmp/") || lower === "/var/tmp" || lower.startsWith("/var/tmp/")
    if (!inWorktree && !inTemp) return undefined
    if (!checkPathSensitivity(copyTarget, ctx).parseable || checkPathSensitivity(copyTarget, ctx).sensitive) {
      return undefined
    }
    if (copySource && checkPathSensitivity(copySource, ctx).sensitive) return undefined
    return {
      verdict: "ALLOW",
      rules: ["filesystem.backup-copy"],
      reason: "Creates a non-critical backup by copying",
      fingerprints: [],
    }
  }

  const deletion = parseDeleteInvocation(segment)
  if (!deletion) return undefined
  const backupTargets = deletion.targets.filter((target) => {
    const literal = literalPathToken(target)
    return Boolean(literal && backupPathIdentity(literal))
  })
  if (backupTargets.length === 0) {
    if (!deletion.parseable && BACKUP_SUFFIX_REFERENCE.test(segment)) {
      return {
        verdict: "DENY",
        rules: ["filesystem.backup-delete-unverified"],
        reason: "Backup deletion could not be verified exactly",
        fingerprints: [],
      }
    }
    return undefined
  }
  if (!deletion.parseable || backupTargets.length !== deletion.targets.length) {
    return {
      verdict: "DENY",
      rules: ["filesystem.backup-delete-unverified"],
      reason: "Backup deletion contains unverified or non-backup targets",
      fingerprints: [],
    }
  }

  for (const target of backupTargets) {
    const inspected = await inspectBackupDeletionTarget(target, input)
    if (!inspected.allowed) {
      return {
        verdict: "DENY",
        rules: ["filesystem.backup-delete"],
        reason: inspected.reason,
        fingerprints: [],
      }
    }
  }
  if (input.strictness === "HARD") {
    return {
      verdict: "DENY",
      rules: ["hard.backup-delete"],
      reason: `Permanent deletion of backup targets is forbidden. ${PERMANENT_DELETE_GUIDANCE}`,
      fingerprints: [],
    }
  }
  return {
    verdict: "ALLOW",
    rules: ["filesystem.backup-delete"],
    reason: "Every backup has an exact original and is older than two minutes",
    fingerprints: [],
  }
}

function decodePowerShellBase64(value: string) {
  try {
    const bytes = Buffer.from(value, "base64")
    if (!bytes.length) return []
    const candidates = [bytes.toString("utf8"), bytes.toString("utf16le")]
    return candidates
      .map((item) => item.replace(/\0/g, "").trim())
      .filter((item) => item.length > 0 && /[\p{L}\p{N}\s"'`$;|&()./\\-]/u.test(item))
  } catch {
    return []
  }
}

function extractDecodedPayloads(script: string) {
  const decoded: string[] = []
  const encodedPatterns = [
    /(?:-encodedcommand|-enc)\s+["']?([A-Za-z0-9+/]{12,}={0,2})["']?/gi,
    /\b(?:echo|printf)\s+["']?([A-Za-z0-9+/]{16,}={0,2})["']?\s*\|\s*base64\s+(?:-d|--decode)/gi,
  ]

  for (const pattern of encodedPatterns) {
    for (const match of script.matchAll(pattern)) {
      for (const candidate of decodePowerShellBase64(match[1] ?? "")) {
        if (!decoded.includes(candidate)) decoded.push(candidate)
        if (decoded.length >= MAX_DECODED_PAYLOADS) return decoded
      }
    }
  }
  return decoded
}

function extractQuotedWrappers(script: string) {
  const payloads: string[] = []
  const patterns = [
    /\b(?:bash|sh|zsh|python(?:3)?(?:\.exe)?|py(?:\.exe)?|node)\b[^\n]{0,80}\s-(?:c|e)\s+(["'])([\s\S]{1,32000}?)\1/gi,
    /\b(?:cmd(?:\.exe)?)\b[^\n]{0,80}\s\/c\s+(["'])([\s\S]{1,32000}?)\1/gi,
    /\b(?:powershell|pwsh)\b[^\n]{0,120}\s-(?:command|c)\s+(["'])([\s\S]{1,32000}?)\1/gi,
  ]
  for (const pattern of patterns) {
    for (const match of script.matchAll(pattern)) {
      const payload = match[2]?.trim()
      if (payload && !payloads.includes(payload)) payloads.push(payload)
      if (payloads.length >= MAX_DECODED_PAYLOADS) return payloads
    }
  }
  return payloads
}

function stripLeadingDirectoryChanges(script: string) {
  let value = script.trim()
  for (let index = 0; index < 4; index += 1) {
    const match = value.match(/^(?:cd|pushd|set-location)\s+(?:"[^"]+"|'[^']+'|[^;&|]+)\s*&&\s*([\s\S]+)$/i)
    if (!match) break
    value = match[1].trim()
  }
  return value
}

const DELETE_COMMANDS = new Set([
  "rm",
  "remove-item",
  "del",
  "erase",
  "unlink",
  "rmdir",
  "rd",
  "ri",
])

function isFullyQuoted(value: string) {
  const trimmed = value.trim()
  if (trimmed.length < 2) return false
  const first = trimmed[0]
  const last = trimmed[trimmed.length - 1]
  return (first === '"' || first === "'") && first === last
}

function isDynamicCdTarget(rawTarget: string, target: string) {
  if (target === "-" || /^~[-+]/.test(target)) return true
  if (/[\n;&|]/.test(rawTarget)) return true
  if (/\$\{|`|\$\(|\$[A-Za-z_]|%/.test(target)) return true
  if (!isFullyQuoted(rawTarget) && /\s/.test(target)) return true
  return false
}

function parseCdSegment(text: string): { dir: string | undefined } | undefined {
  const trimmed = text.trim()
  if (/^\(?\s*(?:cd|pushd|popd|set-location)\s*\)?$/i.test(trimmed)) {
    return { dir: undefined }
  }
  if (/^\(?\s*(?:popd\b|cd\.\.\s*\)?$)/i.test(trimmed)) {
    return { dir: undefined }
  }
  const match = trimmed.match(/^\(?\s*(?:cd|pushd|set-location)\s+(.+)$/i)
  if (!match) return undefined
  const rawTarget = match[1].trim()
  const target = stripMatchingQuotes(rawTarget)
  return { dir: isDynamicCdTarget(rawTarget, target) ? undefined : target }
}

function resolveCdBase(dir: string | undefined, base: string | undefined) {
  if (dir === undefined) return undefined
  const expanded = expandHome(dir)
  if (!expanded || /[*?[\]`$%{}]/.test(expanded) || /[<>|]/.test(expanded)) return undefined
  return path.isAbsolute(expanded) ? path.normalize(expanded) : base ? path.resolve(base, expanded) : undefined
}

function isWorktreeDisposableTarget(target: string, cwd: string, worktree: string): boolean {
  const literal = literalPathToken(target)
  if (!literal) return false
  const resolved = resolveLexical(literal, cwd, expandHome("~"))
  return resolved.absolute !== undefined && isWithinLexical(worktree, resolved.absolute)
}

function isTempDisposableTarget(target: string, cwd: string): boolean {
  const literal = literalPathToken(target)
  if (!literal) return false
  const resolved = resolveLexical(literal, cwd, expandHome("~"))
  if (!resolved.absolute) return false
  const absolute = resolved.absolute.toLowerCase()
  if (absolute === "/tmp" || absolute.startsWith("/tmp/")) return true
  if (absolute === "/var/tmp" || absolute.startsWith("/var/tmp/")) return true
  const downloads = expandHome("~/Downloads").toLowerCase()
  return absolute.startsWith(`${downloads}/`)
}

function isTempFindRoot(root: string, cwd: string): boolean {
  const literal = literalPathToken(root)
  if (!literal) return false
  const resolved = resolveLexical(literal, cwd, expandHome("~"))
  if (!resolved.absolute) return false
  const absolute = resolved.absolute.toLowerCase()
  return absolute === "/tmp" || absolute.startsWith("/tmp/")
}

async function isExplicitDisposableCleanup(script: string, cwd: string, worktree: string): Promise<boolean> {
  const value = stripLeadingDirectoryChanges(script).replace(/\s+/g, " ").trim()

  const findTmp = value.match(/^find\s+(\S+)\b[^;&|]*\s-mtime\s+\+\d+\b[^;&|]*\s-delete$/i)
  if (findTmp) return isTempFindRoot(findTmp[1], cwd)

  // A trailing reinstall keeps the cleanup shape (`rm -rf node_modules && npm i`).
  const withoutInstall = value.replace(/\s*&&\s*(?:npm|pnpm|yarn|bun)\s+(?:install|i)$/i, "")

  const rmForceFile = withoutInstall.match(/^rm\s+-f\s+([^;&|]+)$/i)
  if (rmForceFile) {
    const target = rmForceFile[1].trim()
    if (/^\/tmp\//.test(target) || /^~[\\/]Downloads[\\/][^\s]*\.tmp$/.test(target)) {
      return isTempDisposableTarget(target, cwd)
    }
    return false
  }

  const deletion = parseRecursiveForceDeletion(withoutInstall)
  if (!deletion) return false
  for (const t of deletion.targets) {
    if (!(await isDisposableCleanupTarget(t, cwd, worktree))) return false
  }
  return true
}

function shellEscapeCharacter(shell: string) {
  const name = path.basename(shell).replace(/\.(?:exe|cmd|bat)$/i, "").toLowerCase()
  if (name === "pwsh" || name === "powershell") return "`"
  if (name === "cmd") return "^"
  return "\\"
}

function shellSupportsSingleQuotes(shell: string) {
  return path.basename(shell).replace(/\.(?:exe|cmd|bat)$/i, "").toLowerCase() !== "cmd"
}

function strictTimeoutRemainder(tokens: string[]): string | undefined {
  let i = 1
  for (;;) {
    if (i >= tokens.length) return undefined
    const lower = tokens[i].toLowerCase()
    if (lower === "--") {
      i += 1
      break
    }
    if (!lower.startsWith("-")) break
    if (lower === "-k" || lower === "--kill-after" || lower === "-s" || lower === "--signal") {
      i += 2
      continue
    }
    if (lower === "--verbose" || lower === "--foreground" || lower === "--preserve-status") {
      i += 1
      continue
    }
    return undefined
  }
  if (i >= tokens.length || !/^\d+(\.\d+)?[smhd]?$/.test(tokens[i] ?? "")) return undefined
  i += 1
  if (i >= tokens.length) return undefined
  return tokens.slice(i).join(" ")
}

/**
 * Strict wrapper stripping (mirrors Claude Code `stripWrappersFromArgv`).
 * Unknown or malformed flags ⇒ do NOT strip ⇒ the segment falls through to ASK.
 * `env -S`, `watch`, and flag-injection forms are deliberately not stripped.
 */
function stripWrapperPrefix(segment: string): string | undefined {
  const original = segment
  const tokens = simpleInvocationTokens(segment.trim())
  if (tokens.length === 0) return segment
  const leaf = commandLeaf(tokens[0] ?? "")
  if (leaf === "timeout") return strictTimeoutRemainder(tokens)
  if (leaf === "time" || leaf === "nohup" || leaf === "setsid") {
    if (tokens.length >= 2 && !(tokens[1] ?? "").startsWith("-")) return tokens.slice(1).join(" ")
    return original
  }
  if (leaf === "nice") {
    let i = 1
    if (i < tokens.length && tokens[i] === "--") return tokens.slice(i + 1).join(" ")
    if (i < tokens.length && /^-\d+$/.test(tokens[i] ?? "")) return tokens.slice(i + 1).join(" ")
    if (i < tokens.length && (tokens[i] === "-n" || tokens[i] === "--adjustment")) {
      if (i + 1 < tokens.length && /^-?\d+$/.test(tokens[i + 1] ?? "")) return tokens.slice(i + 2).join(" ")
      return original
    }
    if (i < tokens.length && !(tokens[i] ?? "").startsWith("-")) return tokens.slice(1).join(" ")
    return original
  }
  if (leaf === "ionice") {
    let i = 1
    while (i < tokens.length && (tokens[i] ?? "").startsWith("-") && tokens[i] !== "--") {
      const t = tokens[i] ?? ""
      if (t === "-t") {
        i += 1
      } else if (t === "-c" || t === "-n" || t === "-p") {
        if (i + 1 >= tokens.length) return original
        i += 2
      } else {
        return original
      }
    }
    if (i >= tokens.length || (tokens[i] ?? "").startsWith("-") || (tokens[i] ?? "") === "--") return original
    return tokens.slice(i).join(" ")
  }
  if (leaf === "stdbuf") {
    let i = 1
    while (i < tokens.length && ((tokens[i] ?? "").startsWith("-") || tokens[i] === "--")) {
      const t = tokens[i] ?? ""
      if (t === "--") {
        i += 1
        break
      }
      if (/^-[ioe]$/.test(t)) {
        if (i + 1 >= tokens.length) return original
        i += 2
        continue
      }
      if (/^-[ioe]\S+$/.test(t) || t === "-L" || t === "--line-buffered") {
        i += 1
        continue
      }
      return original
    }
    if (i >= tokens.length) return original
    return tokens.slice(i).join(" ")
  }
  if (leaf === "env") {
    let i = 1
    let sawCommand = false
    while (i < tokens.length) {
      const t = tokens[i] ?? ""
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
        i += 1
        continue
      }
      if (t === "-i" || t === "--ignore-environment" || t === "-0" || t === "--null") {
        i += 1
        continue
      }
      if (t === "-u" || t === "--unset" || t === "--unset-environment") {
        if (i + 1 >= tokens.length) return original
        i += 2
        continue
      }
      if (t === "-v" || t === "--debug") {
        i += 1
        continue
      }
      if (t === "-S" || t === "--split-string" || t === "-C" || t === "-P" || t === "--argv0") {
        return original
      }
      sawCommand = true
      break
    }
    if (!sawCommand || i >= tokens.length) return original
    return tokens.slice(i).join(" ")
  }
  return segment
}

function stripHarmlessPrefixes(segment: string): string {
  let result = segment.trim()
  for (let depth = 0; depth < 3; depth += 1) {
    const subshell = result.match(/^\(([\s\S]+)\)$/)
    if (subshell) {
      result = subshell[1].trim()
      continue
    }
    const wrapperStripped = stripWrapperPrefix(result)
    if (wrapperStripped && wrapperStripped !== result) {
      result = wrapperStripped
      continue
    }
    break
  }
  return result
}

function maskHeredocBody(text: string): string {
  const match = text.match(/<<-?\s*(?:'([^']+)'|"([^"]+)"|(\w+))/)
  if (!match) return text
  const delimiter = match[1] ?? match[2] ?? match[3]
  if (!delimiter) return text
  const bodyStart = (match.index ?? 0) + match[0].length
  const lineEnd = text.indexOf("\n", bodyStart)
  if (lineEnd < 0) return text
  const escapedDelim = delimiter.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  const closingRegex = new RegExp(`^\\s*${escapedDelim}\\s*$`, "m")
  const bodyContent = text.slice(lineEnd + 1)
  const closingMatch = bodyContent.match(closingRegex)
  if (!closingMatch) return text
  const bodyEnd = lineEnd + 1 + (closingMatch.index ?? 0) + closingMatch[0].length
  return text.slice(0, lineEnd + 1) + "[heredoc-body]" + text.slice(bodyEnd)
}

type SegmentConnector = "&&" | "||" | ";" | "newline" | "|" | "&"
type CommandSegment = { text: string; incoming?: SegmentConnector }

/** Non-backtracking test for `(?:^|\s)\d*>\s*$` (an fd-redirect prefix such as
 * `2>` immediately before a `>&N` merge). */
function endsWithFdRedirectPrefix(text: string): boolean {
  let i = text.length
  while (i > 0 && /\s/.test(text[i - 1])) i -= 1
  if (i === 0 || text[i - 1] !== ">") return false
  i -= 1
  while (i > 0 && /\d/.test(text[i - 1])) i -= 1
  return i === 0 || /\s/.test(text[i - 1])
}

function splitCommandSegments(script: string, shell: string) {
  const value = script.trim()
  const escapeCharacter = shellEscapeCharacter(shell)
  const supportsSingleQuotes = shellSupportsSingleQuotes(shell)
  const segments: CommandSegment[] = []
  let current = ""
  let quote: "'" | '"' | undefined
  let escaped = false
  let heredocDelim: string | undefined
  let incoming: SegmentConnector | undefined

  const push = (next?: SegmentConnector) => {
    const segment = current.trim()
    if (segment) segments.push({ text: segment, incoming })
    current = ""
    incoming = next
  }

  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]

    if (heredocDelim !== undefined) {
      current += character
      if (character === "\n") {
        let lineStart = current.length - 1
        while (lineStart > 0 && current[lineStart - 1] !== "\n") lineStart--
        const line = current.slice(lineStart, current.length - 1).trim()
        if (line === heredocDelim) heredocDelim = undefined
      }
      continue
    }

    if (escaped) {
      current += character
      escaped = false
      continue
    }
    if (character === escapeCharacter && quote !== "'") {
      current += character
      escaped = true
      continue
    }
    if (quote) {
      current += character
      if (character === quote) quote = undefined
      continue
    }
    if (character === '"' || (character === "'" && supportsSingleQuotes)) {
      quote = character
      current += character
      continue
    }
    if (character === "`" && escapeCharacter !== "`") return undefined

    if (character === "<" && value[index + 1] === "<") {
      let lookAhead = index + 2
      if (value[lookAhead] === "-") lookAhead += 1
      while (lookAhead < value.length && (value[lookAhead] === " " || value[lookAhead] === "\t")) lookAhead += 1
      let delim = ""
      let delimEnd = lookAhead
      if (value[lookAhead] === "'" || value[lookAhead] === '"') {
        const dq = value[lookAhead]
        delimEnd = lookAhead + 1
        while (delimEnd < value.length && value[delimEnd] !== dq) {
          delim += value[delimEnd]
          delimEnd += 1
        }
        delimEnd += 1
      } else {
        while (delimEnd < value.length && /\w/.test(value[delimEnd])) {
          delim += value[delimEnd]
          delimEnd += 1
        }
      }
      if (delim) {
        current += value.slice(index, delimEnd)
        index = delimEnd - 1
        heredocDelim = delim
        continue
      }
    }

    if (character === ";" || character === "\n" || character === "\r") {
      if (character === "\r" && value[index + 1] === "\n") index += 1
      push(character === ";" ? ";" : "newline")
      continue
    }
    if ((character === "&" || character === "|") && value[index + 1] === character) {
      index += 1
      push(character === "&" ? "&&" : "||")
      continue
    }
    if (character === "&" && endsWithFdRedirectPrefix(current) && /^\d$/.test(value[index + 1] ?? "")) {
      current += character
      continue
    }
    if (character === "&" && value[index + 1] === ">") {
      current += character
      continue
    }
    if (character === "|" || character === "&") {
      push(character as "|" | "&")
      continue
    }
    current += character
  }

  if (quote || escaped) return undefined
  if (heredocDelim !== undefined) {
    const lastLine = current.split("\n").at(-1)?.trim()
    if (lastLine !== heredocDelim) return undefined
  }
  push()
  return segments
}

export function splitSimpleSegments(script: string, shell: string) {
  return splitCommandSegments(script, shell)?.map((segment) => segment.text)
}

function segmentBase(segment: CommandSegment, current: string | undefined, original: string) {
  return segment.incoming === "&&" ? current : original
}

function normalizeCommandInSegment(segment: string): string {
  const callMatch = segment.match(/^&\s+(?:"([^"]+)"|'([^']+)'|(\S+))(?:\s+([\s\S]*))?$/)
  if (callMatch) {
    const exePath = callMatch[1] ?? callMatch[2] ?? callMatch[3] ?? ""
    const leaf = commandLeaf(exePath)
    const rest = callMatch[4] ?? ""
    return rest ? `${leaf} ${rest}` : leaf
  }
  const firstTokenMatch = segment.match(/^(\S+)/)
  if (firstTokenMatch) {
    const firstToken = firstTokenMatch[1]
    const leaf = commandLeaf(firstToken)
    return leaf + segment.slice(firstToken.length)
  }
  return segment
}

function isKnownSafeSegment(segment: string) {
  const value = normalizeCommandInSegment(
    stripTrailingFdMerges(segment)
      .replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*/, "")
      .trim(),
  )
  if (!value) return true
  const harmlessValue = value
    .replace(/>\s*\/dev\/(?:null|stdout|stderr)\b/gi, "")
    .replace(/>\s*\$null\b/gi, "")
    .replace(/<[ \t]*\/?dev\/(?:null|stdin)\b/gi, "")
    .replace(/(?:^|[\s;&|])<<</g, "")
    .replace(/(?:^|[\s;&|])\d*<[ \t]+[^\s<;&|()]+/g, "")
  if (/[<>](?![=])/.test(harmlessValue)) return false
  if (/^(?:true|false|:)\b/i.test(value)) return true

  if (
    /^(?:echo|printf|Write-Output|ls|dir|pwd|whoami|date|uname|hostname|df|du|free|ps|stat|file|head|tail|wc|sort|uniq|which|where|whereis|Get-ChildItem|Get-Location|Get-Content|Select-String|Test-Path|Resolve-Path)\b/i.test(
      value,
    )
  ) {
    return true
  }
  if (/^(?:tasklist|Get-Process|netstat|ss)\b/i.test(value)) return true
  if (/^docker\s+(?:ps|images)\b/i.test(value)) return true
  if (/^(?:Get-Command|Select-Object|Write-Host|findstr|iconv)\b/i.test(value)) return true
  if (/^base64\b/i.test(value) && !/\b(?:bash|sh|zsh|python|node|powershell|pwsh|eval)\b/i.test(value)) return true
  if (/^schtasks\b/i.test(value)) {
    return /\/Query\b/i.test(value) && !/\/(?:Create|Delete|Change|Run|End)\b/i.test(value)
  }
  if (/^wsl(?:\.exe)?\b/i.test(value)) {
    return /\s--(?:help|status|list|verbose)\b/i.test(value) && !/\s--(?:shutdown|terminate)\b/i.test(value)
  }
  if (/^(?:jq|diff)\b/i.test(value)) return true
  if (/^set\b/i.test(value)) {
    const tokens = value.split(/\s+/).slice(1)
    const safeOptions = new Set([
      "pipefail", "errexit", "nounset", "xtrace", "verbose",
      "noclobber", "ignoreeof", "allexport", "nolog", "privileged",
    ])
    if (tokens.every((t) => /^[-+][a-zA-Z]+$/.test(t) || safeOptions.has(t.toLowerCase()) || t === "--" || t === "-")) {
      return true
    }
  }
  if (/^(?:cat|type|more|less)\b/i.test(value)) {
    return !hasSensitiveCredentialReference(value) && !/\b(?:credential|token|secret|password|private)\b/i.test(value)
  }
  if (/^(?:rg|grep|Select-String)\b/i.test(value)) return true
  if (/^find\b/i.test(value)) return !/(?:^|\s)-(?:delete|exec|execdir|ok|okdir)(?:\s|$)/i.test(value)
  if (/^git\s+(?:status|diff|log|show|rev-parse|ls-files|grep|remote\s+-v|add|commit)\b/i.test(value)) return true
  if (/^git\s+(?:fetch|clone|checkout\s+-b|stash\s+(?:list|push)|branch\s+(?!-[dDm]\b)\S+|tag\s+(?!-[dD]\b)\S+|pull|switch|merge)\b/i.test(value)) return true
  if (
    /^git\s+push\b(?![\s\S]*(?:\s--force(?:-with-lease)?\b|\s-[a-zA-Z]*f[a-zA-Z]*\b|\s--(?:delete|mirror)\b|\s\+[^\s:]|\s:(?:refs\/)?[\w./-]+))/i.test(
      value,
    )
  ) {
    return true
  }
  if (/^(?:mkdir|New-Item\s+[^\n]*-ItemType\s+Directory)\b/i.test(value)) return true
  if (/^(?:tar\s+-[a-z]*c[a-z]*f|zip\s+-r)\b/i.test(value)) return !/--remove-files\b/i.test(value)
  if (/^(?:cp|copy|Copy-Item)\b/i.test(value) && /[\s\S]*\s-[A-Za-z]/.test(value)) return false
  if (
    /^(?:(?:python(?:3)?(?:\.exe)?|py(?:\.exe)?)\s+-m\s+pytest|pytest|bun\s+test|cargo\s+(?:test|check|fmt)|go\s+test|black|isort|prettier|eslint|tsc)\b/i.test(
      value,
    )
  ) {
    return true
  }
  if (
    /^(?:node\s+--test|npx\s+(?:--yes\s+)?(?:bun\s+test|vitest|jest|mocha|ava|tap|playwright\s+test|cypress\s+run)|vitest|jest|mocha|ava|tap|dotnet\s+test|mvnw?\s+test|gradlew?\s+test|ctest|make\s+test)\b/i.test(
      value,
    )
  ) {
    return true
  }
  if (/^(?:npm|pnpm|yarn|bun)\s+(?:test|run\s+(?:test|lint|format|check|build))\b/i.test(value)) return true
  if (/^(?:npm|pnpm|yarn|bun)\s+(?:install|i|add|ci)\b/i.test(value)) return true
  if (/^(?:pip(?:3)?|pipx|uv)\s+(?:install|add|list|show|freeze|check)\b/i.test(value)) return true
  if (/^cargo\s+(?:add|fetch|update)\b/i.test(value)) return true
  if (/^go\s+(?:get|mod\s+download)\b/i.test(value)) return true
  if (/^dotnet\s+(?:restore|build)\b/i.test(value)) return true
  if (/^(?:cargo\s+build|go\s+build|cmake\s+--build|ninja|vite\s+build|next\s+build|nuxt\s+build|svelte-kit\s+build|webpack|rollup|esbuild|tsc)\b/i.test(value)) return true
  if (/^make\b/i.test(value) && !/\bclean\b/i.test(value)) return true
  if (/^(?:mvnw?|maven|gradlew?)\s+(?:build|package|compile|install|verify|assemble|bundle|jar|compileJava|deploy)\b/i.test(value) && !/\bclean\b/i.test(value)) return true

  // ===== M3 (P2) §4.9: false-positive reduction with P/E front-end =====
  // Text processing (read-only); `sed -i` write targets are validated by the path layer.
  if (/^(?:cut|column|tr|tac|nl|pr|fmt|fold|paste|join|comm|expand|shuf|strings|xxd|od|hexdump)\b/i.test(value)) return true
  // awk is only acceptable as a pure text filter; `system(` / `| getline` / `getline <`
  // primitives can execute commands or read files, so they force a review.
  if (/^awk\b(?![\s\S]*(?:system\s*\(|\|\s*getline|getline\s*<\s*))/i.test(value)) return true
  if (/^(?:md5sum|sha1sum|sha224sum|sha256sum|sha384sum|sha512sum|basename|dirname|realpath|readlink|seq|expr)\b/i.test(value)) return true
  if (/^yq\b(?![\s\S]*-i\b)/i.test(value)) return true
  if (/^sed\b/i.test(value)) return true

  // Read-only system inspection
  if (/^(?:id|uptime|cal|type|lsattr|getfattr|lscpu|lsmod|lsusb|lspci|locale|getent|atq)\b/i.test(value)) return true
  if (/^(?:jobs|wait|bg|fg)\b/i.test(value)) return true
  if (/^history\s*(?:\d+)?\s*$/i.test(value)) return true
  if (/^alias\s*$/i.test(value)) return true
  if (/^lsof\b(?![\s\S]*\s-k\b)/i.test(value)) return true
  if (/^timedatectl\s+status\b/i.test(value)) return true
  if (/^ip\s+(?:addr|address|link|route)\b[\s\S]*\b(?:show|list)\b/i.test(value)) return true
  if (/^ip\s+(?:addr|address|link|route)\s*$/i.test(value)) return true
  if (/^ifconfig\b(?![\s\S]*(?:\s+up\b|\s+down\b|\s+add\b|\s+del\b|\s+remove\b))/i.test(value)) return true
  if (/^mount\s*(?:-l|l|--list)?\s*$/i.test(value)) return true
  if (/^crontab\s+-l\b/i.test(value)) return true
  if (/^fdisk\s+-[lL]\b/i.test(value)) return true
  if (/^parted\s+(?:--list|-l)\b/i.test(value)) return true
  if (/^parted\b(?![\s\S]*(?:mklabel|mkpart|mkpartfs|resizepart|mkswap|\srm\s|disk_set|disk_toggle))(?:-s\s+)?(?:\/dev\/\S+|-\S+)\s+print\b/i.test(value)) return true
  if (/^lsblk\b/i.test(value)) return true
  if (/^systemctl\s+(?:status|is-active|is-enabled|is-failed|list-units|list-unit-files|show|daemon-reload|cat|help)\b/i.test(value)) return true
  if (/^journalctl\b(?![\s\S]*--vacuum)/i.test(value)) return true
  if (/^ufw\s+status\b/i.test(value)) return true
  if (/^docker\s+(?:logs|inspect|top|events)\b/i.test(value)) return true
  if (/^docker\s+stats\s+--no-stream\b/i.test(value)) return true
  if (/^kubectl\s+(?:logs|top)\b/i.test(value)) return true
  // `kubectl get|describe` is read-only EXCEPT secret/secrets (credential material)
  if (/^kubectl\s+(?:get|describe)\b(?![\s\S]*\b(?:secret|secrets)\b)/i.test(value)) return true
  if (/^(?:test\b|\[)/.test(value)) return true

  // Package managers (declarative read / verify / safe uninstall / known run scripts)
  if (/^npm\s+run\s+(?:dev|start|serve)\b/i.test(value)) return true
  if (/^npm\s+run-script\s+(?:test|lint|format|check|build|dev|start|serve)\b/i.test(value)) return true
  if (/^npm\s+(?:start|list|outdated|view|audit)\b/i.test(value)) return true
  if (/^npm\s+cache\s+verify\b/i.test(value)) return true
  if (/^npm\s+(?:uninstall|remove)\b/i.test(value)) return true
  if (/^(?:pip(?:3)?|pipx|uv)\s+uninstall\b/i.test(value)) return true
  if (/^(?:yarn|pnpm)\s+remove\b/i.test(value)) return true
  if (/^cargo\s+(?:clippy|tree|metadata|uninstall)\b/i.test(value)) return true
  if (/^go\s+(?:fmt|vet|list)\b/i.test(value)) return true
  if (/^npx\s+--no-install\s+(?:eslint|tsc|prettier|vitest|jest|mocha|bun\s+test)\b/i.test(value)) return true

  // git read-only / safe-mutating surface
  if (/^git\s+blame\b/i.test(value)) return true
  if (/^git\s+describe\b/i.test(value)) return true
  if (/^git\s+config\s+(?:--list|-l)\b/i.test(value)) return true
  if (/^git\s+stash\s+(?:push|pop|apply)\b/i.test(value)) return true
  if (/^git\s+tag\s*$/i.test(value)) return true
  if (/^git\s+branch\s+-d\b/.test(value)) return true
  if (/^git\s+branch\s*$/i.test(value)) return true
  if (/^node\s+(?:--version|-v\b|--help)\b/i.test(value)) return true
  if (/^(?:yarn|pnpm|bun)\s+(?:dev|start|serve|build|lint|format|check)\b/i.test(value)) return true
  if (/^poetry\s+(?:add|install|lock|update|export)\b/i.test(value)) return true
  if (/^uv\s+sync\b/i.test(value)) return true
  if (/^terraform\s+(?:plan|validate|fmt|version)\b/i.test(value)) return true
  if (/^(?:nslookup|dig)\b/i.test(value)) return true

  // File operations (write targets validated by the path layer)
  if (/^touch\b/i.test(value)) return true
  if (/^(?:cp|mv)\b(?![\s\S]*\s-[A-Za-z])\b/i.test(value)) return true
  if (/^install\s+-m\s+\d+\b/i.test(value)) return true
  // `rmdir` is the empty-directory remover on POSIX but a Remove-Item alias on
  // PowerShell/cmd: `-r/-recurse/-rf/-fr` and `/s` turn it into a forced
  // recursive delete. Only the plain empty-directory form is provably safe;
  // recursive forms must fall through to the destructive-delete rules.
  if (
    /^rmdir\b/i.test(value) &&
    !/-(?:recurse|rf|fr|\br\b)(?:\s|$)/i.test(value) &&
    !/(?:^|\s)[/\\][\s]*[sS](?=\s|$)/.test(value)
  ) {
    return true
  }

  // Build cleanup (disposable artifacts)
  if (/^make\s+(?:clean|distclean|mrproper)\b|^make\s*$/i.test(value)) return true
  if (/^(?:mvnw?|maven)\s+clean\b/i.test(value)) return true
  if (/^(?:\.?\/)?gradlew\s+clean\b/i.test(value)) return true

  // Scripts / interpreters (mode-agnostic safe surfaces)
  if (/^(?:python(?:3)?(?:\.exe)?|py(?:\.exe)?)\s+-m\s+venv\b/i.test(value)) return true
  if (/^openssl\s+(?:genrsa|req|verify|x509|pkey|ecparam|genpkey|dhparam)\b/i.test(value)) return true
  if (/^gunzip\b|\bgzip\s+-d\b/i.test(value)) return true

  return false
}

function isKnownSafeCommand(script: string, shell: string) {
  if (/^git\s+add\b[^\n;&|]*&&\s*git\s+commit\b[^\n;&|]*$/i.test(stripLeadingDirectoryChanges(script))) return true
  const segments = splitSimpleSegments(script, shell)
  return Boolean(segments?.length && segments.every(isKnownSafeSegment))
}

function hasDynamicShellExpansion(text: string, shell: string) {
  if (/\$\(/.test(text)) return true
  return shellEscapeCharacter(shell) !== "`" && /`[^`\r\n]+`/.test(text)
}

function unwrapPowerShellCommand(script: string) {
  const value = stripLeadingDirectoryChanges(script)
  const invocation = value.match(/^(?:&\s*)?(?:powershell|pwsh)(?:\.exe)?\s+([\s\S]+)$/i)
  if (!invocation) return undefined

  const command = invocation[1].match(/^([\s\S]*?)-(?:command|c)\s+([\s\S]+)$/i)
  if (!command) return undefined

  const prefix = command[1].trim()
  const tokens = prefix.match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
  const switchesWithoutValues = new Set(["-noprofile", "-noninteractive", "-nologo", "-sta", "-mta"])
  const switchesWithValues = new Set(["-executionpolicy", "-ep", "-windowstyle"])

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index].toLowerCase()
    if (switchesWithoutValues.has(token)) continue
    if (switchesWithValues.has(token) && tokens[index + 1]) {
      index += 1
      continue
    }
    return undefined
  }

  const payload = stripMatchingQuotes(command[2].trim()).trim()
  return payload || undefined
}

function recycleCommandInvocation(segment: string) {
  const match = segment
    .trim()
    .match(/^(?:&\s+)?(?:"([^"]+)"|'([^']+)'|(\S+))(?:\s+([\s\S]*))?$/)
  if (!match) return undefined

  const rawExecutable = match[1] ?? match[2] ?? match[3] ?? ""
  const executable = rawExecutable
    .replaceAll("\\", "/")
    .split("/")
    .at(-1)
    ?.replace(/\.(?:exe|cmd|bat|ps1)$/i, "")
    .toLowerCase()
  if (!executable) return undefined
  return { executable, rawExecutable, args: (match[4] ?? "").trim() }
}

function hasPermanentTrashOperation(args: string) {
  return /(?:^|\s)(?:--?(?:empty|purge|delete)|\/(?:empty|purge)|empty|purge)(?:\s|$)/i.test(args)
}

function isPowerShellRecycleSetup(segment: string) {
  return /^add-type\s+-assemblyname\s+(?:"Microsoft\.VisualBasic"|'Microsoft\.VisualBasic'|Microsoft\.VisualBasic)\s*$/i.test(
    segment.trim(),
  )
}

function powerShellRecycleTarget(segment: string) {
  const value = segment.trim()
  const visualBasic = value.match(
    /^\[Microsoft\.VisualBasic\.FileIO\.FileSystem\]::Delete(?:File|Directory)\s*\(\s*(?:"[^"]*"|'[^']*'|\$[A-Za-z_][A-Za-z0-9_:]*)\s*,([\s\S]*)\)\s*$/i,
  )
  if (
    visualBasic &&
    /\bSendToRecycleBin\b/i.test(visualBasic[1]) &&
    /^[\s,'"\[\].:A-Za-z0-9_-]+$/.test(visualBasic[1])
  ) {
    return value.match(/Delete(?:File|Directory)\s*\(\s*("[^"]*"|'[^']*'|\$[A-Za-z_][A-Za-z0-9_:]*)/i)?.[1]
  }

  const shellTarget = value.match(
    /^\(\s*New-Object\s+-ComObject\s+Shell\.Application\s*\)\.Namespace\s*\(\s*(?:10|0xA)\s*\)\.MoveHere\s*\(\s*("[^"]*"|'[^']*'|\$[A-Za-z_][A-Za-z0-9_:]*)\s*(?:,\s*\d+\s*)?\)\s*$/i,
  )
  return shellTarget?.[1]
}

function recycleCliTargets(segment: string) {
  if (/[<>]/.test(segment) || /\$\(|`[^`\r\n]+`/.test(segment)) return false
  const invocation = recycleCommandInvocation(segment)
  if (!invocation) return false
  const { executable, rawExecutable, args } = invocation
  if (/[\\/]/.test(rawExecutable)) return undefined
  const tokens = simpleInvocationTokens(args)

  if (["trash", "recycle", "recycle-bin"].includes(executable)) {
    return hasPermanentTrashOperation(args) ? undefined : tokens.filter((token) => !token.startsWith("-"))
  }
  if (["trash-put", "gvfs-trash", "send2trash"].includes(executable)) {
    return tokens.filter((token) => !token.startsWith("-"))
  }
  if (executable === "gio" && /^trash\b/i.test(args) && !hasPermanentTrashOperation(args)) {
    return tokens.slice(1).filter((token) => !token.startsWith("-"))
  }
  if (/^kioclient(?:5|6)?$/.test(executable) && /^move\b[\s\S]+\strash:\/?\s*$/i.test(args)) {
    return tokens.length >= 3 ? [tokens[1]] : []
  }
  return undefined
}

function explicitRecycleBinOperation(script: string, shell: string) {
  const wrappedPowerShell = unwrapPowerShellCommand(script)
  const payload = wrappedPowerShell ?? script
  const payloadShell = wrappedPowerShell ? "powershell" : shell
  const segments = splitSimpleSegments(payload, payloadShell)
  if (!segments?.length) return undefined

  let recycleActions = 0
  const targets: string[] = []
  for (const segment of segments) {
    if (isPowerShellRecycleSetup(segment)) continue
    const powerShellTarget = powerShellRecycleTarget(segment)
    const cliTargets = recycleCliTargets(segment)
    if (powerShellTarget || cliTargets) {
      recycleActions += 1
      if (powerShellTarget) targets.push(powerShellTarget)
      if (cliTargets) targets.push(...cliTargets)
      continue
    }
    return undefined
  }
  return recycleActions > 0 && targets.length > 0 ? { targets } : undefined
}

function hasForbiddenRecycleDestruction(text: string) {
  if (/\bclear-recyclebin\b/i.test(text)) return true
  if (/\b(?:trash-empty|trash-rm)\b/i.test(text)) return true
  if (/\btrash\b[^\r\n;&|]*(?:--empty|--purge)\b/i.test(text)) return true
  if (/\bgio\s+trash\b[^\r\n;&|]*--empty\b/i.test(text)) return true
  return (
    hasDeletePrimitive(text) &&
    /(?:\$Recycle\.Bin(?:[\\/]|\b)|~[\\/]\.local[\\/]share[\\/]Trash[\\/]files(?:[\\/]|\b)|trash:\/\/)/i.test(text)
  )
}

function hasDataPathDestruction(text: string) {
  return (
    /(?:\b(?:shutil\.rmtree|os\.(?:remove|unlink))\b|\bfs(?:\.promises)?\.(?:rm|unlink)(?:Sync)?\s*\(|\brequire\s*\(\s*["'](?:node:)?fs["']\s*\)\.(?:rm|unlink)(?:Sync)?\s*\(|\.(?:rm|unlink)(?:Sync)?\s*\()/i.test(
      text,
    ) &&
    /(?:\/data\b|\/var\/data\b|\/project\b|\/production\b|\\data\\|\\project\\|\\production\\)/i.test(text)
  )
}

function hasCriticalDataDestruction(text: string) {
  if (!hasDeletePrimitive(text)) return false
  return (
    CRITICAL_DATA_EXTENSION.test(text) ||
    SENSITIVE_ENV_FILE.test(text) ||
    /(?:^|[\\/\s"'])id_(?:rsa|dsa|ecdsa|ed25519)(?=$|[\\/\s"';&|)])/i.test(text) ||
    /(?:^|[\\/\s"'])(?:\.ssh|\.gnupg)(?=$|[\\/\s"';&|)])/i.test(text)
  )
}

function hasGeneralDataDestruction(text: string) {
  if (!hasDeletePrimitive(text)) return false
  return GENERAL_DATA_EXTENSION.test(text) || hasDataPathDestruction(text)
}

function isCriticalDeletionTarget(target: string) {
  const literal = literalPathToken(target)
  return Boolean(literal && isCriticalOriginalPath(literal))
}

function isGeneralDataTarget(target: string) {
  const literal = literalPathToken(target)
  return Boolean(literal && GENERAL_DATA_EXTENSION.test(literal))
}

function hasDataDestruction(text: string) {
  if (!hasDeletePrimitive(text)) return false
  if (DATA_EXTENSION.test(text)) return true
  return hasDataPathDestruction(text)
}

function hasDestructiveOpenOverwrite(text: string) {
  const pattern = /\bopen\s*\([^)]*\)/gi
  let match: RegExpExecArray | null
  while ((match = pattern.exec(text)) !== null) {
    const call = match[0]
    if (!/\.(?:csv|json|db|sqlite|xlsx?|parquet)\b/i.test(call)) continue
    if (/mode\s*=\s*["'][wax]/i.test(call)) return true
    if (/["'][wax][b+]*["']/.test(call)) return true
  }
  return false
}

function hasDestructiveOverwrite(text: string) {
  return (
    /\bsed\b[^\n]*(?:-i\b|--in-place\b)[^\n]*\.(?:csv|json|db|sqlite|xlsx?|parquet)\b/i.test(text) ||
    /\b(?:set-content|out-file)\b[^\n]*\.(?:csv|json|db|sqlite|xlsx?|parquet)\b/i.test(text) ||
    /\b(?:write_text|write_bytes)\s*\([^)]*\.(?:csv|json|db|sqlite|xlsx?|parquet)\b/i.test(text) ||
    hasDestructiveOpenOverwrite(text)
  )
}

function hasFileWritePrimitive(text: string): boolean {
  if (/\btee\b/i.test(text)) return true
  if (/\btouch\b/i.test(text)) return true
  if (/\bmkdir\b/i.test(text)) return true
  if (/\b(?:cp|copy|copy-item)\b/i.test(text)) return true
  if (/\b(?:mv|move|move-item|rename-item|ren)\b/i.test(text)) return true
  if (/\bsed\b[^\n]*-i\b/i.test(text)) return true
  if (/\b(?:set-content|out-file)\b/i.test(text)) return true
  if (/\bnew-item\b/i.test(text)) return true
  if (/open\s*\([^)]*['"][wax]/i.test(text)) return true
  if (/\.write_text\s*\(/i.test(text) || /\.write_bytes\s*\(/i.test(text)) return true
  if (/\b(?:writeFile|writeFileSync|appendFile|appendFileSync|copyFile|copyFileSync)\s*\(/i.test(text)) return true
  if (/\bcreateWriteStream\s*\(/i.test(text)) return true
  const redirectCleaned = text
    .replace(/>\s*\/dev\/(?:null|stdout|stderr)\b/gi, "")
    .replace(/>\s*\$null\b/gi, "")
    .replace(/\d*>&\d+/g, "")
  if (/(?:^|[^=>])>(?![=>])/m.test(redirectCleaned)) return true
  return false
}

function hasLocalScriptReviewSignal(text: string): boolean {
  // Script content is matched raw: quote stripping is only safe for command text,
  // where extractQuotedWrappers re-surfaces quoted payloads; string literals inside
  // a script file have no such secondary surface, so stripping would hide payloads.
  if (SCRIPT_DESTRUCTIVE_PRIMITIVE.test(text)) return true
  if (hasFileWritePrimitive(text)) return true
  return false
}

function stripMatchingQuotes(value: string) {
  if (value.length < 2) return value
  const first = value[0]
  const last = value[value.length - 1]
  return (first === '"' || first === "'") && first === last ? value.slice(1, -1) : value
}

type DeletionTargetCandidate = { target: string; cwd: string }

function deletionTargetCandidates(script: string, shell: string, cwd: string) {
  const items: DeletionTargetCandidate[] = []
  const seen = new Set<string>()
  let truncated = false
  const surfaces = [script, ...extractQuotedWrappers(script)]

  const add = (target: string, base: string) => {
    const cleaned = stripMatchingQuotes(target)
    const key = `${path.resolve(base)}\0${cleaned}`
    if (seen.has(key)) return
    seen.add(key)
    if (items.length >= MAX_TARGET_DIRECTORIES) {
      truncated = true
      return
    }
    items.push({ target: cleaned, cwd: base })
  }

  for (const surface of surfaces) {
    const segments = splitCommandSegments(surface, shell) ?? [{ text: surface }]
    let base: string | undefined = cwd
    for (const item of segments) {
      base = segmentBase(item, base, cwd)
      const segment = stripHarmlessPrefixes(item.text)
      const cd = parseCdSegment(segment)
      if (cd) {
        base = resolveCdBase(cd.dir, base)
        continue
      }
      if (!base) continue
      const deletion = parseDeleteInvocation(segment)
      if (deletion?.parseable) {
        for (const target of deletion.targets) add(target, base)
      }
      const recycle = explicitRecycleBinOperation(segment, shell)
      if (recycle) {
        for (const target of recycle.targets) add(target, base)
      }
    }
  }
  return { items, truncated }
}

function referencedPathCandidates(script: string, shell: string) {
  const candidates = new Set<string>()
  let truncated = false
  const surfaces = [script, ...extractQuotedWrappers(script)]

  const add = (candidate: string) => {
    if (candidates.has(candidate)) return false
    if (candidates.size >= MAX_REFERENCED_PATHS) {
      truncated = true
      return true
    }
    candidates.add(candidate)
    return false
  }

  const consider = (rawToken: string) => {
    if (rawToken.startsWith("-") || /^\d*(?:>>?|<<?|&>)\S*/.test(rawToken)) return false
    const literal = literalPathToken(rawToken)
    if (!literal || /^(?:https?:|data:)/i.test(literal)) return false
    const normalizedPath = normalizeMsysPath(expandHome(literal))
    const looksLikePath =
      path.isAbsolute(normalizedPath) ||
      /^\.{1,2}[\\/]/.test(normalizedPath) ||
      normalizedPath.startsWith("~/") ||
      /[\\/]/.test(normalizedPath) ||
      /\.[A-Za-z0-9][A-Za-z0-9._-]{0,15}$/.test(normalizedPath)
    return looksLikePath ? add(literal) : false
  }

  for (const surface of surfaces) {
    const segments = splitSimpleSegments(surface, shell) ?? [surface]
    for (const segment of segments) {
      const tokens = simpleInvocationTokens(segment)
      const start = tokens[0] && /[\\/]/.test(stripMatchingQuotes(tokens[0])) ? 0 : 1
      for (const rawToken of tokens.slice(start)) {
        if (consider(rawToken)) return { paths: [...candidates], truncated }
      }
      for (const match of segment.matchAll(/["']([^"'\r\n]+)["']/g)) {
        if (consider(match[1] ?? "")) return { paths: [...candidates], truncated }
      }
    }
  }
  return { paths: [...candidates], truncated }
}

function directoryEntryType(entry: Dirent) {
  if (entry.isDirectory()) return "directory" as const
  if (entry.isFile()) return "file" as const
  if (entry.isSymbolicLink()) return "symlink" as const
  return "other" as const
}

async function inspectTargetDirectory(candidate: string, cwd: string, worktree: string) {
  const expanded = expandHome(candidate)
  if (!expanded || /[*?[\]`$%]/.test(expanded)) return { uninspected: candidate }
  const absolute = path.isAbsolute(expanded) ? expanded : path.resolve(cwd, expanded)

  let canonical: string
  try {
    canonical = await realpath(absolute)
  } catch {
    return { uninspected: candidate }
  }
  if (!isWithin(worktree, canonical)) return { uninspected: candidate }

  let info
  try {
    info = await stat(canonical)
  } catch {
    return { uninspected: candidate }
  }
  if (!info.isDirectory()) return {}

  try {
    const all = await readdir(canonical, { withFileTypes: true })
    all.sort((left, right) => left.name.localeCompare(right.name))
    const entries = all.slice(0, MAX_DIRECTORY_ENTRIES).map((entry) => ({
      name: entry.name.slice(0, MAX_DIRECTORY_ENTRY_NAME_CHARS),
      type: directoryEntryType(entry),
    }))
    return {
      context: {
        path: path.relative(worktree, canonical).replaceAll("\\", "/") || ".",
        entries,
        truncated: all.length > entries.length,
      } satisfies TargetDirectoryReviewContext,
    }
  } catch {
    return { uninspected: candidate }
  }
}

function localScriptCandidates(script: string, shell: string) {
  const candidates = new Set<string>()
  const segments = splitSimpleSegments(script, shell) ?? [script]

  for (const segment of segments) {
    let tokens = simpleInvocationTokens(segment)
      .map(stripMatchingQuotes)
      .filter((token) => !/^\d*>&\d+$/.test(token))
    while (tokens[0] && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) tokens = tokens.slice(1)
    if (["command", "sudo"].includes((tokens[0] ?? "").toLowerCase())) tokens = tokens.slice(1)
    if ((tokens[0] ?? "").toLowerCase() === "env") {
      tokens = tokens.slice(1)
      while (tokens[0] && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) tokens = tokens.slice(1)
    }
    if ((tokens[0] ?? "").toLowerCase() === "wsl") {
      const separator = tokens.indexOf("--")
      tokens = separator >= 0 ? tokens.slice(separator + 1) : tokens.slice(1)
    }
    if (tokens.length === 0) continue

    const command = commandLeaf(tokens[0]) ?? ""
    let candidate: string | undefined
    if (["python", "python3", "py"].includes(command)) {
      for (let index = 1; index < tokens.length; index += 1) {
        const token = tokens[index]
        if (["-c", "-m", "-e"].includes(token.toLowerCase())) {
          candidate = undefined
          break
        }
        if (token.startsWith("-")) continue
        candidate = token
        break
      }
    } else if (["node", "bash", "sh", "zsh"].includes(command)) {
      if (command === "node" && tokens.slice(1).some((token) => token.toLowerCase() === "--test")) {
        candidate = undefined
        continue
      }
      for (let index = 1; index < tokens.length; index += 1) {
        const token = tokens[index]
        if (["-c", "-e"].includes(token.toLowerCase())) {
          candidate = undefined
          break
        }
        if (token.startsWith("-")) continue
        candidate = token
        break
      }
    } else if (["powershell", "pwsh"].includes(command)) {
      const fileIndex = tokens.findIndex((token) => token.toLowerCase() === "-file")
      if (fileIndex >= 0) candidate = tokens[fileIndex + 1]
    } else if (/^\.{1,2}[\\/]/.test(tokens[0])) {
      candidate = tokens[0]
    }

    if (!candidate || candidate.startsWith("-") || /^(?:https?:|data:)/i.test(candidate)) continue
    candidates.add(candidate)
    if (candidates.size >= MAX_LOCAL_SCRIPTS) return [...candidates]
  }
  return [...candidates]
}

async function fingerprintLocalScript(candidate: string, cwd: string, worktree: string) {
  if (isCriticalOriginalPath(candidate) || /(?:^|[\\/])\.env(?:\.|$)/i.test(candidate)) return undefined
  const expanded = expandHome(candidate)
  const absolute = path.isAbsolute(expanded) ? expanded : path.resolve(cwd, expanded)
  let canonical: string
  try {
    canonical = await realpath(absolute)
  } catch {
    return undefined
  }
  if (!isWithin(worktree, canonical)) return undefined

  const info = await stat(canonical)
  if (!info.isFile() || info.size > MAX_LOCAL_SCRIPT_BYTES) return undefined
  const content = await readFile(canonical)
  if (content.includes(0)) return undefined

  let linkPath: string | undefined
  let linkDev: number | undefined
  let linkIno: number | undefined
  let linkMtimeMs: number | undefined
  if (canonical !== absolute) {
    try {
      const linkInfo = await lstat(absolute)
      if (linkInfo.isSymbolicLink()) {
        linkPath = absolute
        linkDev = linkInfo.dev
        linkIno = linkInfo.ino
        linkMtimeMs = linkInfo.mtimeMs
      }
    } catch {
      return undefined
    }
  }

  return {
    content: content.toString("utf8"),
    reviewPath: path.relative(worktree, canonical).replaceAll("\\", "/") || path.basename(canonical),
    fingerprint: {
      path: canonical,
      size: info.size,
      mtimeMs: info.mtimeMs,
      sha256: createHash("sha256").update(content).digest("hex"),
      ...(linkPath !== undefined
        ? { linkPath, linkDev: linkDev as number, linkIno: linkIno as number, linkMtimeMs: linkMtimeMs as number }
        : {}),
    } satisfies ScriptFingerprint,
  }
}

export async function verifyScriptFingerprints(fingerprints: ScriptFingerprint[]) {
  for (const fingerprint of fingerprints) {
    if (fingerprint.linkPath !== undefined) {
      let linkInfo
      try {
        linkInfo = await lstat(fingerprint.linkPath)
      } catch {
        return false
      }
      if (!linkInfo.isSymbolicLink()) return false
      if (
        linkInfo.dev !== fingerprint.linkDev ||
        linkInfo.ino !== fingerprint.linkIno ||
        linkInfo.mtimeMs !== fingerprint.linkMtimeMs
      ) {
        return false
      }
      let canonical
      try {
        canonical = await realpath(fingerprint.linkPath)
      } catch {
        return false
      }
      if (canonical !== fingerprint.path) return false
    }
    let info
    let content
    try {
      info = await stat(fingerprint.path)
      content = await readFile(fingerprint.path)
    } catch {
      return false
    }
    if (!info.isFile() || info.size !== fingerprint.size || info.mtimeMs !== fingerprint.mtimeMs) return false
    if (createHash("sha256").update(content).digest("hex") !== fingerprint.sha256) return false
  }
  return true
}

type SegmentDecision = {
  verdict: SecurityVerdict
  rules: string[]
  reason: string
}

const MAX_WRAPPER_DEPTH = 4

function combineSegmentDecisions(results: SegmentDecision[]): SegmentDecision {
  const denied = results.find((result) => result.verdict === "DENY")
  if (denied) return denied
  const asks = results.filter((result) => result.verdict === "ASK")
  if (asks.length > 0) {
    return {
      verdict: "ASK",
      rules: [...new Set(asks.flatMap((result) => result.rules))],
      reason: asks[0].reason,
    }
  }
  return {
    verdict: "ALLOW",
    rules: [...new Set(results.flatMap((result) => result.rules))],
    reason: "All segments are recognized safe operations",
  }
}

async function classifyHardDeletionPolicy(
  segment: string,
  input: ClassifyShellCommandInput,
): Promise<StaticSecurityDecision | undefined> {
  const surfaces = [segment, ...extractDecodedPayloads(segment), ...extractQuotedWrappers(segment)]
  const combined = surfaces.join("\n\n")
  const bypassed = input.bypassedCategories

  // HARD-mode exemption for clearing recognized disposable directories inside
  // the working tree (node_modules, dist, .venv, .next, out, ... §4.9).
  if (
    input.cwd !== undefined &&
    input.worktree !== undefined &&
    await isDisposableDirectoryDelete(segment, input.cwd, input.worktree)
  ) {
    return {
      verdict: "ALLOW",
      rules: ["cleanup.disposable"],
      reason: "Forced deletion is limited to a recognized disposable directory inside the working tree",
      fingerprints: [],
    }
  }

  // An echo/printf of a delete-looking string is documentation, not deletion.
  // Trust that only for a bare output command with no extra decoded or wrapped
  // surfaces and no command substitution.
  const inertOutput =
    surfaces.length === 1 &&
    commandSubstitutionBodies(segment).length === 0 &&
    /^(?:echo|printf|write-output|write-host)\b/i.test(stripHarmlessPrefixes(segment).trim())

  if (hasForcedRecursiveDelete(combined) && !inertOutput && !ruleBypassed("hard.forced-recursive-delete", bypassed)) {
    return {
      verdict: "DENY",
      rules: ["hard.forced-recursive-delete"],
      reason: "Forced recursive deletion is forbidden. DO NOT retry any rm -rf, split -r/-f, or equivalent recursive deletion command",
      fingerprints: [],
    }
  }

  const roots = await trustedUserLocalTempRoots(input)
  for (const surface of surfaces) {
    const wrappedPowerShell = unwrapPowerShellCommand(surface)
    const payload = wrappedPowerShell ?? surface
    const payloadShell = wrappedPowerShell ? "powershell" : input.shell
    const segments = splitCommandSegments(payload, payloadShell)
    if (!segments) continue

    let base: string | undefined = input.cwd
    for (const item of segments) {
      base = segmentBase(item, base, input.cwd)
      const seg = item.text
      const cd = parseCdSegment(seg)
      if (cd) {
        base = resolveCdBase(cd.dir, base)
        continue
      }

      const deletion = parseDeleteInvocation(seg)
      if (!deletion?.parseable || deletion.targets.length === 0) continue

      for (const target of deletion.targets) {
        const cleaned = stripMatchingQuotes(target)
        const pathFinding = classifyPathTarget(cleaned, "delete", {
          cwd: base ?? input.cwd,
          worktree: input.worktree,
          strictness: "HARD",
        })
        if (pathFinding.kind === "deny" && !ruleBypassed(pathFinding.rule, bypassed)) {
          return {
            verdict: "DENY",
            rules: [pathFinding.rule],
            reason: pathFinding.reason,
            fingerprints: [],
          }
        }
        if (hasNamedTempPathSegment(cleaned) && !ruleBypassed("hard.temp-target-delete", bypassed)) {
          return {
            verdict: "DENY",
            rules: ["hard.temp-target-delete"],
            reason: `Permanent deletion of temp/tmp targets is forbidden. ${PERMANENT_DELETE_GUIDANCE}`,
            fingerprints: [],
          }
        }
        const literal = literalPathToken(target)
        if (literal && backupPathIdentity(literal) && !ruleBypassed("hard.backup-target-delete", bypassed)) {
          return {
            verdict: "DENY",
            rules: ["hard.backup-target-delete"],
            reason: `Permanent deletion of backup targets is forbidden. ${PERMANENT_DELETE_GUIDANCE}`,
            fingerprints: [],
          }
        }
        if (
          base &&
          roots.length > 0 &&
          (await isTrustedTempPath(target, base, roots)) &&
          !ruleBypassed("hard.local-temp-delete", bypassed)
        ) {
          return {
            verdict: "DENY",
            rules: ["hard.local-temp-delete"],
            reason: `Permanent deletion inside the trusted Local Temp directory is forbidden. ${PERMANENT_DELETE_GUIDANCE}`,
            fingerprints: [],
          }
        }
      }
    }
  }
  return undefined
}

async function recycleTargetsFinding(
  targets: string[],
  base: string,
  input: ClassifyShellCommandInput,
  strictness: Strictness,
): Promise<SegmentDecision | undefined> {
  const ctx: PathContext = { cwd: base, worktree: input.worktree, strictness }
  const home = expandHome("~")
  const tempRoots = await trustedUserLocalTempRoots(input)
  for (const target of targets) {
    const literal = literalPathToken(target)
    if (!literal) {
      return {
        verdict: "ASK",
        rules: ["filesystem.recycle-bin-unverified"],
        reason: "The recycle-bin target is not a verifiable literal path",
      }
    }
    const decision = classifyPathTarget(literal, "delete", ctx)
    if (decision.kind !== "pass") {
      return {
        verdict: decision.kind === "deny" ? "DENY" : "ASK",
        rules: [decision.rule],
        reason: decision.reason,
      }
    }
    const resolved = resolveLexical(literal, base, home)
    const absolute = resolved.absolute
    if (!absolute) {
      return {
        verdict: "ASK",
        rules: ["filesystem.recycle-bin-unverified"],
        reason: "The recycle-bin target cannot be resolved to a concrete path",
      }
    }
    const inWorktree = isWithinLexical(input.worktree, absolute)
    const inTemp = tempRoots.some((root) => isWithinLexical(root, absolute))
    if (!inWorktree && !inTemp && !hasNamedTempPathSegment(literal)) {
      return {
        verdict: "ASK",
        rules: ["filesystem.recycle-bin-outside"],
        reason: "Moving a target outside the working tree to the recycle bin requires review",
      }
    }
  }
  return undefined
}

async function classifySegment(
  segment: string,
  base: string,
  input: InternalClassifyInput,
): Promise<SegmentDecision> {
  const segInput: InternalClassifyInput = { ...input, script: segment, cwd: base }
  const strictness: Strictness = input.strictness ?? "LOOSE"
  const bypassed = input.bypassedCategories

  if (segment.trim().startsWith("#")) {
    return {
      verdict: "ALLOW",
      rules: ["operation.comment"],
      reason: "The segment is a shell comment",
    }
  }

  if (isPowerShellRecycleSetup(segment)) {
    return {
      verdict: "ALLOW",
      rules: ["filesystem.recycle-bin-setup"],
      reason: "Loads the operating-system recycle-bin API",
    }
  }

  if (hasForbiddenRecycleDestruction(segment)) {
    // Recycle-bin permanent deletion follows the filesystem bypass category.
    if (!bypassed?.has("filesystem")) {
      return {
        verdict: "DENY",
        rules: ["filesystem.recycle-bin-permanent-delete"],
        reason: "Permanently deleting recycle-bin contents is forbidden",
      }
    }
  }

  const recycle = explicitRecycleBinOperation(segment, input.shell)
  if (recycle && !bypassed?.has("filesystem")) {
    const recycleFinding = await recycleTargetsFinding(recycle.targets, base, segInput, strictness)
    if (recycleFinding && !recycleFinding.rules.every((rule) => ruleBypassed(rule, bypassed))) {
      return recycleFinding
    }
    if (strictness === "HARD") {
      const tempRoots = await trustedUserLocalTempRoots(segInput)
      for (const target of recycle.targets) {
        const literal = literalPathToken(target)
        const protectedTarget = Boolean(
          literal && (backupPathIdentity(literal) || hasNamedTempPathSegment(literal)),
        )
        const inLocalTemp = tempRoots.length > 0 && await isTrustedTempPath(target, base, tempRoots)
        if ((protectedTarget || inLocalTemp) && !ruleBypassed("filesystem.protected-target-delete", bypassed)) {
          return {
            verdict: "DENY",
            rules: ["filesystem.protected-target-delete"],
            reason: `Removing a protected temporary or backup target is forbidden. ${PERMANENT_DELETE_GUIDANCE}`,
          }
        }
      }
      if (recycle.targets.some(isCriticalDeletionTarget) && !ruleBypassed("data.critical-delete", bypassed)) {
        return {
          verdict: "DENY",
          rules: ["data.critical-delete"],
          reason: `Attempts to delete credential or key material. ${PERMANENT_DELETE_GUIDANCE}`,
        }
      }
      if (recycle.targets.some(isGeneralDataTarget) && !ruleBypassed("data.destructive-delete", bypassed)) {
        return {
          verdict: "DENY",
          rules: ["data.destructive-delete"],
          reason: `Attempts to delete a durable structured data file. ${PERMANENT_DELETE_GUIDANCE}`,
        }
      }
      return {
        verdict: "ALLOW",
        rules: ["filesystem.recycle-bin"],
        reason: "Moves items to the recoverable operating-system recycle bin",
      }
    }
    return {
      verdict: "ALLOW",
      rules: ["filesystem.recycle-bin"],
      reason: "Moves items to the recoverable operating-system recycle bin",
    }
  }


  const stripped = stripHarmlessPrefixes(segment)
  if (stripped && stripped !== segment.trim()) {
    return classifySegment(stripped, base, input)
  }

  if (strictness === "HARD") {
    // Deletion/backup policies gate their individual DENY verdicts with
    // ruleBypassed (filesystem vs secret categories differ per rule).
    const hardDecision = await classifyHardDeletionPolicy(segment, segInput)
    if (hardDecision && !hardDecision.rules.every((rule) => ruleBypassed(rule, bypassed))) {
      return { verdict: hardDecision.verdict, rules: hardDecision.rules, reason: hardDecision.reason }
    }
    const backupDecision = await classifyBackupPolicy(segment, segInput)
    if (backupDecision && !backupDecision.rules.every((rule) => ruleBypassed(rule, bypassed))) {
      if (backupDecision.verdict === "ALLOW" && backupDecision.rules.includes("filesystem.backup-delete")) {
        return {
          verdict: "DENY",
          rules: ["hard.backup-delete"],
          reason: `Permanent deletion of backup targets is forbidden. ${PERMANENT_DELETE_GUIDANCE}`,
        }
      }
      return { verdict: backupDecision.verdict, rules: backupDecision.rules, reason: backupDecision.reason }
    }
  } else {
    if (!segInput.cwdUnknown) {
      const namedTempDecision = await classifyNamedTempDeletionPolicy(segment, segInput)
      if (namedTempDecision && !namedTempDecision.rules.every((rule) => ruleBypassed(rule, bypassed))) {
        return { verdict: namedTempDecision.verdict, rules: namedTempDecision.rules, reason: namedTempDecision.reason }
      }

      const userLocalTempDecision = await classifyUserLocalTempSegment(segment, segInput)
      if (
        userLocalTempDecision &&
        !userLocalTempDecision.rules.every((rule) => ruleBypassed(rule, bypassed))
      ) {
        return {
          verdict: userLocalTempDecision.verdict,
          rules: userLocalTempDecision.rules,
          reason: userLocalTempDecision.reason,
        }
      }
      const backupDecision = await classifyBackupPolicy(segment, segInput)
      if (backupDecision && !backupDecision.rules.every((rule) => ruleBypassed(rule, bypassed))) {
        return { verdict: backupDecision.verdict, rules: backupDecision.rules, reason: backupDecision.reason }
      }
    }
  }

  const wslPayload = segment.match(/^wsl(?:\.exe)?\s+--\s+([\s\S]+)$/i)
  if (wslPayload && (wslPayload[1] ?? "").trim()) {
    const payload = wslPayload[1] ?? ""
    const strippedPayload = stripOutputRedirects(payload) ?? payload
    if (
      isKnownSafeSegment(strippedPayload) &&
      !hasDynamicShellExpansion(payload, input.shell) &&
      !hasUnquotedExpansion(maskHeredocBody(payload), input.shell) &&
      !hasSensitiveEnvPrefix(payload) &&
      analyzeSegmentPaths(payload, { cwd: base, worktree: input.worktree, strictness }).kind === "pass"
    ) {
      return {
        verdict: "ALLOW",
        rules: ["operation.wsl-safe"],
        reason: "The WSL payload is a recognized safe operation",
      }
    }
  }

  // ---- M3 (P2) §4.9: dedicated safe surfaces -----------------------------
  const m3ctx: PathContext = { cwd: base, worktree: input.worktree, strictness }

  const tarOrUnzip = classifyTarExtractOrUnzip(segment, m3ctx, strictness, /^unzip\b/i.test(segment))
  if (tarOrUnzip && !tarOrUnzip.rules.every((rule) => ruleBypassed(rule, bypassed))) return tarOrUnzip

  if ((/^curl\b/i.test(segment) || /^wget\b/i.test(segment)) && strictness === "LOOSE" && !input.cwdUnknown) {
    if (isSafeDownloadTarget(segment, m3ctx)) {
      return {
        verdict: "ALLOW",
        rules: ["operation.download"],
        reason: "Downloads a file into the working tree from an HTTPS URL",
      }
    }
  } else if (/^python(?:3)?(?:\.exe)?\s+-m\s+http\.server\b/i.test(segment) && !input.cwdUnknown) {
    if (strictness === "LOOSE" && !hasDynamicShellExpansion(segment, input.shell)) {
      return { verdict: "ALLOW", rules: ["operation.dev-server"], reason: "Serves a local development HTTP server" }
    }
    return { verdict: "ASK", rules: ["operation.context-required"], reason: "Starting a local development server requires review" }
  } else if (/^ssh-keygen\b/i.test(segment) && strictness === "LOOSE" && !input.cwdUnknown) {
    if (!/\s-y\b|--print/.test(segment) && /\s-N\s+['""]['""]/.test(segment) && !hasDynamicShellExpansion(segment, input.shell)) {
      return { verdict: "ALLOW", rules: ["operation.keygen"], reason: "Generates a new SSH key pair locally" }
    }
  }

  const safeChmod = classifySafeChmod(segment, m3ctx, strictness)
  if (safeChmod) return safeChmod

  // `[ ... ]` / `test` literal test expressions (framing brackets are not globs here)
  const bracketMatch = segment.match(/^\[\s+([\s\S]*?)\s*\]\s*$/) ?? ( /^test\b/i.test(segment) ? [null, segment.replace(/^test\b/i, "").trim()] : null )
  if (bracketMatch && !input.cwdUnknown) {
    const inner = bracketMatch[1] ?? ""
    if (commandSubstitutionBodies(segment).length === 0 && !hasUnquotedExpansion(inner, input.shell)) {
      return { verdict: "ALLOW", rules: ["operation.test-expression"], reason: "Evaluates a literal shell test expression" }
    }
  }

  // Command substitution whose inner reads are entirely safe: `echo $(date)` etc.
  const substitutionBodies = commandSubstitutionBodies(segment)
  if (
    substitutionBodies.length > 0 &&
    !input.cwdUnknown &&
    isSafeSubstitutionSurface(segment, input.shell, m3ctx)
  ) {
    const maskedOuter = maskCommandSubstitutions(segment)
    const substitutionFinding = analyzeSegmentPaths(maskedOuter, m3ctx)
    if (substitutionFinding.kind === "pass") {
      return {
        verdict: "ALLOW",
        rules: ["operation.command-substitution"],
        reason: "Command substitution contains only recognized safe operations",
      }
    }
  }

  // heredoc: `cat <<EOF` (stdout) or `cat <<EOF > worktree-file`
  if (/^cat\b[^\n]*<<-?["']?[A-Za-z0-9_]+/i.test(segment) && !input.cwdUnknown) {
    const newline = segment.indexOf("\n")
    const header = newline === -1 ? segment : segment.slice(0, newline)
    const headerCmd = header.replace(/<<-?\s*(?:'[^']*'|"[^"]*"|\w+)\s*/g, " ")
    const heredocFinding = analyzeSegmentPaths(headerCmd, m3ctx)
    if (heredocFinding.kind === "pass") {
      return { verdict: "ALLOW", rules: ["operation.heredoc"], reason: "Writes recognized heredoc content to stdout or a working-tree file" }
    }
    if (!ruleBypassed(heredocFinding.rule, bypassed)) {
      return { verdict: heredocFinding.kind === "deny" ? "DENY" : "ASK", rules: [heredocFinding.rule], reason: heredocFinding.reason }
    }
  }

  const ansiSurfaces = decodeAnsiCContent(segment)
  const varSurface = substituteDeleteVars(segment)
  const quoteSurface = quoteStrippedDeleteSurface(segment)
  const surfaces = [
    segment,
    ...extractDecodedPayloads(segment),
    ...extractQuotedWrappers(segment),
    ...ansiSurfaces,
    ...(varSurface ? [varSurface] : []),
    ...(quoteSurface ? [quoteSurface] : []),
  ]
  const combined = surfaces.map(maskHeredocBody).join("\n\n")
  const reviewSignals = new Map<string, string>()
  // A quote-stripped variant of THIS same segment (`Remove-Item -LiteralPath
  // ".\dist" -Recurse -Force` unquotes to the identical delete invocation) is
  // not an evasion surface, so it must not suppress disposable-cleanup
  // recognition. Any other extra surface (decoded payload, wrapped payload,
  // ANSI, variable substitution) still denies the exemption.
  const quoteSurfaceOfThisSegment = quoteStrippedDeleteSurface(segment)
  const onlyInnocentSurfaces =
    surfaces.length === 1 ||
    (surfaces.length === 2 && quoteSurfaceOfThisSegment !== undefined && surfaces[1] === quoteSurfaceOfThisSegment)
  const explicitDisposableCleanup =
    (await isExplicitDisposableCleanup(segment, base, input.worktree)) && onlyInnocentSurfaces

  const knownSafe = isKnownSafeSegment(stripOutputRedirects(segment) ?? segment)
  const hasExpansion = hasDynamicShellExpansion(segment, input.shell)
  const provablySafe =
    knownSafe &&
    !hasExpansion &&
    !hasUnquotedExpansion(maskHeredocBody(segment), input.shell) &&
    !hasSensitiveEnvPrefix(segment)

  // Kernel-trigger / core_pattern writs must not be masked by the
  // provably-safe early allow (e.g. `echo '|/bin/evil' > /proc/sys/kernel/core_pattern`).
  // Other DEFINITE rules keep running after EXIT-1 so that harmless echo/printf of
  // delete strings (`echo 'rm -rf /'`) are not misclassified as deletions.
  // Kernel primitives are floor rules: never bypassable.
  for (const ruleId of ["filesystem.kernel-trigger", "filesystem.kernel-core-pattern"]) {
    const rule = SECURITY_SIGNAL_RULES.find((entry) => entry.id === ruleId)
    if (rule && rule.test(combined)) {
      return { verdict: "DENY", rules: [rule.id], reason: rule.reason }
    }
  }

  if (provablySafe) {
    const finding = analyzeSegmentPaths(segment, { cwd: base, worktree: input.worktree, strictness })
    if (finding.kind === "pass") {
      // Durable-data in-place overwrite must not ride the provably-safe early
      // allow (`sed -i` on .csv/.json/db/sqlite/xlsx/parquet).
      if (!bypassed?.has("filesystem") && hasDestructiveOverwrite(segment)) {
        return {
          verdict: "ASK",
          rules: ["data.destructive-overwrite"],
          reason: "Attempts in-place destructive modification of durable structured data",
        }
      }
      return {
        verdict: "ALLOW",
        rules: ["operation.known-safe"],
        reason: "The segment is a recognized read-only or normal low-risk development action",
      }
    }
    if (!ruleBypassed(finding.rule, bypassed)) {
      return {
        verdict: finding.kind === "deny" ? "DENY" : "ASK",
        rules: [finding.rule],
        reason: finding.reason,
      }
    }
  }

  for (const rule of SECURITY_SIGNAL_RULES) {
    if (ruleBypassed(rule.id, bypassed)) continue
    if (rule.test(combined)) {
      if (DEFINITE_DESTRUCTIVE_RULES.has(rule.id)) {
        if (rule.id === "filesystem.forced-recursive-delete" && explicitDisposableCleanup && strictness !== "HARD") continue
        return { verdict: "DENY", rules: [rule.id], reason: rule.reason }
      }
      reviewSignals.set(rule.id, rule.reason)
    }
  }

  const compressionFinding = compressionDestructionFinding(segment, {
    cwd: base,
    worktree: input.worktree,
    strictness,
  })
  if (compressionFinding && !compressionFinding.rules.every((rule) => ruleBypassed(rule, bypassed))) {
    return { verdict: compressionFinding.verdict, rules: compressionFinding.rules, reason: compressionFinding.reason }
  }

  // Credential/key-material data rules belong to the secret category: arming
  // `secret` clears them; arming `filesystem` alone must not.
  if (!bypassed?.has("secret") && hasCriticalDataDestruction(combined)) {
    return {
      verdict: "DENY",
      rules: ["data.critical-delete"],
      reason: strictness === "HARD"
        ? `Attempts to delete credential or key material. ${PERMANENT_DELETE_GUIDANCE}`
        : "Attempts to delete credential or key material",
    }
  }
  if (!bypassed?.has("filesystem") && hasGeneralDataDestruction(combined)) {
    if (strictness === "HARD") {
      return {
        verdict: "DENY",
        rules: ["data.destructive-delete"],
        reason: `Attempts to permanently delete a durable structured data file. ${PERMANENT_DELETE_GUIDANCE}`,
      }
    }
    reviewSignals.set(
      "data.destructive-delete",
      "Attempts to delete user data or durable structured files and requires review",
    )
  }
  if (!bypassed?.has("filesystem") && hasDestructiveOverwrite(combined)) {
    reviewSignals.set(
      "data.destructive-overwrite",
      "Attempts in-place destructive modification of durable structured data",
    )
  }
  const sensitivePath = sensitivePathFinding(segment, { cwd: base, worktree: input.worktree, strictness })
  if (sensitivePath && sensitivePath.kind !== "pass") {
    if (!ruleBypassed(sensitivePath.rule, bypassed)) {
      return {
        verdict: sensitivePath.kind === "deny" ? "DENY" : "ASK",
        rules: [sensitivePath.rule],
        reason: sensitivePath.reason,
      }
    }
  }

  const exfilRule = hasExfilOrDangerousPerms(segment, combined, {
    cwd: base,
    worktree: input.worktree,
    strictness,
  })
  if (exfilRule && !ruleBypassed(exfilRule, bypassed)) {
    const reason = exfilRule === "permissions.sensitive-mode"
      ? "Setting dangerous permissions on a credential or system file requires review"
      : "Sending credential or system data off-host requires review"
    if (strictness === "HARD") {
      return { verdict: "DENY", rules: [exfilRule], reason }
    }
    reviewSignals.set(exfilRule, reason)
  }

  for (const rule of HARD_DENY_LOOSE_ASK_RULES) {
    if (ruleBypassed(rule.id, bypassed)) continue
    if (rule.test(combined)) {
      if (strictness === "HARD") {
        return { verdict: "DENY", rules: [rule.id], reason: rule.reason }
      }
      reviewSignals.set(rule.id, rule.reason)
    }
  }

  if (explicitDisposableCleanup && strictness !== "HARD") {
    return {
      verdict: "ALLOW",
      rules: ["cleanup.disposable"],
      reason: "Cleanup is narrowly scoped to a recognized disposable cache, dependency, build, or temporary target",
    }
  }
  if (reviewSignals.size > 0) {
    return {
      verdict: "ASK",
      rules: [...reviewSignals.keys()],
      reason: [...reviewSignals.values()][0] ?? "The command contains a security-sensitive operation requiring review",
    }
  }

  if (localScriptCandidates(segment, input.shell).length > 0 && !ruleBypassed("execution.local-script", bypassed)) {
    return {
      verdict: "ASK",
      rules: ["execution.local-script"],
      reason: "The command executes a local script and requires contextual review",
    }
  }

  if (!bypassed?.has("filesystem") && WRAPPER_PRIMITIVE.test(combined)) {
    return {
      verdict: "ASK",
      rules: ["execution.wrapper"],
      reason: "The command uses an interpreter, encoded payload, or dynamic execution wrapper",
    }
  }
  if (!bypassed?.has("filesystem") && hasDynamicShellExpansion(combined, input.shell)) {
    return {
      verdict: "ASK",
      rules: ["execution.wrapper"],
      reason: "The command uses dynamic shell expansion and cannot be proven safe",
    }
  }
  if (!bypassed?.has("filesystem") && extractDecodedPayloads(segment).length > 0) {
    return {
      verdict: "ASK",
      rules: ["execution.wrapper"],
      reason: "The command carries an encoded payload that requires review",
    }
  }

  if (!bypassed?.has("filesystem") && hasDeletePrimitive(combined)) {
    return {
      verdict: "ASK",
      rules: ["filesystem.scoped-delete"],
      reason: "The command deletes files but is not an obvious broad or durable-data deletion",
    }
  }

  // Composite context-required check: each trigger family follows the category
  // of its primitive so an armed category actually clears its family. Network
  // clients are matched as command words only — a bare `\bssh\b` would also hit
  // paths like `~/.ssh/id_rsa` and wrongly defeat a secret bypass.
  const combinedWithoutFdMerges = combined
    .replace(/>\s*\/dev\/(?:null|stdout|stderr)\b/gi, "")
    .replace(/>\s*\$null\b/gi, "")
    .replace(/\d*>&\d+/g, "")
  const killTrigger = !bypassed?.has("os") && /\b(?:kill|pkill|killall|taskkill|stop-process)\b/i.test(combined)
  const networkTrigger = !bypassed?.has("web") && NETWORK_CLIENT_WORD.test(combined)
  const privilegeTrigger = !bypassed?.has("os") && /\b(?:sudo|runas)\b/i.test(combined)
  const overwriteTrigger = !bypassed?.has("filesystem") && /(?:^|[^>])>(?!>)/m.test(combinedWithoutFdMerges)
  if (killTrigger || networkTrigger || privilegeTrigger || overwriteTrigger) {
    return {
      verdict: "ASK",
      rules: ["operation.context-required"],
      reason: "The command performs a process, network, installation, privilege, or overwrite operation requiring review",
    }
  }

  // With any trigger-family category armed, the surviving fallback describes
  // itself as bypass-gated: the armed BYPASS RULE lets the dynamic reviewer
  // decide consistently instead of reading "unprovable" as high-risk.
  if (
    bypassed &&
    (bypassed.has("filesystem") || bypassed.has("os") || bypassed.has("secret") || bypassed.has("web"))
  ) {
    return {
      verdict: "ASK",
      rules: ["bypass.static-allow"],
      reason: "Static checks are disabled for this command's categories by a user-armed bypass",
    }
  }
  return {
    verdict: "ASK",
    rules: ["operation.unknown"],
    reason: "The local classifier cannot prove the complete command safe",
  }
}

async function classifySegments(
  script: string,
  input: InternalClassifyInput,
  depth = 0,
): Promise<SegmentDecision> {
  if (depth > MAX_WRAPPER_DEPTH) {
    return { verdict: "ASK", rules: ["execution.wrapper"], reason: "Command wrappers exceed the review depth limit" }
  }

  // Cross-segment variable tracking: in `D=rm; $D -rf x` neither segment alone
  // carries the delete shape (the assignment and the usage split apart), so
  // classify the substituted surface as well and keep the worse verdict.
  const varSurface = depth === 0 ? substituteDeleteVars(script) : undefined
  const substituted =
    varSurface && varSurface !== script ? await classifySegments(varSurface, input, depth + 1) : undefined

  const rawSegments = splitCommandSegments(script, input.shell) ?? [{ text: script }]
  const results: SegmentDecision[] = []
  let base: string | undefined = input.cwd
  let sawDirectoryChange = false

  for (const raw of rawSegments) {
    base = segmentBase(raw, base, input.cwd)
    const segment = raw.text.trim()
    if (!segment) continue
    const cd = parseCdSegment(segment)
    if (cd) {
      sawDirectoryChange = true
      base = resolveCdBase(cd.dir, base)
      continue
    }
    const decision = await classifySegment(
      segment,
      base ?? input.cwd,
      base === undefined ? { ...input, cwdUnknown: true } : input,
    )
    results.push(decision)
  }

  const direct =
    results.length === 0
      ? {
          verdict: "ALLOW" as SecurityVerdict,
          rules: [sawDirectoryChange ? "operation.directory-change" : "input.empty"],
          reason: sawDirectoryChange ? "The command only changes the working directory" : "The executable script is empty",
        }
      : combineSegmentDecisions(results)
  return substituted ? combineSegmentDecisions([direct, substituted]) : direct
}

const DOWNLOAD_OR_BUILD_PATTERN = new RegExp(
  [
    // Network download / transfer
    String.raw`\b(?:curl|wget|wget2|aria2c|yt-dlp|gdown|scp|rsync|invoke-webrequest|iwr|irm)\b`,
    String.raw`\bgit\s+(?:clone|fetch|pull|submodule\s+update)\b`,
    String.raw`\bgh\s+repo\s+clone\b`,
    String.raw`\b(?:hg|svn)\s+(?:clone|checkout|update)\b`,
    // Package manager install / dependency fetch / download-and-run
    String.raw`\b(?:npm|pnpm|yarn|bun)\s+(?:install|i|add|ci)\b`,
    String.raw`\b(?:npx|bunx|pnpm\s+dlx)\b`,
    String.raw`\b(?:pip(?:3)?|pipx|uv)\s+install\b`,
    String.raw`\b(?:cargo\s+(?:fetch|update|add)|go\s+(?:mod\s+download|get)|dotnet\s+(?:restore|add|tool\s+install))\b`,
    String.raw`\b(?:apt(?:-get)?\s+install|apt-get\s+(?:update|dist-upgrade)|brew\s+(?:install|upgrade|bundle)|winget\s+install|scoop\s+install|choco\s+install|dnf\s+install|yum\s+install|pacman\s+(?:-S|--sync))\b`,
    // Build / packaging
    String.raw`\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?(?:build|release)\b`,
    String.raw`\b(?:mvnw?|maven|gradle|gradlew)\s+(?:clean\s+)?(?:build|package|install|compile|verify|test|assemble|bundle|jar|compileJava|deploy)\b`,
    String.raw`\b(?:make|cmake\s+--build|meson\s+compile|ninja|cargo\s+build|go\s+build|dotnet\s+build|tsc|vite\s+build|webpack|rollup|esbuild|next\s+build|nuxt\s+build|svelte-kit\s+build)\b`,
  ].join("|"),
  "i",
)

export function isDownloadOrBuildCommand(script: string) {
  const value = stripLeadingDirectoryChanges(script.trim())
  return DOWNLOAD_OR_BUILD_PATTERN.test(value)
}

function isPowerShellShellName(shell: string) {
  const name = path.basename(shell).replace(/\.(?:exe|cmd|bat)$/i, "").toLowerCase()
  return name === "pwsh" || name === "powershell"
}

const DETACHED_START_PREFIX =
  /^(?:Start-Process\b|Start-Job\b|start\b|cmd(?:\.exe)?\s+(?:\/\/c|\/c)\s+start\b)/i

/**
 * `start` / `cmd /c start` / `Start-Process` launch detached processes that
 * inherit the bash tool's stdout/stderr pipe, so OpenCode waits for the pipe
 * to reach EOF and the command hangs until the launched program exits. This
 * rewrites the leading detached-start segment to redirect its handles away
 * from the pipe, letting the tool return immediately while the launched
 * program keeps running in the background.
 */
export function isolateDetachedStartCommand(command: string, shell: string) {
  const value = command.trim()
  const match = value.match(new RegExp(`^${DETACHED_START_PREFIX.source}([^;&|\\n]*)`, "i"))
  if (!match) return command
  const args = match[1] ?? ""
  if (/[<>]/.test(args)) return command
  const redirect = isPowerShellShellName(shell) ? "> $null 2>&1" : ">/dev/null 2>&1"
  const rest = value.slice(match[0].length)
  const separator = rest.match(/^\s*(&&|\|\||;|\||\r?\n)/)
  if (!separator) return `${value} ${redirect}`
  const sep = separator[1]
  const tail = rest.slice(separator[0].length).trim()
  const prefix = value.slice(0, match[0].length).trimEnd()
  return `${prefix} ${redirect} ${sep} ${tail}`
}

export async function classifyShellCommand(input: ClassifyShellCommandInput): Promise<StaticSecurityDecision> {
  const source = normalized(input.script).trim()
  if (!source) {
    return { verdict: "DENY", rules: ["input.empty"], reason: "The executable script is empty", fingerprints: [] }
  }
  if (source.length > MAX_COMMAND_CHARS || source.includes("\0")) {
    return {
      verdict: "ASK",
      rules: ["input.opaque"],
      reason: "The command is too large or contains opaque bytes for reliable local classification",
      fingerprints: [],
    }
  }
  const executableSurfaces = [source, ...extractDecodedPayloads(source), ...extractQuotedWrappers(source)]
  const bypassed = input.bypassedCategories
  // Pipe-separated segments are classified individually, so remote-pipe
  // (`curl ... | bash`) must be judged on the full script. HARD mode denies
  // download-and-execute outright; LOOSE defers it to the dynamic reviewer
  // (which applies the official-installer rule).
  const remotePipeRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "execution.remote-pipe")
  if (
    (input.strictness ?? "LOOSE") === "HARD" &&
    remotePipeRule &&
    !ruleBypassed("execution.remote-pipe", bypassed) &&
    remotePipeRule.test(source)
  ) {
    return {
      verdict: "DENY",
      rules: ["execution.remote-pipe"],
      reason: remotePipeRule.reason,
      fingerprints: [],
    }
  }
  // Reverse shells / xargs deletion may span `|`/`;` segments, so judge them
  // on the full script (both modes: these are DEFINITE-destructive). Reverse
  // shells are floor rules and never bypassable.
  const reverseShellRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "network.reverse-shell")
  const xargsRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "execution.xargs-destructive")
  for (const rule of [reverseShellRule, xargsRule]) {
    if (!rule || ruleBypassed(rule.id, bypassed)) continue
    if (rule.test(source)) {
      return { verdict: "DENY", rules: [rule.id], reason: rule.reason, fingerprints: [] }
    }
  }
  // Floor rules that can span `|`/`&` segment splits: fork bombs (the `&`
  // inside the function body splits the pattern) and kernel-trigger /
  // kernel-core-pattern writes via `tee`/`cp`-style pipes. `splitCommandSegments`
  // runs before the per-segment SECURITY_SIGNAL_RULES loop, so the per-segment
  // check alone never sees the full shape; these are floor rules (never
  // bypassable) and DEFINITE-destructive, so DENY on the full script up front.
  const forkBombRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "execution.fork-bomb")
  const kernelTriggerRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "filesystem.kernel-trigger")
  const kernelCorePatternRule = SECURITY_SIGNAL_RULES.find((rule) => rule.id === "filesystem.kernel-core-pattern")
  for (const rule of [forkBombRule, kernelTriggerRule, kernelCorePatternRule]) {
    if (!rule || ruleBypassed(rule.id, bypassed)) continue
    if (rule.test(executableSurfaces.join("\n\n"))) {
      return { verdict: "DENY", rules: [rule.id], reason: rule.reason, fingerprints: [] }
    }
  }
  // Literal piped into a shell interpreter: `printf 'rm -rf /' | sh`.
  const literalShell = /(?:echo|printf)\s+["'][^"']{0,200}?(?:\brm\b[^\n;|"'&]*-[rf]|\bshred\b|\brm\s+-rf\b)[^"']*["']\s*\|\s*(?:sh|bash|zsh|dash)\b/i.test(
    source,
  )
  if (literalShell) {
    return {
      verdict: "DENY",
      rules: ["execution.literal-shell"],
      reason: "Pipes a destructive literal command into a shell interpreter",
      fingerprints: [],
    }
  }
  const localScriptSurfaces: string[] = []
  const fingerprints: ScriptFingerprint[] = []
  const localScripts: LocalScriptReviewContext[] = []
  const uninspectedLocalScripts: string[] = []
  const targetDirectories: TargetDirectoryReviewContext[] = []
  const uninspectedTargetDirectories: string[] = []
  const referenced = referencedPathCandidates(source, input.shell)
  const deletionTargets = deletionTargetCandidates(source, input.shell, input.cwd)
  let cloudScriptChars = 0

  for (const candidate of localScriptCandidates(source, input.shell)) {
    const inspected = await fingerprintLocalScript(candidate, input.cwd, input.worktree)
    if (!inspected) {
      uninspectedLocalScripts.push(candidate)
      continue
    }
    fingerprints.push(inspected.fingerprint)
    localScriptSurfaces.push(normalized(inspected.content))
    if (cloudScriptChars + inspected.content.length <= MAX_CLOUD_LOCAL_SCRIPT_CHARS) {
      localScripts.push({
        path: inspected.reviewPath,
        content: inspected.content,
        sha256: inspected.fingerprint.sha256,
      })
      cloudScriptChars += inspected.content.length
    } else {
      // Single file exceeds cloud budget: send head+tail window with truncation marker
      const content = inspected.content
      const headSize = 64000
      const tailSize = 64000
      if (content.length > headSize + tailSize) {
        const head = content.slice(0, headSize)
        const tail = content.slice(content.length - tailSize)
        const middleOmitted = content.length - headSize - tailSize
        localScripts.push({
          path: inspected.reviewPath,
          content: head + `\n[TRUNCATED: middle ${middleOmitted} bytes omitted of ${content.length} total]\n` + tail,
          sha256: inspected.fingerprint.sha256,
        })
      } else {
        localScripts.push({
          path: inspected.reviewPath,
          content: content,
          sha256: inspected.fingerprint.sha256,
        })
      }
      uninspectedLocalScripts.push(candidate)
    }
  }

  for (const candidate of deletionTargets.items) {
    const inspected = await inspectTargetDirectory(candidate.target, candidate.cwd, input.worktree)
    if (inspected.context) targetDirectories.push(inspected.context)
    if (inspected.uninspected) uninspectedTargetDirectories.push(inspected.uninspected)
  }

  const reviewContext: StaticReviewContext = {
    localScripts,
    uninspectedLocalScripts,
    targetDirectories,
    uninspectedTargetDirectories,
    referencedPaths: referenced.paths,
    referencedPathsTruncated: referenced.truncated,
  }
  const decisionState = { fingerprints, reviewContext }
  const executableCombined = executableSurfaces.join("\n\n")
  const localScriptCombined = localScriptSurfaces.join("\n\n")

  const segmentDecision = await classifySegments(source, input)

  if (segmentDecision.verdict === "DENY") {
    return { verdict: "DENY", rules: segmentDecision.rules, reason: segmentDecision.reason, ...decisionState }
  }

  if (deletionTargets.truncated && !bypassed?.has("filesystem")) {
    return {
      verdict: "ASK",
      rules: [...new Set([...segmentDecision.rules, "filesystem.deletion-targets-truncated"])],
      reason: "The command has more deletion targets than can be inspected safely",
      ...decisionState,
    }
  }

  if (
    await isExplicitDisposableCleanup(source, input.cwd, input.worktree) &&
    executableSurfaces.length === 1 &&
    localScriptSurfaces.length === 0 &&
    (input.strictness ?? "LOOSE") !== "HARD"
  ) {
    return {
      verdict: "ALLOW",
      rules: ["cleanup.disposable"],
      reason: "Cleanup is narrowly scoped to a recognized disposable cache, dependency, build, or temporary target",
      ...decisionState,
    }
  }

  const extraSignals = new Map<string, string>()
  for (const rule of SECURITY_SIGNAL_RULES) {
    if (ruleBypassed(rule.id, bypassed)) continue
    if (rule.id === "execution.remote-pipe" && rule.test(executableCombined)) {
      extraSignals.set(rule.id, rule.reason)
    }
  }
  if (localScriptCombined) {
    for (const rule of SECURITY_SIGNAL_RULES) {
      if (ruleBypassed(rule.id, bypassed)) continue
      if (rule.test(localScriptCombined)) extraSignals.set(rule.id, rule.reason)
    }
    // Exfiltration primitives inside an inspected script must surface as review
    // signals too; without this, `bash script.sh` with a curl -T/scp upload is
    // ALLOWed on the strength of the script's otherwise-clean content.
    const scriptExfil = hasExfilOrDangerousPerms(localScriptCombined, localScriptCombined, {
      cwd: input.cwd,
      worktree: input.worktree,
      strictness: input.strictness ?? "LOOSE",
    })
    if (scriptExfil && !ruleBypassed(scriptExfil, bypassed)) {
      extraSignals.set(
        scriptExfil,
        scriptExfil === "permissions.sensitive-mode"
          ? "The local script sets dangerous permissions on a credential or system file and requires review"
          : "The local script sends credential or system data off-host and requires review",
      )
    }
    if (!ruleBypassed("data.critical-delete", bypassed) && hasCriticalDataDestruction(localScriptCombined)) {
      extraSignals.set("data.critical-delete", "Local script may delete credential or key material and requires review")
    }
    if (!ruleBypassed("data.destructive-delete", bypassed) && hasGeneralDataDestruction(localScriptCombined)) {
      extraSignals.set("data.destructive-delete", "Local script may delete durable data and requires semantic review")
    }
    if (!ruleBypassed("data.destructive-overwrite", bypassed) && hasDestructiveOverwrite(localScriptCombined)) {
      extraSignals.set("data.destructive-overwrite", "Local script may overwrite durable data and requires semantic review")
    }
    if (hasLocalScriptReviewSignal(localScriptCombined) && !ruleBypassed("execution.local-script-signal", bypassed)) {
      extraSignals.set("execution.local-script-signal", "Local script contains a review-requiring primitive")
    }
  }

  if (
    segmentDecision.verdict === "ASK" &&
    segmentDecision.rules.length === 1 &&
    segmentDecision.rules[0] === "execution.local-script" &&
    localScriptSurfaces.length > 0 &&
    uninspectedLocalScripts.length === 0 &&
    extraSignals.size === 0
  ) {
    return {
      verdict: "ALLOW",
      rules: ["execution.local-script-inspected"],
      reason: "The local script was fully read and fingerprinted and contains no review-requiring behavior",
      ...decisionState,
    }
  }

  const rules = [...segmentDecision.rules]
  for (const [id, reason] of extraSignals) {
    if (!rules.includes(id)) rules.push(id)
  }
  if (segmentDecision.verdict === "ALLOW" && extraSignals.size > 0) {
    return {
      verdict: "ASK",
      rules,
      reason: [...extraSignals.values()][0],
      ...decisionState,
    }
  }

  return { verdict: segmentDecision.verdict, rules, reason: segmentDecision.reason, ...decisionState }
}
