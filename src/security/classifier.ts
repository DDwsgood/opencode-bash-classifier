import { createHash } from "node:crypto"
import type { Dirent } from "node:fs"
import { lstat, readFile, readdir, realpath, stat } from "node:fs/promises"
import path from "node:path"

export type SecurityVerdict = "ALLOW" | "DENY" | "ASK"

export type ScriptFingerprint = {
  path: string
  size: number
  mtimeMs: number
  sha256: string
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
}

type InternalClassifyInput = ClassifyShellCommandInput & {
  /** The effective working directory of this segment is not statically known. */
  cwdUnknown?: boolean
}

const MAX_COMMAND_CHARS = 128_000
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
  /\b(?:rm|ri|del|erase|rmdir|rd|remove-item|clear-content|unlink|unlinkSync|rmSync|rmtree|os\.remove|os\.unlink|shutil\.rmtree)\b|(?:^|\s)-delete(?:\s|$)|\.unlink\s*\(/i
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

async function isNamedTempTargetResolved(target: string, base: string | undefined) {
  if (base === undefined) return false
  const literal = literalPathToken(target)
  if (!literal) return false
  const cleaned = literal.replaceAll("\\", "/")
  if (cleaned.split("/").some((segment) => segment === "..")) return false
  const lexical = normalizeMsysPath(path.resolve(normalizeMsysPath(base), cleaned))
  if (!hasNamedTempPathSegment(lexical)) return false
  const canonical = await canonicalProjectedPath(lexical)
  return Boolean(canonical && hasNamedTempPathSegment(canonical))
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
  }
  return false
}

function hasDeletePrimitive(text: string): boolean {
  const stripped = text.replace(/'[^']*'/g, "").replace(/"(?:[^"]|"")*"/g, "")
  return DELETE_PRIMITIVE.test(stripped)
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
    reason: "Attempts broad recursive deletion at a filesystem, home, or working-directory root",
    test: (text) =>
      /\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+(?:--no-preserve-root\s+)?(?:\/|~\/?|\.\.?\/?|\*)(?:\s|$|[;&|])/im.test(text) ||
      /\b(?:rmdir|rd)\s+\/s\s+\/q\s+(?:[a-z]:\\|\\|\/|\.\.?|\*)(?:\s|$)/im.test(text) ||
      /\bdel\s+\/[a-z]*s[a-z]*\s+\/[a-z]*q[a-z]*\s+(?:[a-z]:\\|\\|\/|\*)(?:\s|$)/im.test(text) ||
      /\bremove-item\b[^\n]*(?:-recurse[^\n]*-force|-force[^\n]*-recurse)[^\n]*(?:[a-z]:\\(?:\*|$)|\/(?:\*|$)|~(?:\/|\s|$)|\.\.?(?:\/|\s|$)|\*)(?:\s|$)/im.test(
        text,
      ),
  },
  {
    id: "filesystem.disk-destruction",
    reason: "Attempts to format, overwrite, or destroy a disk or filesystem",
    test: (text) =>
      /\b(?:mkfs(?:\.\w+)?|wipefs|fdisk|parted)\b/i.test(text) ||
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
      /\bkill\s+(?:-[a-z]*9|-KILL)\s+(?:-1|0|1)\b/i.test(text) ||
      /\b(?:pkill|killall)\b[^\n]*(?:-9|-KILL)\b/i.test(text) ||
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
      /\baws\s+s3\s+rm\b[^\n]*--recursive\b/i.test(text) ||
      /\bgcloud\s+[^\n]*\bdelete\b[^\n]*(?:project|cluster|instance)\b/i.test(text),
  },
  {
    id: "git.irrecoverable-change",
    reason: "Attempts to discard local work or rewrite shared Git history",
    test: (text) =>
      /\bgit\s+clean\b[^\n]*(?:-[a-z]*f[a-z]*d[a-z]*x|-[a-z]*x[a-z]*d[a-z]*f)\b/i.test(text) ||
      /\bgit\s+reset\s+--hard\b/i.test(text) ||
      /\bgit\s+(?:checkout|restore)\s+--?\s*(?:\.|\*)\b/i.test(text) ||
      /\bgit\s+push\b[^\n]*(?:--force(?:-with-lease)?|-f)\b/i.test(text),
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
      /\b(?:systemctl\s+enable|launchctl\s+enable)\b/i.test(text),
  },
  {
    id: "network.reverse-shell",
    reason: "Contains a reverse-shell or remote-control primitive",
    test: (text) =>
      /\/dev\/tcp\/|\/dev\/udp\//i.test(text) ||
      /\b(?:nc|ncat|netcat)\b[^\n]*(?:\s-e\s|\s--exec\s)/i.test(text) ||
      /\bsocket\.connect\s*\([^)]*(?:4444|1337|9001)/i.test(text),
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
  "filesystem.disk-destruction",
  "filesystem.backup-destruction",
  "system.service-destruction",
  "system.shutdown",
  "system.critical-process-kill",
  "database.destructive-statement",
  "infrastructure.destructive-operation",
])

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
  if (!["rm", "remove-item", "del", "erase", "unlink", "rmdir", "rd", "ri"].includes(command ?? "")) {
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
      if (base === undefined || !(await deletionTargetsAreNamedTemp(deletion.targets, base))) {
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

async function deletionTargetsAreNamedTemp(targets: string[], base: string) {
  for (const target of targets) {
    if (!(await isNamedTempTargetResolved(target, base))) return false
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

function isExplicitDisposableCleanup(script: string) {
  const value = stripLeadingDirectoryChanges(script).replace(/\s+/g, " ").trim()
  const disposableDirectory =
    String.raw`(?:\.?[\\/])?(?:node_modules|dist|build|coverage|target|\.cache|\.pytest_cache|__pycache__)(?:[\\/]|\b)`
  const reinstall = String.raw`(?:\s*&&\s*(?:npm|pnpm|yarn|bun)\s+(?:install|i))?`
  const patterns = [
    new RegExp(String.raw`^rm\s+-[a-z]*[rf][a-z]*\s+${disposableDirectory}[\\/]?${reinstall}$`, "i"),
    /^rm\s+-f\s+(?:\/tmp\/[^\s;&|]+|~[\\/]Downloads[\\/][^\s;&|]*\.tmp)$/i,
    /^find\s+\/tmp\b[^;&|]*\s-mtime\s+\+\d+\b[^;&|]*\s-delete$/i,
    new RegExp(
      String.raw`^remove-item\s+(?:"|')?${disposableDirectory}(?:"|')?\s+(?:(?:-recurse|-force)\s*){1,2}$`,
      "i",
    ),
  ]
  if (patterns.some((pattern) => pattern.test(value))) return true

  const rmMultiMatch = value.match(/^rm\s+-[a-z]*[rf][a-z]*\s+(.+)$/i)
  if (rmMultiMatch) {
    const targets = rmMultiMatch[1].trim().split(/\s+/)
    const disposablePattern =
      /^(?:\.?[\\/])?(?:node_modules|dist|build|coverage|target|\.cache|\.pytest_cache|__pycache__)[\\/]?$/i
    if (targets.length > 0 && targets.every((t) => disposablePattern.test(t))) return true
  }

  const invocation = value.match(/^(?:remove-item|rm)\s+(.+)$/i)
  if (!invocation) return false
  const tokens = invocation[1].match(/"(?:[^"]|"")*"|'[^']*'|\S+/g) ?? []
  const flags = tokens.filter((token) => token.startsWith("-")).map((token) => token.toLowerCase())
  if (!flags.includes("-recurse")) return false
  if (flags.some((flag) => !["-recurse", "-force", "-path", "-literalpath"].includes(flag))) return false

  let target: string | undefined
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]
    const flag = token.toLowerCase()
    if (flag === "-path" || flag === "-literalpath") {
      if (target || !tokens[index + 1]) return false
      target = tokens[index + 1]
      index += 1
      continue
    }
    if (token.startsWith("-")) continue
    if (target) return false
    target = token
  }
  if (!target) return false

  const normalizedTarget = target
    .replace(/^(["'])([\s\S]*)\1$/, "$2")
    .replaceAll("\\", "/")
    .replace(/\/+$/, "")
  return /(?:^|\/)(?:node_modules|dist|build|coverage|target|\.cache|\.pytest_cache|__pycache__)(?:\/.*)?$/i.test(
    normalizedTarget,
  )
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

function stripTimeoutPrefix(segment: string): string | undefined {
  const tokens = simpleInvocationTokens(segment.trim())
  if (commandLeaf(tokens[0] ?? "") !== "timeout") return segment
  let index = 1
  while (index < tokens.length) {
    const lower = tokens[index].toLowerCase()
    if (lower === "--" || !lower.startsWith("-")) break
    if (lower === "-k" || lower === "--kill-after" || lower === "-s" || lower === "--signal") {
      index += 2
      continue
    }
    index += 1
  }
  if (index >= tokens.length) return undefined
  index += 1
  if (index >= tokens.length) return undefined
  return tokens.slice(index).join(" ")
}

function stripHarmlessPrefixes(segment: string): string {
  let result = segment.trim()
  for (let depth = 0; depth < 3; depth += 1) {
    const subshell = result.match(/^\(([\s\S]+)\)$/)
    if (subshell) {
      result = subshell[1].trim()
      continue
    }
    const timeoutStripped = stripTimeoutPrefix(result)
    if (timeoutStripped && timeoutStripped !== result) {
      result = timeoutStripped
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
    if (character === "&" && /(?:^|\s)\d*>\s*$/.test(current) && /^\d$/.test(value[index + 1] ?? "")) {
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

function splitSimpleSegments(script: string, shell: string) {
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
    segment
      .replace(/(?:\s+\d*>&\d+)+\s*$/, "")
      .replace(/^(?:[A-Za-z_][A-Za-z0-9_]*=[^\s]+\s+)*/, "")
      .trim(),
  )
  if (!value) return true
  const harmlessValue = value
    .replace(/>\s*\/dev\/(?:null|stdout|stderr)\b/gi, "")
    .replace(/>\s*\$null\b/gi, "")
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
  if (/^git\s+(?:fetch|clone|checkout\s+-b|stash\s+(?:list|push)|branch\s+(?!-[dDm]\b)\S+|tag\s+(?!-[dD]\b)\S+)\b/i.test(value)) return true
  if (/^(?:mkdir|New-Item\s+[^\n]*-ItemType\s+Directory)\b/i.test(value)) return true
  if (/^(?:tar\s+-[a-z]*c[a-z]*f|zip\s+-r)\b/i.test(value)) return !/--remove-files\b/i.test(value)
  if (/^(?:cp|copy|Copy-Item)\b/i.test(value)) return false
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
  if (/^(?:pip(?:3)?|pipx|uv)\s+(?:install|add)\b/i.test(value)) return true
  if (/^cargo\s+(?:add|fetch|update)\b/i.test(value)) return true
  if (/^go\s+(?:get|mod\s+download)\b/i.test(value)) return true
  if (/^dotnet\s+(?:restore|build)\b/i.test(value)) return true
  if (/^(?:cargo\s+build|go\s+build|cmake\s+--build|ninja|vite\s+build|next\s+build|nuxt\s+build|svelte-kit\s+build|webpack|rollup|esbuild|tsc)\b/i.test(value)) return true
  if (/^make\b/i.test(value) && !/\bclean\b/i.test(value)) return true
  if (/^(?:mvnw?|maven|gradlew?)\s+(?:build|package|compile|install|verify|assemble|bundle|jar|compileJava|deploy)\b/i.test(value) && !/\bclean\b/i.test(value)) return true
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
    /\bsed\b[^\n]*-i\b[^\n]*\.(?:csv|json|db|sqlite|xlsx?|parquet)\b/i.test(text) ||
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
  return {
    content: content.toString("utf8"),
    reviewPath: path.relative(worktree, canonical).replaceAll("\\", "/") || path.basename(canonical),
    fingerprint: {
      path: canonical,
      size: info.size,
      mtimeMs: info.mtimeMs,
      sha256: createHash("sha256").update(content).digest("hex"),
    } satisfies ScriptFingerprint,
  }
}

export async function verifyScriptFingerprints(fingerprints: ScriptFingerprint[]) {
  for (const fingerprint of fingerprints) {
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

  if (hasForcedRecursiveDelete(combined)) {
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
        if (hasNamedTempPathSegment(cleaned)) {
          return {
            verdict: "DENY",
            rules: ["hard.temp-target-delete"],
            reason: `Permanent deletion of temp/tmp targets is forbidden. ${PERMANENT_DELETE_GUIDANCE}`,
            fingerprints: [],
          }
        }
        const literal = literalPathToken(target)
        if (literal && backupPathIdentity(literal)) {
          return {
            verdict: "DENY",
            rules: ["hard.backup-target-delete"],
            reason: `Permanent deletion of backup targets is forbidden. ${PERMANENT_DELETE_GUIDANCE}`,
            fingerprints: [],
          }
        }
        if (base && roots.length > 0 && (await isTrustedTempPath(target, base, roots))) {
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

async function classifySegment(
  segment: string,
  base: string,
  input: InternalClassifyInput,
): Promise<SegmentDecision> {
  const segInput: InternalClassifyInput = { ...input, script: segment, cwd: base }
  const strictness: Strictness = input.strictness ?? "LOOSE"

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
    return {
      verdict: "DENY",
      rules: ["filesystem.recycle-bin-permanent-delete"],
      reason: "Permanently deleting recycle-bin contents is forbidden",
    }
  }

  const recycle = explicitRecycleBinOperation(segment, input.shell)
  if (recycle) {
    if (strictness === "HARD") {
      const tempRoots = await trustedUserLocalTempRoots(segInput)
      for (const target of recycle.targets) {
        const literal = literalPathToken(target)
        const protectedTarget = Boolean(
          literal && (backupPathIdentity(literal) || hasNamedTempPathSegment(literal)),
        )
        const inLocalTemp = tempRoots.length > 0 && await isTrustedTempPath(target, base, tempRoots)
        if (protectedTarget || inLocalTemp) {
          return {
            verdict: "DENY",
            rules: ["filesystem.protected-target-delete"],
            reason: `Removing a protected temporary or backup target is forbidden. ${PERMANENT_DELETE_GUIDANCE}`,
          }
        }
      }
      if (recycle.targets.some(isCriticalDeletionTarget)) {
        return {
          verdict: "DENY",
          rules: ["data.critical-delete"],
          reason: `Attempts to delete credential or key material. ${PERMANENT_DELETE_GUIDANCE}`,
        }
      }
      if (recycle.targets.some(isGeneralDataTarget)) {
        return {
          verdict: "DENY",
          rules: ["data.destructive-delete"],
          reason: `Attempts to delete a durable structured data file. ${PERMANENT_DELETE_GUIDANCE}`,
        }
      }
      return {
        verdict: "ASK",
        rules: ["filesystem.recycle-bin"],
        reason: "Moving this item to the recycle bin requires review",
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
    const hardDecision = await classifyHardDeletionPolicy(segment, segInput)
    if (hardDecision) {
      return { verdict: hardDecision.verdict, rules: hardDecision.rules, reason: hardDecision.reason }
    }
    const backupDecision = await classifyBackupPolicy(segment, segInput)
    if (backupDecision) {
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
      if (namedTempDecision) {
        return { verdict: namedTempDecision.verdict, rules: namedTempDecision.rules, reason: namedTempDecision.reason }
      }

      const userLocalTempDecision = await classifyUserLocalTempSegment(segment, segInput)
      if (userLocalTempDecision) {
        return {
          verdict: userLocalTempDecision.verdict,
          rules: userLocalTempDecision.rules,
          reason: userLocalTempDecision.reason,
        }
      }
      const backupDecision = await classifyBackupPolicy(segment, segInput)
      if (backupDecision) {
        return { verdict: backupDecision.verdict, rules: backupDecision.rules, reason: backupDecision.reason }
      }
    }
  }

  const surfaces = [segment, ...extractDecodedPayloads(segment), ...extractQuotedWrappers(segment)]
  const combined = surfaces.map(maskHeredocBody).join("\n\n")
  const reviewSignals = new Map<string, string>()
  const explicitDisposableCleanup = isExplicitDisposableCleanup(segment) && surfaces.length === 1

  const knownSafe = isKnownSafeSegment(segment)
  const hasExpansion = hasDynamicShellExpansion(segment, input.shell)
  if (knownSafe && !hasExpansion && !hasFileWritePrimitive(segment)) {
    return {
      verdict: "ALLOW",
      rules: ["operation.known-safe"],
      reason: "The segment is a recognized read-only or normal low-risk development action",
    }
  }

  for (const rule of SECURITY_SIGNAL_RULES) {
    if (rule.test(combined)) {
      if (DEFINITE_DESTRUCTIVE_RULES.has(rule.id)) {
        if (rule.id === "filesystem.forced-recursive-delete" && explicitDisposableCleanup && strictness !== "HARD") continue
        return { verdict: "DENY", rules: [rule.id], reason: rule.reason }
      }
      reviewSignals.set(rule.id, rule.reason)
    }
  }
  if (hasCriticalDataDestruction(combined)) {
    return {
      verdict: "DENY",
      rules: ["data.critical-delete"],
      reason: strictness === "HARD"
        ? `Attempts to delete credential or key material. ${PERMANENT_DELETE_GUIDANCE}`
        : "Attempts to delete credential or key material",
    }
  }
  if (hasGeneralDataDestruction(combined)) {
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
  if (hasDestructiveOverwrite(combined)) {
    reviewSignals.set(
      "data.destructive-overwrite",
      "Attempts in-place destructive modification of durable structured data",
    )
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

  if (localScriptCandidates(segment, input.shell).length > 0) {
    return {
      verdict: "ASK",
      rules: ["execution.local-script"],
      reason: "The command executes a local script and requires contextual review",
    }
  }

  if (
    WRAPPER_PRIMITIVE.test(combined) ||
    hasDynamicShellExpansion(combined, input.shell) ||
    extractDecodedPayloads(segment).length > 0
  ) {
    return {
      verdict: "ASK",
      rules: ["execution.wrapper"],
      reason: "The command uses an interpreter, encoded payload, or dynamic execution wrapper",
    }
  }

  if (hasDeletePrimitive(combined)) {
    return {
      verdict: "ASK",
      rules: ["filesystem.scoped-delete"],
      reason: "The command deletes files but is not an obvious broad or durable-data deletion",
    }
  }

  const combinedWithoutFdMerges = combined
    .replace(/>\s*\/dev\/(?:null|stdout|stderr)\b/gi, "")
    .replace(/>\s*\$null\b/gi, "")
    .replace(/\d*>&\d+/g, "")
  if (
    /\b(?:kill|pkill|killall|taskkill|stop-process)\b/i.test(combined) ||
    /\b(?:curl|wget|invoke-webrequest|iwr|irm|ssh|scp|rsync)\b/i.test(combined) ||
    /\b(?:sudo|runas)\b/i.test(combined) ||
    /(?:^|[^>])>(?!>)/m.test(combinedWithoutFdMerges)
  ) {
    return {
      verdict: "ASK",
      rules: ["operation.context-required"],
      reason: "The command performs a process, network, installation, privilege, or overwrite operation requiring review",
    }
  }

  if (isKnownSafeSegment(segment)) {
    return {
      verdict: "ALLOW",
      rules: ["operation.known-safe"],
      reason: "The segment is a recognized read-only or normal low-risk development action",
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

  if (results.length === 0) {
    return {
      verdict: "ALLOW",
      rules: [sawDirectoryChange ? "operation.directory-change" : "input.empty"],
      reason: sawDirectoryChange ? "The command only changes the working directory" : "The executable script is empty",
    }
  }
  return combineSegmentDecisions(results)
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

  if (deletionTargets.truncated) {
    return {
      verdict: "ASK",
      rules: [...new Set([...segmentDecision.rules, "filesystem.deletion-targets-truncated"])],
      reason: "The command has more deletion targets than can be inspected safely",
      ...decisionState,
    }
  }

  if (
    isExplicitDisposableCleanup(source) &&
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
    if (rule.id === "execution.remote-pipe" && rule.test(executableCombined)) {
      extraSignals.set(rule.id, rule.reason)
    }
  }
  if (localScriptCombined) {
    for (const rule of SECURITY_SIGNAL_RULES) {
      if (rule.test(localScriptCombined)) extraSignals.set(rule.id, rule.reason)
    }
    if (hasCriticalDataDestruction(localScriptCombined)) {
      extraSignals.set("data.critical-delete", "Local script may delete credential or key material and requires review")
    }
    if (hasGeneralDataDestruction(localScriptCombined)) {
      extraSignals.set("data.destructive-delete", "Local script may delete durable data and requires semantic review")
    }
    if (hasDestructiveOverwrite(localScriptCombined)) {
      extraSignals.set("data.destructive-overwrite", "Local script may overwrite durable data and requires semantic review")
    }
    if (hasLocalScriptReviewSignal(localScriptCombined)) {
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
