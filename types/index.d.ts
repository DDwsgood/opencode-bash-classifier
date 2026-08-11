import type { Plugin } from "@opencode-ai/plugin"

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

export type ClassifyShellCommandInput = {
  script: string
  cwd: string
  worktree: string
  shell: string
  nowMs?: number
  trustedTempRoot?: string
  strictness?: Strictness
}

/** Review strictness. LOOSE allows temp/backup/cleanup relaxation; HARD disables it. */
export type Strictness = "LOOSE" | "HARD"

/** Policy applied when dynamic review cannot reach a verdict. */
export type FailPolicy = "fail_ask" | "fail_open" | "fail_close"

export type CloudReviewDecision = "ALLOW" | "DENY"

export type PreviousRejectedCommand = {
  command: string
  reason: string
  /** Strict uppercase union naming the classifier that produced the rejection. */
  classifier: "STATIC" | "DYNAMIC" | "FAIL_POLICY"
}

export type PreviousFailedCommand = {
  command: string
  exitCode: number
  outputTail?: string
}

/** The bypass flag is emitted only by the strict dynamic-review policy. */
export type CloudReviewResult = {
  decision: CloudReviewDecision
  reason: string
  bypassing?: boolean
}

export type CloudReviewRequest = {
  command: string
  localScripts: LocalScriptReviewContext[]
  uninspectedLocalScripts: string[]
  targetDirectories: TargetDirectoryReviewContext[]
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
  policy: Strictness
  allowFullReadAccess?: boolean
  python?: string
  auditorPath?: string
  timeout?: number
  signal?: AbortSignal
}

export type ReviewCommand = (
  request: CloudReviewRequest,
  options: ReviewCommandOptions,
) => Promise<CloudReviewResult>

export type DynamicReviewOptions = {
  baseURL?: string
  model?: string
  apiKey?: string
  apiKeyEnv?: string
  timeoutMs?: number
  maxRounds?: number
  /** Allow bounded read-only tools to inspect the full filesystem. */
  allowFullReadAccess?: boolean
  /** Python interpreter for the auditor. A bare command name (no path separator)
   * defers to PATH lookup at spawn time; a path containing a separator is resolved
   * relative to the package root and must be an existing regular file. */
  pythonPath?: string
  /** Path to the auditor script. Relative paths resolve against the package root
   * and must point to an existing regular file (directories are rejected). */
  auditorPath?: string
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
  /** Test-injection only; never wired by the plugin itself. */
  reviewCommand?: ReviewCommand
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
  dynamicReview: ResolvedDynamicReview
  reviewCommand?: ReviewCommand
}

export declare const BashSummaryPlugin: Plugin
export default BashSummaryPlugin

export declare function classifyShellCommand(input: ClassifyShellCommandInput): Promise<StaticSecurityDecision>
export declare function verifyScriptFingerprints(fingerprints: ScriptFingerprint[]): Promise<boolean>
export declare function reviewCommandWithAuditor(
  request: CloudReviewRequest | string,
  options: ReviewCommandOptions,
): Promise<CloudReviewResult>
/**
 * @deprecated Use {@link reviewCommandWithAuditor} instead. This alias is kept only
 * for backwards-compatible imports and will be removed in a future release.
 */
export declare function reviewCommandWithDeepSeek(
  request: CloudReviewRequest | string,
  options: ReviewCommandOptions,
): Promise<CloudReviewResult>
export declare function resolvePluginConfig(raw?: BashClassifierOptions): ResolvedPluginConfig
