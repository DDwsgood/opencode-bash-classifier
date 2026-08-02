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
}

export type CloudReviewDecision = "ALLOW" | "DENY"

export type CloudReviewResult = {
  decision: CloudReviewDecision
  reason: string
}

export type CloudReviewRequest = {
  command: string
  localScripts: LocalScriptReviewContext[]
  uninspectedLocalScripts: string[]
  targetDirectories: TargetDirectoryReviewContext[]
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

export declare const BashSummaryPlugin: Plugin
export default BashSummaryPlugin

export declare function classifyShellCommand(input: ClassifyShellCommandInput): Promise<StaticSecurityDecision>
export declare function verifyScriptFingerprints(fingerprints: ScriptFingerprint[]): Promise<boolean>
export declare function reviewCommandWithDeepSeek(
  request: CloudReviewRequest | string,
  options?: ReviewCommandOptions,
): Promise<CloudReviewResult>
