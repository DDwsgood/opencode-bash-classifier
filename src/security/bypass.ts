// Bypass-category escape hatches for the static classifier.
//
// A session's armed categories flow in as `bypassedCategories` on the classify
// input. Rules tagged with a category are skipped when that category is armed,
// EXCEPT for the unconditional floor: literal filesystem-root and
// system-critical-root destruction, disk-device destruction, fork bombs,
// kernel execution primitives, and reverse shells are always enforced
// regardless of any bypass.

import type { BypassCategory } from "../config"

/** Rules that no bypass category may ever disable. */
const FLOOR_RULES = new Set([
  // Literal root and system-critical-root destruction (`rm -rf /`,
  // `rm -rf /etc`, brace-root deletes, root-glob deletes, `find / -delete`).
  "filesystem.root-delete",
  "filesystem.brace-root-delete",
  "filesystem.root-glob-delete",
  "filesystem.find-delete-root",
  // Whole-disk / device destruction.
  "filesystem.disk-destruction",
  // Process storms and kernel execution primitives.
  "execution.fork-bomb",
  "filesystem.kernel-trigger",
  "filesystem.kernel-core-pattern",
  // Remote-control primitives stay out of scope of every category (including
  // `web`, whose trust semantics cover HTTP destinations, not shells).
  "network.reverse-shell",
  "execution.literal-shell",
])

/** Default rule → bypass-category membership. Prefix keys cover every rule
 * whose id starts with them. */
const RULE_PREFIXES: ReadonlyArray<readonly [string, BypassCategory]> = [
  ["filesystem.", "filesystem"],
  ["data.", "filesystem"],
  ["git.irrecoverable-change", "filesystem"],
  ["cleanup.", "filesystem"],
  ["operation.", "filesystem"],
  ["execution.unparseable-path", "filesystem"],
  ["execution.local-script", "filesystem"],
  ["execution.local-script-inspected", "filesystem"],
  ["execution.local-script-signal", "filesystem"],
  ["execution.wrapper", "filesystem"],

  ["system.", "os"],
  ["process.", "os"],
  ["permissions.", "os"],
  ["kernel.", "os"],
  ["namespace.", "os"],
  ["persistence.", "os"],
  ["forensic.", "os"],
  ["git.remote-history-rewrite", "os"],
  ["infrastructure.", "os"],
  ["database.", "os"],
  ["execution.encoded-shell", "os"],
  ["execution.kernel-module-load", "os"],

  ["credentials.", "secret"],
  ["exfiltration.", "secret"],

  ["network.", "web"],
]

/** Exact overrides for rules the prefix table cannot express precisely.
 * `undefined` marks a rule that is deliberately NOT bypassable. */
const RULE_EXACT: ReadonlyArray<readonly [string, BypassCategory | undefined]> = [
  // Credential/key-material data rules follow the secret category, not the
  // filesystem category: arming `secret` must clear them and arming
  // `filesystem` alone must not.
  ["data.critical-delete", "secret"],
  ["data.critical-read", "secret"],
  ["data.critical-write", "secret"],
  // Secret-flavored filesystem rules.
  ["filesystem.compression-sensitive", "secret"],
  ["filesystem.critical-backup", "secret"],
  ["permissions.sensitive-mode", "secret"],
  // Snapshot/recovery-data destruction is data destruction: filesystem family
  // (vssadmin delete shadows, zfs destroy tank/backup).
  ["filesystem.backup-destruction", "filesystem"],
  // Filesystem-flavored execution rules.
  ["execution.script-one-liner-destructive", "filesystem"],
  ["execution.xargs-destructive", "filesystem"],
  // Web-flavored execution rule (download-and-execute).
  ["execution.remote-pipe", "web"],
  // HARD-mode policy rules follow the filesystem category they enforce.
  ["hard.forced-recursive-delete", "filesystem"],
  ["hard.temp-target-delete", "filesystem"],
  ["hard.named-temp-delete", "filesystem"],
  ["hard.backup-delete", "filesystem"],
  ["hard.backup-target-delete", "filesystem"],
  ["hard.local-temp-delete", "filesystem"],
  // Recycle-bin permanent deletion is filesystem-destroying behavior and is
  // explicitly covered by the filesystem bypass (user spec: stop all
  // filesystem checks); classifier.ts gates it with the same category.
  ["filesystem.recycle-bin-permanent-delete", "filesystem"],
  // Empty/opaque input is never bypassable (classifier.ts checks it before
  // consulting bypassedCategories).
  ["input.empty", undefined],
  ["input.opaque", undefined],
]

const EXACT_MAP = new Map<string, BypassCategory | undefined>(RULE_EXACT)

/** Returns the bypass category a rule id belongs to, or undefined when the rule
 * is not bypassable at all (floor rules, unclassified rules). */
export function ruleBypassCategory(rule: string): BypassCategory | undefined {
  if (FLOOR_RULES.has(rule)) return undefined
  if (EXACT_MAP.has(rule)) return EXACT_MAP.get(rule)
  for (const [prefix, category] of RULE_PREFIXES) {
    if (rule.startsWith(prefix)) return category
  }
  return undefined
}

/** True when the rule is disabled by one of the armed bypass categories. */
export function ruleBypassed(rule: string, bypassed: ReadonlySet<BypassCategory> | undefined): boolean {
  if (!bypassed || bypassed.size === 0) return false
  const category = ruleBypassCategory(rule)
  return category !== undefined && bypassed.has(category)
}