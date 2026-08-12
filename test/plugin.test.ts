import { describe, expect, test } from "bun:test"
import path from "node:path"
import BashSummaryPlugin from "../src/index"
import type { CloudReviewRequest, ReviewCommandOptions } from "../src/security/reviewer"

function createMockClient() {
  const abortCalls: Array<{ id: string; directory: string }> = []
  const client = {
    session: {
      abort: async (opts: {
        path: { id: string }
        query?: { directory?: string }
        throwOnError?: boolean
      }) => {
        abortCalls.push({ id: opts.path.id, directory: opts.query?.directory ?? "" })
        return { data: true, error: undefined, request: {} }
      },
    },
  }
  return { client: client as never, abortCalls }
}

function context() {
  const { client, abortCalls } = createMockClient()
  return {
    ctx: {
      directory: process.cwd(),
      worktree: process.cwd(),
      client,
    } as never,
    abortCalls,
  }
}

type BeforeHook = (input: Record<string, unknown>, output: { args: Record<string, unknown> }) => Promise<void>

async function beforeHook(options: Record<string, unknown> = {}) {
  const { ctx, abortCalls } = context()
  const hooks = await BashSummaryPlugin(ctx, options)
  expect(hooks.tool).toBeDefined()
  expect(hooks["tool.execute.before"]).toBeDefined()
  return {
    hook: hooks["tool.execute.before"]! as BeforeHook,
    hooks: hooks!,
    abortCalls,
  }
}

async function invoke(
  hook: BeforeHook,
  command: string,
  workdir?: string,
  tool = "bash",
  sessionID = "test-session",
) {
  const args: Record<string, unknown> = { command }
  if (workdir !== undefined) args.workdir = workdir
  await hook(
    { tool, sessionID, callID: "test-call" },
    { args },
  )
  return args
}

async function invokeRaw(
  hook: BeforeHook,
  args: Record<string, unknown>,
  tool = "bash",
  sessionID = "test-session",
) {
  await hook({ tool, sessionID, callID: "test-call" }, { args })
  return args
}

function mockToolContext(overrides: Partial<{
  sessionID: string
  ask: () => Promise<void>
}> = {}) {
  return {
    sessionID: overrides.sessionID ?? "test-session",
    messageID: "msg-1",
    agent: "build",
    directory: process.cwd(),
    worktree: process.cwd(),
    abort: new AbortController().signal,
    metadata: () => {},
    ask: overrides.ask ?? (async () => {}),
  } as never
}

const ALLOW = { decision: "ALLOW" as const, reason: "" }
const DENY = (reason: string) => ({ decision: "DENY" as const, reason })
const STRICT_ALLOW = { decision: "ALLOW" as const, reason: "", bypassing: false }
const STRICT_DENY = (reason: string, bypassing = false) => ({
  decision: "DENY" as const,
  reason,
  bypassing,
})
const BLOCK_SUFFIX =
  "DO NOT retry the same command or try using alternative method.Skip the step or stop and report the user if it's a essential step of the work"

describe("OpenCode native Bash security hook", () => {
  test("does not override the built-in bash tool or mutate the command text", async () => {
    const { hook } = await beforeHook()
    const args = await invoke(hook, "Get-Content README.md")
    expect(args.command).toBe("Get-Content README.md")
    expect(args.timeout).toBe(120_000)
  })

  test("ignores non-bash tools", async () => {
    let reviews = 0
    const { hook } = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return DENY("should not run")
      },
    })
    await invoke(hook, "custom-project-command --repair", undefined, "write")
    expect(reviews).toBe(0)
  })

  test("reviews only static ASK commands before native execution", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook } = await beforeHook({
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        return { decision: "ALLOW", reason: "The command has no concrete destructive behavior." }
      },
    })
    const command = "custom-project-command --repair"
    await invoke(hook, command)

    expect(reviewed).toHaveLength(1)
    const request = reviewed[0]
    expect(request.command).toBe(command)
    expect(request.localScripts).toEqual([])
    expect(request.uninspectedLocalScripts).toEqual([])
    expect(request.targetDirectories).toEqual([])
    expect(request.uninspectedTargetDirectories).toEqual([])
    expect(request.worktree).toBeTypeOf("string")
    expect(request.cwd).toBeTypeOf("string")
    expect(request).not.toHaveProperty("strictness")
    expect(request.referencedPaths).toEqual([])
    expect(request.referencedPathsTruncated).toBe(false)
  })

  test("caches identical dynamic ALLOW decisions for repeated commands", async () => {
    let reviews = 0
    const { hook } = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return ALLOW
      },
    })
    await invoke(hook, "custom-test-runner --smoke")
    await invoke(hook, "custom-test-runner --smoke")
    expect(reviews).toBe(1)
  })

  test("cache is scoped per session and includes sessionID", async () => {
    let reviews = 0
    const { hook } = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return ALLOW
      },
    })
    await invoke(hook, "custom-test-runner --smoke", undefined, "bash", "s1")
    await invoke(hook, "custom-test-runner --smoke", undefined, "bash", "s1")
    expect(reviews).toBe(1)

    await invoke(hook, "custom-test-runner --smoke", undefined, "bash", "s2")
    expect(reviews).toBe(2)
  })

  test("does not cache dynamic ALLOW when a local script is uninspected", async () => {
    let reviews = 0
    const { hook } = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return ALLOW
      },
    })
    await invoke(hook, "python missing_test_runner.py")
    await invoke(hook, "python missing_test_runner.py")
    expect(reviews).toBe(2)
  })

  test("does not cache dynamic DENY decisions", async () => {
    let reviews = 0
    const { hook } = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return DENY("Concrete destructive behavior")
      },
    })
    await expect(invoke(hook, "custom-test-runner --unsafe")).rejects.toThrow(
      "Blocked by dynamic classifier: Concrete destructive behavior",
    )
    await expect(invoke(hook, "custom-test-runner --unsafe")).rejects.toThrow(
      "Blocked by dynamic classifier: Concrete destructive behavior",
    )
    expect(reviews).toBe(2)
  })

  test("allows common test commands statically without cloud review", async () => {
    let reviews = 0
    const { hook } = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return DENY("should not run")
      },
    })
    await invoke(hook, "bun test ./test/ 2>&1")
    await invoke(hook, "npx bun test ./test/ 2>&1")
    await invoke(hook, "node --test ./test/ 2>&1")
    expect(reviews).toBe(0)
  })

  test("always sends WSL-wrapped broad process termination to dynamic review", async () => {
    const reviewed: string[] = []
    const { hook } = await beforeHook({
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request.command)
        return { decision: "ALLOW", reason: "Test double" }
      },
    })
    const command = 'wsl -- bash -c "killall docker 2>&1"'
    await invoke(hook, command)
    expect(reviewed).toEqual([command])
  })

  test("always allows pure recycle-bin operations without cloud review", async () => {
    let reviews = 0
    const { hook } = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return DENY("should not run")
      },
    })
    await invoke(hook, "trash-put ./project")
    await invoke(
      hook,
      'powershell -NoProfile -Command "[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile(\'customer-data.csv\', \'OnlyErrorDialogs\', \'SendToRecycleBin\')"',
    )
    expect(reviews).toBe(0)
  })

  test("allows failed-clone cleanup inside the Windows user Local Temp without cloud review", async () => {
    if (!process.env.LOCALAPPDATA) return
    let reviews = 0
    const { hook } = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return DENY("should not run")
      },
    })
    const localTemp = path.join(process.env.LOCALAPPDATA, "Temp")
    const clone = path.join(localTemp, "opencode", "opencode-src")
    const gitDirectory = path.join(clone, ".git")
    const renamedClone = path.join(localTemp, "opencode", "opencode-src-old")
    await invoke(hook, `Remove-Item -Recurse "${gitDirectory}"`)
    await invoke(hook, `Rename-Item "${clone}" "${renamedClone}"`)
    expect(reviews).toBe(0)
  })

  test("allows pure named temp/tmp directory deletion without cloud review", async () => {
    let reviews = 0
    const { hook } = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return DENY("should not run")
      },
    })
    await invoke(hook, "rm -rf ./tmp/old-clone")
    await invoke(hook, String.raw`Remove-Item -Recurse -Force .\temp\clone`)
    await invoke(hook, 'wsl -- bash -c "rm -rf ./tmp/old-clone"')
    expect(reviews).toBe(0)
  })

  test("allows copy backups but blocks backup moves before cloud review", async () => {
    let reviews = 0
    const { hook } = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return { decision: "ALLOW", reason: "should not run" }
      },
    })
    await invoke(hook, "cp ./src/data.json ./archive/data.json.backup2")
    await expect(
      invoke(hook, "Move-Item -Path ./data.json -Destination ./data.json.backup2"),
    ).rejects.toThrow(
      "Blocked by static classifier: Moving or renaming data into a backup name is forbidden",
    )
    await expect(invoke(hook, "cp ./server.key ./server.key.backup2")).rejects.toThrow(
      "Blocked by static classifier: Critical credential files cannot use the backup exception",
    )
    expect(reviews).toBe(0)
  })

  test("hard-denies wrapped forced recursive directory deletion without cloud review", async () => {
    let reviews = 0
    const { hook } = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return { decision: "ALLOW", reason: "should not run" }
      },
    })
    const command = String.raw`powershell -NoProfile -Command rm -Force -Recurse C:\workspace\project\sentinel`
    await expect(invoke(hook, command)).rejects.toThrow(
      "Blocked by static classifier: Force-recursive directory deletion",
    )
    expect(reviews).toBe(0)
  })

  test("sends local script content to the cloud reviewer", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook } = await beforeHook({
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        return { decision: "ALLOW", reason: "The dangerous text is an inert example string." }
      },
    })
    await invoke(hook, "python ./test/fixtures/safe_agent_script.py")
    expect(reviewed).toHaveLength(1)
    expect(reviewed[0]?.localScripts[0]?.path).toBe("test/fixtures/safe_agent_script.py")
    expect(reviewed[0]?.localScripts[0]?.content).toContain("local-script-review-ok")
    expect(reviewed[0]?.uninspectedLocalScripts).toEqual([])
  })

  test("sends the target directory listing to cloud review", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook } = await beforeHook({
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        return { decision: "ALLOW", reason: "Test double only; no native command is executed." }
      },
    })
    await invoke(hook, "Remove-Item -Recurse .")
    expect(reviewed[0]?.targetDirectories[0]?.path).toBe(".")
    expect(reviewed[0]?.targetDirectories[0]?.entries).toContainEqual({ name: "src", type: "directory" })
    expect(reviewed[0]?.targetDirectories[0]?.entries).toContainEqual({ name: "package.json", type: "file" })
  })

  test("lets the cloud reviewer deny a destructive local script", async () => {
    const { hook } = await beforeHook({
      reviewCommand: async () => ({ decision: "DENY", reason: "Deletes durable data" }),
    })
    await expect(invoke(hook, "python ./test/fixtures/dangerous_agent_script.py")).rejects.toThrow(
      "Blocked by dynamic classifier: Deletes durable data",
    )
  })

  test("keeps policy out of the review request", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        return STRICT_ALLOW
      },
    })
    await invoke(hook, "custom-project-command --repair")
    expect(reviewed[0]).not.toHaveProperty("strictness")
  })

  test("HARD mode disables dynamic ALLOW caching", async () => {
    let reviews = 0
    const { hook } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async () => {
        reviews += 1
        return STRICT_ALLOW
      },
    })
    await invoke(hook, "custom-test-runner --smoke")
    await invoke(hook, "custom-test-runner --smoke")
    expect(reviews).toBe(2)
  })

  test("passes endpoint, model, and apiKey to the review function", async () => {
    const reviewedOptions: ReviewCommandOptions[] = []
    const { hook } = await beforeHook({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
      },
      reviewCommand: async (_req: CloudReviewRequest, opts: ReviewCommandOptions) => {
        reviewedOptions.push(opts)
        return ALLOW
      },
    })
    await invoke(hook, "custom-project-command --repair")
    expect(reviewedOptions).toHaveLength(1)
    expect(reviewedOptions[0]?.endpoint).toBe("https://api.openai.com/v1/chat/completions")
    expect(reviewedOptions[0]?.model).toBe("gpt-4o-mini")
    expect(reviewedOptions[0]?.apiKey).toBe("sk-test-key")
    expect(reviewedOptions[0]?.maxRounds).toBe(1)
    expect(reviewedOptions[0]?.policy).toBe("LOOSE")
    expect(reviewedOptions[0]?.allowFullReadAccess).toBe(false)
    expect(reviewedOptions[0]?.timeout).toBe(30_000)
  })

  test("passes python and auditorPath to the review function", async () => {
    const reviewedOptions: ReviewCommandOptions[] = []
    const auditorPath = path.join(process.cwd(), "src", "security", "auditor.py")
    const { hook } = await beforeHook({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        pythonPath: process.execPath,
        auditorPath,
      },
      reviewCommand: async (_req: CloudReviewRequest, opts: ReviewCommandOptions) => {
        reviewedOptions.push(opts)
        return ALLOW
      },
    })
    await invoke(hook, "custom-project-command --repair")
    expect(reviewedOptions[0]?.python).toBe(process.execPath)
    expect(reviewedOptions[0]?.auditorPath).toBe(auditorPath)
  })

  test("dynamic review is available when fully configured even without injected reviewCommand", async () => {
    let reviews = 0
    const { hook } = await beforeHook({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
      },
      reviewCommand: async () => {
        reviews += 1
        return ALLOW
      },
    })
    await invoke(hook, "custom-project-command --repair")
    expect(reviews).toBe(1)
  })

  test("dynamic review unavailable with invalid config falls back to fail_open by default", async () => {
    const { hook } = await beforeHook({
      dynamicReview: {
        baseURL: "not a url",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
      },
    })
    await invoke(hook, "custom-project-command --repair")
  })

  test("default fail_open allows when no reviewer is configured", async () => {
    const { hook } = await beforeHook()
    await invoke(hook, "custom-project-command --repair")
  })

  test("fail_open allows when reviewer is unavailable", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_open" })
    await invoke(hook, "custom-project-command --repair")
  })

  test("fail_close blocks when reviewer is unavailable", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_close" })
    await expect(invoke(hook, "custom-project-command --repair")).rejects.toThrow(
      "Blocked by policy classifier",
    )
  })

  test("fail_ask blocks with tool instruction when reviewer is unavailable", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_ask" })
    await expect(invoke(hook, "custom-project-command --repair")).rejects.toThrow(
      /bash_classifier_confirm/,
    )
  })

  test("fail_open allows when review call throws", async () => {
    const { hook } = await beforeHook({
      failPolicy: "fail_open",
      reviewCommand: async () => {
        throw new Error("review service unavailable")
      },
    })
    await invoke(hook, "custom-project-command --repair")
  })

  test("fail_close blocks when review call throws", async () => {
    const { hook } = await beforeHook({
      failPolicy: "fail_close",
      reviewCommand: async () => {
        throw new Error("review service unavailable")
      },
    })
    await expect(invoke(hook, "custom-project-command --repair")).rejects.toThrow(
      "Blocked by policy classifier",
    )
  })

  test("fail_ask creates pending request when review call throws", async () => {
    const { hook } = await beforeHook({
      failPolicy: "fail_ask",
      reviewCommand: async () => {
        throw new Error("review service unavailable")
      },
    })
    await expect(invoke(hook, "custom-project-command --repair")).rejects.toThrow(
      /bash_classifier_confirm/,
    )
  })

  test("relaxed policy neither records nor sends previous rejection context", async () => {
    const reviewed: CloudReviewRequest[] = []
    let callCount = 0
    const { hook } = await beforeHook({
      reviewCommand: async (req: CloudReviewRequest) => {
        callCount += 1
        reviewed.push(req)
        if (callCount === 1) return DENY("Dangerous")
        return ALLOW
      },
    })
    await expect(invoke(hook, "custom-dangerous-command")).rejects.toThrow(
      "Blocked by dynamic classifier: Dangerous",
    )
    await invoke(hook, "ls -la")
    expect(reviewed).toHaveLength(1)
    expect(reviewed[0]?.previousRejectedCommand).toBeUndefined()
  })

  test("strict policy forces dynamic re-review after a static rejection", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async (req: CloudReviewRequest) => {
        reviewed.push(req)
        return STRICT_ALLOW
      },
    })
    await expect(invoke(hook, "rm -rf /")).rejects.toThrow("Blocked by static classifier")
    await invoke(hook, "ls -la")
    expect(reviewed).toHaveLength(1)
    expect(reviewed[0]?.previousRejectedCommand?.command).toBe("rm -rf /")
    expect(reviewed[0]?.previousRejectedCommand?.classifier).toBe("STATIC")
  })

  test("bypassing:true blocks and aborts the session", async () => {
    let callCount = 0
    const { hook, abortCalls } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async () => {
        callCount += 1
        if (callCount === 1) return STRICT_DENY("Initial reject")
        return { decision: "DENY", reason: "Bypassing rejection", bypassing: true }
      },
    })
    await expect(invoke(hook, "custom-dangerous-command")).rejects.toThrow(
      "Blocked by dynamic classifier: Initial reject",
    )
    expect(abortCalls).toHaveLength(0)

    await expect(invoke(hook, "ls -la")).rejects.toThrow("Blocked by dynamic classifier: Bypassing rejection")
    expect(abortCalls).toHaveLength(1)
    expect(abortCalls[0]?.id).toBe("test-session")
  })

  test("bypassing:true with ALLOW also blocks and aborts", async () => {
    let callCount = 0
    const { hook, abortCalls } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async () => {
        callCount += 1
        if (callCount === 1) return STRICT_DENY("Initial reject")
        return { decision: "ALLOW", reason: "", bypassing: true }
      },
    })
    await expect(invoke(hook, "custom-dangerous-command")).rejects.toThrow()
    await expect(invoke(hook, "ls -la")).rejects.toThrow(/Blocked by dynamic classifier/)
    expect(abortCalls).toHaveLength(1)
  })

  test("abort failure still blocks the command", async () => {
    const abortCalls: Array<{ id: string; directory: string }> = []
    const failingClient = {
      session: {
        abort: async (opts: { path: { id: string }; query?: { directory?: string } }) => {
          abortCalls.push({ id: opts.path.id, directory: opts.query?.directory ?? "" })
          throw new Error("abort failed")
        },
      },
    } as never
    const ctx = {
      directory: process.cwd(),
      worktree: process.cwd(),
      client: failingClient,
    } as never
    let callCount = 0
    const hooks = await BashSummaryPlugin(ctx, {
      strictness: "HARD",
      reviewCommand: async () => {
        callCount += 1
        if (callCount === 1) return STRICT_DENY("Initial reject")
        return { decision: "DENY", reason: "bypass", bypassing: true }
      },
    })
    const hook = hooks["tool.execute.before"]! as BeforeHook
    await expect(invoke(hook, "custom-dangerous-command")).rejects.toThrow()
    await expect(invoke(hook, "ls -la")).rejects.toThrow(/Blocked by dynamic/)
    expect(abortCalls).toHaveLength(1)
    expect(abortCalls[0]?.id).toBe("test-session")
  })

  test("rejection state is isolated per session", async () => {
    const reviewed: CloudReviewRequest[] = []
    let callCount = 0
    const { hook } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async (req: CloudReviewRequest) => {
        callCount += 1
        reviewed.push(req)
        if (callCount === 1) return STRICT_DENY("Reject")
        return STRICT_ALLOW
      },
    })
    await expect(invoke(hook, "custom-dangerous-command", undefined, "bash", "s1")).rejects.toThrow()
    await invoke(hook, "custom-other-command", undefined, "bash", "s2")
    expect(reviewed).toHaveLength(2)
    expect(reviewed[0]?.previousRejectedCommand).toBeUndefined()
    expect(reviewed[1]?.previousRejectedCommand).toBeUndefined()
  })

  test("exit!=0 forces script re-review on next local script execution", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook, hooks } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async (req: CloudReviewRequest) => {
        reviewed.push(req)
        return STRICT_ALLOW
      },
    })
    await hooks["tool.execute.after"]?.(
      { tool: "bash", sessionID: "s1", callID: "c1", args: { command: "python ./failed.py" } },
      { title: "", output: "Error: something failed", metadata: { exit: 1 } },
    )
    await invoke(hook, "python ./test/fixtures/safe_agent_script.py", undefined, "bash", "s1")
    expect(reviewed).toHaveLength(1)
    expect(reviewed[0]?.previousFailedCommand?.command).toBe("python ./failed.py")
    expect(reviewed[0]?.previousFailedCommand?.exitCode).toBe(1)
  })

  test("exit!=0 does not force re-review for non-script commands in LOOSE", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook, hooks } = await beforeHook({
      reviewCommand: async (req: CloudReviewRequest) => {
        reviewed.push(req)
        return ALLOW
      },
    })
    await hooks["tool.execute.after"]?.(
      { tool: "bash", sessionID: "s1", callID: "c1", args: { command: "failing-cmd" } },
      { title: "", output: "error", metadata: { exit: 1 } },
    )
    await invoke(hook, "ls -la", undefined, "bash", "s1")
    expect(reviewed).toHaveLength(0)
  })

  test("HARD exit!=0 forces re-review for any next command including non-scripts", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook, hooks } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async (req: CloudReviewRequest) => {
        reviewed.push(req)
        return STRICT_ALLOW
      },
    })
    await hooks["tool.execute.after"]?.(
      { tool: "bash", sessionID: "s1", callID: "c1", args: { command: "failing-cmd" } },
      { title: "", output: "error", metadata: { exit: 1 } },
    )
    await invoke(hook, "ls -la", undefined, "bash", "s1")
    expect(reviewed).toHaveLength(1)
    expect(reviewed[0]?.previousFailedCommand?.command).toBe("failing-cmd")
    expect(reviewed[0]?.previousFailedCommand?.exitCode).toBe(1)
  })

  test("LOOSE exit!=0 never attaches failure context to the next local script execution", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook, hooks } = await beforeHook({
      reviewCommand: async (req: CloudReviewRequest) => {
        reviewed.push(req)
        return ALLOW
      },
    })
    await hooks["tool.execute.after"]?.(
      { tool: "bash", sessionID: "s1", callID: "c1", args: { command: "python ./failed.py" } },
      { title: "", output: "error", metadata: { exit: 1 } },
    )
    await invoke(hook, "python ./test/fixtures/safe_agent_script.py", undefined, "bash", "s1")
    // The local script is still reviewed on its own merits (static ASK), but LOOSE
    // never records lastFailed, so no previousFailedCommand context is attached.
    expect(reviewed).toHaveLength(1)
    expect(reviewed[0]?.previousFailedCommand).toBeUndefined()
  })

  test("HARD exit!=0 keeps static DENY without consuming the failure record", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook, hooks } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async (req: CloudReviewRequest) => {
        reviewed.push(req)
        return STRICT_ALLOW
      },
    })
    await hooks["tool.execute.after"]?.(
      { tool: "bash", sessionID: "s1", callID: "c1", args: { command: "failing-cmd" } },
      { title: "", output: "error", metadata: { exit: 1 } },
    )
    await expect(invoke(hook, "rm -rf ./some-dir", undefined, "bash", "s1")).rejects.toThrow(
      "Blocked by static classifier",
    )
    expect(reviewed).toHaveLength(0)
    await invoke(hook, "ls -la", undefined, "bash", "s1")
    expect(reviewed).toHaveLength(1)
    expect(reviewed[0]?.previousFailedCommand?.command).toBe("failing-cmd")
  })

  test("ordinary success does not clear failed script context", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook, hooks } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async (req: CloudReviewRequest) => {
        reviewed.push(req)
        return STRICT_ALLOW
      },
    })
    await hooks["tool.execute.after"]?.(
      { tool: "bash", sessionID: "s1", callID: "c1", args: { command: "python ./failed.py" } },
      { title: "", output: "error", metadata: { exit: 1 } },
    )
    await hooks["tool.execute.after"]?.(
      { tool: "bash", sessionID: "s1", callID: "c2", args: { command: "echo ok" } },
      { title: "", output: "ok", metadata: { exit: 0 } },
    )
    await invoke(hook, "python ./test/fixtures/safe_agent_script.py", undefined, "bash", "s1")
    expect(reviewed).toHaveLength(1)
    expect(reviewed[0]?.previousFailedCommand?.command).toBe("python ./failed.py")
  })

  test("exitCode field is compatible with exit", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook, hooks } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async (req: CloudReviewRequest) => {
        reviewed.push(req)
        return STRICT_ALLOW
      },
    })
    await hooks["tool.execute.after"]?.(
      { tool: "bash", sessionID: "s1", callID: "c1", args: { command: "python ./failed.py" } },
      { title: "", output: "error", metadata: { exitCode: 42 } },
    )
    await invoke(hook, "python ./test/fixtures/safe_agent_script.py", undefined, "bash", "s1")
    expect(reviewed[0]?.previousFailedCommand?.exitCode).toBe(42)
  })

  test("failed command state does not chain across sessions", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook, hooks } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async (req: CloudReviewRequest) => {
        reviewed.push(req)
        return STRICT_ALLOW
      },
    })
    await hooks["tool.execute.after"]?.(
      { tool: "bash", sessionID: "s1", callID: "c1", args: { command: "python ./failed.py" } },
      { title: "", output: "error", metadata: { exit: 1 } },
    )
    await invoke(hook, "python ./test/fixtures/safe_agent_script.py", undefined, "bash", "s2")
    expect(reviewed).toHaveLength(1)
    expect(reviewed[0]?.previousFailedCommand).toBeUndefined()
  })

  test("human approval allows the exact command once via bash_classifier_confirm", async () => {
    const { hook, hooks } = await beforeHook({ failPolicy: "fail_ask" })
    let blockError: Error | undefined
    try {
      await invoke(hook, "custom-project-command --repair", undefined, "bash", "s1")
    } catch (e) {
      blockError = e as Error
    }
    expect(blockError?.message).toMatch(/bash_classifier_confirm/)
    const match = blockError?.message.match(/requestId "([^"]+)"/)
    const requestId = match?.[1]
    expect(requestId).toBeDefined()

    const result = await hooks.tool!.bash_classifier_confirm.execute(
      { requestId: requestId! },
      mockToolContext({ sessionID: "s1" }),
    )
    expect(typeof result === "object" && (result as { output: string }).output).toMatch(/approved/i)

    await invoke(hook, "custom-project-command --repair", undefined, "bash", "s1")

    await expect(invoke(hook, "custom-project-command --repair", undefined, "bash", "s1")).rejects.toThrow(
      /bash_classifier_confirm/,
    )
  })

  test("human approval only works for the exact same command fingerprint", async () => {
    const { hook, hooks } = await beforeHook({ failPolicy: "fail_ask" })
    let blockError: Error | undefined
    try {
      await invoke(hook, "custom-project-command --repair", undefined, "bash", "s1")
    } catch (e) {
      blockError = e as Error
    }
    const match = blockError?.message.match(/requestId "([^"]+)"/)
    const requestId = match?.[1]

    await hooks.tool!.bash_classifier_confirm.execute(
      { requestId: requestId! },
      mockToolContext({ sessionID: "s1" }),
    )

    await expect(invoke(hook, "custom-other-command", undefined, "bash", "s1")).rejects.toThrow(
      /bash_classifier_confirm/,
    )
  })

  test("human approval in one session does not affect another", async () => {
    const { hook, hooks } = await beforeHook({ failPolicy: "fail_ask" })
    let blockError: Error | undefined
    try {
      await invoke(hook, "custom-project-command --repair", undefined, "bash", "s1")
    } catch (e) {
      blockError = e as Error
    }
    const match = blockError?.message.match(/requestId "([^"]+)"/)
    const requestId = match?.[1]

    await hooks.tool!.bash_classifier_confirm.execute(
      { requestId: requestId! },
      mockToolContext({ sessionID: "s1" }),
    )

    await expect(invoke(hook, "custom-project-command --repair", undefined, "bash", "s2")).rejects.toThrow(
      /bash_classifier_confirm/,
    )
  })

  test("bash_classifier_confirm rejects mismatched requestId", async () => {
    const { hook, hooks } = await beforeHook({ failPolicy: "fail_ask" })
    try {
      await invoke(hook, "custom-project-command --repair", undefined, "bash", "s1")
    } catch {
      // expected
    }
    const result = await hooks.tool!.bash_classifier_confirm.execute(
      { requestId: "wrong-id" },
      mockToolContext({ sessionID: "s1" }),
    )
    expect(typeof result === "object" && (result as { output: string }).output).toMatch(/mismatch|No pending|expired|not match/i)
  })

  test("bash_classifier_confirm rejects when no pending request exists", async () => {
    const { hooks } = await beforeHook({ failPolicy: "fail_ask" })
    const result = await hooks.tool!.bash_classifier_confirm.execute(
      { requestId: "whatever" },
      mockToolContext({ sessionID: "no-such-session" }),
    )
    expect(typeof result === "object" && (result as { output: string }).output).toMatch(/No pending/i)
  })

  test("bash_classifier_confirm uses context.ask with always:[] for one-time approval", async () => {
    const { hook, hooks } = await beforeHook({ failPolicy: "fail_ask" })
    let askInput: Record<string, unknown> | undefined
    let blockError: Error | undefined
    try {
      await invoke(hook, "custom-project-command --repair", undefined, "bash", "s1")
    } catch (e) {
      blockError = e as Error
    }
    const reqId = blockError?.message.match(/requestId "([^"]+)"/)?.[1]
    await hooks.tool!.bash_classifier_confirm.execute(
      { requestId: reqId! },
      mockToolContext({
        sessionID: "s1",
        ask: async (input: Record<string, unknown>) => {
          askInput = input
        },
      }),
    )
    expect(askInput?.always).toEqual([])
    expect(askInput?.permission).toBe("bash-classifier-confirm")
  })

  test("bash_classifier_confirm returns denied when user rejects", async () => {
    const { hook, hooks } = await beforeHook({ failPolicy: "fail_ask" })
    let blockError: Error | undefined
    try {
      await invoke(hook, "custom-project-command --repair", undefined, "bash", "s1")
    } catch (e) {
      blockError = e as Error
    }
    const reqId = blockError?.message.match(/requestId "([^"]+)"/)?.[1]
    const result = await hooks.tool!.bash_classifier_confirm.execute(
      { requestId: reqId! },
      mockToolContext({
        sessionID: "s1",
        ask: async () => {
          throw new Error("user denied")
        },
      }),
    )
    expect(typeof result === "object" && (result as { output: string }).output).toMatch(/Denied/i)
  })

  test("static DENY cannot be overridden by bash_classifier_confirm", async () => {
    const { hook, hooks } = await beforeHook({ failPolicy: "fail_ask" })
    await expect(invoke(hook, "rm -rf /")).rejects.toThrow("Blocked by static classifier")
    await expect(invoke(hook, "rm -rf /")).rejects.toThrow("Blocked by static classifier")
  })

  test("blocks apply_patch file deletion", async () => {
    const { hooks } = await beforeHook()
    await expect(
      hooks["tool.execute.before"]!(
        { tool: "apply_patch", sessionID: "s1", callID: "c1" },
        { args: { patchText: "*** Delete File: foo.txt\n--- foo.txt\n+++ /dev/null\n" } },
      ),
    ).rejects.toThrow(/apply_patch cannot delete/)
  })

  test("blocks apply_patch file deletion via patch field", async () => {
    const { hooks } = await beforeHook()
    await expect(
      hooks["tool.execute.before"]!(
        { tool: "apply_patch", sessionID: "s1", callID: "c1" },
        { args: { patch: "*** Delete File: bar.txt\n" } },
      ),
    ).rejects.toThrow(/apply_patch cannot delete/)
  })

  test("blocks apply_patch file deletion via diff field", async () => {
    const { hooks } = await beforeHook()
    await expect(
      hooks["tool.execute.before"]!(
        { tool: "apply_patch", sessionID: "s1", callID: "c1" },
        { args: { diff: "*** Delete File: baz.txt\n" } },
      ),
    ).rejects.toThrow(/apply_patch cannot delete/)
  })

  test("allows apply_patch updates and adds", async () => {
    const { hooks } = await beforeHook()
    await hooks["tool.execute.before"]!(
      { tool: "apply_patch", sessionID: "s1", callID: "c1" },
      { args: { patchText: "*** Update File: foo.txt\n--- foo.txt\n+++ foo.txt\n@@\n-old\n+new\n" } },
    )
    await hooks["tool.execute.before"]!(
      { tool: "apply_patch", sessionID: "s1", callID: "c2" },
      { args: { patchText: "*** Add File: new.txt\n--- /dev/null\n+++ new.txt\n@@\n+content\n" } },
    )
  })

  test("static rejection includes the DO NOT retry suffix", async () => {
    const { hook } = await beforeHook()
    await expect(invoke(hook, "rm -rf /")).rejects.toThrow(BLOCK_SUFFIX)
  })

  test("dynamic rejection includes the DO NOT retry suffix", async () => {
    const { hook } = await beforeHook({
      reviewCommand: async () => DENY("Dangerous operation"),
    })
    await expect(invoke(hook, "custom-dangerous-command")).rejects.toThrow(BLOCK_SUFFIX)
  })

  test("fail_close rejection includes the DO NOT retry suffix", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_close" })
    await expect(invoke(hook, "custom-project-command --repair")).rejects.toThrow(BLOCK_SUFFIX)
  })

  test("fail_ask rejection avoids the DO NOT retry suffix", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_ask" })
    let blockError: Error | undefined
    try {
      await invoke(hook, "custom-project-command --repair")
    } catch (e) {
      blockError = e as Error
    }
    expect(blockError?.message).toMatch(/bash_classifier_confirm/)
    expect(blockError?.message).not.toMatch(/DO NOT retry the same command/)
  })

  test("uses the native tool workdir as the local-script review base", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook } = await beforeHook({
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        return { decision: "ALLOW", reason: "Reviewed local script." }
      },
    })
    await invoke(hook, "python ./safe_agent_script.py", path.join("test", "fixtures"))
    expect(reviewed[0]?.localScripts[0]?.path).toBe("test/fixtures/safe_agent_script.py")
  })

  test("preserves an explicit timeout above the default limit", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_open" })
    const args = await invokeRaw(hook, { command: "ls -la", timeout: 600_000 })
    expect(args.timeout).toBe(600_000)
  })

  test("sets the hard limit when no timeout is supplied", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_open" })
    const args = await invokeRaw(hook, { command: "ls -la" })
    expect(args.timeout).toBe(120_000)
  })

  test("keeps an explicit timeout below the hard limit", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_open" })
    const args = await invokeRaw(hook, { command: "ls -la", timeout: 30_000 })
    expect(args.timeout).toBe(30_000)
  })

  test("does not cap download and build commands", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_open" })
    const commands = [
      "curl -fsSL https://example.com/install.sh -o install.sh",
      "git clone https://github.com/anomalyco/opencode.git",
      "wget -q https://example.com/file.zip",
      "npm install",
      "pnpm add lodash",
      "pip install requests",
      "npm run build",
      "make",
      "cargo build --release",
    ]
    for (const command of commands) {
      const args = await invokeRaw(hook, { command, timeout: 600_000 })
      expect(args.timeout, command).toBe(600_000)
    }
  })

  test("disables the hard timeout when hardTimeoutMs is zero", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_open", hardTimeoutMs: 0 })
    const args = await invokeRaw(hook, { command: "ls -la", timeout: 600_000 })
    expect(args.timeout).toBe(600_000)
  })

  test("still blocks destructive commands before touching timeout", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_open" })
    const args: Record<string, unknown> = { command: "rm -rf /", timeout: 600_000 }
    await expect(
      hook(
        { tool: "bash", sessionID: "test-session", callID: "test-call" },
        { args },
      ),
    ).rejects.toThrow("Blocked by static classifier")
    expect(args.timeout).toBe(600_000)
  })

  test("isolates detached start commands so the pipe is not held open", async () => {
    const { hook } = await beforeHook({
      failPolicy: "fail_open",
      shell: "C:/msys64/usr/bin/bash.exe",
    })
    const cases: Array<[string, string]> = [
      ['start "" "C:/Program Files/Docker/Docker/Docker Desktop.exe" && echo LAUNCHED', 'start "" "C:/Program Files/Docker/Docker/Docker Desktop.exe" >/dev/null 2>&1 && echo LAUNCHED'],
      ["start foo", "start foo >/dev/null 2>&1"],
      ["cmd //c start foo", "cmd //c start foo >/dev/null 2>&1"],
      ["Start-Process foo", "Start-Process foo >/dev/null 2>&1"],
      ["Start-Process foo && echo done", "Start-Process foo >/dev/null 2>&1 && echo done"],
      ["Start-Job { Start-Sleep 5 }", "Start-Job { Start-Sleep 5 } >/dev/null 2>&1"],
    ]
    for (const [command, expected] of cases) {
      const args = await invokeRaw(hook, { command })
      expect(args.command, command).toBe(expected)
    }
  })

  test("uses PowerShell null redirection for detached starts on pwsh", async () => {
    const { hook } = await beforeHook({
      failPolicy: "fail_open",
      shell: "C:/Program Files/PowerShell/7/pwsh.exe",
    })
    const args = await invokeRaw(hook, { command: "Start-Process foo" })
    expect(args.command).toBe("Start-Process foo > $null 2>&1")
  })

  test("does not touch commands that are not detached starts", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_open" })
    const commands = [
      "npm start",
      "docker start container-a",
      "git status && ls -la",
      "start foo > log.txt",
      "start foo 2> err.txt",
      "python server.py",
    ]
    for (const command of commands) {
      const args = await invokeRaw(hook, { command })
      expect(args.command, command).toBe(command)
    }
  })

  test("disables detached start isolation when configured off", async () => {
    const { hook } = await beforeHook({ failPolicy: "fail_open", detachedStartIsolation: false })
    const args = await invokeRaw(hook, { command: "start foo" })
    expect(args.command).toBe("start foo")
  })

  test("uses the supervisor as the live shell without rewriting commands", async () => {
    const realShell = "C:/msys64/usr/bin/bash.exe"
    const { ctx } = context()
    const hooks = await BashSummaryPlugin(ctx, {
      failPolicy: "fail_open",
      shell: realShell,
      supervisorPath: process.execPath,
    })
    const config = { shell: realShell }
    await hooks.config?.(config as never)
    expect(config.shell).toBe(path.resolve(process.execPath))

    const env = { env: {} as Record<string, string> }
    await hooks["shell.env"]?.(
      { cwd: process.cwd(), sessionID: "test-session", callID: "test-call" },
      env,
    )
    expect(env.env.OPENCODE_REAL_BASH).toBe(realShell)

    const args: Record<string, unknown> = { command: "start foo" }
    await hooks["tool.execute.before"]?.(
      { tool: "bash", sessionID: "test-session", callID: "test-call" },
      { args },
    )
    expect(args.command).toBe("start foo")
  })

  test("does not write OPENCODE_REAL_BASH to process.env globally", async () => {
    const realShell = "C:/msys64/usr/bin/bash.exe"
    const { ctx } = context()
    const savedEnv = process.env.OPENCODE_REAL_BASH
    delete process.env.OPENCODE_REAL_BASH
    try {
      const hooks = await BashSummaryPlugin(ctx, {
        failPolicy: "fail_open",
        shell: realShell,
        supervisorPath: process.execPath,
      })
      const config = { shell: realShell }
      await hooks.config?.(config as never)
      expect(process.env.OPENCODE_REAL_BASH).toBeUndefined()
    } finally {
      if (savedEnv !== undefined) process.env.OPENCODE_REAL_BASH = savedEnv
    }
  })

  test("forwards referenced path context without a policy field", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook } = await beforeHook({
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        return ALLOW
      },
    })
    await invoke(hook, "custom-reader ./README.md")
    expect(reviewed[0]?.referencedPaths.some((value) => /README\.md$/i.test(value))).toBe(true)
    expect(reviewed[0]?.referencedPathsTruncated).toBe(false)
    expect(reviewed[0]).not.toHaveProperty("strictness")
  })

  test("passes access and configured round limits through review options", async () => {
    let seen: ReviewCommandOptions | undefined
    const { hook } = await beforeHook({
      dynamicReview: {
        baseURL: "https://api.openai.com/v1",
        model: "gpt-4o-mini",
        apiKey: "sk-test-key",
        maxRounds: 3,
        allowFullReadAccess: true,
      },
      reviewCommand: async (_request: CloudReviewRequest, options: ReviewCommandOptions) => {
        seen = options
        return ALLOW
      },
    })
    await invoke(hook, "custom-project-command --repair")
    expect(seen?.maxRounds).toBe(3)
    expect(seen?.allowFullReadAccess).toBe(true)
    expect(seen?.policy).toBe("LOOSE")
  })

  test("rejects policy-incompatible injected result schemas through fail policy", async () => {
    const relaxed = await beforeHook({
      failPolicy: "fail_close",
      reviewCommand: async () => STRICT_ALLOW,
    })
    await expect(invoke(relaxed.hook, "custom-relaxed-command")).rejects.toThrow(
      "Blocked by policy classifier: Dynamic review returned an invalid result",
    )
    expect(relaxed.abortCalls).toHaveLength(0)

    const strict = await beforeHook({
      strictness: "HARD",
      failPolicy: "fail_close",
      reviewCommand: async () => ALLOW,
    })
    await expect(invoke(strict.hook, "custom-strict-command")).rejects.toThrow(
      "Blocked by policy classifier: Dynamic review returned an invalid result",
    )
  })

  test("strict recursive rejection adds a command-family retry pattern without exposing policy names", async () => {
    const { hook } = await beforeHook({ strictness: "HARD" })
    let message = ""
    try {
      await invoke(hook, "rm -rf ./tmp/old-clone")
    } catch (error) {
      message = (error as Error).message
    }
    expect(message).toMatch(/DO NOT retry any rm -rf, split -r\/-f, .*recursive deletion command/)
    expect(message).not.toMatch(/\b(?:HARD|LOOSE)\b/)
  })

  test("a concurrent strict ALLOW cannot consume a newer rejection generation", async () => {
    const reviewed: CloudReviewRequest[] = []
    let calls = 0
    let releaseAllow!: () => void
    let signalAllowEntered!: () => void
    const allowGate = new Promise<void>((resolve) => {
      releaseAllow = resolve
    })
    const allowEntered = new Promise<void>((resolve) => {
      signalAllowEntered = resolve
    })
    const { hook } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        calls += 1
        if (calls === 1) return STRICT_DENY("initial")
        if (calls === 2) {
          signalAllowEntered()
          await allowGate
          return STRICT_ALLOW
        }
        if (calls === 3) return STRICT_DENY("newer")
        return STRICT_ALLOW
      },
    })
    await expect(invoke(hook, "custom-dangerous-command")).rejects.toThrow()
    const olderAllow = invoke(hook, "ls -la")
    await allowEntered
    await expect(invoke(hook, "pwd")).rejects.toThrow("newer")
    releaseAllow()
    await olderAllow
    await invoke(hook, "echo ok")
    expect(reviewed.at(-1)?.previousRejectedCommand?.command).toBe("pwd")
  })

  test("successful reviewed script consumes only its claimed failure generation", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook, hooks } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        return STRICT_ALLOW
      },
    })
    await hooks["tool.execute.after"]?.(
      { tool: "bash", sessionID: "s1", callID: "failed", args: { command: "python failed.py" } },
      { title: "", output: "failed", metadata: { exit: 1 } },
    )
    await hook(
      { tool: "bash", sessionID: "s1", callID: "reviewed" },
      { args: { command: "python ./test/fixtures/safe_agent_script.py" } },
    )
    await hooks["tool.execute.after"]?.(
      {
        tool: "bash",
        sessionID: "s1",
        callID: "reviewed",
        args: { command: "python ./test/fixtures/safe_agent_script.py" },
      },
      { title: "", output: "ok", metadata: { exit: 0 } },
    )
    await invoke(hook, "python ./test/fixtures/safe_agent_script.py", undefined, "bash", "s1")
    expect(reviewed).toHaveLength(2)
    expect(reviewed[0]?.previousFailedCommand?.command).toBe("python failed.py")
    expect(reviewed[1]?.previousFailedCommand).toBeUndefined()
  })

  test("human confirmation cannot overwrite a newer pending generation", async () => {
    const { hook, hooks } = await beforeHook({ failPolicy: "fail_ask" })
    const firstError = await invoke(hook, "custom-first", undefined, "bash", "s1").catch(
      (error: Error) => error,
    )
    const firstId = (firstError as Error).message.match(/requestId "([^"]+)"/)?.[1]
    let releaseAsk!: () => void
    const askGate = new Promise<void>((resolve) => {
      releaseAsk = resolve
    })
    const confirming = hooks.tool!.bash_classifier_confirm.execute(
      { requestId: firstId! },
      mockToolContext({ sessionID: "s1", ask: async () => askGate }),
    )
    await Promise.resolve()
    const secondError = await invoke(hook, "custom-second", undefined, "bash", "s1").catch(
      (error: Error) => error,
    )
    const secondId = (secondError as Error).message.match(/requestId "([^"]+)"/)?.[1]
    releaseAsk()
    const firstResult = await confirming
    expect((firstResult as { title: string }).title).toBe("Request superseded")
    const secondResult = await hooks.tool!.bash_classifier_confirm.execute(
      { requestId: secondId! },
      mockToolContext({ sessionID: "s1" }),
    )
    expect((secondResult as { title: string }).title).toBe("Approved")
  })

  test("session state expires and bounded state evicts the oldest session", async () => {
    const reviewed: CloudReviewRequest[] = []
    const { hook } = await beforeHook({
      strictness: "HARD",
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        return STRICT_DENY("reject")
      },
    })
    await expect(invoke(hook, "custom-dangerous", undefined, "bash", "oldest")).rejects.toThrow()
    for (let index = 0; index < 512; index += 1) {
      await invoke(hook, "ls -la", undefined, "bash", `bounded-${index}`)
    }
    await invoke(hook, "ls -la", undefined, "bash", "oldest")
    expect(reviewed).toHaveLength(1)

    const originalNow = Date.now
    let now = originalNow()
    Date.now = () => now
    try {
      await expect(invoke(hook, "custom-dangerous", undefined, "bash", "ttl")).rejects.toThrow()
      now += 31 * 60 * 1000
      await invoke(hook, "ls -la", undefined, "bash", "ttl")
    } finally {
      Date.now = originalNow
    }
  }, 15_000)

  test("session deletion clears the relaxed dynamic cache", async () => {
    let reviews = 0
    const { hook, hooks } = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return ALLOW
      },
    })
    await invoke(hook, "custom-cache-command", undefined, "bash", "s1")
    await invoke(hook, "custom-cache-command", undefined, "bash", "s1")
    await hooks.event?.({ event: { type: "session.deleted", properties: { info: { id: "s1" } } } } as never)
    await invoke(hook, "custom-cache-command", undefined, "bash", "s1")
    expect(reviews).toBe(2)
  })

  test("session.deleted event cleans up session state", async () => {
    const { hook, hooks } = await beforeHook({
      failPolicy: "fail_ask",
    })
    try {
      await invoke(hook, "custom-dangerous-command", undefined, "bash", "s1")
    } catch {
      // expected
    }
    await hooks.event?.({ event: { type: "session.deleted", properties: { info: { id: "s1" } } } } as never)
    await hooks["tool.execute.after"]?.(
      { tool: "bash", sessionID: "s1", callID: "c1", args: { command: "cmd" } },
      { title: "", output: "", metadata: { exit: 1 } },
    )
  })

  test("dispose cleans up all state", async () => {
    const { hook, hooks } = await beforeHook({
      reviewCommand: async () => DENY("reject"),
    })
    await expect(invoke(hook, "custom-dangerous-command", undefined, "bash", "s1")).rejects.toThrow()
    await hooks.dispose?.()
  })
})
