import { describe, expect, test } from "bun:test"
import path from "node:path"
import BashSummaryPlugin from "../src/index"
import type { CloudReviewRequest } from "../src/security/reviewer"

function context() {
  return {
    directory: process.cwd(),
    worktree: process.cwd(),
  } as never
}

async function beforeHook(options: Record<string, unknown> = {}) {
  const hooks = await BashSummaryPlugin(context(), options)
  expect(hooks.tool).toBeUndefined()
  expect(hooks["tool.execute.before"]).toBeDefined()
  return hooks["tool.execute.before"]!
}

async function invoke(
  hook: Awaited<ReturnType<typeof beforeHook>>,
  command: string,
  workdir?: string,
  tool = "bash",
) {
  const args: Record<string, unknown> = { command }
  if (workdir !== undefined) args.workdir = workdir
  await hook(
    {
      tool,
      sessionID: "test-session",
      callID: "test-call",
    },
    { args },
  )
  return args
}

describe("OpenCode native Bash security hook", () => {
  test("does not override the built-in bash tool or rewrite the command meaning", async () => {
    const hook = await beforeHook({ shell: "C:/msys64/usr/bin/bash.exe" })
    const args = await invoke(hook, "Get-Content README.md")
    // the hard-timeout feature wraps the command with a shell timeout, but the
    // command text itself is preserved as the timeout argument
    expect(args.command).toBe("timeout -k 3 120s Get-Content README.md")
    expect(args.timeout).toBe(120_000)
  })

  test("ignores non-bash tools", async () => {
    let reviews = 0
    const hook = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return { decision: "DENY", reason: "should not run" }
      },
    })

    await invoke(hook, "custom-project-command --repair", undefined, "write")
    expect(reviews).toBe(0)
  })

  test("reviews only static ASK commands before native execution", async () => {
    const reviewed: CloudReviewRequest[] = []
    const hook = await beforeHook({
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        return {
          decision: "ALLOW",
          reason: "The command has no concrete destructive behavior.",
        }
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
    expect(typeof request.worktree).toBe("string")
    expect(request.worktree?.length).toBeGreaterThan(0)
    expect(typeof request.cwd).toBe("string")
    expect(request.cwd?.length).toBeGreaterThan(0)
  })

  test("caches identical dynamic ALLOW decisions for repeated commands", async () => {
    let reviews = 0
    const hook = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return {
          decision: "ALLOW",
          reason: "",
        }
      },
    })

    await invoke(hook, "custom-test-runner --smoke")
    await invoke(hook, "custom-test-runner --smoke")

    expect(reviews).toBe(1)
  })

  test("does not cache dynamic ALLOW when a local script is uninspected", async () => {
    let reviews = 0
    const hook = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return {
          decision: "ALLOW",
          reason: "",
        }
      },
    })

    await invoke(hook, "python missing_test_runner.py")
    await invoke(hook, "python missing_test_runner.py")

    expect(reviews).toBe(2)
  })

  test("does not cache dynamic DENY decisions", async () => {
    let reviews = 0
    const hook = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return {
          decision: "DENY",
          reason: "Concrete destructive behavior",
        }
      },
    })

    await expect(invoke(hook, "custom-test-runner --unsafe")).rejects.toThrow(
      "Command blocked by dynamic classifier:Concrete destructive behavior",
    )
    await expect(invoke(hook, "custom-test-runner --unsafe")).rejects.toThrow(
      "Command blocked by dynamic classifier:Concrete destructive behavior",
    )

    expect(reviews).toBe(2)
  })

  test("allows common test commands statically without cloud review", async () => {
    let reviews = 0
    const hook = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return { decision: "DENY", reason: "should not run" }
      },
    })

    await invoke(hook, "bun test ./test/ 2>&1")
    await invoke(hook, "npx bun test ./test/ 2>&1")
    await invoke(hook, "node --test ./test/ 2>&1")

    expect(reviews).toBe(0)
  })

  test("always sends WSL-wrapped broad process termination to dynamic review", async () => {
    const reviewed: string[] = []
    const hook = await beforeHook({
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request.command)
        return {
          decision: "ALLOW",
          reason: "Test double",
        }
      },
    })
    const command = 'wsl -- bash -c "killall docker 2>&1"'

    await invoke(hook, command)

    expect(reviewed).toEqual([command])
  })

  test("always allows pure recycle-bin operations without cloud review", async () => {
    let reviews = 0
    const hook = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return { decision: "DENY", reason: "should not run" }
      },
    })

    await invoke(hook, "trash-put ./project")
    await invoke(
      hook,
      "powershell -NoProfile -Command \"[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile('customer-data.csv', 'OnlyErrorDialogs', 'SendToRecycleBin')\"",
    )

    expect(reviews).toBe(0)
  })

  test("allows failed-clone cleanup inside the Windows user Local Temp without cloud review", async () => {
    if (!process.env.LOCALAPPDATA) return
    let reviews = 0
    const hook = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return { decision: "DENY", reason: "should not run" }
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

  test("allows any pure tmp or temp named deletion without cloud review", async () => {
    let reviews = 0
    const hook = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return { decision: "DENY", reason: "should not run" }
      },
    })

    await invoke(hook, "rm -rf ./durable-project ./tmp-marker")
    await invoke(hook, String.raw`Remove-Item -Recurse -Force .\template-clone`)
    await invoke(hook, 'wsl -- bash -c "rm -rf ./durable-project ./temp-marker"')

    expect(reviews).toBe(0)
  })

  test("allows copy backups but blocks backup moves before cloud review", async () => {
    let reviews = 0
    const hook = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return { decision: "ALLOW", reason: "should not run" }
      },
    })

    await invoke(hook, "cp ./src/data.json ./archive/data.json.backup2")
    await expect(
      invoke(hook, "Move-Item -Path ./data.json -Destination ./data.json.backup2"),
    ).rejects.toThrow(
      "Command blocked by static classifier : Moving or renaming data into a backup name is forbidden",
    )
    await expect(invoke(hook, "cp ./server.key ./server.key.backup2")).rejects.toThrow(
      "Command blocked by static classifier : Critical credential files cannot use the backup exception",
    )
    expect(reviews).toBe(0)
  })

  test("hard-denies wrapped forced recursive directory deletion without cloud review", async () => {
    let reviews = 0
    const hook = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        return { decision: "ALLOW", reason: "should not run" }
      },
    })
    const command = String.raw`powershell -NoProfile -Command rm -Force -Recurse C:\Users\34177\AIGC\opencode-local-plugins\opencode-sentinel`

    await expect(invoke(hook, command)).rejects.toThrow(
      "Command blocked by static classifier : Force-recursive directory deletion",
    )
    expect(reviews).toBe(0)
  })

  test("sends local script content to the cloud reviewer", async () => {
    const reviewed: CloudReviewRequest[] = []
    const hook = await beforeHook({
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        return {
          decision: "ALLOW",
          reason: "The dangerous text is an inert example string.",
        }
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
    const hook = await beforeHook({
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        return {
          decision: "ALLOW",
          reason: "Test double only; no native command is executed.",
        }
      },
    })

    await invoke(hook, "Remove-Item -Recurse .")

    expect(reviewed[0]?.targetDirectories[0]?.path).toBe(".")
    expect(reviewed[0]?.targetDirectories[0]?.entries).toContainEqual({
      name: "src",
      type: "directory",
    })
    expect(reviewed[0]?.targetDirectories[0]?.entries).toContainEqual({
      name: "package.json",
      type: "file",
    })
  })

  test("lets the cloud reviewer deny a destructive local script", async () => {
    const hook = await beforeHook({
      reviewCommand: async () => ({
        decision: "DENY",
        reason: "Deletes durable data",
      }),
    })

    await expect(invoke(hook, "python ./test/fixtures/dangerous_agent_script.py")).rejects.toThrow(
      "Command blocked by dynamic classifier:Deletes durable data",
    )
  })

  test("fails open without caching when the cloud reviewer is unavailable", async () => {
    let reviews = 0
    const hook = await beforeHook({
      reviewCommand: async () => {
        reviews += 1
        throw new Error("review service unavailable")
      },
    })

    await invoke(hook, "custom-project-command --repair")
    await invoke(hook, "custom-project-command --repair")

    expect(reviews).toBe(2)
  })

  test("allows contextual commands when cloud review is disabled", async () => {
    const hook = await beforeHook({ cloudReviewEnabled: false })

    await invoke(hook, "custom-project-command --repair")
  })

  test("uses the native tool workdir as the local-script review base", async () => {
    const reviewed: CloudReviewRequest[] = []
    const hook = await beforeHook({
      reviewCommand: async (request: CloudReviewRequest) => {
        reviewed.push(request)
        return { decision: "ALLOW", reason: "Reviewed local script." }
      },
    })

    await invoke(hook, "python ./safe_agent_script.py", path.join("test", "fixtures"))

    expect(reviewed[0]?.localScripts[0]?.path).toBe("test/fixtures/safe_agent_script.py")
  })

  test("caps non-download/build command timeout to the hard limit", async () => {
    const hook = await beforeHook({ cloudReviewEnabled: false })
    const args: Record<string, unknown> = { command: "ls -la", timeout: 600_000 }
    await hook(
      {
        tool: "bash",
        sessionID: "test-session",
        callID: "test-call",
      },
      { args },
    )
    expect(args.timeout).toBe(120_000)
  })

  test("sets the hard limit when no timeout is supplied", async () => {
    const hook = await beforeHook({ cloudReviewEnabled: false })
    const args: Record<string, unknown> = { command: "ls -la" }
    await hook(
      {
        tool: "bash",
        sessionID: "test-session",
        callID: "test-call",
      },
      { args },
    )
    expect(args.timeout).toBe(120_000)
  })

  test("keeps an explicit timeout below the hard limit", async () => {
    const hook = await beforeHook({ cloudReviewEnabled: false })
    const args: Record<string, unknown> = { command: "ls -la", timeout: 30_000 }
    await hook(
      {
        tool: "bash",
        sessionID: "test-session",
        callID: "test-call",
      },
      { args },
    )
    expect(args.timeout).toBe(30_000)
  })

  test("does not cap download and build commands", async () => {
    const hook = await beforeHook({ cloudReviewEnabled: false })
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
      const args: Record<string, unknown> = { command, timeout: 600_000 }
      await hook(
        {
          tool: "bash",
          sessionID: "test-session",
          callID: "test-call",
        },
        { args },
      )
      expect(args.timeout, command).toBe(600_000)
    }
  })

  test("disables the hard timeout when hardTimeoutMs is zero", async () => {
    const hook = await beforeHook({ cloudReviewEnabled: false, hardTimeoutMs: 0 })
    const args: Record<string, unknown> = { command: "ls -la", timeout: 600_000 }
    await hook(
      {
        tool: "bash",
        sessionID: "test-session",
        callID: "test-call",
      },
      { args },
    )
    expect(args.timeout).toBe(600_000)
  })

  test("still blocks destructive commands before touching timeout", async () => {
    const hook = await beforeHook({ cloudReviewEnabled: false })
    const args: Record<string, unknown> = { command: "rm -rf /", timeout: 600_000 }
    await expect(
      hook(
        {
          tool: "bash",
          sessionID: "test-session",
          callID: "test-call",
        },
        { args },
      ),
    ).rejects.toThrow("blocked")
    expect(args.timeout).toBe(600_000)
  })

  test("isolates detached start commands so the pipe is not held open", async () => {
    const hook = await beforeHook({
      cloudReviewEnabled: false,
      hardTimeoutMs: 0,
      shell: "C:/msys64/usr/bin/bash.exe",
    })
    const cases: Array<[string, string]> = [
      [
        'start "" "C:/Program Files/Docker/Docker/Docker Desktop.exe" && echo LAUNCHED',
        'start "" "C:/Program Files/Docker/Docker/Docker Desktop.exe" >/dev/null 2>&1 && echo LAUNCHED',
      ],
      ["start foo", "start foo >/dev/null 2>&1"],
      ["cmd //c start foo", "cmd //c start foo >/dev/null 2>&1"],
      ["Start-Process foo", "Start-Process foo >/dev/null 2>&1"],
      ["Start-Process foo && echo done", "Start-Process foo >/dev/null 2>&1 && echo done"],
      ["Start-Job { Start-Sleep 5 }", "Start-Job { Start-Sleep 5 } >/dev/null 2>&1"],
    ]
    for (const [command, expected] of cases) {
      const args: Record<string, unknown> = { command }
      await hook(
        {
          tool: "bash",
          sessionID: "test-session",
          callID: "test-call",
        },
        { args },
      )
      expect(args.command, command).toBe(expected)
    }
  })

  test("uses PowerShell null redirection for detached starts on pwsh", async () => {
    const hook = await beforeHook({
      cloudReviewEnabled: false,
      hardTimeoutMs: 0,
      shell: "C:/Program Files/PowerShell/7/pwsh.exe",
    })
    const args: Record<string, unknown> = { command: "Start-Process foo" }
    await hook(
      {
        tool: "bash",
        sessionID: "test-session",
        callID: "test-call",
      },
      { args },
    )
    expect(args.command).toBe("Start-Process foo > $null 2>&1")
  })

  test("does not touch commands that are not detached starts", async () => {
    const hook = await beforeHook({ cloudReviewEnabled: false, hardTimeoutMs: 0 })
    const commands = [
      "npm start",
      "docker start container-a",
      "git status && ls -la",
      "start foo > log.txt",
      "start foo 2> err.txt",
      "python server.py",
    ]
    for (const command of commands) {
      const args: Record<string, unknown> = { command }
      await hook(
        {
          tool: "bash",
          sessionID: "test-session",
          callID: "test-call",
        },
        { args },
      )
      expect(args.command, command).toBe(command)
    }
  })

  test("disables detached start isolation when configured off", async () => {
    const hook = await beforeHook({ cloudReviewEnabled: false, detachedStartIsolation: false })
    const args: Record<string, unknown> = { command: "start foo" }
    await hook(
      {
        tool: "bash",
        sessionID: "test-session",
        callID: "test-call",
      },
      { args },
    )
    expect(args.command).toBe("start foo")
  })

  test("wraps non-download/build commands with a shell timeout as the real fallback", async () => {
    const hook = await beforeHook({
      cloudReviewEnabled: false,
      shell: "C:/msys64/usr/bin/bash.exe",
    })
    const cases: Array<[string, string]> = [
      ["ls -la", "timeout -k 3 120s ls -la"],
      [
        'ollama list 2>&1 | head -30; echo "---ENV---"; env | grep -i ollama',
        'timeout -k 3 120s ollama list 2>&1 | head -30; echo "---ENV---"; env | grep -i ollama',
      ],
      ["cd /tmp && ollama list", "cd /tmp && timeout -k 3 120s ollama list"],
      ["timeout 30 ping 1.1.1.1", "timeout 30 ping 1.1.1.1"],
      ["start foo && echo done", "timeout -k 3 120s start foo >/dev/null 2>&1 && echo done"],
    ]
    for (const [command, expected] of cases) {
      const args: Record<string, unknown> = { command }
      await hook(
        {
          tool: "bash",
          sessionID: "test-session",
          callID: "test-call",
        },
        { args },
      )
      expect(args.command, command).toBe(expected)
    }
  })

  test("does not wrap downloads, builds, or PowerShell shells", async () => {
    const hook = await beforeHook({ cloudReviewEnabled: false })
    const commands = [
      "npm install",
      "curl -fsSL https://example.com/x",
      "npm run build",
      "git clone https://github.com/a/b.git",
    ]
    for (const command of commands) {
      const args: Record<string, unknown> = { command }
      await hook(
        {
          tool: "bash",
          sessionID: "test-session",
          callID: "test-call",
        },
        { args },
      )
      expect(args.command, command).toBe(command)
    }

    const pwsh = await beforeHook({
      cloudReviewEnabled: false,
      shell: "C:/Program Files/PowerShell/7/pwsh.exe",
    })
    const psArgs: Record<string, unknown> = { command: "Get-ChildItem" }
    await pwsh(
      {
        tool: "bash",
        sessionID: "test-session",
        callID: "test-call",
      },
      { args: psArgs },
    )
    expect(psArgs.command).toBe("Get-ChildItem")
  })
})
