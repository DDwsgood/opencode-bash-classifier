import { spawn } from "node:child_process"
import { once } from "node:events"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import os from "node:os"
import path from "node:path"

const executable = process.argv[2]
if (!executable) throw new Error("usage: node test/integration.mjs <supervisor.exe>")

// The caller must point at the real Bash executable; no machine-specific default
// is permitted so the test never accidentally exercises a foreign shell.
const realBash = process.env.OPENCODE_REAL_BASH
if (!realBash) {
  throw new Error("OPENCODE_REAL_BASH must be set to the real Bash executable path before running the integration test")
}
const environment = { ...process.env, OPENCODE_REAL_BASH: realBash }

function run(file, args, options = {}) {
  const started = performance.now()
  const child = spawn(file, args, {
    env: environment,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
  })
  let stdout = ""
  let stderr = ""
  child.stdout.on("data", (chunk) => (stdout += chunk))
  child.stderr.on("data", (chunk) => (stderr += chunk))
  return {
    child,
    result: once(child, "close").then(([code, signal]) => ({
      code,
      signal,
      stdout,
      stderr,
      elapsedMs: performance.now() - started,
    })),
  }
}

function runThroughShell(command) {
  return run(command, [], { shell: executable })
}

function runInteractive(input) {
  const started = performance.now()
  const child = spawn(executable, ["-i"], {
    env: environment,
    windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"],
  })
  let stdout = ""
  let stderr = ""
  child.stdout.on("data", (chunk) => (stdout += chunk))
  child.stderr.on("data", (chunk) => (stderr += chunk))
  child.stdin.end(input)
  return once(child, "close").then(([code, signal]) => ({
    code,
    signal,
    stdout,
    stderr,
    elapsedMs: performance.now() - started,
  }))
}

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

async function processExists(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

async function waitForFile(file, timeoutMs) {
  const deadline = performance.now() + timeoutMs
  while (performance.now() < deadline) {
    try {
      return await readFile(file, "utf8")
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 25))
    }
  }
  throw new Error(`timed out waiting for ${file}`)
}

const temp = await mkdtemp(path.join(os.tmpdir(), "opencode-supervisor-test-"))
try {
  const passthrough = run(executable, ["-c", "printf 'OUT'; printf 'ERR' >&2; exit 7"])
  const passthroughResult = await passthrough.result
  assert(passthroughResult.code === 7, `expected exit 7, got ${passthroughResult.code}`)
  assert(passthroughResult.stdout === "OUT", `unexpected stdout: ${JSON.stringify(passthroughResult.stdout)}`)
  assert(passthroughResult.stderr === "ERR", `unexpected stderr: ${JSON.stringify(passthroughResult.stderr)}`)

  const throughShell = runThroughShell("printf 'SHELL'; printf 'ERROR' >&2; exit 9")
  const throughShellResult = await throughShell.result
  assert(throughShellResult.code === 9, `shell mode expected exit 9, got ${throughShellResult.code}`)
  assert(throughShellResult.stdout === "SHELL", `shell mode stdout mismatch: ${JSON.stringify(throughShellResult.stdout)}`)
  assert(throughShellResult.stderr === "ERROR", `shell mode stderr mismatch: ${JSON.stringify(throughShellResult.stderr)}`)

  const interactiveResult = await runInteractive("printf 'PTY'; exit 11\n")
  assert(interactiveResult.code === 11, `interactive mode expected exit 11, got ${interactiveResult.code}`)
  assert(interactiveResult.stdout.includes("PTY"), `interactive stdin/stdout was not inherited: ${JSON.stringify(interactiveResult.stdout)}`)

  const invalidBash = run(executable, ["-c", "printf unreachable"], {
    env: { ...environment, OPENCODE_REAL_BASH: path.join(temp, "missing-bash.exe") },
  })
  const invalidBashResult = await invalidBash.result
  assert(invalidBashResult.code === 125, `invalid bash expected exit 125, got ${invalidBashResult.code}`)
  assert(invalidBashResult.stderr.includes("Win32 error"), `invalid bash omitted diagnostics: ${JSON.stringify(invalidBashResult.stderr)}`)

  const largeOutput = run(executable, [
    "-c",
    "head -c 262144 /dev/zero; head -c 262144 /dev/zero >&2",
  ])
  const largeOutputResult = await largeOutput.result
  assert(largeOutputResult.code === 0, `large output exited ${largeOutputResult.code}`)
  assert(largeOutputResult.stdout.length === 262_144, `stdout truncated at ${largeOutputResult.stdout.length}`)
  assert(largeOutputResult.stderr.length === 262_144, `stderr truncated at ${largeOutputResult.stderr.length}`)

  const heldPipeCommand = "(sleep 2; printf late) & printf ready"
  const direct = run(realBash, ["-c", heldPipeCommand])
  const directResult = await direct.result
  const supervised = run(executable, ["-c", heldPipeCommand])
  const supervisedResult = await supervised.result
  assert(directResult.elapsedMs >= 1_500, `baseline did not reproduce pipe hold: ${directResult.elapsedMs.toFixed(0)}ms`)
  assert(supervisedResult.elapsedMs < 2_000, `supervisor remained pipe-bound: ${supervisedResult.elapsedMs.toFixed(0)}ms`)
  assert(supervisedResult.elapsedMs + 500 < directResult.elapsedMs, "supervisor did not materially beat inherited-pipe baseline")
  assert(supervisedResult.stdout.startsWith("ready"), `missing foreground output: ${JSON.stringify(supervisedResult.stdout)}`)

  const survivorFile = path.join(temp, "detached-survived.txt").replaceAll("\\", "/")
  const survivorProgram = `setTimeout(()=>require('fs').writeFileSync(${JSON.stringify(survivorFile)},'yes'),800)`
  const detached = run(executable, ["-c", `node -e ${JSON.stringify(survivorProgram)} & printf detached`])
  const detachedResult = await detached.result
  assert(detachedResult.elapsedMs < 2_000, `normal detached launch returned too slowly: ${detachedResult.elapsedMs.toFixed(0)}ms`)
  assert(detachedResult.stdout.startsWith("detached"), `detached foreground output missing: ${JSON.stringify(detachedResult.stdout)}`)
  assert((await waitForFile(survivorFile, 3_000)) === "yes", "normal completion killed the intended detached child")

  const pidFile = path.join(temp, "child.pid").replaceAll("\\", "/")
  const nodeProgram = `require('fs').writeFileSync(${JSON.stringify(pidFile)},String(process.pid));setInterval(()=>{},1000)`
  const longRunning = run(executable, ["-c", `node -e ${JSON.stringify(nodeProgram)}`])
  const childPid = Number.parseInt(await waitForFile(pidFile, 5_000), 10)
  assert(Number.isInteger(childPid) && childPid > 0, `invalid child pid: ${childPid}`)
  assert(await processExists(childPid), `child ${childPid} was not running before supervisor termination`)

  const killed = spawn("taskkill.exe", ["/PID", String(longRunning.child.pid), "/F"], {
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  })
  const [taskkillCode] = await once(killed, "close")
  assert(taskkillCode === 0, `taskkill failed with ${taskkillCode}`)
  const killedResult = await Promise.race([
    longRunning.result,
    new Promise((_, reject) => setTimeout(() => reject(new Error("supervisor pipe did not close after forced termination")), 3_000)),
  ])
  assert(killedResult.elapsedMs < 6_000, `forced termination returned too slowly: ${killedResult.elapsedMs.toFixed(0)}ms`)

  const deadline = performance.now() + 3_000
  while ((await processExists(childPid)) && performance.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 25))
  }
  assert(!(await processExists(childPid)), `job child ${childPid} survived supervisor termination`)

  console.log(JSON.stringify({
    passthrough: passthroughResult,
    throughShell: throughShellResult,
    interactive: {
      code: interactiveResult.code,
      stdoutContainsPty: interactiveResult.stdout.includes("PTY"),
    },
    largeOutputBytes: {
      stdout: largeOutputResult.stdout.length,
      stderr: largeOutputResult.stderr.length,
    },
    directHeldPipeMs: Math.round(directResult.elapsedMs),
    supervisedHeldPipeMs: Math.round(supervisedResult.elapsedMs),
    detachedSurvived: true,
    forcedTerminationMs: Math.round(killedResult.elapsedMs),
    killedChildPid: childPid,
  }, null, 2))
} finally {
  await rm(temp, { recursive: true, force: true })
}
