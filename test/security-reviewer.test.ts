import { describe, expect, test } from "bun:test"
import { once } from "node:events"
import { createServer } from "node:http"
import os from "node:os"
import {
  normalizeReviewRequest,
  parseReviewResult,
  requestForPolicy,
  reviewerEnvironment,
  reviewCommandWithAuditor,
  type CloudReviewRequest,
} from "../src/security/reviewer"

const baseRequest = (): CloudReviewRequest => ({
  command: "git status",
  localScripts: [],
  uninspectedLocalScripts: [],
  targetDirectories: [],
  uninspectedTargetDirectories: [],
  referencedPaths: [],
  referencedPathsTruncated: false,
  worktree: process.cwd(),
  cwd: process.cwd(),
})

describe("policy-specific result validation", () => {
  test("accepts exactly the two-field relaxed result", () => {
    expect(parseReviewResult('{"decision":"ALLOW","reason":""}', "LOOSE")).toEqual({ decision: "ALLOW", reason: "" })
    expect(parseReviewResult('{"decision":"DENY","reason":"Deletes durable data"}', "LOOSE")).toEqual({ decision: "DENY", reason: "Deletes durable data" })
  })

  test("accepts exactly the three-field strict result", () => {
    expect(parseReviewResult('{"decision":"DENY","reason":"Deletes durable data","bypassing":true}', "HARD")).toEqual({ decision: "DENY", reason: "Deletes durable data", bypassing: true })
  })

  test("rejects missing, extra, duplicate, and wrongly typed policy fields", () => {
    expect(() => parseReviewResult('{"decision":"ALLOW","reason":"","bypassing":false}', "LOOSE")).toThrow(/unexpected/)
    expect(() => parseReviewResult('{"decision":"ALLOW","reason":""}', "HARD")).toThrow(/unexpected/)
    expect(() => parseReviewResult('{"decision":"ALLOW","reason":"","bypassing":"false"}', "HARD")).toThrow(/bypassing/)
    expect(() => parseReviewResult('{"decision":"ALLOW","decision":"DENY","reason":""}', "LOOSE")).toThrow(/duplicate/)
    expect(() => parseReviewResult('{"decision":"DENY","reason":"x","extra":1}', "LOOSE")).toThrow(/unexpected/)
  })

  test("enforces reason semantics and normalization", () => {
    expect(() => parseReviewResult('{"decision":"ALLOW","reason":"ok"}', "LOOSE")).toThrow(/reason for ALLOW/)
    expect(() => parseReviewResult('{"decision":"DENY","reason":""}', "LOOSE")).toThrow(/empty reason/)
    const result = parseReviewResult(JSON.stringify({ decision: "DENY", reason: "word \n".repeat(50) }), "LOOSE")
    expect(result.reason.length).toBeLessThanOrEqual(80)
    expect(result.reason).not.toContain("\n")
  })
})

describe("request and trusted routing", () => {
  test("normalizes legacy strings without exposing a policy field", () => {
    const normalized = normalizeReviewRequest("git status")
    expect(normalized.referencedPaths).toEqual([])
    expect(normalized.referencedPathsTruncated).toBe(false)
    expect(normalized.cwd).toBe(process.cwd())
    expect(normalized).not.toHaveProperty("strictness")
  })

  test("removes previous rejection from relaxed user JSON only", () => {
    const request = { ...baseRequest(), previousRejectedCommand: { command: "rm x", reason: "Deletes data", classifier: "DYNAMIC" as const } }
    expect(requestForPolicy(request, "LOOSE")).not.toHaveProperty("previousRejectedCommand")
    expect(requestForPolicy(request, "HARD")).toEqual(request)
  })

  test("sanitizes legacy mode fields and supplies referenced-path defaults", () => {
    const legacy = { ...baseRequest(), strictness: "HARD" } as CloudReviewRequest & { strictness: string }
    delete (legacy as Partial<CloudReviewRequest>).referencedPaths
    delete (legacy as Partial<CloudReviewRequest>).referencedPathsTruncated
    const normalized = requestForPolicy(legacy, "HARD")
    expect(normalized).not.toHaveProperty("strictness")
    expect(normalized.referencedPaths).toEqual([])
    expect(normalized.referencedPathsTruncated).toBe(false)
  })

  test("routes policy, access, and canonical temp roots only through env", () => {
    const env = reviewerEnvironment({ endpoint: "https://example.com", model: "m", apiKey: "k", maxRounds: 2, policy: "HARD", allowFullReadAccess: true })
    expect(env.OPENCODE_BASH_REVIEW_POLICY).toBe("HARD")
    expect(env.OPENCODE_BASH_REVIEW_FULL_READ).toBe("1")
    expect(JSON.parse(env.OPENCODE_BASH_REVIEW_TEMP_ROOTS!)).toContain(os.tmpdir())
    expect(env.HOME).toBeUndefined()
  })
})

describe("auditor subprocess integration", () => {
  test("keeps policy and access out of user JSON and allows one extra final request", async () => {
    const payloads: Array<Record<string, unknown>> = []
    let count = 0
    const server = createServer(async (request, response) => {
      let body = ""
      for await (const chunk of request) body += chunk.toString()
      payloads.push(JSON.parse(body))
      count++
      const message = count === 1
        ? { role: "assistant", content: null, tool_calls: [{ id: "c1", type: "function", function: { name: "read_file", arguments: JSON.stringify({ path: "test/fixtures/safe_agent_script.py" }) } }] }
        : { role: "assistant", content: '{"decision":"ALLOW","reason":""}' }
      response.writeHead(200, { "content-type": "application/json" })
      response.end(JSON.stringify({ choices: [{ finish_reason: count === 1 ? "tool_calls" : "stop", message }] }))
    })
    server.listen(0, "127.0.0.1")
    await once(server, "listening")
    try {
      const address = server.address()
      if (!address || typeof address === "string") throw new Error("no port")
      const result = await reviewCommandWithAuditor({ ...baseRequest(), command: "python test/fixtures/safe_agent_script.py", uninspectedLocalScripts: ["test/fixtures/safe_agent_script.py"], previousRejectedCommand: { command: "rm x", reason: "Deletes data", classifier: "DYNAMIC" } }, {
        endpoint: `http://127.0.0.1:${address.port}/v1/chat/completions`, model: "mock", apiKey: "test", maxRounds: 1, policy: "LOOSE", timeout: 10_000,
      })
      expect(result).toEqual({ decision: "ALLOW", reason: "" })
      expect(payloads).toHaveLength(2)
      expect(payloads[0]?.tools).toBeArray()
      expect(payloads[1]?.tools).toBeUndefined()
      const user = (payloads[0]?.messages as Array<{ role: string; content: string }>).find((message) => message.role === "user")!
      const input = JSON.parse(user.content)
      expect(input).not.toHaveProperty("strictness")
      expect(input).not.toHaveProperty("policy")
      expect(input).not.toHaveProperty("allowFullReadAccess")
      expect(input).not.toHaveProperty("previousRejectedCommand")
    } finally {
      server.close()
      await once(server, "close")
    }
  }, 20_000)
})
