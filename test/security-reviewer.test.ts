import { describe, expect, test } from "bun:test"
import { normalizeReviewRequest, parseReviewResult } from "../src/security/reviewer"

describe("DeepSeek reviewer result validation", () => {
  test("accepts ALLOW only with an empty reason", () => {
    expect(
      parseReviewResult(
        JSON.stringify({
          decision: "ALLOW",
          reason: "",
        }),
      ),
    ).toEqual({
      decision: "ALLOW",
      reason: "",
    })

    expect(() =>
      parseReviewResult(
        JSON.stringify({
          decision: "ALLOW",
          reason: "The operation is read-only.",
        }),
      ),
    ).toThrow("reason for ALLOW")
  })

  test("accepts DENY only with a non-empty reason", () => {
    const result = parseReviewResult(
      JSON.stringify({
        decision: "DENY",
        reason: "Deletes durable project data.",
      }),
    )
    expect(result).toEqual({
      decision: "DENY",
      reason: "Deletes durable project data.",
    })

    expect(() =>
      parseReviewResult(
        JSON.stringify({
          decision: "DENY",
          reason: "",
        }),
      ),
    ).toThrow("empty reason for DENY")
  })

  test("rejects non-binary decisions and unexpected fields", () => {
    expect(() =>
      parseReviewResult(
        JSON.stringify({
          decision: "USER_CONFIRM",
          reason: "Ask the user.",
        }),
      ),
    ).toThrow()
    expect(() =>
      parseReviewResult(
        JSON.stringify({
          decision: "ALLOW",
          reason: "",
          confidence: 1,
        }),
      ),
    ).toThrow("unexpected fields")
  })

  test("normalizes legacy command strings into structured review requests", () => {
    expect(normalizeReviewRequest("git status")).toEqual({
      command: "git status",
      localScripts: [],
      uninspectedLocalScripts: [],
      targetDirectories: [],
      uninspectedTargetDirectories: [],
    })
  })
})
